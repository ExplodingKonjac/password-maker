use std::convert::TryInto;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::fill as fill_random;
use postcard::{from_bytes, to_allocvec};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::model::VaultPayload;

const MAGIC: &[u8; 4] = b"PMV1";
const FORMAT_VERSION: u16 = 1;
const KDF_ID_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const HEADER_LEN: usize = 4 + 2 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VaultCryptoError {
    #[error("hyper password must contain at least 12 Unicode characters")]
    HyperPasswordTooShort,
    #[error("hyper password is too long")]
    HyperPasswordTooLong,
    #[error("randomness provider failed")]
    Randomness,
    #[error("invalid vault envelope")]
    InvalidEnvelope,
    #[error("unsupported vault format version")]
    UnsupportedVersion,
    #[error("invalid Argon2 parameters")]
    InvalidKdfParameters,
    #[error("vault authentication failed")]
    AuthenticationFailed,
    #[error("vault payload serialization failed")]
    Serialization,
    #[error("vault payload schema is unsupported")]
    UnsupportedSchema,
}

pub fn validate_hyper_password(password: &str) -> Result<(), VaultCryptoError> {
    if password.chars().count() < 12 {
        return Err(VaultCryptoError::HyperPasswordTooShort);
    }
    if password.len() > 4096 {
        return Err(VaultCryptoError::HyperPasswordTooLong);
    }
    Ok(())
}

pub fn seal(password: &str, payload: &VaultPayload) -> Result<Vec<u8>, VaultCryptoError> {
    validate_hyper_password(password)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut salt).map_err(|_| VaultCryptoError::Randomness)?;
    fill_random(&mut nonce).map_err(|_| VaultCryptoError::Randomness)?;

    let header = encode_header(&salt, &nonce);
    let key = derive_key(password.as_bytes(), &salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let plaintext =
        Zeroizing::new(to_allocvec(payload).map_err(|_| VaultCryptoError::Serialization)?);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| VaultCryptoError::AuthenticationFailed)?;

    let mut envelope = header;
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

pub fn open(password: &str, envelope: &[u8]) -> Result<VaultPayload, VaultCryptoError> {
    validate_hyper_password(password)?;
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(VaultCryptoError::InvalidEnvelope);
    }

    let header = &envelope[..HEADER_LEN];
    if &header[..4] != MAGIC {
        return Err(VaultCryptoError::InvalidEnvelope);
    }
    let version = u16::from_be_bytes(header[4..6].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Err(VaultCryptoError::UnsupportedVersion);
    }
    if header[6] != KDF_ID_ARGON2ID {
        return Err(VaultCryptoError::InvalidEnvelope);
    }

    let memory = u32::from_be_bytes(header[7..11].try_into().unwrap());
    let iterations = u32::from_be_bytes(header[11..15].try_into().unwrap());
    let parallelism = u32::from_be_bytes(header[15..19].try_into().unwrap());
    validate_kdf_parameters(memory, iterations, parallelism)?;

    let salt: [u8; SALT_LEN] = header[19..35].try_into().unwrap();
    let nonce: [u8; NONCE_LEN] = header[35..59].try_into().unwrap();
    let key =
        derive_key_with_parameters(password.as_bytes(), &salt, memory, iterations, parallelism)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &envelope[HEADER_LEN..],
                    aad: header,
                },
            )
            .map_err(|_| VaultCryptoError::AuthenticationFailed)?,
    );
    let payload: VaultPayload =
        from_bytes(&plaintext).map_err(|_| VaultCryptoError::Serialization)?;
    if payload.schema_version != VaultPayload::CURRENT_SCHEMA_VERSION {
        return Err(VaultCryptoError::UnsupportedSchema);
    }
    Ok(payload)
}

fn encode_header(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    header.push(KDF_ID_ARGON2ID);
    header.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    header.extend_from_slice(&ARGON2_ITERATIONS.to_be_bytes());
    header.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    header
}

fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; 32]>, VaultCryptoError> {
    derive_key_with_parameters(
        password,
        salt,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
    )
}

fn derive_key_with_parameters(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    memory: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>, VaultCryptoError> {
    validate_kdf_parameters(memory, iterations, parallelism)?;
    let params = Params::new(memory, iterations, parallelism, Some(32))
        .map_err(|_| VaultCryptoError::InvalidKdfParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| VaultCryptoError::AuthenticationFailed)?;
    Ok(key)
}

fn validate_kdf_parameters(
    memory: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), VaultCryptoError> {
    if !(32 * 1024..=512 * 1024).contains(&memory)
        || !(1..=10).contains(&iterations)
        || !(1..=16).contains(&parallelism)
    {
        return Err(VaultCryptoError::InvalidKdfParameters);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> VaultPayload {
        VaultPayload::new([7u8; 32])
    }

    #[test]
    fn round_trip_preserves_payload() {
        let original = payload();
        let envelope = seal("correct horse battery staple", &original).unwrap();
        let restored = open("correct horse battery staple", &envelope).unwrap();
        assert_eq!(restored, original);
        assert_eq!(&envelope[..4], MAGIC);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let envelope = seal("correct horse battery staple", &payload()).unwrap();
        assert_eq!(
            open("a different password", &envelope),
            Err(VaultCryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let mut envelope = seal("correct horse battery staple", &payload()).unwrap();
        envelope[HEADER_LEN + 2] ^= 0x80;
        assert_eq!(
            open("correct horse battery staple", &envelope),
            Err(VaultCryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn short_password_is_rejected() {
        assert_eq!(
            seal("too short", &payload()),
            Err(VaultCryptoError::HyperPasswordTooShort)
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut envelope = seal("correct horse battery staple", &payload()).unwrap();
        envelope[4] = 0;
        envelope[5] = 2;
        assert_eq!(
            open("correct horse battery staple", &envelope),
            Err(VaultCryptoError::UnsupportedVersion)
        );
    }
}
