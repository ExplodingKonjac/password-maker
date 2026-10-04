use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::model::{MAX_KEYWORD_BYTES, OptionsError, PasswordOptions};

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;=?@[]^_{|}~";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GenerationError {
    #[error("keyword must not be empty")]
    EmptyKeyword,
    #[error("keyword is longer than {MAX_KEYWORD_BYTES} UTF-8 bytes")]
    KeywordTooLong,
    #[error(transparent)]
    InvalidOptions(#[from] OptionsError),
}

pub fn generate_password(
    generation_key: &[u8; 32],
    keyword: &str,
    options: PasswordOptions,
) -> Result<String, GenerationError> {
    if keyword.len() > MAX_KEYWORD_BYTES {
        return Err(GenerationError::KeywordTooLong);
    }
    let normalized_keyword = Zeroizing::new(keyword.nfc().collect::<String>());
    if normalized_keyword.is_empty() {
        return Err(GenerationError::EmptyKeyword);
    }
    if normalized_keyword.len() > MAX_KEYWORD_BYTES {
        return Err(GenerationError::KeywordTooLong);
    }
    options.validate()?;

    let mut canonical = Zeroizing::new(Vec::with_capacity(32 + normalized_keyword.len()));
    canonical.extend_from_slice(b"password-maker/generator/v1\0");
    canonical.push(options.algorithm_version);
    canonical.push(options.alphabet_version);
    canonical.push(options.flags());
    canonical.extend_from_slice(&options.length.to_be_bytes());
    canonical.extend_from_slice(&(normalized_keyword.len() as u32).to_be_bytes());
    canonical.extend_from_slice(normalized_keyword.as_bytes());

    let digest = blake3::keyed_hash(generation_key, &canonical);
    let mut rng = ChaCha20Rng::from_seed(*digest.as_bytes());

    let mut selected_classes = Vec::with_capacity(options.selected_class_count() as usize);
    if options.lowercase {
        selected_classes.push(LOWERCASE);
    }
    if options.uppercase {
        selected_classes.push(UPPERCASE);
    }
    if options.numbers {
        selected_classes.push(NUMBERS);
    }
    if options.symbols {
        selected_classes.push(SYMBOLS);
    }

    let mut combined = Vec::new();
    for class in &selected_classes {
        combined.extend_from_slice(class);
    }

    let mut password = Zeroizing::new(Vec::with_capacity(options.length as usize));
    for class in selected_classes {
        password.push(class[bounded_index(&mut rng, class.len())]);
    }
    while password.len() < options.length as usize {
        password.push(combined[bounded_index(&mut rng, combined.len())]);
    }

    for index in (1..password.len()).rev() {
        let swap_index = bounded_index(&mut rng, index + 1);
        password.swap(index, swap_index);
    }

    Ok(String::from_utf8(password.to_vec()).expect("alphabet is ASCII"))
}

fn bounded_index(rng: &mut ChaCha20Rng, upper_bound: usize) -> usize {
    debug_assert!(upper_bound > 0);
    let upper_bound = upper_bound as u32;
    let zone = u32::MAX - (u32::MAX % upper_bound);
    loop {
        let value = rng.next_u32();
        if value < zone {
            return (value % upper_bound) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn generation_is_deterministic() {
        let options = PasswordOptions::default();
        let first = generate_password(&KEY, "example", options).unwrap();
        let second = generate_password(&KEY, "example", options).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, "7rSFInA0DzYyJ3;}");
        assert_eq!(first.len(), 16);
    }

    #[test]
    fn every_selected_class_is_present() {
        let options = PasswordOptions {
            length: 8,
            ..PasswordOptions::default()
        };
        let password = generate_password(&KEY, "example", options).unwrap();
        assert!(password.bytes().any(|c| c.is_ascii_lowercase()));
        assert!(password.bytes().any(|c| c.is_ascii_uppercase()));
        assert!(password.bytes().any(|c| c.is_ascii_digit()));
        assert!(password.bytes().any(|c| SYMBOLS.contains(&c)));
    }

    #[test]
    fn equivalent_nfc_keywords_have_the_same_result() {
        let options = PasswordOptions::default();
        let composed = generate_password(&KEY, "café", options).unwrap();
        let decomposed = generate_password(&KEY, "cafe\u{301}", options).unwrap();
        assert_eq!(composed, decomposed);
    }

    #[test]
    fn invalid_options_are_rejected() {
        let no_classes = PasswordOptions {
            lowercase: false,
            uppercase: false,
            numbers: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert_eq!(
            generate_password(&KEY, "example", no_classes),
            Err(GenerationError::InvalidOptions(
                OptionsError::NoCharacterClasses
            ))
        );

        let too_short = PasswordOptions {
            length: 8,
            lowercase: true,
            uppercase: true,
            numbers: true,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert!(generate_password(&KEY, "example", too_short).is_ok());
    }

    #[test]
    fn keyword_is_required() {
        assert_eq!(
            generate_password(&KEY, "", PasswordOptions::default()),
            Err(GenerationError::EmptyKeyword)
        );
    }
}
