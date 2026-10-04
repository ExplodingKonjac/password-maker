use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use directories::ProjectDirs;
use getrandom::fill as fill_random;
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::{
    crypto::{self, VaultCryptoError},
    model::VaultPayload,
};

const VAULT_FILENAME: &str = "vault.pmv";
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("could not determine the application data directory")]
    NoDataDirectory,
    #[error("vault already exists")]
    AlreadyExists,
    #[error("vault file is too large")]
    FileTooLarge,
    #[error("vault file is missing")]
    Missing,
    #[error("storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Crypto(#[from] VaultCryptoError),
}

#[derive(Clone, Debug)]
pub struct VaultStore {
    path: PathBuf,
}

impl VaultStore {
    pub fn default_location() -> Result<Self, StorageError> {
        let project_dirs = ProjectDirs::from("com", "Password Maker", "Password Maker")
            .ok_or(StorageError::NoDataDirectory)?;
        Ok(Self::at(project_dirs.data_dir().join(VAULT_FILENAME)))
    }

    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    pub fn create(&self, password: &str) -> Result<VaultPayload, StorageError> {
        if self.exists() {
            return Err(StorageError::AlreadyExists);
        }
        let mut generation_key = [0u8; 32];
        fill_random(&mut generation_key).map_err(|_| StorageError::Crypto(VaultCryptoError::Randomness))?;
        let payload = VaultPayload::new(generation_key);
        self.save(password, &payload)?;
        Ok(payload)
    }

    pub fn load(&self, password: &str) -> Result<VaultPayload, StorageError> {
        let bytes = read_limited(&self.path)?;
        Ok(crypto::open(password, &bytes)?)
    }

    pub fn save(&self, password: &str, payload: &VaultPayload) -> Result<(), StorageError> {
        let bytes = crypto::seal(password, payload)?;
        write_atomic(&self.path, &bytes)
    }

    pub fn export(
        &self,
        password: &str,
        payload: &VaultPayload,
        destination: &Path,
    ) -> Result<(), StorageError> {
        let bytes = crypto::seal(password, payload)?;
        write_atomic(destination, &bytes)
    }

    pub fn import(&self, password: &str, source: &Path) -> Result<VaultPayload, StorageError> {
        let bytes = read_limited(source)?;
        Ok(crypto::open(password, &bytes)?)
    }
}

fn read_limited(path: &Path) -> Result<Vec<u8>, StorageError> {
    if !path.is_file() {
        return Err(StorageError::Missing);
    }
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_VAULT_BYTES {
        return Err(StorageError::FileTooLarge);
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "vault path has no parent")
    })?;
    fs::create_dir_all(parent)?;

    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let temporary_path = temporary.into_temp_path();

    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }

    fs::rename(&temporary_path, path)?;
    Ok(temporary_path.keep().map(|_| ()).map_err(|error| error.error)?)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn create_and_load_round_trip() {
        let directory = tempdir().unwrap();
        let store = VaultStore::at(directory.path().join("vault.pmv"));
        let created = store.create("correct horse battery staple").unwrap();
        let loaded = store.load("correct horse battery staple").unwrap();
        assert_eq!(loaded, created);
        assert!(store.exists());
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let directory = tempdir().unwrap();
        let store = VaultStore::at(directory.path().join("vault.pmv"));
        store.create("correct horse battery staple").unwrap();
        assert!(matches!(
            store.create("correct horse battery staple"),
            Err(StorageError::AlreadyExists)
        ));
    }

    #[test]
    fn export_and_import_round_trip() {
        let directory = tempdir().unwrap();
        let store = VaultStore::at(directory.path().join("vault.pmv"));
        let export_path = directory.path().join("backup.pmv");
        let created = store.create("correct horse battery staple").unwrap();
        store
            .export("correct horse battery staple", &created, &export_path)
            .unwrap();
        let imported = store
            .import("correct horse battery staple", &export_path)
            .unwrap();
        assert_eq!(imported, created);
    }

    #[test]
    fn missing_vault_is_reported() {
        let directory = tempdir().unwrap();
        let store = VaultStore::at(directory.path().join("missing.pmv"));
        assert!(matches!(
            store.load("correct horse battery staple"),
            Err(StorageError::Missing)
        ));
    }
}
