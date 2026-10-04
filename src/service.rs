use crate::{
    crypto::{VaultCryptoError, validate_hyper_password},
    generator::{GenerationError, generate_password},
    model::{MAX_KEYWORD_BYTES, PasswordOptions, VaultEntry, VaultPayload, VaultSettings},
    storage::{StorageError, VaultStore},
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Unlock the vault first.")]
    Locked,
    #[error("Entry not found.")]
    NotFound,
    #[error("Use a label between 1 and 256 bytes.")]
    InvalidLabel,
    #[error("Unable to unlock vault. Check the password and file.")]
    Unlock,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Generation(#[from] GenerationError),
    #[error(transparent)]
    Crypto(#[from] VaultCryptoError),
    #[error("Choose an auto-lock timeout of 1, 5, 15, 30 minutes, or never.")]
    InvalidTimeout,
    #[error("Choose a backup file separate from the active vault.")]
    ActiveVaultDestination,
}
struct Session {
    password: Zeroizing<String>,
    payload: VaultPayload,
}
pub struct VaultService {
    store: VaultStore,
    session: Option<Session>,
}
impl VaultService {
    pub fn new(store: VaultStore) -> Self {
        Self {
            store,
            session: None,
        }
    }
    pub fn create(&mut self, password: Zeroizing<String>) -> Result<(), ServiceError> {
        let payload = self.store.create(&password)?;
        self.session = Some(Session { password, payload });
        Ok(())
    }
    pub fn unlock(&mut self, password: Zeroizing<String>) -> Result<(), ServiceError> {
        let payload = self
            .store
            .load(&password)
            .map_err(|_| ServiceError::Unlock)?;
        validate_payload(&payload)?;
        self.session = Some(Session { password, payload });
        Ok(())
    }
    pub fn lock(&mut self) {
        self.session = None;
    }
    fn session(&self) -> Result<&Session, ServiceError> {
        self.session.as_ref().ok_or(ServiceError::Locked)
    }
    pub fn entries(&self) -> Result<Vec<VaultEntry>, ServiceError> {
        Ok(self.session()?.payload.entries.clone())
    }
    pub fn settings(&self) -> Result<VaultSettings, ServiceError> {
        Ok(self.session()?.payload.settings.clone())
    }
    pub fn entry(&self, id: Uuid) -> Result<VaultEntry, ServiceError> {
        self.session()?
            .payload
            .entries
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .ok_or(ServiceError::NotFound)
    }
    pub fn generate(
        &self,
        keyword: &str,
        options: PasswordOptions,
    ) -> Result<Zeroizing<String>, ServiceError> {
        Ok(Zeroizing::new(generate_password(
            &self.session()?.payload.generation_key,
            keyword,
            options,
        )?))
    }
    pub fn save_entry(
        &mut self,
        id: Option<Uuid>,
        label: String,
        keyword: Zeroizing<String>,
        options: PasswordOptions,
    ) -> Result<(), ServiceError> {
        if label.trim().is_empty() || label.len() > 256 {
            return Err(ServiceError::InvalidLabel);
        }
        self.generate(&keyword, options)?;
        let mut candidate = self.session()?.payload.clone();
        let now = chrono::Utc::now().timestamp();
        if let Some(id) = id {
            let entry = candidate
                .entries
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or(ServiceError::NotFound)?;
            entry.label = label.trim().to_string();
            entry.keyword = keyword.to_string();
            entry.options = options;
            entry.updated_at = now;
        } else {
            candidate.entries.push(VaultEntry {
                id: Uuid::new_v4(),
                label: label.trim().to_string(),
                keyword: keyword.to_string(),
                options,
                created_at: now,
                updated_at: now,
            });
        }
        self.commit(candidate)
    }
    pub fn delete_entry(&mut self, id: Uuid) -> Result<(), ServiceError> {
        self.entry(id)?;
        let mut candidate = self.session()?.payload.clone();
        candidate.entries.retain(|e| e.id != id);
        self.commit(candidate)
    }
    pub fn update_settings(&mut self, settings: VaultSettings) -> Result<(), ServiceError> {
        validate_timeout(settings.auto_lock_minutes)?;
        let mut candidate = self.session()?.payload.clone();
        candidate.settings = settings;
        self.commit(candidate)
    }
    fn commit(&mut self, candidate: VaultPayload) -> Result<(), ServiceError> {
        self.store.save(&self.session()?.password, &candidate)?;
        self.session.as_mut().ok_or(ServiceError::Locked)?.payload = candidate;
        Ok(())
    }
    pub fn change_password(
        &mut self,
        current: &str,
        next: Zeroizing<String>,
    ) -> Result<(), ServiceError> {
        if current != self.session()?.password.as_str() {
            return Err(ServiceError::Unlock);
        }
        validate_hyper_password(&next)?;
        self.store.save(&next, &self.session()?.payload)?;
        self.session.as_mut().ok_or(ServiceError::Locked)?.password = next;
        Ok(())
    }
    pub fn export(&self, destination: &Path) -> Result<(), ServiceError> {
        if same_path(destination, self.store.path()) {
            return Err(ServiceError::ActiveVaultDestination);
        }
        let session = self.session()?;
        self.store
            .export(&session.password, &session.payload, destination)?;
        Ok(())
    }
    pub fn restore(
        &mut self,
        source: &Path,
        backup_password: &str,
        new_password: Zeroizing<String>,
    ) -> Result<PathBuf, ServiceError> {
        if same_path(source, self.store.path()) {
            return Err(ServiceError::ActiveVaultDestination);
        }
        let candidate = self
            .store
            .import(backup_password, source)
            .map_err(|_| ServiceError::Unlock)?;
        validate_payload(&candidate)?;
        let previous = self
            .store
            .path()
            .with_file_name(format!("pre-restore-{}.pmv", Uuid::new_v4()));
        if let Some(session) = self.session.as_ref() {
            self.store
                .export(&session.password, &session.payload, &previous)?;
            self.commit(candidate)?;
        } else {
            if self.store.exists() {
                return Err(ServiceError::Locked);
            }
            validate_hyper_password(&new_password)?;
            self.store.create_from(&new_password, &candidate)?;
            self.session = Some(Session {
                password: new_password,
                payload: candidate,
            });
        }
        Ok(previous)
    }
}
fn same_path(a: &Path, b: &Path) -> bool {
    a == b
        || a.canonicalize()
            .ok()
            .zip(b.canonicalize().ok())
            .is_some_and(|(a, b)| a == b)
}
fn validate_timeout(timeout: Option<u32>) -> Result<(), ServiceError> {
    if timeout.is_some_and(|t| ![1, 5, 15, 30].contains(&t)) {
        return Err(ServiceError::InvalidTimeout);
    }
    Ok(())
}
pub fn validate_payload(payload: &VaultPayload) -> Result<(), ServiceError> {
    if payload.schema_version != 1 {
        return Err(VaultCryptoError::UnsupportedSchema.into());
    }
    validate_timeout(payload.settings.auto_lock_minutes)?;
    let mut seen = std::collections::HashSet::new();
    if payload.entries.len() > 10_000 {
        return Err(StorageError::FileTooLarge.into());
    }
    for entry in &payload.entries {
        if entry.label.trim().is_empty() || entry.label.len() > 256 || !seen.insert(entry.id) {
            return Err(ServiceError::InvalidLabel);
        }
        if entry.keyword.is_empty() || entry.keyword.len() > MAX_KEYWORD_BYTES {
            return Err(GenerationError::KeywordTooLong.into());
        }
        entry.options.validate().map_err(GenerationError::from)?;
    }
    Ok(())
}
/// Timeouts are based on application input, with a wall-clock heartbeat fallback after a pause.
pub struct LockPolicy {
    last_activity: Instant,
    last_heartbeat: std::time::SystemTime,
    timeout: Option<u32>,
}
impl LockPolicy {
    pub fn new(timeout: Option<u32>) -> Self {
        Self {
            last_activity: Instant::now(),
            last_heartbeat: std::time::SystemTime::now(),
            timeout,
        }
    }
    pub fn activity(&mut self) {
        self.last_activity = Instant::now();
    }
    pub fn set_timeout(&mut self, timeout: Option<u32>) {
        self.timeout = timeout;
        self.activity();
    }
    pub fn tick(&mut self) -> bool {
        let now = std::time::SystemTime::now();
        let pause = now
            .duration_since(self.last_heartbeat)
            .map_or(true, |elapsed| elapsed > Duration::from_secs(3));
        self.last_heartbeat = now;
        pause
            || self.timeout.is_some_and(|minutes| {
                self.last_activity.elapsed() >= Duration::from_secs(minutes as u64 * 60)
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const PASSWORD: &str = "correct horse battery staple";
    #[test]
    fn lifecycle_rotation_backup_and_edit_preserve_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::at(dir.path().join("vault.pmv"));
        let mut service = VaultService::new(store.clone());
        service.create(Zeroizing::new(PASSWORD.into())).unwrap();
        service
            .save_entry(
                None,
                "Email".into(),
                Zeroizing::new("mail".into()),
                PasswordOptions::default(),
            )
            .unwrap();
        let entry = service.entries().unwrap().remove(0);
        let original = service.generate(&entry.keyword, entry.options).unwrap();
        let backup = dir.path().join("backup.pmv");
        service.export(&backup).unwrap();
        service
            .change_password(PASSWORD, Zeroizing::new("a new long hyper password".into()))
            .unwrap();
        assert_eq!(
            original,
            service.generate(&entry.keyword, entry.options).unwrap()
        );
        service
            .save_entry(
                Some(entry.id),
                "Personal email".into(),
                Zeroizing::new("mail".into()),
                entry.options,
            )
            .unwrap();
        assert_eq!(service.entries().unwrap()[0].label, "Personal email");
        service
            .restore(&backup, PASSWORD, Zeroizing::new(String::new()))
            .unwrap();
        assert_eq!(service.entries().unwrap()[0].label, "Email");
        assert_eq!(
            original,
            service.generate(&entry.keyword, entry.options).unwrap()
        );
        service.lock();
        assert!(matches!(
            service.generate("mail", entry.options),
            Err(ServiceError::Locked)
        ));
        assert!(service.unlock(Zeroizing::new(PASSWORD.into())).is_err());
        service
            .unlock(Zeroizing::new("a new long hyper password".into()))
            .unwrap();
        service.delete_entry(entry.id).unwrap();
        assert!(service.entries().unwrap().is_empty());
        assert!(
            store
                .load("a new long hyper password")
                .unwrap()
                .entries
                .is_empty()
        );
    }
    #[test]
    fn failed_save_does_not_change_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pmv");
        let mut service = VaultService::new(VaultStore::at(&path));
        service.create(Zeroizing::new(PASSWORD.into())).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(
            service
                .save_entry(
                    None,
                    "Email".into(),
                    Zeroizing::new("mail".into()),
                    PasswordOptions::default()
                )
                .is_err()
        );
        assert!(service.entries().unwrap().is_empty());
    }
    #[test]
    fn timeout_and_resume_override_never() {
        let mut policy = LockPolicy::new(Some(1));
        policy.last_activity = Instant::now() - Duration::from_secs(61);
        assert!(policy.tick());
        policy.set_timeout(None);
        assert!(!policy.tick());
        policy.last_heartbeat = std::time::SystemTime::now() - Duration::from_secs(10);
        assert!(policy.tick());
    }
    #[test]
    fn settings_are_validated() {
        assert!(validate_timeout(Some(2)).is_err());
        assert!(validate_timeout(None).is_ok());
    }
}
