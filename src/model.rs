use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MIN_PASSWORD_LENGTH: u16 = 8;
pub const MAX_PASSWORD_LENGTH: u16 = 128;
pub const DEFAULT_PASSWORD_LENGTH: u16 = 16;
pub const MAX_KEYWORD_BYTES: usize = 4096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OptionsError {
    #[error("password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}")]
    LengthOutOfRange,
    #[error("at least one character class must be selected")]
    NoCharacterClasses,
    #[error("password length is shorter than the number of selected character classes")]
    TooShortForSelectedClasses,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PasswordOptions {
    pub length: u16,
    pub lowercase: bool,
    pub uppercase: bool,
    pub numbers: bool,
    pub symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            lowercase: true,
            uppercase: true,
            numbers: true,
            symbols: true,
        }
    }
}

impl PasswordOptions {
    pub fn validate(self) -> Result<(), OptionsError> {
        if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&self.length) {
            return Err(OptionsError::LengthOutOfRange);
        }

        let class_count = self.selected_class_count();
        if class_count == 0 {
            return Err(OptionsError::NoCharacterClasses);
        }
        if self.length < class_count {
            return Err(OptionsError::TooShortForSelectedClasses);
        }
        Ok(())
    }

    pub const fn flags(self) -> u8 {
        (self.lowercase as u8)
            | ((self.uppercase as u8) << 1)
            | ((self.numbers as u8) << 2)
            | ((self.symbols as u8) << 3)
    }

    pub const fn selected_class_count(self) -> u16 {
        self.lowercase as u16
            + self.uppercase as u16
            + self.numbers as u16
            + self.symbols as u16
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultEntry {
    #[zeroize(skip)]
    pub id: Uuid,
    pub label: String,
    pub keyword: String,
    #[zeroize(skip)]
    pub options: PasswordOptions,
    #[zeroize(skip)]
    pub created_at: i64,
    #[zeroize(skip)]
    pub updated_at: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultSettings {
    #[zeroize(skip)]
    pub auto_lock_minutes: Option<u32>,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: Some(15),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultPayload {
    #[zeroize(skip)]
    pub schema_version: u16,
    pub generation_key: [u8; 32],
    pub entries: Vec<VaultEntry>,
    #[zeroize(skip)]
    pub settings: VaultSettings,
}

impl VaultPayload {
    pub const CURRENT_SCHEMA_VERSION: u16 = 1;

    pub fn new(generation_key: [u8; 32]) -> Self {
        Self {
            schema_version: Self::CURRENT_SCHEMA_VERSION,
            generation_key,
            entries: Vec::new(),
            settings: VaultSettings::default(),
        }
    }
}
