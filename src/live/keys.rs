use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;

use super::storage::PROFILE;
use super::storage::Profile;
use super::storage::Protection;
use super::storage::protect;
use super::storage::validate_key;
use crate::DEFAULT_ALIAS;
use crate::protocol::*;
use crate::validate_alias;

pub(super) const ADD: u8 = 1;
pub(super) const DELETE: u8 = 2;
pub(super) const ALIAS_MISSING: u16 = 0x640B;

pub(super) enum KeyAction {
    Add(String),
    Delete(String),
}

impl KeyAction {
    pub(super) fn decode(data: &[u8]) -> Result<Self, u16> {
        let (&action, alias) = data.split_first().ok_or(BAD_DATA)?;
        let alias = std::str::from_utf8(alias).map_err(|_| BAD_DATA)?;
        validate_alias(alias).map_err(|_| BAD_DATA)?;
        match action {
            ADD => Ok(Self::Add(alias.to_owned())),
            DELETE => Ok(Self::Delete(alias.to_owned())),
            _ => Err(BAD_DATA),
        }
    }

    pub(super) fn commit(self, directory: &Path, key: &[u8]) -> Result<(), u16> {
        if matches!(&self, Self::Add(_)) {
            std::fs::create_dir_all(directory).map_err(|_| CREDENTIAL_STORE_FAILED)?;
        } else if !directory
            .try_exists()
            .map_err(|_| CREDENTIAL_STORE_FAILED)?
        {
            return Err(ALIAS_MISSING);
        }
        let _lock = lock_profile(directory).map_err(|_| CREDENTIAL_STORE_FAILED)?;
        let mut profile = Profile::load_if_present(directory)
            .map_err(|_| CREDENTIAL_STORE_FAILED)?
            .unwrap_or_default();
        match self {
            Self::Add(alias) => {
                if profile.has_key(&alias) {
                    return Err(ALIAS_EXISTS);
                }
                validate_key(key).map_err(|_| BAD_DATA)?;
                let encrypted =
                    protect(key, Protection::Encrypt).map_err(|_| CREDENTIAL_STORE_FAILED)?;
                profile.keys.insert(alias, encrypted.to_vec());
            }
            Self::Delete(alias) => {
                if !profile.has_key(&alias) {
                    return Err(ALIAS_MISSING);
                }
                profile.keys.remove(&alias);
                if alias == DEFAULT_ALIAS {
                    profile.protected_key.clear();
                }
            }
        }
        save_profile(directory, &profile).map_err(|_| CREDENTIAL_STORE_FAILED)
    }
}

impl Profile {
    pub(super) fn has_key(&self, alias: &str) -> bool {
        self.keys.contains_key(alias) || (alias == DEFAULT_ALIAS && !self.protected_key.is_empty())
    }
}

pub(super) fn list(directory: &Path) -> Result<Vec<String>, u16> {
    let Some(profile) = Profile::load_if_present(directory).map_err(|_| CREDENTIAL_STORE_FAILED)?
    else {
        return Ok(Vec::new());
    };
    let mut aliases: Vec<_> = profile.keys.keys().cloned().collect();
    if !profile.protected_key.is_empty() && !profile.keys.contains_key(DEFAULT_ALIAS) {
        aliases.push(DEFAULT_ALIAS.to_string());
        aliases.sort_unstable();
    }
    for alias in &aliases {
        validate_alias(alias).map_err(|_| CREDENTIAL_STORE_FAILED)?;
    }
    Ok(aliases)
}

fn lock_profile(directory: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("deepseek-profile.lock"))?;
    lock.try_lock().context("the DeepSeek key store is busy")?;
    Ok(lock)
}

fn save_profile(directory: &Path, profile: &Profile) -> Result<()> {
    let mut staging = tempfile::NamedTempFile::new_in(directory)?;
    staging.write_all(&serde_json::to_vec(profile)?)?;
    staging.as_file().sync_all()?;
    staging.persist(directory.join(PROFILE))?;
    Ok(())
}
