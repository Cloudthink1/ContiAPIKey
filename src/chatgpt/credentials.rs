use std::fs::File;
use std::fs::OpenOptions;
use std::fs::TryLockError;
use std::fs::{self};
use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::live::storage::Protection;
use crate::live::storage::protect;
use crate::protocol::BAD_STATE;
use crate::protocol::CREDENTIAL_STORE_FAILED;
use crate::protocol::UPSTREAM_FAILED;
use crate::protocol::chatgpt::LOGIN_REQUIRED;

const FILE: &str = "credentials.dpapi";
const ACCOUNT_DIR: &str = "accounts";
const ACCOUNT_PREFIX: &str = "account-";
const MAX_FILE: u64 = 256 * 1024;
pub const MAX_TOKEN_REPLY: usize = 128 * 1024;

pub fn account_directory(root: &Path, alias: &str) -> PathBuf {
    if alias == crate::DEFAULT_ALIAS {
        root.to_owned()
    } else {
        root.join(ACCOUNT_DIR)
            .join(format!("{ACCOUNT_PREFIX}{alias}"))
    }
}

pub fn list_accounts(root: &Path) -> io::Result<Vec<String>> {
    let mut aliases = Vec::new();
    if root.join(FILE).try_exists()? {
        aliases.push(crate::DEFAULT_ALIAS.to_string());
    }
    let entries = match fs::read_dir(root.join(ACCOUNT_DIR)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(aliases),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(alias) = name
            .to_str()
            .and_then(|name| name.strip_prefix(ACCOUNT_PREFIX))
            && alias != crate::DEFAULT_ALIAS
            && crate::validate_alias(alias).is_ok()
            && entry.file_type()?.is_dir()
            && entry.path().join(FILE).try_exists()?
        {
            aliases.push(alias.to_string());
        }
    }
    aliases.sort_unstable();
    Ok(aliases)
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub expires_at: u64,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

impl Credentials {
    pub fn account(&self) -> Option<String> {
        jwt(&self.id_token)?["https://api.openai.com/auth"]["chatgpt_account_id"]
            .as_str()
            .map(str::to_owned)
    }

    pub fn near_expiry(&self) -> bool {
        self.expires_at <= now().saturating_add(60)
    }

    pub fn same_account(&self, other: &Self) -> bool {
        fn subject(token: &str) -> Option<String> {
            jwt(token)?["sub"].as_str().map(str::to_owned)
        }
        self.account() == other.account() && subject(&self.id_token) == subject(&other.id_token)
    }

    pub fn from_reply(body: &[u8], previous: Option<&Self>) -> Result<Self, u16> {
        #[derive(Deserialize)]
        struct Reply {
            access_token: String,
            refresh_token: Option<String>,
            id_token: Option<String>,
            expires_in: Option<u64>,
        }
        let reply: Reply = serde_json::from_slice(body).map_err(|_| UPSTREAM_FAILED)?;
        let current = now();
        let expiry = reply
            .expires_in
            .and_then(|seconds| current.checked_add(seconds))
            .into_iter()
            .chain(jwt(&reply.access_token).and_then(|claims| claims["exp"].as_u64()))
            .min()
            .unwrap_or(0);
        let credentials = Self {
            access_token: reply.access_token,
            refresh_token: reply
                .refresh_token
                .or_else(|| previous.map(|old| old.refresh_token.clone()))
                .unwrap_or_default(),
            id_token: reply
                .id_token
                .or_else(|| previous.map(|old| old.id_token.clone()))
                .unwrap_or_default(),
            expires_at: expiry,
        };
        if expiry <= current
            || credentials.account().is_none()
            || [
                &credentials.access_token,
                &credentials.refresh_token,
                &credentials.id_token,
            ]
            .into_iter()
            .any(|token| token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()))
        {
            return Err(UPSTREAM_FAILED);
        }
        if previous.is_some_and(|old| !old.same_account(&credentials)) {
            return Err(LOGIN_REQUIRED);
        }
        Ok(credentials)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn jwt(token: &str) -> Option<Value> {
    let payload = Zeroizing::new(URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?);
    serde_json::from_slice(&payload).ok()
}

pub struct Store {
    directory: PathBuf,
    _lock: File,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self, u16> {
        fs::create_dir_all(directory).map_err(|_| CREDENTIAL_STORE_FAILED)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("credentials.lock"))
            .map_err(|_| CREDENTIAL_STORE_FAILED)?;
        lock.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => BAD_STATE,
            TryLockError::Error(_) => CREDENTIAL_STORE_FAILED,
        })?;
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
        })
    }

    pub fn load(&self) -> Result<Option<Credentials>, u16> {
        let file = match File::open(self.directory.join(FILE)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CREDENTIAL_STORE_FAILED),
        };
        let mut ciphertext = Vec::new();
        file.take(MAX_FILE + 1)
            .read_to_end(&mut ciphertext)
            .map_err(|_| CREDENTIAL_STORE_FAILED)?;
        if ciphertext.len() as u64 > MAX_FILE {
            return Err(CREDENTIAL_STORE_FAILED);
        }
        let plaintext =
            protect(&ciphertext, Protection::Decrypt).map_err(|_| CREDENTIAL_STORE_FAILED)?;
        serde_json::from_slice(&plaintext)
            .map(Some)
            .map_err(|_| CREDENTIAL_STORE_FAILED)
    }

    pub fn save(&self, credentials: &Credentials) -> Result<(), u16> {
        let plaintext =
            Zeroizing::new(serde_json::to_vec(credentials).map_err(|_| CREDENTIAL_STORE_FAILED)?);
        let ciphertext =
            protect(&plaintext, Protection::Encrypt).map_err(|_| CREDENTIAL_STORE_FAILED)?;
        let mut staging = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| CREDENTIAL_STORE_FAILED)?;
        staging
            .write_all(&ciphertext)
            .map_err(|_| CREDENTIAL_STORE_FAILED)?;
        staging
            .as_file()
            .sync_all()
            .map_err(|_| CREDENTIAL_STORE_FAILED)?;
        staging
            .persist(self.directory.join(FILE))
            .map_err(|_| CREDENTIAL_STORE_FAILED)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<(), u16> {
        match fs::remove_file(self.directory.join(FILE)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CREDENTIAL_STORE_FAILED),
        }
    }
}
