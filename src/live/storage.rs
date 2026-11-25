use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::Path;
use std::ptr;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

pub(super) const PROFILE: &str = "deepseek-profile.json";

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Profile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) protected_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) keys: BTreeMap<String, Vec<u8>>,
}

impl Profile {
    pub(super) fn load(directory: &Path) -> Result<Self> {
        Self::load_if_present(directory)?.context("DeepSeek key store is missing")
    }

    pub(super) fn load_if_present(directory: &Path) -> Result<Option<Self>> {
        match std::fs::read(directory.join(PROFILE)) {
            Ok(data) => serde_json::from_slice(&data)
                .context("invalid DeepSeek key store")
                .map(Some),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).context("read DeepSeek key store"),
        }
    }

    pub(super) fn api_key(&self, alias: &str) -> Result<Zeroizing<Vec<u8>>> {
        let ciphertext = self.keys.get(alias).or_else(|| {
            (alias == crate::DEFAULT_ALIAS && !self.protected_key.is_empty())
                .then_some(&self.protected_key)
        });
        let key = protect(
            ciphertext.context("unknown DeepSeek key alias")?,
            Protection::Decrypt,
        )?;
        validate_key(&key)?;
        Ok(key)
    }
}

pub(crate) enum Protection {
    Encrypt,
    Decrypt,
}

pub(crate) fn protect(data: &[u8], operation: Protection) -> Result<Zeroizing<Vec<u8>>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len())?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        match operation {
            Protection::Encrypt => CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            ),
            Protection::Decrypt => CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            ),
        }
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("Windows DPAPI operation failed");
    }
    ensure!(!output.pbData.is_null(), "DPAPI returned no data");
    let result = unsafe {
        let buffer = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let result = Zeroizing::new(buffer.to_vec());
        buffer.zeroize();
        LocalFree(output.pbData.cast());
        result
    };
    Ok(result)
}

pub(super) const MAX_KEY_BYTES: usize = 512;

pub(super) fn validate_key(key: &[u8]) -> Result<()> {
    ensure!(
        (8..=MAX_KEY_BYTES).contains(&key.len()) && key.iter().all(u8::is_ascii_graphic),
        "invalid DeepSeek API key format"
    );
    Ok(())
}
