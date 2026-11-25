use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use zeroize::Zeroizing;

use super::APDU_TIMEOUT;
use super::keys;
use super::status_description;
use super::storage::Profile;
use super::storage::validate_key;
use crate::DEFAULT_ALIAS;
use crate::credential_list;
use crate::host::Session;
use crate::protocol::*;

pub async fn list_keys(helper: &Path, directory: &Path) -> Result<Vec<String>> {
    let mut session = Session::start_stdio(helper, "live-chip", directory, APDU_TIMEOUT)?;
    credential_list::receive(&mut session).await
}

pub async fn delete_key(helper: &Path, directory: &Path, alias: &str) -> Result<()> {
    let mut session = Session::start_stdio(helper, "live-chip", directory, APDU_TIMEOUT)?;
    begin_change(&mut session, keys::DELETE, alias).await?;
    commit(&mut session).await
}

pub async fn setup_live(directory: &Path, file: &Path) -> Result<()> {
    if !Profile::load_if_present(directory)?.is_some_and(|profile| profile.has_key(DEFAULT_ALIAS)) {
        import_key_file(directory, DEFAULT_ALIAS, file).await?;
    }
    Ok(())
}

/// Runs in the provisioning frontend, so Codex does not read the import file.
pub async fn import_key_file(directory: &Path, alias: &str, file: &Path) -> Result<()> {
    crate::validate_alias(alias)?;
    let helper = std::env::current_exe()?;
    let mut session = Session::start_stdio(&helper, "live-chip", directory, APDU_TIMEOUT)?;

    let file = File::open(file).context("open the DeepSeek API key file")?;
    ensure!(
        file.metadata()?.is_file(),
        "the API key source must be a file"
    );
    let mut data = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut data)?;
    ensure!(data.len() <= 4096, "the API key file is too large");
    let key = std::str::from_utf8(&data)
        .map_err(|_| anyhow::anyhow!("the API key file must be UTF-8"))?
        .trim_start_matches('\u{feff}')
        .trim()
        .as_bytes();
    validate_key(key)?;
    begin_change(&mut session, keys::ADD, alias).await?;
    for (index, fragment) in key.chunks(CHUNK).enumerate() {
        session
            .checked(KEY_WRITE, u16::try_from(index)?, fragment)
            .await?;
    }
    commit(&mut session).await
}

async fn begin_change(session: &mut Session, action: u8, alias: &str) -> Result<()> {
    crate::validate_alias(alias)?;
    let mut data = vec![action];
    data.extend_from_slice(alias.as_bytes());
    session.checked(KEY_CHANGE_BEGIN, 0, &data).await?;
    Ok(())
}

async fn commit(session: &mut Session) -> Result<()> {
    let status = session.exchange(KEY_COMMIT, 0, &[]).await?.1;
    ensure!(
        status == OK,
        "{} ({status:04X})",
        status_description(status)
    );
    Ok(())
}
