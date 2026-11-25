mod deepseek;
mod keys;
mod management;
pub(crate) mod mbedtls;
pub(crate) mod storage;

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::{ByteStream, TransportError};
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use bytes::Bytes;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::sync::Mutex;
use tokio::sync::OwnedMutexGuard;
use tokio::time::Instant as TokioInstant;
use zeroize::Zeroizing;

use crate::credential_list::CredentialList;
use crate::host::Session;
use crate::network::Network;
use crate::network::Relay;
use crate::operation::Operation;
use crate::operation::TURN_TIMEOUT;
use crate::protocol::*;
use storage::MAX_KEY_BYTES;
use storage::Profile;

use keys::KeyAction;
pub use management::delete_key;
pub use management::import_key_file;
pub use management::list_keys;
pub use management::setup_live;
const CHANGE_TTL: Duration = Duration::from_secs(30);
const APDU_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default, Clone)]
pub struct LiveTransport {
    session: Arc<Mutex<Option<Session>>>,
}

impl std::fmt::Debug for LiveTransport {
    fn fmt(&self, format: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format.debug_struct("LiveTransport").finish_non_exhaustive()
    }
}

struct Lease {
    slot: OwnedMutexGuard<Option<Session>>,
    session: Session,
    relay: Relay,
    next: u16,
    deadline: TokioInstant,
}

impl LiveTransport {
    async fn open_session(directory: &Path) -> Result<Session> {
        let helper = PathBuf::from(
            std::env::var_os("CODEX_APDU_HELPER").context("CODEX_APDU_HELPER is required")?,
        );
        ensure!(helper.is_absolute(), "APDU helper path must be absolute");
        let alias = std::env::var("CODEX_APDU_LIVE_ALIAS").context("DeepSeek alias is required")?;
        crate::validate_alias(&alias)?;
        let mut session = Session::start_stdio(&helper, "live-chip", directory, APDU_TIMEOUT)?;
        session
            .checked(SELECT_CREDENTIAL, 0, alias.as_bytes())
            .await?;
        Ok(session)
    }

    pub async fn prepare(&self) -> Result<()> {
        let mut slot = self.session.lock().await;
        if slot.is_none() {
            *slot = Some(Self::open_session(&profile_path()?).await?);
        }
        Ok(())
    }

    async fn begin(&self, body: Bytes) -> Result<Lease> {
        ensure!(
            !body.is_empty() && body.len() <= MAX_REQUEST,
            "live APDU request exceeds the size limit"
        );
        let mut slot = self.session.clone().lock_owned().await;
        let directory = profile_path()?;
        let mut session = match slot.take() {
            Some(session) => session,
            None => Self::open_session(&directory).await?,
        };
        session.checked(BEGIN_REQUEST, 0, &[]).await?;
        for (index, data) in body.chunks(CHUNK).enumerate() {
            session.checked(WRITE, u16::try_from(index)?, data).await?;
        }
        let (_, status) = session.exchange(EXECUTE, 0, &[]).await?;
        ensure!(status == OK, "{}", status_description(status));
        Ok(Lease {
            slot,
            session,
            relay: Relay::deepseek(),
            next: 0,
            deadline: TokioInstant::now() + TURN_TIMEOUT,
        })
    }
}

fn profile_path() -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os("CODEX_APDU_LIVE_PROFILE")
            .context("CODEX_APDU_LIVE_PROFILE is required")?,
    );
    ensure!(
        path.is_absolute(),
        "APDU live profile path must be absolute"
    );
    Ok(path)
}

fn status_description(status: u16) -> &'static str {
    match status {
        BAD_DATA => "DeepSeek APDU mode supports plain text conversation only",
        deepseek::UPSTREAM_AUTH => {
            "DeepSeek refused authentication or the local API credential could not be opened"
        }
        deepseek::UPSTREAM_LIMIT => "DeepSeek rate limit reached",
        deepseek::UPSTREAM_TLS => "Could not establish authenticated Mbed TLS 1.3 to DeepSeek",
        deepseek::UPSTREAM_TRUNCATED => "DeepSeek's streaming reply was interrupted",
        deepseek::UPSTREAM_BALANCE => "DeepSeek account balance is insufficient",
        CREDENTIAL_STORE_FAILED => "The simulated chip could not update its credential store",
        ALIAS_EXISTS => "That credential alias is already saved",
        keys::ALIAS_MISSING => "That credential alias is no longer saved",
        _ => "DeepSeek APDU request failed",
    }
}

impl LiveTransport {
    pub async fn stream(&self, body: Bytes) -> Result<ByteStream, TransportError> {
        let lease = self
            .begin(body)
            .await
            .map_err(|err| TransportError::Network(format!("APDU: {err:#}")))?;
        let bytes = futures::stream::try_unfold(Some(lease), |lease| async move {
            let Some(mut lease) = lease else {
                return Ok(None);
            };
            let result = tokio::time::timeout_at(
                lease.deadline,
                lease.relay.next(&mut lease.session, &mut lease.next),
            )
            .await
            .map_err(|_| TransportError::Network("DeepSeek APDU operation timed out".into()))?
            .map_err(|err| TransportError::Network(format!("APDU: {err:#}")))?;
            match result {
                Ok((data, true)) => {
                    // Codex stops polling on its terminal SSE event, so restore the session
                    // before handing over the last fragment.
                    *lease.slot = Some(lease.session);
                    Ok((!data.is_empty()).then_some((data, None)))
                }
                Ok((data, false)) => Ok(Some((data, Some(lease)))),
                Err(status) => Err(TransportError::Chip {
                    status,
                    message: status_description(status).into(),
                }),
            }
        });
        Ok(Box::pin(bytes))
    }
}

#[derive(Default)]
struct Upload {
    data: Zeroizing<Vec<u8>>,
    next: u16,
}

impl Upload {
    fn add(&mut self, sequence: u16, data: &[u8], limit: usize) -> Result<(), u16> {
        if sequence != self.next {
            return Err(BAD_SEQUENCE);
        }
        if self.data.len() + data.len() > limit {
            return Err(TOO_LARGE);
        }
        self.data.extend_from_slice(data);
        self.next = self.next.checked_add(1).ok_or(TOO_LARGE)?;
        Ok(())
    }
}

struct KeyChange {
    action: KeyAction,
    started: Instant,
    key: Upload,
}

struct Chip {
    directory: PathBuf,
    alias: Option<String>,
    network: Arc<Network>,
    request: Option<Upload>,
    operation: Option<Operation>,
    aliases: CredentialList,
    change: Option<KeyChange>,
}

impl Chip {
    async fn dispatch(&mut self, command: Command<'_>) -> Result<(Vec<u8>, u16), u16> {
        if let Some(result) = self.network.command(&command) {
            return result;
        }
        let Command {
            ins,
            sequence,
            data,
        } = command;
        if !matches!(ins, WRITE | READ | LIST_CREDENTIALS | KEY_WRITE) && sequence != 0 {
            return Err(BAD_SEQUENCE);
        }
        match ins {
            READ => return Operation::read(&mut self.operation, sequence).await,
            _ if self.operation.is_some() && ins != CANCEL => return Err(BAD_STATE),
            LIST_CREDENTIALS => return self.aliases.page(sequence, || keys::list(&self.directory)),
            SELECT_CREDENTIAL
                if self.alias.is_none() && self.request.is_none() && self.change.is_none() =>
            {
                let alias = std::str::from_utf8(data).map_err(|_| BAD_DATA)?;
                crate::validate_alias(alias).map_err(|_| BAD_DATA)?;
                if !Profile::load(&self.directory)
                    .map_err(|_| deepseek::UPSTREAM_AUTH)?
                    .has_key(alias)
                {
                    return Err(deepseek::UPSTREAM_AUTH);
                }
                self.alias = Some(alias.to_string());
            }
            KEY_CHANGE_BEGIN if self.request.is_none() && self.alias.is_none() => {
                self.change = Some(KeyChange {
                    action: KeyAction::decode(data)?,
                    started: Instant::now(),
                    key: Upload::default(),
                });
            }
            KEY_WRITE => {
                let change = self.change.as_mut().ok_or(BAD_STATE)?;
                if change.started.elapsed() >= CHANGE_TTL {
                    self.change = None;
                    return Err(BAD_STATE);
                }
                if !matches!(change.action, KeyAction::Add(_)) {
                    return Err(BAD_STATE);
                }
                change.key.add(sequence, data, MAX_KEY_BYTES)?;
            }
            KEY_COMMIT => {
                let change = self.change.take().ok_or(BAD_STATE)?;
                if change.started.elapsed() >= CHANGE_TTL {
                    return Err(BAD_STATE);
                }
                change.action.commit(&self.directory, &change.key.data)?;
            }
            BEGIN_REQUEST if self.request.is_none() && self.alias.is_some() => {
                self.request = Some(Upload::default());
            }
            WRITE => self
                .request
                .as_mut()
                .ok_or(BAD_STATE)?
                .add(sequence, data, MAX_REQUEST)?,
            EXECUTE if data.is_empty() => {
                let uploaded = self.request.take().ok_or(BAD_STATE)?;
                let network = Arc::clone(&self.network);
                let directory = self.directory.clone();
                let alias = self.alias.clone().ok_or(BAD_STATE)?;
                self.operation = Some(Operation::launch(move |output| async move {
                    let profile = Profile::load(&directory).map_err(|_| deepseek::UPSTREAM_AUTH)?;
                    deepseek::stream(&network, &profile, &alias, &uploaded.data, output).await
                }));
            }
            CANCEL => {
                self.request = None;
                self.operation = None;
                self.change = None;
            }
            _ => return Err(BAD_STATE),
        }
        Ok((Vec::new(), OK))
    }
}

pub async fn run_live_chip(
    directory: &Path,
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut chip = Chip {
        directory: directory.to_owned(),
        alias: None,
        network: Arc::new(Network::default()),
        request: None,
        operation: None,
        aliases: CredentialList::default(),
        change: None,
    };
    while let Some(frame) = read_frame(&mut reader).await? {
        let frame = Zeroizing::new(frame);
        let (mut response, status) = match Command::decode(&frame) {
            Ok(command) => chip
                .dispatch(command)
                .await
                .unwrap_or_else(|sw| (Vec::new(), sw)),
            Err(sw) => (Vec::new(), sw),
        };
        response.extend_from_slice(&status.to_be_bytes());
        write_frame(&mut writer, &response).await?;
    }
    Ok(())
}
