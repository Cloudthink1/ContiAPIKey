use std::future::Future;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::credentials::Store;
use super::credentials::account_directory;
use super::service;
use crate::credential_list::CredentialList;
use crate::network::Network;
use crate::operation::Operation;
use crate::operation::Output;
use crate::protocol::chatgpt::*;
use crate::protocol::*;

#[cfg(test)]
mod tests;

pub const LOGIN_TTL: Duration = Duration::from_secs(300);
pub const REDIRECT_PORTS: [u16; 2] = [1455, 1457];
const MAX_CALLBACK: usize = 8 * 1024;

#[derive(Default)]
struct Upload {
    bytes: Vec<u8>,
    next: u16,
}

impl Drop for Upload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

impl Upload {
    fn extend(&mut self, sequence: u16, bytes: &[u8], limit: usize) -> Result<(), u16> {
        if sequence != self.next {
            return Err(BAD_SEQUENCE);
        }
        if bytes.is_empty() || self.bytes.len() + bytes.len() > limit {
            return Err(TOO_LARGE);
        }
        self.next = self.next.checked_add(1).ok_or(TOO_LARGE)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

struct Login {
    verifier: Zeroizing<String>,
    state: String,
    redirect: String,
    start: Instant,
    callback: Upload,
    intent: service::LoginIntent,
}

impl Login {
    fn begin(port: u16, intent: service::LoginIntent) -> Result<(Self, Vec<u8>), u16> {
        if !REDIRECT_PORTS.contains(&port) {
            return Err(BAD_DATA);
        }
        let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(rand::random::<[u8; 64]>()));
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let public = serde_json::to_vec(&serde_json::json!({"challenge":challenge,"state":state}))
            .map_err(|_| BAD_DATA)?;
        Ok((
            Self {
                verifier,
                state,
                redirect: format!("http://localhost:{port}/auth/callback"),
                start: Instant::now(),
                callback: Upload::default(),
                intent,
            },
            public,
        ))
    }

    fn code(&mut self) -> Result<Zeroizing<String>, u16> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Callback {
            code: String,
            state: String,
        }
        let callback = std::mem::take(&mut self.callback);
        let payload: Callback = serde_json::from_slice(&callback.bytes).map_err(|_| BAD_DATA)?;
        let code = Zeroizing::new(payload.code);
        if self.start.elapsed() >= LOGIN_TTL || payload.state != self.state || code.is_empty() {
            return Err(LOGIN_MISMATCH);
        }
        Ok(code)
    }
}

struct Chip {
    directory: PathBuf,
    selected: bool,
    network: Arc<Network>,
    login: Option<Login>,
    request: Option<Upload>,
    operation: Option<Operation>,
    aliases: CredentialList,
}

impl Chip {
    fn launch<F, Fut>(&mut self, task: F)
    where
        F: FnOnce(Arc<Network>, PathBuf, mpsc::Sender<Output>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), u16>> + Send + 'static,
    {
        let network = self.network.clone();
        let directory = self.directory.clone();
        self.operation = Some(Operation::launch(move |output| {
            task(network, directory, output)
        }));
    }

    async fn dispatch(&mut self, cmd: Command<'_>) -> Result<(Vec<u8>, u16), u16> {
        if let Some(result) = self.network.command(&cmd) {
            return result;
        }
        if !matches!(cmd.ins, WRITE | READ | CALLBACK_WRITE | LIST_CREDENTIALS) && cmd.sequence != 0
        {
            return Err(BAD_SEQUENCE);
        }
        match cmd.ins {
            SELECT_CREDENTIAL
                if !self.selected
                    && self.login.is_none()
                    && self.request.is_none()
                    && self.operation.is_none() =>
            {
                let alias = std::str::from_utf8(cmd.data).map_err(|_| BAD_DATA)?;
                crate::validate_alias(alias).map_err(|_| BAD_DATA)?;
                self.directory = account_directory(&self.directory, alias);
                self.selected = true;
            }
            CANCEL => {
                self.login = None;
                self.request = None;
                self.operation = None;
            }
            READ => return Operation::read(&mut self.operation, cmd.sequence).await,
            _ if self.operation.is_some() => return Err(BAD_STATE),
            LIST_CREDENTIALS if !self.selected => {
                return self.aliases.page(cmd.sequence, || {
                    super::credentials::list_accounts(&self.directory)
                        .map_err(|_| CREDENTIAL_STORE_FAILED)
                });
            }
            LOGIN_STATUS => {
                let store = Store::open(&self.directory)?;
                let credentials = store.load()?.ok_or(LOGIN_REQUIRED)?;
                return Ok((credentials.expires_at.to_be_bytes().to_vec(), OK));
            }
            LOGIN_BEGIN => {
                let (port, intent) = match cmd.data {
                    [hi, lo] => (u16::from_be_bytes([*hi, *lo]), service::LoginIntent::Reuse),
                    [hi, lo, 1] => (u16::from_be_bytes([*hi, *lo]), service::LoginIntent::Add),
                    _ => return Err(BAD_LENGTH),
                };
                let (login, public) = Login::begin(port, intent)?;
                self.login = Some(login);
                return Ok((public, OK));
            }
            CALLBACK_WRITE => {
                let login = self.login.as_mut().ok_or(BAD_STATE)?;
                if login.start.elapsed() >= LOGIN_TTL {
                    self.login = None;
                    return Err(LOGIN_MISMATCH);
                }
                login
                    .callback
                    .extend(cmd.sequence, cmd.data, MAX_CALLBACK)?;
            }
            LOGIN_FINISH => {
                let code = self.login.as_mut().ok_or(BAD_STATE)?.code()?;
                let login = self.login.take().ok_or(BAD_STATE)?;
                self.launch(move |network, directory, _| async move {
                    service::exchange(
                        &network,
                        &directory,
                        &code,
                        &login.verifier,
                        &login.redirect,
                        login.intent,
                    )
                    .await
                });
            }
            LOGOUT => {
                self.login = None;
                Store::open(&self.directory)?.clear()?;
            }
            MODELS => {
                self.launch(|network, directory, output| async move {
                    let models = service::models(&network, &directory).await?;
                    output
                        .send(Output {
                            bytes: models,
                            last: true,
                        })
                        .await
                        .map_err(|_| UPSTREAM_FAILED)
                });
            }
            BEGIN_REQUEST if self.request.is_none() => {
                self.request = Some(Upload::default());
            }
            WRITE => self.request.as_mut().ok_or(BAD_STATE)?.extend(
                cmd.sequence,
                cmd.data,
                MAX_REQUEST,
            )?,
            EXECUTE if cmd.data.is_empty() => {
                let request = self.request.take().ok_or(BAD_STATE)?;
                self.launch(move |network, directory, output| async move {
                    service::chat(&network, &directory, &request.bytes, &output).await
                });
            }
            _ => return Err(BAD_STATE),
        }
        Ok((Vec::new(), OK))
    }
}

pub async fn run_chip(
    directory: &Path,
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> anyhow::Result<()> {
    let mut chip = Chip {
        directory: directory.to_owned(),
        selected: false,
        network: Arc::new(Network::default()),
        login: None,
        request: None,
        operation: None,
        aliases: CredentialList::default(),
    };
    while let Some(frame) = read_frame(&mut reader).await? {
        let result = match Command::decode(&frame) {
            Ok(cmd) => chip.dispatch(cmd).await,
            Err(status) => Err(status),
        };
        let (mut bytes, status) = result.unwrap_or_else(|status| (Vec::new(), status));
        anyhow::ensure!(bytes.len() <= CHUNK, "invalid chip response length");
        bytes.extend_from_slice(&status.to_be_bytes());
        write_frame(&mut writer, &bytes).await?;
    }
    Ok(())
}
