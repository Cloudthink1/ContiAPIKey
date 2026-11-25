use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use crate::{ByteStream, TransportError};
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use bytes::Bytes;
use tokio::sync::Mutex;
use tokio::sync::OwnedMutexGuard;

use super::callback::Authorization;
use super::callback::Browser;
use super::callback::{self};
use super::service;
use super::service::LoginIntent;
use crate::credential_list;
use crate::host::Session;
use crate::network::Relay;
use crate::operation::TURN_TIMEOUT;
use crate::protocol::chatgpt::*;
use crate::protocol::*;

static SESSION: LazyLock<Arc<Mutex<Option<HostChip>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));
const APDU_TIMEOUT: Duration = Duration::from_secs(10);
const BROWSER_PROMPT: &str =
    "Opening the official ChatGPT sign-in page. Complete authorization in your browser.";
const SIGN_IN_CANCELLED: &str = "ChatGPT sign-in canceled.";

pub fn profile_path() -> Result<PathBuf> {
    let directory = PathBuf::from(
        std::env::var_os("CODEX_APDU_CHATGPT_PROFILE")
            .context("an independent ChatGPT chip profile is required")?,
    );
    ensure!(
        directory.is_absolute(),
        "ChatGPT APDU profile path must be absolute"
    );
    Ok(directory)
}

pub async fn list_accounts() -> Result<Vec<String>> {
    let mut session = start_session(&profile_path()?)?;
    credential_list::receive(&mut session).await
}

fn start_session(profile: &std::path::Path) -> Result<Session> {
    let helper = std::env::current_exe()?.with_file_name("codex-chatgpt-chip.exe");
    ensure!(
        helper.is_file(),
        "codex-chatgpt-chip.exe must be beside the gateway"
    );
    Session::start_stdio(&helper, "chip", profile, APDU_TIMEOUT)
}

struct HostChip {
    session: Session,
    relay: Relay,
    sequence: u16,
}

impl HostChip {
    async fn start() -> Result<Self> {
        let alias = std::env::var("CODEX_APDU_CHATGPT_ALIAS").ok();
        Self::open(alias.as_deref()).await
    }

    async fn open(alias: Option<&str>) -> Result<Self> {
        if let Some(alias) = alias {
            crate::validate_alias(alias)?;
        }
        let profile = profile_path()?;
        let mut session = start_session(&profile)?;
        if let Some(alias) = alias {
            session
                .checked(SELECT_CREDENTIAL, 0, alias.as_bytes())
                .await?;
        }
        Ok(Self {
            session,
            relay: Relay::chatgpt(),
            sequence: 0,
        })
    }

    async fn upload(&mut self, instruction: u8, bytes: &[u8]) -> Result<()> {
        for (sequence, fragment) in bytes.chunks(CHUNK).enumerate() {
            self.session
                .checked(instruction, u16::try_from(sequence)?, fragment)
                .await?;
        }
        Ok(())
    }

    async fn next(&mut self) -> Result<Result<(Bytes, bool), u16>> {
        self.relay.next(&mut self.session, &mut self.sequence).await
    }

    async fn collect(&mut self, limit: usize) -> Result<Result<Vec<u8>, u16>> {
        self.sequence = 0;
        let mut result = Vec::new();
        let operation = async {
            loop {
                match self.next().await? {
                    Ok((chunk, done)) => {
                        ensure!(
                            result.len() + chunk.len() <= limit,
                            "APDU operation exceeded its response limit"
                        );
                        result.extend_from_slice(&chunk);
                        if done {
                            return Ok(Ok(result));
                        }
                    }
                    Err(status) => return Ok(Err(status)),
                }
            }
        };
        tokio::time::timeout(TURN_TIMEOUT, operation)
            .await
            .context("ChatGPT APDU operation timed out")?
    }

    async fn login(
        &mut self,
        progress: &(impl Fn(&str) + Sync),
        intent: LoginIntent,
    ) -> Result<()> {
        let (listener, port) = callback::bind().await?;
        let mut request = port.to_be_bytes().to_vec();
        if intent == LoginIntent::Add {
            request.push(1);
        }
        let parameters = self.session.checked(LOGIN_BEGIN, 0, &request).await?;
        let authorization: Authorization = serde_json::from_slice(&parameters)?;
        let mut browser = Browser::new(listener, port, authorization.state.clone());
        progress(BROWSER_PROMPT);
        authorization.open(port, intent)?;
        let callback = browser.callback().await?;
        let result = async {
            self.upload(CALLBACK_WRITE, &callback.encode()?).await?;
            self.session.checked(LOGIN_FINISH, 0, &[]).await?;
            self.collect(0).await?.map_err(status_error)?;
            Ok(())
        }
        .await;
        let _ = callback.result.send(result.is_ok());
        if result.is_ok() {
            browser.show_success().await;
        }
        result
    }

    async fn models(&mut self) -> Result<Result<Vec<service::Model>, u16>> {
        self.session.checked(MODELS, 0, &[]).await?;
        match self.collect(256 * 1024).await? {
            Ok(bytes) => Ok(Ok(
                serde_json::from_slice(&bytes).context("invalid APDU model catalog")?
            )),
            Err(status) => Ok(Err(status)),
        }
    }
}

fn status_error(status: u16) -> anyhow::Error {
    anyhow!("{} (APDU {status:04X})", status_message(status))
}

fn status_message(status: u16) -> &'static str {
    match status {
        LOGIN_REQUIRED => {
            "ChatGPT sign-in is required. Reopen the gateway in ChatGPT mode to sign in."
        }
        LOGIN_MISMATCH => {
            "ChatGPT authorization expired or did not match this sign-in or saved account."
        }
        ALIAS_EXISTS => {
            "This ChatGPT account alias is already saved. Choose it or use another alias."
        }
        CREDENTIAL_STORE_FAILED => "The simulated chip could not access its encrypted credentials.",
        service::FORBIDDEN => "ChatGPT denied this account or workspace access.",
        service::RATE_LIMITED => "ChatGPT rate limit reached.",
        service::TRUNCATED => "ChatGPT closed the response before completing it.",
        service::TLS_FAILED => {
            "Could not establish verified TLS to ChatGPT or its authorization service."
        }
        service::MODEL_REJECTED => "ChatGPT rejected the model or request upstream.",
        BAD_DATA => "The simulated chip rejected the request format before forwarding it.",
        BAD_STATE => "The APDU operation is busy or its session expired.",
        _ => "The ChatGPT APDU operation failed.",
    }
}

pub async fn prepare(progress: impl Fn(&str) + Sync) -> Result<Vec<service::Model>> {
    prepare_for(LoginIntent::Reuse, progress).await
}

pub async fn prepare_new(progress: impl Fn(&str) + Sync) -> Result<Vec<service::Model>> {
    prepare_for(LoginIntent::Add, progress).await
}

async fn prepare_for(
    intent: LoginIntent,
    progress: impl Fn(&str) + Sync,
) -> Result<Vec<service::Model>> {
    let mut slot = SESSION.clone().lock_owned().await;
    let startup = async {
        let mut chip = HostChip::start().await?;
        let status = chip.session.exchange(LOGIN_STATUS, 0, &[]).await?.1;
        let models = match status {
            OK if intent == LoginIntent::Add => return Err(status_error(ALIAS_EXISTS)),
            OK => chip.models().await?,
            LOGIN_REQUIRED => Err(LOGIN_REQUIRED),
            status => return Err(status_error(status)),
        };
        let models = match models {
            Ok(models) => models,
            Err(LOGIN_REQUIRED) => {
                chip.login(&progress, intent).await?;
                chip.models().await?.map_err(status_error)?
            }
            Err(status) => return Err(status_error(status)),
        };
        ensure!(
            !models.is_empty(),
            "This ChatGPT account returned no selectable models"
        );
        Ok((chip, models))
    };
    let (chip, models) = tokio::select! {
        result = startup => result?,
        _ = tokio::signal::ctrl_c() => return Err(anyhow!(SIGN_IN_CANCELLED)),
    };
    *slot = Some(chip);
    Ok(models)
}

pub async fn logout(alias: &str) -> Result<()> {
    let _slot = SESSION.clone().lock_owned().await;
    let mut chip = HostChip::open(Some(alias)).await?;
    chip.session.checked(LOGOUT, 0, &[]).await?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct ChatGptTransport;

struct Active {
    slot: OwnedMutexGuard<Option<HostChip>>,
    chip: HostChip,
    deadline: tokio::time::Instant,
}

impl ChatGptTransport {
    pub async fn stream(&self, body: Bytes) -> Result<ByteStream, TransportError> {
        if body.is_empty() || body.len() > MAX_REQUEST {
            return Err(TransportError::Build(
                "ChatGPT APDU request exceeds the supported size".into(),
            ));
        }
        let mut slot = SESSION.clone().lock_owned().await;
        let begin = async {
            let mut chip = match slot.take() {
                Some(chip) => chip,
                None => HostChip::start().await?,
            };
            chip.session.checked(BEGIN_REQUEST, 0, &[]).await?;
            chip.upload(WRITE, &body).await?;
            chip.session.checked(EXECUTE, 0, &[]).await?;
            chip.sequence = 0;
            Ok::<_, anyhow::Error>(chip)
        };
        let chip = begin
            .await
            .map_err(|error| TransportError::Network(error.to_string()))?;
        let active = Active {
            slot,
            chip,
            deadline: tokio::time::Instant::now() + TURN_TIMEOUT,
        };
        let stream = futures::stream::try_unfold(Some(active), |active| async move {
            let Some(mut active) = active else {
                return Ok(None);
            };
            let next = tokio::time::timeout_at(active.deadline, active.chip.next())
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|error| TransportError::Network(error.to_string()))?;
            match next {
                Ok((bytes, false)) => Ok(Some((bytes, Some(active)))),
                Ok((bytes, true)) => {
                    *active.slot = Some(active.chip);
                    Ok((!bytes.is_empty()).then_some((bytes, None)))
                }
                Err(status) => {
                    *active.slot = Some(active.chip);
                    Err(TransportError::Chip {
                        status,
                        message: status_message(status).to_owned(),
                    })
                }
            }
        });
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::BROWSER_PROMPT;
    use super::LOGIN_MISMATCH;
    use super::SIGN_IN_CANCELLED;
    use super::status_error;

    #[test]
    fn sign_in_progress_and_errors_snapshot() {
        insta::assert_snapshot!(format!("{BROWSER_PROMPT}\n{SIGN_IN_CANCELLED}\n{}", status_error(LOGIN_MISMATCH)), @r"
        Opening the official ChatGPT sign-in page. Complete authorization in your browser.
        ChatGPT sign-in canceled.
        ChatGPT authorization expired or did not match this sign-in or saved account. (APDU 6407)
        ");
    }
}
