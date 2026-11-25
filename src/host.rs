use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use crate::{ByteStream, TransportError};
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use bytes::Bytes;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::process::ChildStdin;
use tokio::process::ChildStdout;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::chip::DEMO_USER;
use crate::protocol::*;

const CALL_TIMEOUT: Duration = Duration::from_secs(25);

/// The local Responses transport. The only application data sent to the helper is the JSON APDU payload.
pub struct ApduTransport {
    helper: PathBuf,
    fixture: PathBuf,
    model_service: SocketAddr,
}

impl ApduTransport {
    pub fn new(helper: PathBuf, fixture: PathBuf, model_service: SocketAddr) -> Result<Self> {
        ensure!(
            helper.is_absolute() && fixture.is_absolute(),
            "APDU paths must be absolute"
        );
        ensure!(
            model_service.ip().is_loopback() && model_service.port() != 0,
            "APDU model service must be on loopback"
        );
        Ok(Self {
            helper,
            fixture,
            model_service,
        })
    }

    pub fn from_env() -> Result<Self> {
        let helper =
            std::env::var_os("CODEX_APDU_HELPER").context("CODEX_APDU_HELPER is required")?;
        let fixture =
            std::env::var_os("CODEX_APDU_FIXTURE").context("CODEX_APDU_FIXTURE is required")?;
        let model_service = std::env::var("CODEX_APDU_MODEL_ADDR")
            .context("CODEX_APDU_MODEL_ADDR is required")?
            .parse()
            .context("invalid CODEX_APDU_MODEL_ADDR")?;
        Self::new(helper.into(), fixture.into(), model_service)
    }

    async fn open(&self, body: Bytes) -> Result<Session> {
        ensure!(
            !body.is_empty() && body.len() <= MAX_REQUEST,
            "APDU request exceeds the supported size"
        );
        let seed: [u8; 32] = tokio::fs::read(self.fixture.join("client.seed"))
            .await
            .context("read demo signing key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid demo signing key length"))?;
        let signing_key = SigningKey::from_bytes(&seed);

        let destination = self.model_service;
        let mut session = Session::start(
            &self.helper,
            "chip",
            &self.fixture.join("chip"),
            CALL_TIMEOUT,
            move |listener| async move {
                let (mut chip, _) = listener.accept().await?;
                let mut model = TcpStream::connect(destination).await?;
                let (sent, received) = tokio::io::copy_bidirectional(&mut chip, &mut model).await?;
                tracing::debug!(sent, received, "APDU TLS relay byte counts");
                std::io::Result::Ok(())
            },
        )
        .await?;
        let nonce: [u8; 32] = session
            .checked(CHALLENGE, 0, &[])
            .await?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid APDU challenge length"))?;
        for (sequence, data) in body.chunks(CHUNK).enumerate() {
            let sequence = u16::try_from(sequence)?;
            ensure!(
                session.checked(WRITE, sequence, data).await?.is_empty(),
                "unexpected APDU upload response"
            );
        }
        let signature = signing_key.sign(&signed_message(&nonce, &body));
        let mut authorization = vec![DEMO_USER];
        authorization.extend_from_slice(&signature.to_bytes());
        ensure!(
            session
                .checked(EXECUTE, 0, &authorization)
                .await?
                .is_empty(),
            "unexpected APDU execute response"
        );
        Ok(session)
    }
}

pub(crate) struct Session {
    writer: ChildStdin,
    reader: ChildStdout,
    child: Child,
    _relay_task: Option<RelayTask>,
    next: u16,
    command_timeout: Duration,
}

struct RelayTask(JoinHandle<std::io::Result<()>>);

impl Drop for RelayTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Session {
    pub async fn start<F, Fut>(
        helper: &std::path::Path,
        mode: &str,
        directory: &std::path::Path,
        command_timeout: Duration,
        forward: F,
    ) -> Result<Self>
    where
        F: FnOnce(TcpListener) -> Fut,
        Fut: Future<Output = std::io::Result<()>> + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let relay = listener.local_addr()?;
        let mut session = Self::spawn(helper, mode, directory, Some(relay), command_timeout)?;
        session._relay_task = Some(RelayTask(tokio::spawn(forward(listener))));
        Ok(session)
    }

    #[cfg(windows)]
    pub fn start_stdio(
        helper: &std::path::Path,
        mode: &str,
        directory: &std::path::Path,
        command_timeout: Duration,
    ) -> Result<Self> {
        Self::spawn(helper, mode, directory, None, command_timeout)
    }

    fn spawn(
        helper: &std::path::Path,
        mode: &str,
        directory: &std::path::Path,
        relay: Option<SocketAddr>,
        command_timeout: Duration,
    ) -> Result<Self> {
        let mut command = tokio::process::Command::new(helper);
        command
            .arg(mode)
            .arg(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(relay) = relay {
            command.arg(relay.to_string());
        }
        command.kill_on_drop(true).env_clear();
        if let Some(system_root) = std::env::var_os("SystemRoot") {
            command.env("SystemRoot", system_root);
        }
        let mut child = command.spawn().context("launch APDU simulator")?;
        Ok(Self {
            writer: child.stdin.take().context("open simulator input")?,
            reader: child.stdout.take().context("open simulator output")?,
            child,
            _relay_task: None,
            next: 0,
            command_timeout,
        })
    }

    pub async fn exchange(
        &mut self,
        ins: u8,
        sequence: u16,
        data: &[u8],
    ) -> Result<(Vec<u8>, u16)> {
        let start = Instant::now();
        let command = Command {
            ins,
            sequence,
            data,
        }
        .encode()?;
        #[cfg(windows)]
        let command = zeroize::Zeroizing::new(command);
        let mut frame = timeout(self.command_timeout, async {
            write_frame(&mut self.writer, &command).await?;
            read_frame(&mut self.reader).await
        })
        .await
        .context("APDU command timed out")??
        .context("simulator closed the APDU channel")?;
        let data_len = frame.len() - 2;
        let [sw1, sw2] = [frame[data_len], frame[data_len + 1]];
        frame.truncate(data_len);
        let status = u16::from_be_bytes([sw1, sw2]);
        tracing::info!(
            ins,
            sequence,
            command_bytes = command.len(),
            response_bytes = frame.len() + 2,
            status = %format_args!("{status:04X}"),
            elapsed_us = start.elapsed().as_micros() as u64,
            "APDU exchange"
        );
        ensure!(frame.len() <= CHUNK, "invalid APDU response length");
        Ok((frame, status))
    }

    pub async fn checked(&mut self, ins: u8, sequence: u16, data: &[u8]) -> Result<Vec<u8>> {
        let (body, status) = self.exchange(ins, sequence, data).await?;
        ensure!(status == OK, "APDU command {ins:02X} returned {status:04X}");
        Ok(body)
    }

    async fn read(&mut self) -> Result<Option<Bytes>> {
        let (body, status) = self.exchange(READ, self.next, &[]).await?;
        match status {
            OK if body.is_empty() => Ok(None),
            MORE if !body.is_empty() && self.next < u16::MAX => {
                self.next += 1;
                Ok(Some(body.into()))
            }
            _ => anyhow::bail!("APDU read returned invalid response or status {status:04X}"),
        }
    }
}

impl ApduTransport {
    pub async fn stream(&self, body: Bytes) -> Result<ByteStream, TransportError> {
        let session = timeout(CALL_TIMEOUT, self.open(body))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|err| TransportError::Network(format!("APDU: {err:#}")))?;
        let stream = futures::stream::try_unfold(session, |mut session| async move {
            match session.read().await {
                Ok(Some(bytes)) => Ok(Some((bytes, session))),
                Ok(None) => {
                    // Close stdin to let the helper exit normally when the consumer reads to EOF.
                    drop(session.writer);
                    let exit = timeout(CALL_TIMEOUT, session.child.wait()).await;
                    match exit {
                        Ok(Ok(status)) if status.success() => Ok(None),
                        _ => Err(TransportError::Network("APDU helper failed to exit".into())),
                    }
                }
                Err(err) => Err(TransportError::Network(format!("APDU: {err:#}"))),
            }
        });
        Ok(Box::pin(stream))
    }
}
