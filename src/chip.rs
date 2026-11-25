use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use bytes::Bytes;
use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;
use http::header;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::protocol::*;
use crate::tls;

pub const DEMO_USER: u8 = 1;
const EXECUTE_SIZE: usize = 65;
const AUTH_TTL: Duration = Duration::from_secs(30);

struct Identity {
    user_key: VerifyingKey,
    tls: Arc<ClientConfig>,
    authorization: http::HeaderValue,
}

impl Identity {
    fn load(directory: &Path) -> Result<Self> {
        let public: [u8; 32] = std::fs::read(directory.join("user.pub"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid user public key length"))?;
        let ca = std::fs::read(directory.join("ca.der"))?;
        let mut authorization =
            http::HeaderValue::from_str(&format!("Bearer {}", tls::read_api_key(directory)?))?;
        authorization.set_sensitive(true);
        Ok(Self {
            user_key: VerifyingKey::from_bytes(&public)?,
            tls: Arc::new(tls::client_config(ca)?),
            authorization,
        })
    }
}

enum State {
    Ready,
    Upload {
        nonce: [u8; 32],
        issued: Instant,
        request: Vec<u8>,
        next: u16,
    },
    Download {
        stream: ModelStream,
        next: u16,
    },
    Done,
}

struct ModelStream {
    body: Incoming,
    pending: Bytes,
    size: usize,
    connection: JoinHandle<Result<(), hyper::Error>>,
}

impl Drop for ModelStream {
    fn drop(&mut self) {
        self.connection.abort();
    }
}

impl ModelStream {
    async fn open(identity: &Identity, relay: SocketAddr, request: Vec<u8>) -> Result<Self> {
        let socket = TcpStream::connect(relay)
            .await
            .context("connect to TLS relay")?;
        let name = ServerName::try_from(tls::SERVER_NAME)?;
        let encrypted = TlsConnector::from(identity.tls.clone())
            .connect(name, socket)
            .await
            .context("establish verified TLS 1.3 connection")?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(encrypted)).await?;
        let http_request = http::Request::post(tls::RESPONSES_PATH)
            .header(header::HOST, tls::SERVER_NAME)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "text/event-stream")
            .header(header::AUTHORIZATION, identity.authorization.clone())
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::from(request)))?;
        let mut stream = tokio::spawn(connection);
        let result = sender.send_request(http_request).await.map(|response| {
            let valid = response.status() == http::StatusCode::OK
                && response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|value| {
                        value.as_bytes().split(|b| *b == b';').next() == Some(b"text/event-stream")
                    });
            (valid, response.into_body())
        });
        match result {
            Ok((true, body)) => Ok(Self {
                body,
                pending: Bytes::new(),
                size: 0,
                connection: stream,
            }),
            other => {
                stream.abort();
                let _ = (&mut stream).await;
                drop(other.context("send model HTTP request")?);
                anyhow::bail!("model service did not return a successful SSE response");
            }
        }
    }

    async fn read(&mut self) -> Result<Bytes> {
        while self.pending.is_empty() {
            let Some(frame) = self.body.frame().await else {
                return Ok(Bytes::new());
            };
            if let Ok(data) = frame?.into_data() {
                self.size += data.len();
                ensure!(self.size <= MAX_RESPONSE, "response exceeds limit");
                self.pending = data;
            }
        }
        Ok(self.pending.split_to(self.pending.len().min(CHUNK)))
    }
}

struct Chip {
    identity: Identity,
    relay: SocketAddr,
    state: State,
}

impl Chip {
    async fn command(&mut self, command: Command<'_>) -> Result<(Bytes, u16), u16> {
        let Command {
            ins,
            sequence,
            data,
        } = command;
        if matches!(ins, CHALLENGE | EXECUTE | CANCEL) && sequence != 0 {
            return Err(BAD_SEQUENCE);
        }
        match (ins, &mut self.state) {
            (CANCEL, _) => self.state = State::Done,
            (CHALLENGE, State::Ready) => {
                let nonce: [u8; 32] = rand::random();
                self.state = State::Upload {
                    nonce,
                    issued: Instant::now(),
                    request: Vec::new(),
                    next: 0,
                };
                return Ok((Bytes::copy_from_slice(&nonce), OK));
            }
            (WRITE, State::Upload { request, next, .. }) => {
                if sequence != *next {
                    return Err(BAD_SEQUENCE);
                }
                if request.len() + data.len() > MAX_REQUEST {
                    self.state = State::Done;
                    return Err(TOO_LARGE);
                }
                request.extend_from_slice(data);
                *next += 1;
            }
            (EXECUTE, State::Upload { .. }) => {
                let State::Upload {
                    nonce,
                    issued,
                    request,
                    ..
                } = std::mem::replace(&mut self.state, State::Done)
                else {
                    unreachable!("upload state is matched above");
                };
                if data.len() != EXECUTE_SIZE {
                    return Err(BAD_LENGTH);
                }
                let signature = Signature::from_slice(&data[1..]).map_err(|_| DENIED)?;
                if data[0] != DEMO_USER
                    || issued.elapsed() >= AUTH_TTL
                    || self
                        .identity
                        .user_key
                        .verify_strict(&signed_message(&nonce, &request), &signature)
                        .is_err()
                {
                    return Err(DENIED);
                }
                let body: serde_json::Value =
                    serde_json::from_slice(&request).map_err(|_| BAD_DATA)?;
                if !body.is_object()
                    || body.get("stream").and_then(serde_json::Value::as_bool) != Some(true)
                {
                    return Err(BAD_DATA);
                }
                let stream = ModelStream::open(&self.identity, self.relay, request)
                    .await
                    .map_err(|_| UPSTREAM_FAILED)?;
                self.state = State::Download { stream, next: 0 };
            }
            (READ, State::Download { stream, next }) => {
                if sequence != *next {
                    return Err(BAD_SEQUENCE);
                }
                match stream.read().await {
                    Ok(bytes) if bytes.is_empty() => self.state = State::Done,
                    Ok(bytes) if *next < u16::MAX => {
                        *next += 1;
                        return Ok((bytes, MORE));
                    }
                    Ok(_) | Err(_) => {
                        self.state = State::Done;
                        return Err(UPSTREAM_FAILED);
                    }
                }
            }
            _ => return Err(BAD_STATE),
        }
        Ok((Bytes::new(), OK))
    }
}

pub async fn run_chip(
    directory: &Path,
    relay: SocketAddr,
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    ensure!(
        relay.ip().is_loopback() && relay.port() != 0,
        "relay must use a loopback socket"
    );
    let mut chip = Chip {
        identity: Identity::load(directory)?,
        relay,
        state: State::Ready,
    };
    while let Some(frame) = read_frame(&mut reader).await? {
        let (data, status) = match Command::decode(&frame) {
            Ok(command) => chip
                .command(command)
                .await
                .unwrap_or_else(|sw| (Bytes::new(), sw)),
            Err(sw) => (Bytes::new(), sw),
        };
        let mut response = data.to_vec();
        response.extend_from_slice(&status.to_be_bytes());
        write_frame(&mut writer, &response).await?;
    }
    match chip.state {
        State::Ready | State::Done => Ok(()),
        State::Upload { .. } | State::Download { .. } => {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "APDU channel closed mid-call").into())
        }
    }
}
