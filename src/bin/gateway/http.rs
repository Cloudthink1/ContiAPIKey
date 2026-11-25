use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use codex_apdu::{ApduTransport, ByteStream, TransportError};
use futures::{StreamExt, stream};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    body::{Frame, Incoming},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
};
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 1024 * 1024;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(175);
const TOKEN_LIFETIME: Duration = Duration::from_secs(300);
const MIN_REMAINING: Duration = Duration::from_secs(135);
type Body = UnsyncBoxBody<Bytes, TransportError>;

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    DeepSeek,
    ChatGpt,
}

impl FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "deepseek" => Ok(Self::DeepSeek),
            "chatgpt" => Ok(Self::ChatGpt),
            _ => bail!("mode must be deepseek or chatgpt"),
        }
    }
}

pub enum Backend {
    Offline(ApduTransport),
    #[cfg(windows)]
    DeepSeek(codex_apdu::LiveTransport),
    #[cfg(windows)]
    ChatGpt(codex_apdu::ChatGptTransport),
}

enum SessionModels {
    Offline,
    #[cfg(any(windows, test))]
    Fixed(String),
    #[cfg(any(windows, test))]
    ChatGpt {
        configured: String,
        default: String,
        offered: Vec<String>,
    },
}

impl SessionModels {
    fn resolve<'a>(&'a self, requested: &'a str) -> Result<&'a str, String> {
        match self {
            Self::Offline => Ok(requested),
            #[cfg(any(windows, test))]
            Self::Fixed(model) => (requested == model).then_some(requested).ok_or_else(|| {
                format!("This gateway session supports only {model}. Select that model.")
            }),
            #[cfg(any(windows, test))]
            Self::ChatGpt {
                configured,
                default,
                offered,
            } => {
                if requested == configured {
                    Ok(default)
                } else if offered.iter().any(|model| model == requested) {
                    Ok(requested)
                } else {
                    Err(format!(
                        "This ChatGPT account offers these models: {}.",
                        offered.join(", ")
                    ))
                }
            }
        }
    }
}

impl Backend {
    async fn prepare(&self, model: &str) -> Result<SessionModels> {
        #[cfg(not(windows))]
        let _ = model;
        match self {
            Self::Offline(_) => Ok(SessionModels::Offline),
            #[cfg(windows)]
            Self::DeepSeek(transport) => {
                transport.prepare().await?;
                Ok(SessionModels::Fixed(model.to_owned()))
            }
            #[cfg(windows)]
            Self::ChatGpt(_) => {
                let models = codex_apdu::prepare_chatgpt(|message| eprintln!("{message}")).await?;
                let selected = if model == "apdu-chatgpt-auto" {
                    models.first()
                } else {
                    models.iter().find(|entry| entry.slug == model)
                }
                .with_context(|| {
                    format!(
                        "model {model} is unavailable; offered models: {}",
                        models
                            .iter()
                            .map(|entry| entry.slug.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
                tracing::info!(configured_model = model, upstream_model = %selected.slug, "resolved ChatGPT model");
                let default = selected.slug.clone();
                let offered = models.into_iter().map(|entry| entry.slug).collect();
                Ok(SessionModels::ChatGpt {
                    configured: model.to_owned(),
                    default,
                    offered,
                })
            }
        }
    }

    async fn stream(&self, body: Bytes) -> Result<ByteStream, TransportError> {
        match self {
            Self::Offline(transport) => transport.stream(body).await,
            #[cfg(windows)]
            Self::DeepSeek(transport) => transport.stream(body).await,
            #[cfg(windows)]
            Self::ChatGpt(transport) => transport.stream(body).await,
        }
    }
}

struct Lease {
    bearer: Zeroizing<String>,
    digest: [u8; 32],
    expires: Instant,
    models: Arc<SessionModels>,
}

impl Lease {
    fn issue(models: SessionModels) -> Result<Self> {
        let mut bearer = Zeroizing::new(String::from("gateway-"));
        for byte in rand::random::<[u8; 32]>() {
            write!(bearer, "{byte:02x}")?;
        }
        let digest = digest(bearer.as_bytes());
        Ok(Self {
            bearer,
            digest,
            expires: Instant::now() + TOKEN_LIFETIME,
            models: Arc::new(models),
        })
    }
}

struct Gateway {
    backend: Backend,
    bootstrap: [u8; 32],
    // One gateway process represents one selected mode and alias.
    lease: Mutex<Option<Lease>>,
    login: Mutex<()>,
    model: String,
}

fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn matches_bearer(request: &Request<Incoming>, expected: &[u8; 32]) -> bool {
    request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.as_bytes().strip_prefix(b"Bearer "))
        .is_some_and(|actual| bool::from(digest(actual).ct_eq(expected)))
}

fn full(status: StatusCode, content_type: &'static str, bytes: Bytes) -> Response<Body> {
    let mut response = Response::new(
        Full::new(bytes)
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn error(status: StatusCode, code: &str, message: &str) -> Response<Body> {
    full(
        status,
        "application/json",
        Bytes::from(json!({"error":{"message":message,"code":code}}).to_string()),
    )
}

impl Gateway {
    async fn session(&self, request: &Request<Incoming>) -> Response<Body> {
        if !matches_bearer(request, &self.bootstrap) {
            return error(
                StatusCode::UNAUTHORIZED,
                "gateway_bootstrap",
                "Gateway bootstrap credential is missing or invalid.",
            );
        }
        let Ok(_login) = tokio::time::timeout(LOGIN_TIMEOUT, self.login.lock()).await else {
            return error(
                StatusCode::GATEWAY_TIMEOUT,
                "login_busy",
                "The current gateway sign-in is still pending.",
            );
        };
        if let Some(lease) = self.lease.lock().await.as_ref()
            && lease.expires.saturating_duration_since(Instant::now()) > MIN_REMAINING
        {
            return full(
                StatusCode::OK,
                "text/plain",
                Bytes::copy_from_slice(lease.bearer.as_bytes()),
            );
        }
        let models =
            match tokio::time::timeout(LOGIN_TIMEOUT, self.backend.prepare(&self.model)).await {
                Ok(Ok(models)) => models,
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "chip sign-in failed");
                    return error(
                        StatusCode::BAD_GATEWAY,
                        "chip_login",
                        "Chip authorization failed. Check the gateway console and retry.",
                    );
                }
                Err(_) => {
                    return error(
                        StatusCode::GATEWAY_TIMEOUT,
                        "login_timeout",
                        "Chip authorization timed out. Restart sign-in.",
                    );
                }
            };
        let Ok(lease) = Lease::issue(models) else {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "gateway_token",
                "Could not create the gateway session.",
            );
        };
        let token = Bytes::copy_from_slice(lease.bearer.as_bytes());
        *self.lease.lock().await = Some(lease);
        full(StatusCode::OK, "text/plain", token)
    }

    async fn responses(&self, request: Request<Incoming>) -> Response<Body> {
        let models = self
            .lease
            .lock()
            .await
            .as_ref()
            .filter(|lease| {
                lease.expires > Instant::now() && matches_bearer(&request, &lease.digest)
            })
            .map(|lease| lease.models.clone());
        let Some(models) = models else {
            return error(
                StatusCode::UNAUTHORIZED,
                "gateway_token",
                "Gateway session is missing or expired.",
            );
        };
        if request.headers().contains_key(header::CONTENT_ENCODING) {
            return error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "content_encoding",
                "Use an uncompressed JSON request.",
            );
        }
        let body = match tokio::time::timeout(
            Duration::from_secs(20),
            Limited::new(request.into_body(), MAX_REQUEST).collect(),
        )
        .await
        {
            Ok(Ok(body)) => body.to_bytes(),
            Ok(Err(err)) if err.is::<http_body_util::LengthLimitError>() => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "apdu_limit",
                    "Request exceeds the 1 MiB APDU limit.",
                );
            }
            Ok(Err(_)) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "body",
                    "Could not read model request.",
                );
            }
            Err(_) => {
                return error(
                    StatusCode::REQUEST_TIMEOUT,
                    "body_timeout",
                    "Timed out reading model request.",
                );
            }
        };
        let Ok(mut value) = serde_json::from_slice::<Value>(&body) else {
            return error(
                StatusCode::BAD_REQUEST,
                "json",
                "Expected a JSON Responses request.",
            );
        };
        if value["stream"] != true || !value["input"].is_array() {
            return error(
                StatusCode::BAD_REQUEST,
                "responses_request",
                "Use stream=true with an input array.",
            );
        }
        let Some(requested) = value["model"]
            .as_str()
            .filter(|model| !model.trim().is_empty())
        else {
            return error(
                StatusCode::BAD_REQUEST,
                "responses_request",
                "Provide a model name.",
            );
        };
        let upstream_model = match models.resolve(requested) {
            Ok(model) => model,
            Err(message) => return error(StatusCode::BAD_REQUEST, "model_unavailable", &message),
        };
        let body = if upstream_model == requested {
            body
        } else {
            value["model"] = Value::String(upstream_model.to_owned());
            Bytes::from(value.to_string())
        };
        let mut bytes = match self.backend.stream(body).await {
            Ok(bytes) => bytes,
            Err(err) => return apdu_error(err),
        };
        let first = match bytes.next().await {
            Some(Ok(bytes)) => bytes,
            Some(Err(err)) => {
                if matches!(err, TransportError::Chip { status: 0x6406, .. }) {
                    *self.lease.lock().await = None;
                }
                return apdu_error(err);
            }
            None => {
                return error(
                    StatusCode::BAD_GATEWAY,
                    "apdu_stream",
                    "The chip returned an empty response.",
                );
            }
        };
        let frames = stream::once(async { Ok(first) })
            .chain(bytes)
            .map(|chunk| chunk.map(Frame::data));
        let mut response = Response::new(StreamBody::new(frames).boxed_unsync());
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/event-stream"),
        );
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<Body> {
        match (
            request.method(),
            request
                .uri()
                .path_and_query()
                .map(http::uri::PathAndQuery::as_str),
        ) {
            (&Method::POST, Some("/session")) => self.session(&request).await,
            (&Method::POST, Some("/v1/responses")) => self.responses(request).await,
            _ => error(
                StatusCode::NOT_FOUND,
                "route",
                "Gateway endpoint not found.",
            ),
        }
    }
}

fn apdu_error(err: TransportError) -> Response<Body> {
    let status = match err {
        TransportError::Build(_) | TransportError::Chip { status: 0x6A80, .. } => {
            StatusCode::BAD_REQUEST
        }
        TransportError::Chip { status: 0x6402, .. } => StatusCode::TOO_MANY_REQUESTS,
        TransportError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_GATEWAY,
    };
    error(status, "apdu", &err.to_string())
}

pub async fn serve(
    listener: TcpListener,
    backend: Backend,
    mode: Mode,
    alias: String,
    model: String,
    bootstrap: &str,
) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "gateway must listen on loopback"
    );
    let gateway = Arc::new(Gateway {
        backend,
        bootstrap: digest(bootstrap.as_bytes()),
        lease: Mutex::new(None),
        login: Mutex::new(()),
        model,
    });
    let connections = Arc::new(Semaphore::new(32));
    tracing::info!(?mode, %alias, "gateway started");
    loop {
        let (socket, _) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request| {
                let gateway = gateway.clone();
                async move { Ok::<_, std::convert::Infallible>(gateway.handle(request).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .keep_alive(false)
                .serve_connection(TokioIo::new(socket), service)
                .await;
        });
    }
}

pub async fn read_secret(path: &Path) -> Result<Zeroizing<String>> {
    let raw = Zeroizing::new(
        tokio::fs::read_to_string(path)
            .await
            .context("read gateway bootstrap file")?,
    );
    ensure!(
        raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid gateway bootstrap file"
    );
    Ok(raw)
}

pub async fn credential(address: SocketAddr, secret: &Path) -> Result<Zeroizing<String>> {
    ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "credential helper accepts a local gateway only"
    );
    let secret = read_secret(secret).await?;
    let socket =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(address)).await??;
    let (mut client, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    tokio::spawn(connection);
    let mut auth = header::HeaderValue::from_str(&format!("Bearer {}", &*secret))?;
    auth.set_sensitive(true);
    let request = Request::post("/session")
        .header(header::HOST, address.to_string())
        .header(header::AUTHORIZATION, auth)
        .body(Full::new(Bytes::new()))?;
    let response = tokio::time::timeout(
        LOGIN_TIMEOUT + Duration::from_secs(5),
        client.send_request(request),
    )
    .await??;
    ensure!(
        response.status().is_success(),
        "gateway sign-in failed (HTTP {}). Check the gateway console.",
        response.status().as_u16()
    );
    let body = tokio::time::timeout(
        Duration::from_secs(5),
        Limited::new(response.into_body(), 256).collect(),
    )
    .await?
    .map_err(|_| anyhow::anyhow!("invalid gateway credential response"))?
    .to_bytes();
    let token = Zeroizing::new(std::str::from_utf8(&body)?.to_owned());
    ensure!(
        token.len() == 72
            && token
                .strip_prefix("gateway-")
                .is_some_and(|suffix| suffix.bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid gateway credential"
    );
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::SessionModels;

    #[test]
    fn chatgpt_switches_to_an_offered_model_and_preserves_the_default_alias() {
        let models = SessionModels::ChatGpt {
            configured: "apdu-chatgpt-auto".to_owned(),
            default: "gpt-6.2-sol".to_owned(),
            offered: vec!["gpt-6.2-sol".to_owned(), "gpt-5.4".to_owned()],
        };
        assert_eq!(models.resolve("apdu-chatgpt-auto").unwrap(), "gpt-6.2-sol");
        assert_eq!(models.resolve("gpt-5.4").unwrap(), "gpt-5.4");
        assert_eq!(models.resolve("gpt-6.2-sol").unwrap(), "gpt-6.2-sol");
        assert!(models.resolve("unknown").unwrap_err().contains("gpt-5.4"));
    }

    #[test]
    fn fixed_model_rejects_other_models_with_a_specific_message() {
        let models = SessionModels::Fixed("deepseek-flash".to_owned());
        assert_eq!(models.resolve("deepseek-flash").unwrap(), "deepseek-flash");
        assert!(
            models
                .resolve("gpt-6.2-sol")
                .unwrap_err()
                .contains("deepseek-flash")
        );
    }
}
