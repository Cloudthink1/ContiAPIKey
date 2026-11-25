use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use bytes::Bytes;
use http::Method;
use http::Response;
use http::StatusCode;
use http::header;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;
use url::Url;
use zeroize::Zeroizing;

use super::chip::LOGIN_TTL;
use super::chip::REDIRECT_PORTS;
use super::service::CLIENT_ID;
use super::service::LoginIntent;
use crate::network::AUTH_HOST;

#[derive(Deserialize)]
pub struct Authorization {
    challenge: String,
    pub state: String,
}

impl Authorization {
    pub fn open(&self, port: u16, intent: LoginIntent) -> Result<()> {
        let mut url = Url::parse(&format!("https://{AUTH_HOST}/oauth/authorize"))?;
        let redirect = format!("http://localhost:{port}/auth/callback");
        ensure!(
            valid_parameter(&self.challenge) && valid_parameter(&self.state),
            "invalid chip authorization parameters"
        );
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", CLIENT_ID),
            ("redirect_uri", &redirect),
            (
                "scope",
                "openid profile email offline_access api.connectors.read api.connectors.invoke",
            ),
            ("code_challenge", &self.challenge),
            ("code_challenge_method", "S256"),
            ("state", &self.state),
            ("id_token_add_organizations", "true"),
            ("codex_cli_simplified_flow", "true"),
            ("originator", "codex_cli_rs"),
        ]);
        if intent == LoginIntent::Add {
            url.query_pairs_mut().append_pair("prompt", "login");
        }
        webbrowser::open(url.as_str()).context("could not open the system browser")
    }
}

fn valid_parameter(parameter: &str) -> bool {
    parameter.len() == 43
        && parameter
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

pub struct Callback {
    code: Zeroizing<String>,
    state: String,
    pub result: oneshot::Sender<bool>,
}

impl Callback {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        #[derive(Serialize)]
        struct Fields<'a> {
            code: &'a str,
            state: &'a str,
        }
        Ok(Zeroizing::new(serde_json::to_vec(&Fields {
            code: self.code.as_str(),
            state: &self.state,
        })?))
    }
}

pub async fn bind() -> Result<(TcpListener, u16)> {
    for port in REDIRECT_PORTS {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok((listener, port)),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => (),
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!(
        "both ChatGPT callback ports are in use (1455, 1457)"
    ))
}

pub struct Browser {
    callback: mpsc::Receiver<Option<Callback>>,
    completed: Arc<Notify>,
    task: JoinHandle<()>,
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Browser {
    pub fn new(listener: TcpListener, port: u16, state: String) -> Self {
        let (output, callback) = mpsc::channel(1);
        let completed = Arc::new(Notify::new());
        let completion = completed.clone();
        let task = tokio::spawn(async move {
            let host = format!("localhost:{port}");
            let success = Arc::new(AtomicBool::new(false));
            let capacity = Arc::new(Semaphore::new(8));
            let mut tasks = JoinSet::new();
            loop {
                while tasks.try_join_next().is_some() {}
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let Ok(permit) = capacity.clone().try_acquire_owned() else {
                    continue;
                };
                let (host, state, output, success, completion) = (
                    host.clone(),
                    state.clone(),
                    output.clone(),
                    success.clone(),
                    completion.clone(),
                );
                tasks.spawn(async move {
                    let _permit = permit;
                    let service = service_fn(|request| {
                        handle(request, &host, &state, &output, &success, &completion)
                    });
                    let connection = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(TokioIo::new(socket), service);
                    let _ = tokio::time::timeout(LOGIN_TTL, connection).await;
                });
            }
        });
        Self {
            callback,
            completed,
            task,
        }
    }

    pub async fn callback(&mut self) -> Result<Callback> {
        tokio::time::timeout(LOGIN_TTL, self.callback.recv())
            .await
            .context("ChatGPT browser login timed out")?
            .flatten()
            .context("ChatGPT browser authorization canceled")
    }

    pub async fn show_success(&self) {
        if tokio::time::timeout(std::time::Duration::from_secs(2), self.completed.notified())
            .await
            .is_ok()
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
}

async fn handle(
    request: http::Request<Incoming>,
    host: &str,
    expected: &str,
    output: &mpsc::Sender<Option<Callback>>,
    success: &AtomicBool,
    completed: &Notify,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let response = if request.method() != Method::GET
        || request
            .headers()
            .get(header::HOST)
            .and_then(|header| header.to_str().ok())
            != Some(host)
    {
        page(StatusCode::BAD_REQUEST, "Invalid sign-in request.")
    } else {
        match request.uri().path() {
            "/complete" if success.load(Ordering::Acquire) => {
                // Let the HTTP connection flush before the host stops the listener.
                let response = page(
                    StatusCode::OK,
                    "ChatGPT sign-in completed. You can close this tab.",
                );
                completed.notify_one();
                response
            }
            "/auth/callback" => match parse(request.uri().query().unwrap_or_default(), expected) {
                Some(Some((code, state))) => {
                    let (result, done) = oneshot::channel();
                    if output
                        .try_send(Some(Callback {
                            code,
                            state,
                            result,
                        }))
                        .is_ok()
                        && done.await == Ok(true)
                    {
                        success.store(true, Ordering::Release);
                        let mut response = page(StatusCode::SEE_OTHER, "");
                        response.headers_mut().insert(
                            header::LOCATION,
                            http::HeaderValue::from_static("/complete"),
                        );
                        response
                    } else {
                        page(
                            StatusCode::BAD_REQUEST,
                            "ChatGPT sign-in did not complete. Return to Codex.",
                        )
                    }
                }
                Some(None) => {
                    let _ = output.try_send(None);
                    page(StatusCode::BAD_REQUEST, "ChatGPT sign-in canceled.")
                }
                None => page(StatusCode::BAD_REQUEST, "Invalid sign-in callback."),
            },
            _ => page(StatusCode::NOT_FOUND, "Sign-in page not found."),
        }
    };
    Ok(response)
}

fn parse(query: &str, expected: &str) -> Option<Option<(Zeroizing<String>, String)>> {
    if query.len() > 8192 {
        return None;
    }
    let mut code = None;
    let mut state = None;
    let mut error = false;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "code" if code.is_none() => code = Some(Zeroizing::new(value.into_owned())),
            "state" if state.is_none() => state = Some(value.into_owned()),
            "error" if !error => error = true,
            "code" | "state" | "error" => return None,
            _ => (),
        }
    }
    let state = state.filter(|state| state == expected)?;
    match (code, error) {
        (None, true) => Some(None),
        (Some(code), false) if !code.is_empty() && code.len() <= 4096 => Some(Some((code, state))),
        _ => None,
    }
}

fn page(status: StatusCode, text: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
    *response.status_mut() = status;
    for (name, value) in [
        (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
        (header::CACHE_CONTROL, "no-store"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ] {
        response
            .headers_mut()
            .insert(name, http::HeaderValue::from_static(value));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn only_accepts_the_current_callback_and_rejects_duplicates() {
        let (code, _) = parse("code=one%2Btwo&state=current", "current")
            .unwrap()
            .unwrap();
        assert_eq!(code.as_str(), "one+two");
        assert!(
            parse("error=access_denied&state=current", "current")
                .unwrap()
                .is_none()
        );
        assert!(parse("code=code&state=stale", "current").is_none());
        assert!(parse("code=code&code=other&state=current", "current").is_none());
    }
}
