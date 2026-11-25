use std::path::Path;

use bytes::Bytes;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use http::HeaderValue;
use http::Request;
use http::StatusCode;
use http::header;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use url::form_urlencoded;
use zeroize::Zeroizing;

use super::credentials::Credentials;
use super::credentials::MAX_TOKEN_REPLY;
use super::credentials::Store;
use crate::network::Destination;
use crate::network::Network;
use crate::operation::Output;
use crate::protocol::ALIAS_EXISTS;
use crate::protocol::BAD_DATA;
use crate::protocol::MAX_RESPONSE;
use crate::protocol::UPSTREAM_FAILED;
use crate::protocol::chatgpt::LOGIN_REQUIRED;

pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const TLS_FAILED: u16 = 0x6403;
pub const RATE_LIMITED: u16 = 0x6402;
pub const TRUNCATED: u16 = 0x6404;
pub const FORBIDDEN: u16 = 0x6409;
pub const MODEL_REJECTED: u16 = 0x640C;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Model {
    pub slug: String,
    pub display_name: String,
    pub priority: i64,
}

struct Reply {
    response: http::Response<Incoming>,
    _connection: Connection,
}

struct Connection(JoinHandle<()>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn send(
    network: &Network,
    destination: Destination,
    request: Request<Full<Bytes>>,
) -> Result<Reply, u16> {
    let tls = network.connect(destination).await.map_err(|_| TLS_FAILED)?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|_| UPSTREAM_FAILED)?;
    let connection = Connection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| UPSTREAM_FAILED)?;
    Ok(Reply {
        response,
        _connection: connection,
    })
}

fn auth_request(
    method: http::Method,
    path: &str,
    credentials: &Credentials,
    body: Bytes,
) -> Result<Request<Full<Bytes>>, u16> {
    let mut secret = Zeroizing::new(b"Bearer ".to_vec());
    secret.extend_from_slice(credentials.access_token.as_bytes());
    let mut authorization = HeaderValue::from_bytes(&secret).map_err(|_| LOGIN_REQUIRED)?;
    authorization.set_sensitive(true);
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, Destination::Chat.hostname())
        .header(header::CONNECTION, "close")
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::ACCEPT,
            if path.ends_with("/responses") {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .header(header::AUTHORIZATION, authorization)
        .header(
            "ChatGPT-Account-ID",
            credentials.account().ok_or(LOGIN_REQUIRED)?,
        )
        .header("originator", "codex_cli_rs")
        .header(
            header::USER_AGENT,
            "codex_cli_rs/0.130.0 (Windows) codex-apdu",
        )
        .body(Full::new(body))
        .map_err(|_| BAD_DATA)
}

async fn read_bounded(reply: &mut Reply, limit: usize) -> Result<Zeroizing<Vec<u8>>, u16> {
    let mut body = Zeroizing::new(Vec::new());
    while let Some(frame) = reply.response.body_mut().frame().await {
        if let Ok(data) = frame.map_err(|_| UPSTREAM_FAILED)?.into_data() {
            if body.len() + data.len() > limit {
                return Err(UPSTREAM_FAILED);
            }
            body.extend_from_slice(&data);
        }
    }
    Ok(body)
}

async fn token(
    network: &Network,
    content_type: &'static str,
    body: Vec<u8>,
    old: Option<&Credentials>,
) -> Result<Credentials, u16> {
    let request = Request::post("/oauth/token")
        .header(header::HOST, Destination::Auth.hostname())
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::from_owner(Zeroizing::new(body))))
        .map_err(|_| BAD_DATA)?;
    let mut reply = send(network, Destination::Auth, request).await?;
    match reply.response.status() {
        status if status.is_success() => (),
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED => return Err(LOGIN_REQUIRED),
        status => return Err(classify(status)),
    }
    let body = read_bounded(&mut reply, MAX_TOKEN_REPLY).await?;
    Credentials::from_reply(&body, old)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LoginIntent {
    Reuse,
    Add,
}

pub async fn exchange(
    network: &Network,
    directory: &Path,
    code: &str,
    verifier: &str,
    redirect: &str,
    intent: LoginIntent,
) -> Result<(), u16> {
    let store = Store::open(directory)?;
    let previous = store.load()?;
    if intent == LoginIntent::Add && previous.is_some() {
        return Err(ALIAS_EXISTS);
    }
    let form = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect),
            ("client_id", CLIENT_ID),
            ("code_verifier", verifier),
        ])
        .finish();
    let credentials = token(
        network,
        "application/x-www-form-urlencoded",
        form.into_bytes(),
        None,
    )
    .await?;
    if previous.is_some_and(|saved| !saved.same_account(&credentials)) {
        return Err(crate::protocol::chatgpt::LOGIN_MISMATCH);
    }
    store.save(&credentials)
}

async fn usable_credentials(network: &Network, directory: &Path) -> Result<Credentials, u16> {
    let store = Store::open(directory)?;
    let old = store.load()?.ok_or(LOGIN_REQUIRED)?;
    if !old.near_expiry() {
        return Ok(old);
    }
    #[derive(Serialize)]
    struct Refresh<'a> {
        client_id: &'a str,
        grant_type: &'a str,
        refresh_token: &'a str,
    }
    let request = serde_json::to_vec(&Refresh {
        client_id: CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: &old.refresh_token,
    })
    .map_err(|_| BAD_DATA)?;
    let new = token(network, "application/json", request, Some(&old)).await?;
    store.save(&new)?;
    Ok(new)
}

pub async fn models(network: &Network, directory: &Path) -> Result<Bytes, u16> {
    let credentials = usable_credentials(network, directory).await?;
    let request = auth_request(
        http::Method::GET,
        "/backend-api/codex/models?client_version=0.169.0",
        &credentials,
        Bytes::new(),
    )?;
    let mut reply = send(network, Destination::Chat, request).await?;
    if !reply.response.status().is_success() {
        return Err(classify(reply.response.status()));
    }
    let body = read_bounded(&mut reply, 4 * 1024 * 1024).await?;
    let response: Value = serde_json::from_slice(&body).map_err(|_| UPSTREAM_FAILED)?;
    let mut models = Vec::new();
    for item in response["models"].as_array().ok_or(UPSTREAM_FAILED)? {
        if item["visibility"] != "list" {
            continue;
        }
        let Some(slug) = item["slug"].as_str().filter(|slug| {
            !slug.is_empty()
                && slug.len() <= 128
                && slug
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        }) else {
            continue;
        };
        let name = item["display_name"].as_str().unwrap_or(slug);
        let display_name = name
            .chars()
            .filter(|character| !character.is_control())
            .take(128)
            .collect();
        models.push(Model {
            slug: slug.to_owned(),
            display_name,
            priority: item["priority"].as_i64().unwrap_or(i64::MAX),
        });
    }
    models.sort_by_key(|model| model.priority);
    if models.is_empty() {
        return Err(UPSTREAM_FAILED);
    }
    let json = serde_json::to_vec(&models).map_err(|_| UPSTREAM_FAILED)?;
    if contains_credential(&json, &credentials) {
        return Err(UPSTREAM_FAILED);
    }
    Ok(Bytes::from(json))
}

fn classify(status: StatusCode) -> u16 {
    match status {
        StatusCode::UNAUTHORIZED => LOGIN_REQUIRED,
        StatusCode::FORBIDDEN => FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS => RATE_LIMITED,
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND => BAD_DATA,
        _ => UPSTREAM_FAILED,
    }
}

fn contains_credential(bytes: &[u8], credentials: &Credentials) -> bool {
    [
        &credentials.access_token,
        &credentials.refresh_token,
        &credentials.id_token,
    ]
    .into_iter()
    .any(|secret| {
        !secret.is_empty()
            && bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
    })
}

fn safe_delta(buffer: &mut String, delta: &str, credentials: &Credentials) -> Result<String, u16> {
    buffer.push_str(delta);
    let bytes = buffer.as_bytes();
    if contains_credential(bytes, credentials) {
        return Err(TRUNCATED);
    }
    // Retain only a trailing prefix of a credential, so secrets split across
    // upstream events are never reconstructed from the emitted chunks.
    let withheld = [
        &credentials.access_token,
        &credentials.refresh_token,
        &credentials.id_token,
    ]
    .into_iter()
    .filter_map(|secret| {
        (1..secret.len().min(bytes.len() + 1))
            .rev()
            .find(|&count| bytes.ends_with(&secret.as_bytes()[..count]))
    })
    .max()
    .unwrap_or(0);
    let tail = buffer.split_off(buffer.len() - withheld);
    Ok(std::mem::replace(buffer, tail))
}

fn model_request(body: &[u8]) -> Result<Bytes, u16> {
    let raw: Value = serde_json::from_slice(body).map_err(|_| BAD_DATA)?;
    let model = raw["model"].as_str().ok_or(BAD_DATA)?;
    let mut input = Vec::new();
    for item in raw["input"].as_array().ok_or(BAD_DATA)? {
        let item = match item["type"].as_str() {
            Some("message") => {
                let role = item["role"].as_str().ok_or(BAD_DATA)?;
                if !matches!(role, "user" | "assistant" | "developer" | "system") {
                    return Err(BAD_DATA);
                }
                let content: Vec<_> = item["content"].as_array().ok_or(BAD_DATA)?.iter().map(|part| {
                    let text = part["text"].as_str().ok_or(BAD_DATA)?;
                    Ok(json!({"type": if role == "assistant" { "output_text" } else { "input_text" }, "text": text}))
                }).collect::<Result<_, u16>>()?;
                json!({"type":"message","role":role,"content":content})
            }
            Some("function_call") => {
                json!({"type":"function_call", "call_id":item["call_id"].as_str().ok_or(BAD_DATA)?,
                "name":item["name"].as_str().ok_or(BAD_DATA)?, "arguments":item["arguments"].as_str().ok_or(BAD_DATA)?})
            }
            Some("function_call_output") => {
                json!({"type":"function_call_output", "call_id":item["call_id"].as_str().ok_or(BAD_DATA)?,
                "output":crate::functions_wire::output_text(&item["output"]).ok_or(BAD_DATA)?})
            }
            // The text adapter uses the top-level standard function definitions.
            Some("reasoning" | "additional_tools") => continue,
            _ => return Err(BAD_DATA),
        };
        input.push(item);
    }
    if input.is_empty() {
        return Err(BAD_DATA);
    }
    let tools: Vec<_> = crate::functions_wire::definitions(&raw).collect();
    let request = json!({
        "model": model, "instructions": raw["instructions"].as_str().unwrap_or("Respond to the user."),
        "input": input, "stream": true, "store": false, "include": [],
        "tools": tools, "tool_choice": "auto", "parallel_tool_calls": false, "reasoning": null,
    });
    serde_json::to_vec(&request)
        .map(Bytes::from)
        .map_err(|_| BAD_DATA)
}

pub async fn chat(
    network: &Network,
    directory: &Path,
    request: &[u8],
    output: &mpsc::Sender<Output>,
) -> Result<(), u16> {
    let body = model_request(request)?;
    let credentials = usable_credentials(network, directory).await?;
    let request = auth_request(
        http::Method::POST,
        "/backend-api/codex/responses",
        &credentials,
        body,
    )?;
    let mut reply = send(network, Destination::Chat, request).await?;
    let status = reply.response.status();
    if matches!(status, StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND) {
        return Err(MODEL_REJECTED);
    }
    if !status.is_success() {
        return Err(classify(status));
    }
    let mut total = 0usize;
    let mut stream = reply
        .response
        .body_mut()
        .into_data_stream()
        .map(|chunk| {
            let chunk = chunk.map_err(|_| std::io::Error::other("chat stream interrupted"))?;
            total += chunk.len();
            if total > MAX_RESPONSE {
                return Err(std::io::Error::other("chat stream exceeded limit"));
            }
            Ok(chunk)
        })
        .eventsource();
    let mut text = String::new();
    let mut held = String::new();
    let mut id = None;
    let mut tool_call = false;
    while let Some(event) = stream.next().await {
        let event = event.map_err(|_| TRUNCATED)?;
        if contains_credential(event.data.as_bytes(), &credentials) {
            return Err(TRUNCATED);
        }
        let raw: Value = serde_json::from_str(&event.data).map_err(|_| TRUNCATED)?;
        let (event, done) = match raw["type"].as_str() {
            Some("response.created") if id.is_none() => {
                let response_id = raw["response"]["id"].as_str().ok_or(TRUNCATED)?;
                if response_id.is_empty()
                    || response_id.len() > 128
                    || contains_credential(response_id.as_bytes(), &credentials)
                {
                    return Err(TRUNCATED);
                }
                id = Some(response_id.to_owned());
                emit(
                    output,
                    json!({"type":"response.created","response":{"id":response_id}}),
                    false,
                )
                .await?;
                (
                    json!({"type":"response.output_item.added","item":{
                        "type":"message","role":"assistant","id":response_id,"content":[]
                    }}),
                    false,
                )
            }
            Some("response.output_text.delta" | "response.refusal.delta") => {
                let delta = raw["delta"].as_str().ok_or(TRUNCATED)?;
                if id.is_none() {
                    return Err(TRUNCATED);
                }
                let delta = safe_delta(&mut held, delta, &credentials)?;
                if delta.is_empty() {
                    continue;
                }
                text.push_str(&delta);
                (
                    json!({"type":"response.output_text.delta","delta":delta}),
                    false,
                )
            }
            Some("response.output_item.done") if raw["item"]["type"] == "function_call" => {
                if id.is_none() {
                    return Err(TRUNCATED);
                }
                let item = &raw["item"];
                let read = |key| {
                    item[key]
                        .as_str()
                        .filter(|value| {
                            !value.is_empty()
                                && !contains_credential(value.as_bytes(), &credentials)
                        })
                        .ok_or(TRUNCATED)
                };
                let arguments: Value =
                    serde_json::from_str(read("arguments")?).map_err(|_| TRUNCATED)?;
                let arguments = arguments.to_string();
                if contains_credential(arguments.as_bytes(), &credentials) {
                    return Err(TRUNCATED);
                }
                let item = json!({"type":"function_call","id":read("id")?,"call_id":read("call_id")?,
                    "name":read("name")?,"arguments":arguments});
                emit(
                    output,
                    json!({"type":"response.output_item.added","item":item}),
                    false,
                )
                .await?;
                tool_call = true;
                (
                    json!({"type":"response.output_item.done","item":item}),
                    false,
                )
            }
            Some("response.completed") => {
                let id = id.as_deref().ok_or(TRUNCATED)?;
                if raw["response"]["id"] != id {
                    return Err(TRUNCATED);
                }
                if !held.is_empty() {
                    text.push_str(&held);
                    emit(
                        output,
                        json!({"type":"response.output_text.delta","delta":held}),
                        false,
                    )
                    .await?;
                }
                if !tool_call || !text.is_empty() {
                    let item = json!({"type":"message","id":id,"role":"assistant","content":[{"type":"output_text","text":text}],"phase":"final_answer"});
                    emit(
                        output,
                        json!({"type":"response.output_item.done","item":item}),
                        false,
                    )
                    .await?;
                }
                (
                    json!({"type":"response.completed","response":{"id":id,"end_turn":!tool_call}}),
                    true,
                )
            }
            Some("response.failed" | "response.incomplete" | "error") => return Err(TRUNCATED),
            _ => continue,
        };
        emit(output, event, done).await?;
        if done {
            return Ok(());
        }
    }
    Err(TRUNCATED)
}

async fn emit(output: &mpsc::Sender<Output>, event: Value, last: bool) -> Result<(), u16> {
    output
        .send(Output {
            bytes: Bytes::from(format!("data: {event}\n\n")),
            last,
        })
        .await
        .map_err(|_| TRUNCATED)
}
