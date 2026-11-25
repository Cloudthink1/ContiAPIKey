use std::convert::Infallible;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use anyhow::ensure;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http::Method;
use http::Request;
use http::Response;
use http::StatusCode;
use http::header;
use http_body_util::BodyExt;
use http_body_util::Full;
use http_body_util::Limited;
use http_body_util::StreamBody;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::Frame;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;
use serde_json::Value;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::protocol::MAX_REQUEST;
use crate::tls;

const REPLY: &str = "离线模型响应：已通过 APDU 收到模型请求。";
const TOOL_MARKER: &str = "APDU_GATEWAY_TOOL_TEST";
const TOOL_CALL_ID: &str = "call_apdu_fixture_plan";

/// Create disposable fixture data in a fresh directory. The CA signing key stays in memory.
pub fn init_fixture(directory: &Path, certificate_name: &str) -> Result<()> {
    fs::create_dir(directory)?;
    let chip = directory.join("chip");
    let server = directory.join("server");
    fs::create_dir(&chip)?;
    fs::create_dir(&server)?;

    let seed: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&seed);
    fs::write(directory.join("client.seed"), seed)?;
    fs::write(
        chip.join("user.pub"),
        signing_key.verifying_key().to_bytes(),
    )?;

    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate()?;
    fs::write(chip.join("ca.der"), ca.self_signed(&ca_key)?.der())?;
    let issuer = Issuer::new(ca, ca_key);
    let mut cert = CertificateParams::new(vec![certificate_name.to_owned()])?;
    cert.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    fs::write(
        server.join("cert.der"),
        cert.signed_by(&server_key, &issuer)?.der(),
    )?;
    fs::write(server.join("key.der"), server_key.serialize_der())?;

    let key_bytes: [u8; 32] = rand::random();
    let mut key = "demo-".to_owned();
    use std::fmt::Write as _;
    for byte in key_bytes {
        write!(key, "{byte:02x}")?;
    }
    fs::write(chip.join("api-key"), &key)?;
    fs::write(server.join("api-key"), key)?;
    Ok(())
}

type Body = UnsyncBoxBody<Bytes, Infallible>;

struct Model {
    authorization: http::HeaderValue,
    request_log: Option<PathBuf>,
    requests: AtomicU64,
}

impl Model {
    async fn respond(&self, request: Request<Incoming>) -> Result<Response<Body>> {
        let reject = |status| {
            Ok(Response::builder()
                .status(status)
                .body(Full::new(Bytes::new()).boxed_unsync())?)
        };
        if request.method() != Method::POST
            || request
                .uri()
                .path_and_query()
                .map(http::uri::PathAndQuery::as_str)
                != Some(tls::RESPONSES_PATH)
        {
            return reject(StatusCode::NOT_FOUND);
        }
        if request.headers().get(header::AUTHORIZATION) != Some(&self.authorization) {
            return reject(StatusCode::UNAUTHORIZED);
        }
        let body = Limited::new(request.into_body(), MAX_REQUEST)
            .collect()
            .await
            .map_err(|error| anyhow::anyhow!("read fixture request: {error}"))?
            .to_bytes();
        let json: Value = serde_json::from_slice(&body)?;
        if json.get("input").and_then(Value::as_array).is_none() {
            return reject(StatusCode::BAD_REQUEST);
        }
        if let Some(path) = &self.request_log {
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            let mut line = serde_json::to_vec(&json)?;
            line.push(b'\n');
            file.write_all(&line).await?;
        }
        let id = self.requests.fetch_add(1, Ordering::Relaxed);
        let response_id = format!("resp_apdu_{id}");
        let item_id = format!("msg_apdu_{id}");
        let tool_probe = json["input"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["role"] == "user"
                    && item["content"].as_array().is_some_and(|parts| {
                        parts.iter().any(|part| {
                            part["text"]
                                .as_str()
                                .is_some_and(|text| text.contains(TOOL_MARKER))
                        })
                    })
            })
        });
        let tool_finished = json["input"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["type"] == "function_call_output" && item["call_id"] == TOOL_CALL_ID
            })
        });
        let events = if tool_probe && !tool_finished {
            let tool_available = |name: &str| {
                json["tools"].as_array().is_some_and(|tools| {
                    tools
                        .iter()
                        .any(|tool| tool["type"] == "function" && tool["name"] == name)
                })
            };
            let (name, arguments) = if tool_available("get_goal") {
                ("get_goal", json!({}))
            } else if tool_available("update_plan") {
                (
                    "update_plan",
                    json!({"plan":[{"step":"Check the APDU gateway","status":"completed"}]}),
                )
            } else {
                return reject(StatusCode::BAD_REQUEST);
            };
            let item = json!({"type":"function_call","id":item_id,"call_id":TOOL_CALL_ID,"name":name,"arguments":arguments.to_string()});
            vec![
                json!({"type":"response.created","response":{"id":response_id}}),
                json!({"type":"response.output_item.added","item":item}),
                json!({"type":"response.output_item.done","item":item}),
                json!({"type":"response.completed","response":{"id":response_id,"end_turn":false}}),
            ]
        } else {
            vec![
                json!({"type":"response.created","response":{"id":response_id}}),
                json!({"type":"response.output_item.added","item":{"type":"message","role":"assistant","id":item_id,"content":[]}}),
                json!({"type":"response.output_text.delta","delta":REPLY}),
                json!({"type":"response.output_item.done","item":{"type":"message","role":"assistant","id":item_id,"content":[{"type":"output_text","text":REPLY}]}}),
                json!({"type":"response.completed","response":{"id":response_id}}),
            ]
        };
        let body = futures::stream::iter(events.into_iter().map(|event| {
            let sse = format!("data: {event}\n\n");
            Ok(Frame::data(Bytes::from(sse)))
        }));
        Ok(Response::builder()
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(StreamBody::new(body).boxed_unsync())?)
    }
}

/// Run the loopback HTTP/1.1 model fixture through a real TLS 1.3 server.
pub async fn serve_fixture(
    listener: TcpListener,
    directory: &Path,
    request_log: Option<PathBuf>,
) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "fixture must listen on loopback"
    );
    let server = directory.join("server");
    let tls = TlsAcceptor::from(Arc::new(tls::server_config(
        fs::read(server.join("cert.der"))?,
        fs::read(server.join("key.der"))?,
    )?));
    let mut authorization =
        http::HeaderValue::from_str(&format!("Bearer {}", tls::read_api_key(&server)?))?;
    authorization.set_sensitive(true);
    let model = Arc::new(Model {
        authorization,
        request_log,
        requests: AtomicU64::new(1),
    });
    loop {
        let (socket, _) = listener.accept().await?;
        let tls = tls.clone();
        let model = model.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(30), async move {
                let encrypted = tls.accept(socket).await?;
                hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(
                        TokioIo::new(encrypted),
                        service_fn(move |request| {
                            let model = model.clone();
                            async move { model.respond(request).await }
                        }),
                    )
                    .await?;
                anyhow::Ok(())
            })
            .await;
        });
    }
}
