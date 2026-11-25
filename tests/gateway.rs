use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
};

const MODEL: &str = "gateway-test-model";
const BOOTSTRAP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

async fn server(root: &Path) -> Result<(Child, SocketAddr)> {
    let file = root.join("bootstrap");
    std::fs::write(&file, BOOTSTRAP)?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_codex-apdu-gateway"))
        .args(["serve", "chatgpt", "default", MODEL])
        .arg(file)
        .arg(root)
        .arg("offline")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let address = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await??
        .expect("gateway reports its address")
        .parse()?;
    Ok((child, address))
}

async fn call(
    address: SocketAddr,
    route: &str,
    token: &str,
    body: Bytes,
) -> Result<(StatusCode, Bytes)> {
    let socket = TcpStream::connect(address).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
    tokio::spawn(connection);
    let request = Request::post(route)
        .header(header::HOST, address.to_string())
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Full::new(body))?;
    let response = sender.send_request(request).await?;
    Ok((
        response.status(),
        response.into_body().collect().await?.to_bytes(),
    ))
}

#[tokio::test]
async fn gateway_auth_separates_bootstrap_bearer_and_upstream_credentials() -> Result<()> {
    let temp = TempDir::new()?;
    let (_child, address) = server(temp.path()).await?;
    let body = Bytes::from(json!({"model":MODEL,"stream":true,"input":[{
        "type":"message","role":"user","content":[{"type":"input_text","text":"测试🙂".repeat(90)}]}]}).to_string());
    assert_eq!(
        call(address, "/session", "wrong", Bytes::new()).await?.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(address, "/v1/responses", BOOTSTRAP, body.clone())
            .await?
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, token) = call(address, "/session", BOOTSTRAP, Bytes::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let token = std::str::from_utf8(&token)?;
    assert!(token.starts_with("gateway-"));
    assert_eq!(
        call(address, "/session", token, Bytes::new()).await?.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            address,
            "/v1/responses",
            token,
            Bytes::from(vec![b'x'; 1024 * 1024 + 1])
        )
        .await?
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(!temp.path().join("model-requests.jsonl").exists());
    let (status, reply) = call(address, "/v1/responses", token, body).await?;
    assert_eq!(status, StatusCode::OK);
    let reply = std::str::from_utf8(&reply)?;
    assert!(reply.contains("response.completed"));
    let model_log = std::fs::read_to_string(temp.path().join("model-requests.jsonl"))?;
    let upstream = std::fs::read_to_string(temp.path().join("fixture/chip/api-key"))?;
    for data in [reply, &model_log] {
        assert!(!data.contains(token));
        assert!(!data.contains(&upstream));
    }
    Ok(())
}

#[tokio::test]
async fn gateway_accepts_a_model_switch_under_the_same_session() -> Result<()> {
    let temp = TempDir::new()?;
    let (_child, address) = server(temp.path()).await?;
    let (status, token) = call(address, "/session", BOOTSTRAP, Bytes::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let token = std::str::from_utf8(&token)?;
    let switched_model = "gpt-6.2-sol";
    for model in [MODEL, switched_model, MODEL] {
        let body = json!({"model": model, "stream": true, "input": [{
            "type": "message", "role": "user",
            "content": [{"type": "input_text", "text": "什么是安全芯片？"}]
        }]});
        let (status, reply) = call(
            address,
            "/v1/responses",
            token,
            Bytes::from(body.to_string()),
        )
        .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&reply)
        );
        assert!(std::str::from_utf8(&reply)?.contains("response.completed"));
    }
    let log = std::fs::read_to_string(temp.path().join("model-requests.jsonl"))?;
    let models = log
        .lines()
        .map(|line| {
            Ok(serde_json::from_str::<serde_json::Value>(line)?["model"]
                .as_str()
                .expect("upstream request has a model")
                .to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(models, [MODEL, switched_model, MODEL]);
    Ok(())
}
