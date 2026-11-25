#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use codex_apdu::ApduTransport;
use codex_apdu::init_fixture;
use codex_apdu::serve_fixture;
use futures::TryStreamExt;
use pretty_assertions::assert_eq;
use serde_json::Value;
use serde_json::json;
use tempfile::TempDir;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

fn request(body: &Value) -> bytes::Bytes {
    serde_json::to_vec(body).unwrap().into()
}

async fn record(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
) -> std::io::Result<Vec<u8>> {
    let mut seen = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let count = from.read(&mut buffer).await?;
        if count == 0 {
            let _ = to.shutdown().await;
            return Ok(seen);
        }
        seen.extend_from_slice(&buffer[..count]);
        to.write_all(&buffer[..count]).await?;
    }
}

async fn round_trip(fixture: &Path, verify_bytes: bool) {
    let model = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let destination = model.local_addr().unwrap();
    let request_log = fixture.join("requests.jsonl");
    let server = tokio::spawn({
        let fixture = fixture.to_path_buf();
        let request_log = request_log.clone();
        async move { serve_fixture(model, &fixture, Some(request_log)).await }
    });
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let wire = tokio::spawn(async move {
        let (incoming, _) = proxy.accept().await.unwrap();
        let outgoing = TcpStream::connect(destination).await.unwrap();
        let (ir, iw) = incoming.into_split();
        let (or, ow) = outgoing.into_split();
        tokio::join!(record(ir, ow), record(or, iw))
    });
    let helper = std::path::PathBuf::from(env!("CARGO_BIN_EXE_codex-apdu"));
    let transport = ApduTransport::new(helper, fixture.to_path_buf(), proxy_addr).unwrap();
    let body = json!({"model":"demo","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"分片测试🙂".repeat(128)}]}],"stream":true});
    let response = transport.stream(request(&body)).await;
    if verify_bytes {
        let bytes: Vec<_> = response.unwrap().try_collect().await.unwrap();
        assert!(bytes.len() > 1 && bytes.iter().all(|chunk| chunk.len() <= 255));
        let reply = String::from_utf8(bytes.concat()).unwrap();
        assert!(reply.contains("离线模型响应"));
        assert!(reply.contains("response.completed"));
        assert_eq!(
            serde_json::from_str::<Value>(&std::fs::read_to_string(&request_log).unwrap()).unwrap(),
            body
        );
        let (outgoing, incoming) = tokio::time::timeout(Duration::from_secs(3), wire)
            .await
            .unwrap()
            .unwrap();
        let key = std::fs::read(fixture.join("chip/api-key")).unwrap();
        for wire_bytes in [outgoing.unwrap(), incoming.unwrap()] {
            assert_eq!(wire_bytes[0], 0x16);
            assert!(!wire_bytes.windows(key.len()).any(|window| window == key));
            assert!(
                !wire_bytes
                    .windows(18)
                    .any(|window| window == b"POST /v1/responses")
            );
        }
    } else {
        assert_eq!(
            response.err().unwrap().to_string(),
            "APDU: APDU command 30 returned 6400"
        );
        assert!(!request_log.exists());
        wire.abort();
    }
    server.abort();
}

#[tokio::test]
async fn unicode_apdu_round_trip_uses_tls_and_verified_server_identity() {
    let dir = TempDir::new().unwrap();
    let good = dir.path().join("good");
    let other = dir.path().join("other");
    init_fixture(&good, "codex-apdu.test").unwrap();
    init_fixture(&other, "wrong-name.test").unwrap();
    round_trip(&good, true).await;
    round_trip(&other, false).await;
    std::fs::remove_file(good.join("requests.jsonl")).unwrap();
    std::fs::copy(other.join("chip/ca.der"), good.join("chip/ca.der")).unwrap();
    round_trip(&good, false).await;
}

#[tokio::test]
async fn dropping_call_closes_relay_and_next_call_succeeds() {
    let dir = TempDir::new().unwrap();
    let fixture = dir.path().join("fixture");
    init_fixture(&fixture, "codex-apdu.test").unwrap();
    let stalled_model = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let helper = std::path::PathBuf::from(env!("CARGO_BIN_EXE_codex-apdu"));
    let transport =
        ApduTransport::new(helper, fixture.clone(), stalled_model.local_addr().unwrap()).unwrap();
    let call = tokio::spawn(async move {
        transport
            .stream(request(&json!({"model":"demo","input":[],"stream":true})))
            .await
    });
    let (socket, _) = tokio::time::timeout(Duration::from_secs(5), stalled_model.accept())
        .await
        .unwrap()
        .unwrap();
    call.abort();
    assert!(call.await.is_err());
    let mut bytes = Vec::new();
    let size = tokio::time::timeout(Duration::from_secs(5), async {
        let mut socket = socket;
        socket.read_to_end(&mut bytes).await
    })
    .await;
    assert!(size.is_ok(), "the cancelled call must close the TCP relay");
    round_trip(&fixture, true).await;
}
