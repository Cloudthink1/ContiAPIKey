#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use pretty_assertions::assert_eq;
use tempfile::TempDir;
use tokio::io::DuplexStream;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::chip::DEMO_USER;
use crate::init_fixture;
use crate::protocol::*;
use crate::run_chip;
use crate::tls::SERVER_NAME;

const REQUEST: &[u8] = br#"{"model":"demo","input":[],"stream":true}"#;

async fn chip(fixture: &Path, relay: SocketAddr) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (host, chip) = tokio::io::duplex(1024);
    let (reader, writer) = tokio::io::split(chip);
    let dir = fixture.join("chip");
    (
        host,
        tokio::spawn(async move { run_chip(&dir, relay, reader, writer).await }),
    )
}

async fn command(host: &mut DuplexStream, ins: u8, sequence: u16, data: &[u8]) -> (Vec<u8>, u16) {
    let command = Command {
        ins,
        sequence,
        data,
    }
    .encode()
    .unwrap();
    write_frame(host, &command).await.unwrap();
    let mut frame = read_frame(host).await.unwrap().unwrap();
    let status = u16::from_be_bytes(frame.split_off(frame.len() - 2).try_into().unwrap());
    (frame, status)
}

async fn upload(host: &mut DuplexStream, request: &[u8]) -> [u8; 32] {
    let (nonce, status) = command(host, CHALLENGE, 0, &[]).await;
    assert_eq!(status, OK);
    for (sequence, data) in request.chunks(CHUNK).enumerate() {
        assert_eq!(
            command(host, WRITE, sequence as u16, data).await,
            (vec![], OK)
        );
    }
    nonce.try_into().unwrap()
}

fn proof(fixture: &Path, nonce: &[u8; 32], request: &[u8]) -> Vec<u8> {
    let seed = std::fs::read(fixture.join("client.seed"))
        .unwrap()
        .try_into()
        .unwrap();
    let sign = SigningKey::from_bytes(&seed).sign(&signed_message(nonce, request));
    let mut proof = vec![DEMO_USER];
    proof.extend_from_slice(&sign.to_bytes());
    proof
}

#[tokio::test]
async fn rejects_unknown_user_bad_signature_and_replay_before_connecting() {
    let dir = TempDir::new().unwrap();
    let fixture = dir.path().join("fixture");
    init_fixture(&fixture, SERVER_NAME).unwrap();
    let relay = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = relay.local_addr().unwrap();

    let (mut host, simulator) = chip(&fixture, addr).await;
    let nonce = upload(&mut host, REQUEST).await;
    let valid = proof(&fixture, &nonce, REQUEST);
    let mut unknown = valid.clone();
    unknown[0] += 1;
    assert_eq!(
        command(&mut host, EXECUTE, 0, &unknown).await,
        (vec![], DENIED)
    );
    assert_eq!(
        command(&mut host, EXECUTE, 0, &valid).await,
        (vec![], BAD_STATE)
    );
    drop(host);
    simulator.await.unwrap().unwrap();

    let (mut host, simulator) = chip(&fixture, addr).await;
    let new_nonce = upload(&mut host, REQUEST).await;
    assert_ne!(new_nonce, nonce);
    assert_eq!(
        command(&mut host, EXECUTE, 0, &valid).await,
        (vec![], DENIED)
    );
    drop(host);
    simulator.await.unwrap().unwrap();

    let (mut host, simulator) = chip(&fixture, addr).await;
    let nonce = upload(&mut host, REQUEST).await;
    let wrong = proof(&fixture, &nonce, b"different request");
    assert_eq!(
        command(&mut host, EXECUTE, 0, &wrong).await,
        (vec![], DENIED)
    );
    drop(host);
    simulator.await.unwrap().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), relay.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_bad_lengths_order_and_oversize_upload() {
    let dir = TempDir::new().unwrap();
    let fixture = dir.path().join("fixture");
    init_fixture(&fixture, SERVER_NAME).unwrap();
    let relay = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (mut host, simulator) = chip(&fixture, relay.local_addr().unwrap()).await;
    assert_eq!(command(&mut host, CHALLENGE, 0, &[]).await.1, OK);
    write_frame(&mut host, &[CLA, WRITE, 0, 0, 2, 1])
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut host).await.unwrap(),
        Some(BAD_LENGTH.to_be_bytes().to_vec())
    );
    assert_eq!(
        command(&mut host, WRITE, 1, b"out of order").await,
        (vec![], BAD_SEQUENCE)
    );
    let full = [0; CHUNK];
    let allowed = (MAX_REQUEST / CHUNK) as u16;
    for sequence in 0..allowed {
        assert_eq!(
            command(&mut host, WRITE, sequence, &full).await,
            (vec![], OK)
        );
    }
    assert_eq!(
        command(&mut host, WRITE, allowed, &full).await,
        (vec![], TOO_LARGE)
    );
    assert_eq!(
        command(&mut host, EXECUTE, 0, &[0; 65]).await,
        (vec![], BAD_STATE)
    );
    drop(host);
    simulator.await.unwrap().unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), relay.accept())
            .await
            .is_err()
    );
}
