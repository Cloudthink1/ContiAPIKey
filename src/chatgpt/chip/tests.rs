use std::fs;
use std::net::SocketAddr;

use bytes::Bytes;
use http::Response;
use http::StatusCode;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::live::mbedtls::root_bundle;
use crate::network::AUTH_HOST;
use crate::network::CHAT_HOST;
use crate::network::test_relay::FixtureRelay;

const ACCESS: &str = "apdu-fixture-access-1";
const ROTATED_ACCESS: &str = "apdu-fixture-access-2";
const REFRESH: &str = "apdu-fixture-refresh-1";
const ROTATED_REFRESH: &str = "apdu-fixture-refresh-2";

fn chip(directory: &Path, network: Network) -> Chip {
    fs::create_dir_all(directory).unwrap();
    Chip {
        directory: directory.to_owned(),
        selected: false,
        network: Arc::new(network),
        login: None,
        request: None,
        operation: None,
        aliases: Default::default(),
    }
}

#[tokio::test]
async fn account_selection_is_bound_to_one_slot_and_logout_preserves_the_other() {
    use crate::chatgpt::credentials::Credentials;

    let root = tempfile::tempdir().unwrap();
    let work = account_directory(root.path(), "work");
    let credentials = |access: &str| Credentials {
        access_token: access.into(),
        refresh_token: REFRESH.into(),
        id_token: "fixture-id-token".into(),
        expires_at: 1,
    };
    Store::open(root.path())
        .unwrap()
        .save(&credentials(ACCESS))
        .unwrap();
    Store::open(&work)
        .unwrap()
        .save(&credentials(ROTATED_ACCESS))
        .unwrap();
    assert_eq!(
        crate::chatgpt::credentials::list_accounts(root.path()).unwrap(),
        ["default", "work"]
    );
    let mut chip = chip(root.path(), Network::default());
    assert_eq!(
        apdu(&mut chip, LIST_CREDENTIALS, 0, &[]).await,
        Ok((b"default".to_vec(), MORE))
    );
    assert_eq!(
        apdu(&mut chip, LIST_CREDENTIALS, 2, &[]).await,
        Err(BAD_SEQUENCE)
    );
    assert_eq!(
        apdu(&mut chip, LIST_CREDENTIALS, 1, &[]).await,
        Ok((b"work".to_vec(), LAST))
    );
    assert_eq!(
        apdu(&mut chip, SELECT_CREDENTIAL, 0, b"../default").await,
        Err(BAD_DATA)
    );
    assert_eq!(
        apdu(&mut chip, SELECT_CREDENTIAL, 0, b"work").await,
        Ok((vec![], OK))
    );
    assert_eq!(
        apdu(&mut chip, SELECT_CREDENTIAL, 0, b"default").await,
        Err(BAD_STATE)
    );
    assert_eq!(chip.directory, work);
    assert_eq!(apdu(&mut chip, LOGOUT, 0, &[]).await, Ok((vec![], OK)));
    assert_eq!(
        crate::chatgpt::credentials::list_accounts(root.path()).unwrap(),
        ["default"]
    );
    assert_eq!(
        Store::open(root.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap()
            .access_token,
        ACCESS
    );
}

#[tokio::test]
async fn adding_an_existing_account_alias_cannot_overwrite_it() {
    use crate::chatgpt::credentials::Credentials;

    let root = tempfile::tempdir().unwrap();
    let saved = Credentials {
        access_token: ACCESS.into(),
        refresh_token: REFRESH.into(),
        id_token: "fixture-id-token".into(),
        expires_at: 1,
    };
    Store::open(root.path()).unwrap().save(&saved).unwrap();
    let result = service::exchange(
        &Network::default(),
        root.path(),
        "unused-code",
        "unused-verifier",
        "http://localhost:1455/auth/callback",
        service::LoginIntent::Add,
    )
    .await;
    assert_eq!(result, Err(ALIAS_EXISTS));
    assert_eq!(
        Store::open(root.path())
            .unwrap()
            .load()
            .unwrap()
            .unwrap()
            .access_token,
        ACCESS
    );
}

async fn apdu(chip: &mut Chip, ins: u8, sequence: u16, data: &[u8]) -> Result<(Vec<u8>, u16), u16> {
    let frame = Command {
        ins,
        sequence,
        data,
    }
    .encode()
    .unwrap();
    let result = chip.dispatch(Command::decode(&frame).unwrap()).await;
    if !matches!(ins, CALLBACK_WRITE | WRITE) {
        assert_public(&frame);
    }
    if let Ok((body, _)) = &result {
        assert_public(body);
    }
    result
}

fn assert_public(data: &[u8]) {
    for secret in [
        ACCESS,
        ROTATED_ACCESS,
        REFRESH,
        ROTATED_REFRESH,
        "Authorization: Bearer",
        "code_verifier=",
    ] {
        assert!(
            !data
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }
}

#[tokio::test]
async fn login_state_expiry_and_cancellation() {
    let directory = tempfile::tempdir().unwrap();
    let mut chip = chip(directory.path(), Network::default());
    assert_eq!(
        apdu(&mut chip, LOGIN_BEGIN, 0, &1455u16.to_be_bytes())
            .await
            .unwrap()
            .1,
        OK
    );
    assert_eq!(
        apdu(&mut chip, CALLBACK_WRITE, 1, b"part").await,
        Err(BAD_SEQUENCE)
    );
    assert_eq!(
        apdu(
            &mut chip,
            CALLBACK_WRITE,
            0,
            br#"{"code":"code","state":"wrong"}"#
        )
        .await
        .unwrap()
        .1,
        OK
    );
    assert_eq!(
        apdu(&mut chip, LOGIN_FINISH, 0, &[]).await,
        Err(LOGIN_MISMATCH)
    );
    assert!(chip.login.is_some());
    chip.login.as_mut().unwrap().start = Instant::now() - LOGIN_TTL;
    assert_eq!(
        apdu(&mut chip, CALLBACK_WRITE, 0, b"part").await,
        Err(LOGIN_MISMATCH)
    );
    assert_eq!(apdu(&mut chip, CANCEL, 0, &[]).await.unwrap().1, OK);
    assert!(chip.login.is_none());
    assert_eq!(apdu(&mut chip, LOGIN_FINISH, 0, &[]).await, Err(BAD_STATE));
}

async fn fixture(root: &Path, name: &str) -> (SocketAddr, Vec<u8>, JoinHandle<()>) {
    crate::init_fixture(root, name).unwrap();
    let cert = fs::read(root.join("server/cert.der")).unwrap();
    let key = fs::read(root.join("server/key.der")).unwrap();
    let ca = fs::read(root.join("chip/ca.der")).unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = crate::tls::server_config(cert, key).unwrap();
    let task = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(socket) = acceptor.accept(socket).await else {
                continue;
            };
            let connection = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(socket), service_fn(mock));
            let _ = connection.await;
        }
    });
    (address, ca, task)
}

async fn mock(
    request: http::Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let (parts, body) = request.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let mut status = StatusCode::OK;
    let response = match parts.uri.path() {
        "/oauth/token" => {
            let id = URL_SAFE_NO_PAD
                .encode(r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"mock-account"}}"#);
            if parts.headers[http::header::CONTENT_TYPE] == "application/json" {
                assert_eq!(
                    serde_json::from_slice::<Value>(&bytes).unwrap()["refresh_token"],
                    REFRESH
                );
                json!({"access_token":ROTATED_ACCESS,"refresh_token":ROTATED_REFRESH,"expires_in":3600}).to_string()
            } else {
                let form: std::collections::HashMap<_, _> =
                    url::form_urlencoded::parse(&bytes).collect();
                assert_eq!(form["code"], "one-use-code");
                assert!(form["code_verifier"].len() > 43);
                json!({"access_token":ACCESS,"refresh_token":REFRESH,"id_token":format!("a.{id}.b"),"expires_in":30}).to_string()
            }
        }
        "/backend-api/codex/models" => {
            assert_eq!(
                parts.headers[http::header::AUTHORIZATION],
                format!("Bearer {ROTATED_ACCESS}")
            );
            json!({"models":[{"slug":"fixture-model","visibility":"list","display_name":"Fixture","priority":1}]}).to_string()
        }
        "/backend-api/codex/responses" => {
            assert_eq!(
                parts.headers[http::header::AUTHORIZATION],
                format!("Bearer {ROTATED_ACCESS}")
            );
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            let input = request["input"].as_array().unwrap();
            let prompt = input.last().unwrap()["content"][0]["text"]
                .as_str()
                .unwrap();
            let reply = match prompt {
                "第一轮" => "记住了",
                "第二轮" => {
                    assert_eq!(input[0]["content"][0]["text"], "第一轮");
                    assert_eq!(input[1]["content"][0]["text"], "记住了");
                    "第一轮"
                }
                "model-switch" => {
                    assert_eq!(request["model"], "gpt-6.1-sol");
                    assert_eq!(input.len(), 3);
                    assert_eq!(input[0]["content"][0]["text"], "第一轮");
                    assert_eq!(input[1]["content"][0]["text"], "记住了");
                    assert_eq!(request["tools"][0]["name"], "fixture_function");
                    "switched"
                }
                "rate" => {
                    status = StatusCode::TOO_MANY_REQUESTS;
                    ""
                }
                "unauthorized" => {
                    status = StatusCode::UNAUTHORIZED;
                    ""
                }
                "bad-request" => {
                    status = StatusCode::BAD_REQUEST;
                    ""
                }
                "truncate" => "断流",
                "leak" => "",
                _ => panic!("unknown mock prompt"),
            };
            let mut events = format!(
                ": {}\n\ndata: {{\"type\":\"response.created\",\"response\":{{\"id\":\"mock-id\"}}}}\n\n",
                "x".repeat(700)
            );
            let output = |delta: &str| {
                format!(
                    "data: {}\n\n",
                    json!({"type":"response.output_text.delta","delta":delta})
                )
            };
            events.push_str(&output(reply));
            if prompt == "leak" {
                let (left, right) = ROTATED_ACCESS.split_at(10);
                events.push_str(&output(left));
                events.push_str(&output(right));
            }
            if prompt != "truncate" {
                events.push_str(
                    "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"mock-id\"}}\n\n",
                );
            }
            events
        }
        _ => panic!("unknown fake service endpoint"),
    };
    Ok(Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(response)))
        .unwrap())
}

async fn submit(
    chip: &mut Chip,
    relay: &mut FixtureRelay,
    turns: &[(&str, &str)],
) -> Result<Vec<u8>, u16> {
    let input: Vec<_> = turns
        .iter()
        .map(|(role, text)| json!({"type":"message","role":role,"content":[{"text":text}]}))
        .collect();
    submit_request(chip, relay, json!({"model":"fixture-model","input":input})).await
}

async fn submit_request(
    chip: &mut Chip,
    relay: &mut FixtureRelay,
    request: Value,
) -> Result<Vec<u8>, u16> {
    let body = request.to_string();
    apdu(chip, BEGIN_REQUEST, 0, &[]).await?;
    for (index, chunk) in body.as_bytes().chunks(CHUNK).enumerate() {
        apdu(chip, WRITE, index as u16, chunk).await?;
    }
    apdu(chip, EXECUTE, 0, &[]).await?;
    relay
        .read(async |ins, seq, data| apdu(chip, ins, seq, data).await)
        .await
}

#[tokio::test]
#[ignore = "requires the Mbed TLS bridge built by build.ps1 -Native"]
async fn native_tls_over_apdu_login_refresh_model_and_chat() {
    let root = tempfile::tempdir().unwrap();
    let (auth, auth_ca, auth_task) = fixture(&root.path().join("auth"), AUTH_HOST).await;
    let (chat, chat_ca, chat_task) = fixture(&root.path().join("chat"), CHAT_HOST).await;
    let mut network = Network::default();
    network.roots = Some(root_bundle([auth_ca, chat_ca]));
    let mut chip = chip(&root.path().join("profile"), network);
    let mut relay = FixtureRelay::new(vec![(1, auth), (2, chat)]);
    let response = apdu(&mut chip, LOGIN_BEGIN, 0, &1455u16.to_be_bytes())
        .await
        .unwrap()
        .0;
    let public: Value = serde_json::from_slice(&response).unwrap();
    assert!(public.get("verifier").is_none());
    let callback = json!({"code":"one-use-code","state":public["state"]}).to_string();
    apdu(&mut chip, CALLBACK_WRITE, 0, callback.as_bytes())
        .await
        .unwrap();
    apdu(&mut chip, LOGIN_FINISH, 0, &[]).await.unwrap();
    assert!(
        relay
            .read(async |ins, seq, data| apdu(&mut chip, ins, seq, data).await)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(apdu(&mut chip, LOGIN_FINISH, 0, &[]).await, Err(BAD_STATE));
    apdu(&mut chip, MODELS, 0, &[]).await.unwrap();
    let models: Vec<service::Model> = serde_json::from_slice(
        &relay
            .read(async |ins, seq, data| apdu(&mut chip, ins, seq, data).await)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(models[0].slug, "fixture-model");
    let store = Store::open(&chip.directory).unwrap();
    assert!(Store::open(&chip.directory).is_err());
    let credentials = store.load().unwrap().unwrap();
    assert_eq!(credentials.refresh_token, ROTATED_REFRESH);
    assert_public(&fs::read(chip.directory.join("credentials.dpapi")).unwrap());
    drop(store);
    assert!(
        String::from_utf8(
            submit(&mut chip, &mut relay, &[("user", "第一轮")])
                .await
                .unwrap()
        )
        .unwrap()
        .contains("记住了")
    );
    let second = submit(
        &mut chip,
        &mut relay,
        &[
            ("user", "第一轮"),
            ("assistant", "记住了"),
            ("user", "第二轮"),
        ],
    )
    .await
    .unwrap();
    assert!(String::from_utf8(second).unwrap().contains("第一轮"));
    let switched = submit_request(&mut chip, &mut relay, json!({
        "model": "gpt-6.1-sol",
        "stream": true,
        "reasoning": {"effort": "low"},
        "input": [
            {"type": "additional_tools", "role": "developer", "id": "tools_fixture",
             "tools": [{"type": "namespace", "name": "fixture", "tools": []}]},
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "第一轮"}]},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "记住了"}]},
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "model-switch"}]}
        ],
        "tools": [{"type": "function", "name": "fixture_function", "parameters": {"type": "object"}}]
    })).await.unwrap();
    assert!(String::from_utf8(switched).unwrap().contains("switched"));
    for (prompt, code) in [
        ("rate", service::RATE_LIMITED),
        ("unauthorized", LOGIN_REQUIRED),
        ("bad-request", service::MODEL_REJECTED),
        ("truncate", service::TRUNCATED),
        ("leak", service::TRUNCATED),
    ] {
        assert_eq!(
            submit(&mut chip, &mut relay, &[("user", prompt)]).await,
            Err(code)
        );
    }
    assert!(relay.packets > 25);
    let mut relay = FixtureRelay::new(vec![(1, auth), (2, auth)]);
    assert_eq!(
        submit(&mut chip, &mut relay, &[("user", "第一轮")]).await,
        Err(service::TLS_FAILED)
    );
    apdu(&mut chip, LOGOUT, 0, &[]).await.unwrap();
    assert_eq!(
        apdu(&mut chip, LOGIN_STATUS, 0, &[]).await,
        Err(LOGIN_REQUIRED)
    );
    auth_task.abort();
    chat_task.abort();
}
