use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use bytes::Bytes;
use eventsource_stream::Event;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use futures::stream::BoxStream;
use http::HeaderValue;
use http::StatusCode;
use http::header;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use super::mbedtls::MbedTls;
use super::storage::Profile;
use crate::network::DEEPSEEK_HOST;
use crate::network::Destination;
use crate::network::Network;
use crate::operation::Output;
use crate::protocol::BAD_DATA;
use crate::protocol::MAX_RESPONSE;
use crate::protocol::UPSTREAM_FAILED;

pub const MODEL: &str = "deepseek-flash";
pub const UPSTREAM_AUTH: u16 = 0x6401;
pub const UPSTREAM_LIMIT: u16 = 0x6402;
pub const UPSTREAM_TLS: u16 = 0x6403;
pub const UPSTREAM_TRUNCATED: u16 = 0x6404;
pub const UPSTREAM_BALANCE: u16 = 0x6405;

pub(super) async fn stream(
    network: &Network,
    profile: &Profile,
    alias: &str,
    request: &[u8],
    output: mpsc::Sender<Output>,
) -> Result<(), u16> {
    let mut reply = Reply::open(network, profile, alias, request).await?;
    loop {
        let (bytes, last) = reply.next().await.map_err(|_| UPSTREAM_TRUNCATED)?;
        output
            .send(Output { bytes, last })
            .await
            .map_err(|_| UPSTREAM_FAILED)?;
        if last {
            return Ok(());
        }
    }
}

fn convert_request(raw: &[u8]) -> Result<Vec<u8>> {
    let input: Value = serde_json::from_slice(raw)?;
    ensure!(
        input["model"] == MODEL && input["stream"] == true,
        "unsupported DeepSeek model or response mode"
    );
    let items = input["input"]
        .as_array()
        .context("expected a Responses input array")?;
    let mut messages = Vec::with_capacity(items.len() + 1);
    if let Some(instructions) = input["instructions"]
        .as_str()
        .filter(|text| !text.is_empty())
    {
        messages.push(json!({"role":"system","content":instructions}));
    }
    for item in items {
        match item["type"].as_str() {
            Some("message") => {
                let role = match item["role"].as_str() {
                    Some("developer" | "system") => "system",
                    Some("user") => "user",
                    Some("assistant") => "assistant",
                    _ => anyhow::bail!("unsupported message role"),
                };
                let parts = item["content"]
                    .as_array()
                    .context("expected a message content array")?;
                let mut paragraphs = Vec::with_capacity(parts.len());
                for part in parts {
                    let kind = if role == "assistant" {
                        "output_text"
                    } else {
                        "input_text"
                    };
                    ensure!(
                        part["type"] == kind,
                        "only text message content is supported"
                    );
                    paragraphs.push(part["text"].as_str().context("expected text content")?);
                }
                if !paragraphs.is_empty() {
                    messages.push(json!({"role":role,"content":paragraphs.join("\n")}));
                }
            }
            Some("function_call") => {
                let id = item["call_id"]
                    .as_str()
                    .context("missing function call ID")?;
                let name = item["name"].as_str().context("missing function name")?;
                let arguments = item["arguments"]
                    .as_str()
                    .context("missing function arguments")?;
                let call = json!({"id":id,"type":"function","function":{"name":name,"arguments":arguments}});
                if let Some(previous) = messages
                    .last_mut()
                    .and_then(|msg| msg["tool_calls"].as_array_mut())
                {
                    previous.push(call);
                } else {
                    messages.push(json!({"role":"assistant","content":null,"tool_calls":[call]}));
                }
            }
            Some("function_call_output") => {
                let id = item["call_id"]
                    .as_str()
                    .context("missing function result ID")?;
                let output = crate::functions_wire::output_text(&item["output"])
                    .context("expected a text tool result")?;
                messages.push(json!({"role":"tool","tool_call_id":id,"content":output}));
            }
            // Namespaced tools in the history are metadata for the Responses client.
            Some("reasoning" | "additional_tools") => continue,
            _ => anyhow::bail!("unsupported Responses input item"),
        }
    }
    ensure!(
        messages.iter().any(|message| message["role"] == "user"),
        "missing user message"
    );
    let tools: Vec<_> = crate::functions_wire::definitions(&input)
        .map(|tool| json!({"type":"function","function":{"name":tool["name"],"description":tool["description"],"parameters":tool["parameters"]}}))
        .collect();
    let mut request = json!({"model":MODEL,"messages":messages,"stream":true,
        "stream_options":{"include_usage":true},"thinking":{"type":"disabled"},"max_tokens":4096});
    if !tools.is_empty() {
        request["tools"] = json!(tools);
        request["tool_choice"] = json!("auto");
    }
    Ok(serde_json::to_vec(&request)?)
}

#[derive(Default)]
struct FunctionCall {
    id: String,
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct ToolDelta {
    index: u32,
    id: Option<String>,
    function: Option<FunctionDelta>,
}

#[derive(Deserialize)]
struct FunctionDelta {
    name: Option<String>,
    arguments: Option<String>,
}

struct Reply {
    events: BoxStream<'static, Result<Event>>,
    _connection: Connection,
    response_id: Option<String>,
    text: String,
    finish: Option<String>,
    usage: Option<Value>,
    calls: std::collections::BTreeMap<u32, FunctionCall>,
}

struct Connection(JoinHandle<Result<(), hyper::Error>>);

impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Reply {
    async fn open(
        network: &Network,
        profile: &Profile,
        alias: &str,
        request: &[u8],
    ) -> Result<Self, u16> {
        let payload = convert_request(request).map_err(|_| BAD_DATA)?;
        let encrypted = network
            .connect(Destination::DeepSeek)
            .await
            .map_err(|err| {
                // The shim exposes numeric TLS errors only.
                tracing::debug!(error = %err, "DeepSeek certificate/handshake failure");
                UPSTREAM_TLS
            })?;
        let key = profile.api_key(alias).map_err(|_| UPSTREAM_AUTH)?;
        let mut bearer = Zeroizing::new(b"Bearer ".to_vec());
        bearer.extend_from_slice(&key);
        let mut authorization = HeaderValue::from_bytes(&bearer).map_err(|_| UPSTREAM_AUTH)?;
        authorization.set_sensitive(true);
        let outbound = http::Request::post("/chat/completions")
            .header(header::HOST, DEEPSEEK_HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "text/event-stream")
            .header(header::CONNECTION, "close")
            .header(header::AUTHORIZATION, authorization)
            .body(Full::new(Bytes::from(payload)))
            .map_err(|_| BAD_DATA)?;
        Self::send(encrypted, outbound).await
    }

    async fn send(encrypted: MbedTls, outbound: http::Request<Full<Bytes>>) -> Result<Self, u16> {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(encrypted))
                .await
                .map_err(|_| UPSTREAM_FAILED)?;
        let connection = Connection(tokio::spawn(connection));
        let response = sender
            .send_request(outbound)
            .await
            .map_err(|_| UPSTREAM_FAILED)?;
        let status = response.status();
        let is_sse = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            == Some("text/event-stream");
        if status != StatusCode::OK || !is_sse {
            return Err(match status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => UPSTREAM_AUTH,
                StatusCode::TOO_MANY_REQUESTS => UPSTREAM_LIMIT,
                StatusCode::PAYMENT_REQUIRED => UPSTREAM_BALANCE,
                _ => UPSTREAM_FAILED,
            });
        }
        let mut bytes = 0usize;
        let events = response
            .into_body()
            .into_data_stream()
            .map(move |chunk| {
                let chunk = chunk.context("DeepSeek HTTP stream interrupted")?;
                bytes += chunk.len();
                ensure!(
                    bytes <= MAX_RESPONSE,
                    "DeepSeek stream exceeded response size"
                );
                Ok::<_, anyhow::Error>(chunk)
            })
            .eventsource()
            .map(|event| event.context("invalid DeepSeek event stream"))
            .boxed();
        Ok(Self {
            events,
            _connection: connection,
            response_id: None,
            text: String::new(),
            finish: None,
            usage: None,
            calls: Default::default(),
        })
    }

    async fn next(&mut self) -> Result<(Bytes, bool)> {
        while let Some(event) = self.events.next().await {
            let event = event?;
            if event.data == "[DONE]" {
                return Ok((self.complete()?.into(), true));
            }
            let chunk: ChatChunk = serde_json::from_str(&event.data)?;
            let output = self.consume(chunk)?;
            if !output.is_empty() {
                return Ok((output.into(), false));
            }
        }
        anyhow::bail!("DeepSeek stream ended before its terminal event")
    }

    fn consume(&mut self, chunk: ChatChunk) -> Result<String> {
        ensure!(chunk.model == MODEL, "unexpected DeepSeek model");
        let mut output = String::new();
        if let Some(id) = &self.response_id {
            ensure!(id == &chunk.id, "DeepSeek changed response ID");
        } else {
            ensure!(
                !chunk.id.is_empty() && chunk.id.len() <= 128,
                "invalid DeepSeek response ID"
            );
            output.push_str(&event(
                json!({"type":"response.created","response":{"id":chunk.id}}),
            ));
            output.push_str(&event(json!({"type":"response.output_item.added","item":{
                "type":"message","role":"assistant","id":chunk.id,"content":[]
            }})));
            self.response_id = Some(chunk.id);
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(json!({
                "input_tokens": usage.prompt_tokens,
                "output_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            }));
        }
        for choice in chunk.choices {
            ensure!(
                self.finish.is_none() && choice.index == 0,
                "unexpected DeepSeek choice"
            );
            if let Some(text) = choice.delta.content {
                ensure!(
                    self.text.len() + text.len() <= MAX_RESPONSE / 2,
                    "DeepSeek response too large"
                );
                self.text.push_str(&text);
                output.push_str(&event(
                    json!({"type":"response.output_text.delta","delta":text}),
                ));
            }
            for delta in choice.delta.tool_calls {
                ensure!(delta.index < 128, "too many DeepSeek tool calls");
                let call = self.calls.entry(delta.index).or_default();
                if let Some(id) = delta.id {
                    ensure!(
                        call.id.is_empty() || call.id == id,
                        "DeepSeek changed function call ID"
                    );
                    call.id = id;
                }
                if let Some(function) = delta.function {
                    if let Some(name) = function.name {
                        call.name.push_str(&name);
                    }
                    if let Some(arguments) = function.arguments {
                        call.arguments.push_str(&arguments);
                    }
                }
            }
            self.finish = choice.finish_reason;
        }
        Ok(output)
    }

    fn complete(&self) -> Result<String> {
        let id = self
            .response_id
            .as_deref()
            .context("missing DeepSeek response ID")?;
        let finish = self
            .finish
            .as_deref()
            .context("missing DeepSeek terminal status")?;
        let mut output = String::new();
        if self.calls.is_empty() || !self.text.is_empty() {
            output.push_str(&event(json!({"type":"response.output_item.done","item":{
                "type":"message","role":"assistant","id":id,"content":[{"type":"output_text","text":self.text}]
            }})));
        }
        for (index, call) in &self.calls {
            ensure!(
                !call.id.is_empty() && !call.name.is_empty(),
                "incomplete DeepSeek function call"
            );
            let item = json!({"type":"function_call","id":format!("{id}_tool_{index}"),
                "call_id":call.id,"name":call.name,"arguments":call.arguments});
            output.push_str(&event(
                json!({"type":"response.output_item.added","item":item}),
            ));
            output.push_str(&event(
                json!({"type":"response.output_item.done","item":item}),
            ));
        }
        let done = match finish {
            "stop" if self.calls.is_empty() => {
                json!({"type":"response.completed","response":{"id":id,"usage":self.usage}})
            }
            "tool_calls" if !self.calls.is_empty() => {
                json!({"type":"response.completed","response":{"id":id,"usage":self.usage,"end_turn":false}})
            }
            "length" => json!({"type":"response.incomplete","response":{
                "id":id,"incomplete_details":{"reason":"max_output_tokens"}
            }}),
            _ => anyhow::bail!("DeepSeek did not complete the response"),
        };
        output.push_str(&event(done));
        Ok(output)
    }
}

fn event(value: Value) -> String {
    format!("data: {value}\n\n")
}

#[derive(Deserialize)]
struct ChatChunk {
    id: String,
    model: String,
    choices: Vec<Choice>,
    usage: Option<Usage>,
}
#[derive(Deserialize)]
struct Choice {
    index: u32,
    delta: Delta,
    finish_reason: Option<String>,
}
#[derive(Deserialize)]
struct Delta {
    content: Option<String>,
    #[serde(default, deserialize_with = "null_or_tool_calls")]
    tool_calls: Vec<ToolDelta>,
}
fn null_or_tool_calls<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> Result<Vec<ToolDelta>, D::Error> {
    Ok(Option::deserialize(input)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct Usage {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::Context as TaskContext;
    use std::task::Poll;
    use tokio::io::AsyncRead;
    use tokio::io::AsyncWrite;
    use tokio::io::ReadBuf;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsAcceptor;

    use super::super::Chip;
    use crate::live::mbedtls::root_bundle;
    use crate::live::storage::Protection;
    use crate::live::storage::protect;
    use crate::network::test_relay::FixtureRelay;
    use crate::protocol::*;

    struct ObservedSocket {
        socket: TcpStream,
        wire: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for ObservedSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            let result = Pin::new(&mut self.socket).poll_read(cx, buf);
            if matches!(result, Poll::Ready(Ok(()))) {
                self.wire
                    .lock()
                    .map_err(|_| io::Error::other("capture lock poisoned"))?
                    .extend_from_slice(&buf.filled()[before..]);
            }
            result
        }
    }

    impl AsyncWrite for ObservedSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.socket).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.socket).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.socket).poll_shutdown(cx)
        }
    }

    #[test]
    fn converts_text_history_and_function_results() -> Result<()> {
        let mut input = json!({
            "model": MODEL, "stream": true, "instructions": "Answer briefly.",
            "input":[
                {"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"fixture","tools":[]}]},
                {"type":"message","role":"user","content":[{"type":"input_text","text":"中文🙂"}]},
                {"type":"message","role":"assistant","content":[{"type":"output_text","text":"你好"}]},
                {"type":"message","role":"user","content":[{"type":"input_text","text":"复述"}]}
            ]
        });
        let result: Value =
            serde_json::from_slice(&convert_request(&serde_json::to_vec(&input)?)?)?;
        assert_eq!(
            result["messages"],
            json!([
                {"role":"system","content":"Answer briefly."},
                {"role":"user","content":"中文🙂"}, {"role":"assistant","content":"你好"},
                {"role":"user","content":"复述"}
            ])
        );
        input["tools"] =
            json!([{}, {"type":"function","name":"get_goal","parameters":{"type":"object"}}]);
        input["input"].as_array_mut().unwrap().extend([
            json!({"type":"function_call","call_id":"call_1","name":"get_goal","arguments":"{}"}),
            json!({"type":"function_call_output","call_id":"call_1","output":[{"type":"input_text","text":"no active goal"}]}),
        ]);
        let result: Value =
            serde_json::from_slice(&convert_request(&serde_json::to_vec(&input)?)?)?;
        assert_eq!(result["tools"].as_array().unwrap().len(), 1);
        assert_eq!(result["tools"][0]["function"]["name"], "get_goal");
        assert_eq!(result["messages"][4]["tool_calls"][0]["id"], "call_1");
        assert_eq!(
            result["messages"][5],
            json!({"role":"tool","tool_call_id":"call_1","content":"no active goal"})
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "explicit live TLS probe; connects to DeepSeek without issuing an HTTP request"]
    async fn deepseek_public_tls_probe() -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(25), async {
            let socket = TcpStream::connect((DEEPSEEK_HOST, 443)).await?;
            let roots = root_bundle(webpki_root_certs::TLS_SERVER_ROOT_CERTS);
            MbedTls::connect(socket, DEEPSEEK_HOST, &roots).await
        })
        .await??;
        Ok(())
    }

    async fn exchange(
        chip: &mut Chip,
        ins: u8,
        sequence: u16,
        data: &[u8],
    ) -> Result<(Vec<u8>, u16), u16> {
        let frame = Command {
            ins,
            sequence,
            data,
        }
        .encode()
        .unwrap();
        let result = chip.dispatch(Command::decode(&frame)?).await;
        for bytes in std::iter::once(frame.as_slice())
            .chain(result.as_ref().ok().map(|(data, _)| data.as_slice()))
        {
            assert!(!bytes.windows(11).any(|part| part == b"fixture-key"));
        }
        result
    }

    async fn submit(chip: &mut Chip) -> Result<(), u16> {
        let body = json!({
            "model": MODEL, "stream": true,
            "input": [{"type":"message","role":"user","content":[{"type":"input_text","text":"中文🙂".repeat(250)}]}],
        }).to_string();
        exchange(chip, BEGIN_REQUEST, 0, &[]).await?;
        for (index, chunk) in body.as_bytes().chunks(CHUNK).enumerate() {
            exchange(chip, WRITE, index as u16, chunk).await?;
        }
        assert_eq!(exchange(chip, EXECUTE, 0, &[]).await?, (vec![], OK));
        assert_eq!(exchange(chip, READ, 0, &[]).await?, (vec![], PENDING));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires the Mbed TLS bridge built by build.ps1 -Native"]
    async fn native_tls_checks_identity_and_deepseek_stream_errors() -> Result<()> {
        const SSE: &str = concat!(
            "data: {\"id\":\"mock-1\",\"model\":\"deepseek-flash\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"测试🙂\"}}]}\n\n",
            "data: {\"id\":\"mock-1\",\"model\":\"deepseek-flash\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],",
            "\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n",
            "data: [DONE]\n\n",
        );
        let temp = tempfile::tempdir()?;
        let fixture = temp.path().join("fixture");
        let wrong = temp.path().join("wrong");
        let mut acceptors = Vec::new();
        let mut certificates = Vec::new();
        for (path, hostname) in [(&wrong, "wrong.test"), (&fixture, DEEPSEEK_HOST)] {
            crate::init_fixture(path, hostname)?;
            let server = path.join("server");
            acceptors.push(TlsAcceptor::from(Arc::new(crate::tls::server_config(
                std::fs::read(server.join("cert.der"))?,
                std::fs::read(server.join("key.der"))?,
            )?)));
            certificates.push(std::fs::read(path.join("chip/ca.der"))?);
        }
        let [wrong_name, acceptor]: [TlsAcceptor; 2] = acceptors
            .try_into()
            .map_err(|_| anyhow::anyhow!("missing test TLS acceptors"))?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let wire = Arc::new(Mutex::new(Vec::new()));
        let capture = Arc::clone(&wire);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            ensure!(
                wrong_name.accept(socket).await.is_err(),
                "wrong name unexpectedly completed TLS"
            );
            let fixture_responses = [
                (StatusCode::TOO_MANY_REQUESTS, ""),
                (StatusCode::OK, SSE.trim_end_matches("data: [DONE]\n\n")),
                (StatusCode::OK, SSE),
            ];
            for (status, body) in fixture_responses {
                let (socket, _) = listener.accept().await?;
                let socket = acceptor
                    .accept(ObservedSocket {
                        socket,
                        wire: Arc::clone(&capture),
                    })
                    .await?;
                if status == StatusCode::OK {
                    ensure!(
                        socket.get_ref().1.protocol_version()
                            == Some(rustls::ProtocolVersion::TLSv1_3)
                    );
                }
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| async move {
                        ensure!(request.headers()[header::AUTHORIZATION] == "Bearer fixture-key");
                        ensure!(request.headers()[header::HOST] == DEEPSEEK_HOST);
                        ensure!(request.uri().path() == "/chat/completions");
                        let body = format!(": {}\n\n{body}", "x".repeat(900));
                        Ok::<_, anyhow::Error>(
                            http::Response::builder()
                                .status(status)
                                .header(header::CONTENT_TYPE, "text/event-stream")
                                .body(Full::new(Bytes::from(body)))?,
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            }
            Ok::<_, anyhow::Error>(())
        });
        let profile_file = json!({
            "credential_id": [1, 2, 3],
            "public_key": [4, 5, 6],
            "protected_key": protect(b"fixture-key", Protection::Encrypt)?.as_slice(),
        });
        std::fs::write(
            temp.path().join("deepseek-profile.json"),
            serde_json::to_vec(&profile_file)?,
        )?;
        let mut network = Network::default();
        network.roots = Some(root_bundle(certificates));
        let mut chip = Chip {
            directory: temp.path().to_owned(),
            alias: None,
            network: Arc::new(network),
            request: None,
            operation: None,
            aliases: Default::default(),
            change: None,
        };
        let mut relay = FixtureRelay::new(vec![(Destination::DeepSeek as u8, addr)]);
        tokio::time::timeout(std::time::Duration::from_secs(25), async {
            assert_eq!(
                exchange(&mut chip, BEGIN_REQUEST, 0, &[]).await,
                Err(BAD_STATE)
            );
            assert_eq!(
                exchange(
                    &mut chip,
                    SELECT_CREDENTIAL,
                    0,
                    crate::DEFAULT_ALIAS.as_bytes()
                )
                .await,
                Ok((vec![], OK))
            );
            // Cancel while TLS is waiting for the host to report the connection.
            submit(&mut chip).await.unwrap();
            loop {
                let (report, _) = exchange(&mut chip, NET_STATUS, 0, &[]).await.unwrap();
                if !report.is_empty() {
                    assert_eq!(report[2], Destination::DeepSeek as u8);
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert_eq!(exchange(&mut chip, CANCEL, 0, &[]).await, Ok((vec![], OK)));
            assert_eq!(exchange(&mut chip, READ, 0, &[]).await, Err(BAD_STATE));
            while !exchange(&mut chip, NET_STATUS, 0, &[])
                .await
                .unwrap()
                .0
                .is_empty()
            {
                tokio::task::yield_now().await;
            }

            for status in [UPSTREAM_TLS, UPSTREAM_LIMIT, UPSTREAM_TRUNCATED] {
                submit(&mut chip).await.unwrap();
                assert_eq!(
                    relay
                        .read(async |ins, seq, data| exchange(&mut chip, ins, seq, data).await)
                        .await,
                    Err(status),
                );
            }
            submit(&mut chip).await.unwrap();
            let data = relay
                .read(async |ins, seq, data| exchange(&mut chip, ins, seq, data).await)
                .await
                .map_err(|sw| anyhow::anyhow!("unexpected APDU status {sw:04X}"))?;
            let text = std::str::from_utf8(&data)?;
            assert!(text.contains("测试🙂"));
            assert!(text.contains("response.completed"));
            assert!(relay.packets > 8);
            server.await??;
            let bytes = wire
                .lock()
                .map_err(|_| anyhow::anyhow!("capture lock poisoned"))?;
            assert_eq!(bytes.first(), Some(&0x16));
            for plaintext in [
                b"Bearer fixture-key".as_slice(),
                b"POST /chat/completions",
                "中文🙂".as_bytes(),
            ] {
                assert!(
                    !bytes
                        .windows(plaintext.len())
                        .any(|window| window == plaintext)
                );
            }
            Ok::<_, anyhow::Error>(())
        })
        .await?
    }
}
