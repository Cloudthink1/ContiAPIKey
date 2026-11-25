#[path = "gateway/http.rs"]
mod gateway_http;

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use codex_apdu::{ApduTransport, init_fixture, serve_fixture};
use tokio::net::TcpListener;

use gateway_http::{Backend, Mode};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [command, address, secret] if command == "credential" => {
            let address = address
                .to_str()
                .context("invalid gateway address")?
                .parse::<SocketAddr>()?;
            let token = gateway_http::credential(address, Path::new(secret)).await?;
            println!("{}", &*token);
        }
        [command, mode, alias, model, secret, directory, options @ ..] if command == "serve" => {
            let mode = mode
                .to_str()
                .context("invalid gateway mode")?
                .parse::<Mode>()?;
            let alias = alias.to_str().context("invalid alias")?;
            validate_alias(alias)?;
            let model = model.to_str().context("invalid model")?.to_owned();
            ensure!(!model.is_empty(), "a model must be configured");
            if options.is_empty() && matches!(mode, Mode::DeepSeek) {
                ensure!(
                    model == "deepseek-flash",
                    "the current DeepSeek adapter uses deepseek-flash"
                );
            }
            let directory = PathBuf::from(directory);
            ensure!(
                directory.is_absolute(),
                "gateway data directory must be absolute"
            );
            let bootstrap = gateway_http::read_secret(Path::new(secret)).await?;
            let helper = std::env::current_exe()?.with_file_name(if cfg!(windows) {
                "codex-apdu.exe"
            } else {
                "codex-apdu"
            });
            ensure!(
                helper.is_file(),
                "the chip helper must be beside the gateway"
            );
            let backend = match options {
                [offline] if offline == "offline" => offline_backend(&helper, &directory).await?,
                [] => live_backend(mode, alias, &directory, &helper)?,
                _ => bail!("unsupported gateway option"),
            };
            let _ = tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .try_init();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            println!("{}", listener.local_addr()?);
            std::io::stdout().flush()?;
            gateway_http::serve(listener, backend, mode, alias.to_owned(), model, &bootstrap)
                .await?;
        }
        _ => bail!(
            "usage: codex-apdu-gateway serve MODE ALIAS MODEL BOOTSTRAP DATA [offline] | credential ADDRESS BOOTSTRAP"
        ),
    }
    Ok(())
}

async fn offline_backend(helper: &Path, directory: &Path) -> Result<Backend> {
    let fixture = directory.join("fixture");
    init_fixture(&fixture, "codex-apdu.test")?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let transport = ApduTransport::new(helper.to_owned(), fixture.clone(), listener.local_addr()?)?;
    let log = directory.join("model-requests.jsonl");
    tokio::spawn(async move {
        if let Err(error) = serve_fixture(listener, &fixture, Some(log)).await {
            tracing::error!(%error, "offline model fixture stopped");
        }
    });
    Ok(Backend::Offline(transport))
}

#[cfg(windows)]
fn live_backend(mode: Mode, alias: &str, directory: &Path, helper: &Path) -> Result<Backend> {
    // The launcher sets all profiles before this process starts; runtime never changes its environment.
    let (profile_var, alias_var, subdir) = match mode {
        Mode::DeepSeek => (
            "CODEX_APDU_LIVE_PROFILE",
            "CODEX_APDU_LIVE_ALIAS",
            "DeepSeek",
        ),
        Mode::ChatGpt => (
            "CODEX_APDU_CHATGPT_PROFILE",
            "CODEX_APDU_CHATGPT_ALIAS",
            "ChatGPT",
        ),
    };
    ensure!(
        std::env::var_os(profile_var).map(PathBuf::from) == Some(directory.join(subdir))
            && std::env::var(alias_var).ok().as_deref() == Some(alias),
        "launch the gateway with run.ps1 to select its isolated profile"
    );
    if matches!(mode, Mode::DeepSeek) {
        ensure!(
            std::env::var_os("CODEX_APDU_HELPER")
                .map(PathBuf::from)
                .as_deref()
                == Some(helper),
            "invalid DeepSeek chip helper"
        );
    }
    ensure!(
        helper.with_file_name("codex-apdu-mbedtls.dll").is_file(),
        "build the native Mbed TLS bridge first"
    );
    Ok(match mode {
        Mode::DeepSeek => Backend::DeepSeek(codex_apdu::LiveTransport::default()),
        Mode::ChatGpt => Backend::ChatGpt(codex_apdu::ChatGptTransport),
    })
}

#[cfg(not(windows))]
fn live_backend(_mode: Mode, _alias: &str, _directory: &Path, _helper: &Path) -> Result<Backend> {
    bail!("live chip profiles require Windows")
}

fn validate_alias(alias: &str) -> Result<()> {
    ensure!(
        (1..=32).contains(&alias.len())
            && alias.as_bytes()[0].is_ascii_alphanumeric()
            && alias
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')),
        "invalid credential alias"
    );
    Ok(())
}
