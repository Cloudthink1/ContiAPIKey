use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use anyhow::bail;
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        #[cfg(windows)]
        [command, directory] if command == "key-list" => {
            let helper = std::env::current_exe()?;
            println!(
                "{}",
                serde_json::to_string(
                    &codex_apdu::list_keys(&helper, Path::new(directory)).await?
                )?
            );
            Ok(())
        }
        #[cfg(windows)]
        [command, directory, alias, file] if command == "key-add" => {
            codex_apdu::import_key_file(
                Path::new(directory),
                alias
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid key alias"))?,
                Path::new(file),
            )
            .await
        }
        #[cfg(windows)]
        [command, directory, alias] if command == "key-delete" => {
            codex_apdu::delete_key(
                &std::env::current_exe()?,
                Path::new(directory),
                alias
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid key alias"))?,
            )
            .await
        }
        #[cfg(windows)]
        [command, directory, key_file] if command == "live-setup" => {
            codex_apdu::setup_live(Path::new(directory), Path::new(key_file)).await
        }
        #[cfg(windows)]
        [command, directory] if command == "live-chip" => {
            codex_apdu::run_live_chip(
                Path::new(directory),
                tokio::io::stdin(),
                tokio::io::stdout(),
            )
            .await
        }
        [command, directory] if command == "init" => {
            codex_apdu::init_fixture(Path::new(directory), "codex-apdu.test")
        }
        [command, directory, relay] if command == "chip" => {
            codex_apdu::run_chip(
                Path::new(directory),
                relay.to_string_lossy().parse()?,
                tokio::io::stdin(),
                tokio::io::stdout(),
            )
            .await
        }
        [command, directory, bind, request_log @ ..]
            if command == "serve" && request_log.len() <= 1 =>
        {
            let bind: SocketAddr = bind.to_string_lossy().parse()?;
            anyhow::ensure!(bind.ip().is_loopback(), "fixture must listen on loopback");
            let listener = TcpListener::bind(bind).await?;
            println!("{}", listener.local_addr()?);
            std::io::stdout().flush()?;
            codex_apdu::serve_fixture(
                listener,
                Path::new(directory),
                request_log.first().map(PathBuf::from),
            )
            .await
        }
        _ => bail!(
            "usage: codex-apdu init DIR | serve DIR 127.0.0.1:PORT [REQUEST_LOG] | chip DIR RELAY | live-setup DIR KEY_FILE | live-chip DIR | key-list DIR | key-add DIR ALIAS KEY_FILE | key-delete DIR ALIAS"
        ),
    }
}
