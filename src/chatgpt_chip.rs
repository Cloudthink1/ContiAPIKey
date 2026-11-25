#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [mode, directory] if mode == "chip" => {
            codex_apdu::run_chatgpt_chip(
                std::path::Path::new(directory),
                tokio::io::stdin(),
                tokio::io::stdout(),
            )
            .await
        }
        _ => anyhow::bail!("usage: codex-chatgpt-chip chip PROFILE"),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The ChatGPT chip simulator requires Windows.");
    std::process::exit(1);
}
