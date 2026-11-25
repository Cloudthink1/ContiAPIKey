#[cfg(windows)]
mod chatgpt;
mod chip;
#[cfg(windows)]
mod credential_list;
mod fixture;
#[cfg(windows)]
mod functions_wire;
mod host;
#[cfg(windows)]
mod live;
#[cfg(windows)]
mod network;
#[cfg(windows)]
mod operation;
mod protocol;
mod tls;
mod transport;

#[cfg(test)]
mod tests;

#[cfg(windows)]
pub use chatgpt::ChatGptTransport;
#[cfg(windows)]
pub use chatgpt::Model as ChatGptModel;
#[cfg(windows)]
pub use chatgpt::list_accounts as list_chatgpt_accounts;
#[cfg(windows)]
pub use chatgpt::logout as logout_chatgpt;
#[cfg(windows)]
pub use chatgpt::prepare as prepare_chatgpt;
#[cfg(windows)]
pub use chatgpt::prepare_new as prepare_new_chatgpt;
#[cfg(windows)]
pub use chatgpt::run_chip as run_chatgpt_chip;
pub use chip::run_chip;
pub use fixture::init_fixture;
pub use fixture::serve_fixture;
pub use host::ApduTransport;
#[cfg(windows)]
pub use live::LiveTransport;
#[cfg(windows)]
pub use live::delete_key;
#[cfg(windows)]
pub use live::import_key_file;
#[cfg(windows)]
pub use live::list_keys;
#[cfg(windows)]
pub use live::run_live_chip;
#[cfg(windows)]
pub use live::setup_live;
pub use transport::{ByteStream, TransportError};

#[cfg(windows)]
pub const DEFAULT_ALIAS: &str = "default";

#[cfg(windows)]
pub fn validate_alias(alias: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=32).contains(&alias.len())
            && alias
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && alias.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_')),
        "Use 1 to 32 lowercase English letters, digits, hyphens, or underscores. Start with a letter or digit."
    );
    Ok(())
}
