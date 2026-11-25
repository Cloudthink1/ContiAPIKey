use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;

pub const SERVER_NAME: &str = "codex-apdu.test";
pub const RESPONSES_PATH: &str = "/v1/responses";

pub fn client_config(ca: Vec<u8>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca))?;
    Ok(
        ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub fn server_config(cert: Vec<u8>, key: Vec<u8>) -> Result<ServerConfig> {
    let key = PrivateKeyDer::try_from(key).map_err(anyhow::Error::msg)?;
    Ok(
        ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert)], key)?,
    )
}

pub fn read_api_key(directory: &Path) -> Result<String> {
    let key = std::fs::read_to_string(directory.join("api-key")).context("read test API key")?;
    ensure!(
        key.len() == 69
            && key.starts_with("demo-")
            && key[5..].bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid test API key"
    );
    Ok(key)
}
