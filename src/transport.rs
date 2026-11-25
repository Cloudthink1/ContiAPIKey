use bytes::Bytes;
use futures::stream::BoxStream;

pub type ByteStream = BoxStream<'static, Result<Bytes, TransportError>>;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("invalid request: {0}")]
    Build(String),
    #[error("{0}")]
    Network(String),
    #[error("APDU deadline exceeded")]
    Timeout,
    #[error("{message} (APDU {status:04X})")]
    Chip { status: u16, message: String },
}
