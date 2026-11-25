use std::io;

use sha2::Digest;
use sha2::Sha256;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

pub const CLA: u8 = 0x80;
pub const CHALLENGE: u8 = 0x10;
pub const WRITE: u8 = 0x20;
pub const EXECUTE: u8 = 0x30;
pub const READ: u8 = 0x40;
pub const CANCEL: u8 = 0x50;
#[cfg(windows)]
pub const LIST_CREDENTIALS: u8 = 0x63;
#[cfg(windows)]
pub const KEY_CHANGE_BEGIN: u8 = 0x64;
#[cfg(windows)]
pub const KEY_WRITE: u8 = 0x65;
#[cfg(windows)]
pub const KEY_COMMIT: u8 = 0x66;
#[cfg(windows)]
pub const BEGIN_REQUEST: u8 = 0x70;
#[cfg(windows)]
pub const SELECT_CREDENTIAL: u8 = 0x77;
#[cfg(windows)]
pub const NET_STATUS: u8 = 0x78;
#[cfg(windows)]
pub const NET_READ: u8 = 0x79;
#[cfg(windows)]
pub const NET_WRITE: u8 = 0x7A;
#[cfg(windows)]
pub const NET_RESULT: u8 = 0x7B;
#[cfg(windows)]
pub const PENDING: u16 = 0x6200;
#[cfg(windows)]
pub const CREDENTIAL_STORE_FAILED: u16 = 0x6408;
#[cfg(windows)]
pub const ALIAS_EXISTS: u16 = 0x640A;
#[cfg(windows)]
pub mod chatgpt {
    pub const LOGIN_BEGIN: u8 = 0x71;
    pub const LOGIN_STATUS: u8 = 0x72;
    pub const CALLBACK_WRITE: u8 = 0x73;
    pub const LOGIN_FINISH: u8 = 0x74;
    pub const LOGOUT: u8 = 0x75;
    pub const MODELS: u8 = 0x76;
    pub const LOGIN_REQUIRED: u16 = 0x6406;
    pub const LOGIN_MISMATCH: u16 = 0x6407;
}

#[cfg(windows)]
use chatgpt::*;
pub const CHUNK: usize = 255;
pub const MAX_REQUEST: usize = 1024 * 1024;
pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const MAX_FRAME: usize = 5 + CHUNK;

pub const OK: u16 = 0x9000;
pub const MORE: u16 = 0x6100;
#[cfg(windows)]
pub const LAST: u16 = 0x62F1;
pub const BAD_LENGTH: u16 = 0x6700;
pub const DENIED: u16 = 0x6982;
pub const BAD_STATE: u16 = 0x6985;
pub const BAD_DATA: u16 = 0x6A80;
pub const TOO_LARGE: u16 = 0x6A84;
pub const BAD_SEQUENCE: u16 = 0x6A86;
pub const BAD_INS: u16 = 0x6D00;
pub const BAD_CLA: u16 = 0x6E00;
pub const UPSTREAM_FAILED: u16 = 0x6400;

pub struct Command<'a> {
    pub ins: u8,
    pub sequence: u16,
    pub data: &'a [u8],
}

impl<'a> Command<'a> {
    pub fn decode(frame: &'a [u8]) -> Result<Self, u16> {
        let [cla, ins, p1, p2, tail @ ..] = frame else {
            return Err(BAD_LENGTH);
        };
        if *cla != CLA {
            return Err(BAD_CLA);
        }
        let data = match (*ins, tail) {
            (CHALLENGE, [32]) | (READ, [255]) | (CANCEL, []) => &[][..],
            #[cfg(windows)]
            (LIST_CREDENTIALS | KEY_COMMIT | BEGIN_REQUEST | EXECUTE, []) => &[][..],
            #[cfg(windows)]
            (LOGIN_STATUS | LOGIN_FINISH | LOGOUT | MODELS | NET_STATUS, []) => &[][..],
            #[cfg(windows)]
            (
                SELECT_CREDENTIAL | LOGIN_BEGIN | CALLBACK_WRITE | NET_READ | NET_WRITE
                | NET_RESULT,
                [lc, data @ ..],
            ) if *lc != 0 && usize::from(*lc) == data.len() => data,
            #[cfg(windows)]
            (KEY_CHANGE_BEGIN | KEY_WRITE, [lc, data @ ..])
                if *lc != 0 && usize::from(*lc) == data.len() =>
            {
                data
            }
            #[cfg(windows)]
            (
                LIST_CREDENTIALS | KEY_CHANGE_BEGIN | KEY_WRITE | KEY_COMMIT | BEGIN_REQUEST
                | SELECT_CREDENTIAL,
                _,
            ) => {
                return Err(BAD_LENGTH);
            }
            (WRITE | EXECUTE, [lc, data @ ..]) if *lc != 0 && usize::from(*lc) == data.len() => {
                data
            }
            (CHALLENGE | WRITE | EXECUTE | READ | CANCEL, _) => return Err(BAD_LENGTH),
            _ => return Err(BAD_INS),
        };
        Ok(Self {
            ins: *ins,
            sequence: u16::from_be_bytes([*p1, *p2]),
            data,
        })
    }

    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let [p1, p2] = self.sequence.to_be_bytes();
        let mut frame = vec![CLA, self.ins, p1, p2];
        match self.ins {
            CHALLENGE => frame.push(32),
            READ => frame.push(255),
            WRITE | EXECUTE if !self.data.is_empty() => {
                frame.push(u8::try_from(self.data.len()).map_err(io::Error::other)?);
                frame.extend_from_slice(self.data);
            }
            #[cfg(windows)]
            KEY_CHANGE_BEGIN | KEY_WRITE | SELECT_CREDENTIAL | LOGIN_BEGIN | CALLBACK_WRITE
            | NET_READ | NET_WRITE | NET_RESULT => {
                frame.push(u8::try_from(self.data.len()).map_err(io::Error::other)?);
                frame.extend_from_slice(self.data);
            }
            _ => {}
        }
        Ok(frame)
    }
}

pub fn signed_message(nonce: &[u8; 32], request: &[u8]) -> Vec<u8> {
    let mut message = b"codex-apdu-v1\0".to_vec();
    message.extend_from_slice(nonce);
    message.extend_from_slice(&Sha256::digest(request));
    message
}

pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0; 2];
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..]).await?;
    let len = usize::from(u16::from_be_bytes(prefix));
    if !(2..=MAX_FRAME).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid APDU frame length",
        ));
    }
    let mut frame = vec![0; len];
    reader.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

pub async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &[u8]) -> io::Result<()> {
    let len = u16::try_from(frame.len()).map_err(io::Error::other)?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(frame).await?;
    writer.flush().await
}
