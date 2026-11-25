mod proxy;
mod relay;
#[cfg(test)]
pub(crate) mod test_relay;

pub(crate) use relay::Relay;

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::task::Context;
use std::task::Poll;

use futures::task::AtomicWaker;

use crate::live::mbedtls::Bio;
use crate::live::mbedtls::MbedTls;
use crate::live::mbedtls::root_bundle;
use crate::protocol::BAD_DATA;
use crate::protocol::BAD_LENGTH;
use crate::protocol::BAD_SEQUENCE;
use crate::protocol::BAD_STATE;
use crate::protocol::CHUNK;
use crate::protocol::Command;
use crate::protocol::NET_READ;
use crate::protocol::NET_RESULT;
use crate::protocol::NET_STATUS;
use crate::protocol::NET_WRITE;
use crate::protocol::OK;

pub const AUTH_HOST: &str = "auth.openai.com";
pub const CHAT_HOST: &str = "chatgpt.com";
pub const DEEPSEEK_HOST: &str = "api.deepseek.com";
pub const FRAGMENT: usize = CHUNK - 2;
const BUFFER: usize = 32 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Auth = 1,
    Chat = 2,
    DeepSeek = 3,
}

impl Destination {
    pub fn hostname(self) -> &'static str {
        match self {
            Self::Auth => AUTH_HOST,
            Self::Chat => CHAT_HOST,
            Self::DeepSeek => DEEPSEEK_HOST,
        }
    }

    pub fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Auth),
            2 => Some(Self::Chat),
            3 => Some(Self::DeepSeek),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct Network {
    slot: Mutex<(u16, Option<Arc<Tunnel>>)>,
    #[cfg(test)]
    pub roots: Option<Vec<u8>>,
}

#[derive(Default)]
struct Buffers {
    to_server: VecDeque<u8>,
    from_server: VecDeque<u8>,
    outbound_sequence: u16,
    inbound_sequence: u16,
    opened: bool,
    eof: bool,
    failed: bool,
    closed: bool,
}

struct Tunnel {
    id: u16,
    destination: Destination,
    buffers: Mutex<Buffers>,
    readable: AtomicWaker,
    writable: AtomicWaker,
}

impl Tunnel {
    fn buffers(&self) -> io::Result<MutexGuard<'_, Buffers>> {
        self.buffers
            .lock()
            .map_err(|_| io::Error::other("APDU TLS buffer state poisoned"))
    }
}

pub struct ApduBio(Arc<Tunnel>);

impl Network {
    pub(crate) async fn connect(&self, destination: Destination) -> anyhow::Result<MbedTls> {
        let bio = self.open(destination)?;
        let roots = root_bundle(webpki_root_certs::TLS_SERVER_ROOT_CERTS);
        let roots = roots.as_slice();
        #[cfg(test)]
        let roots = self.roots.as_deref().unwrap_or(roots);
        MbedTls::connect_bio(bio, destination.hostname(), roots).await
    }

    fn open(&self, destination: Destination) -> io::Result<ApduBio> {
        let mut network = self
            .slot
            .lock()
            .map_err(|_| io::Error::other("APDU network state poisoned"))?;
        if let Some(previous) = &network.1 {
            let mut buffers = previous.buffers()?;
            buffers.closed = true;
            buffers.failed = true;
            drop(buffers);
            previous.readable.wake();
            previous.writable.wake();
        }
        network.0 = network
            .0
            .checked_add(1)
            .ok_or_else(|| io::Error::other("connection identifiers exhausted"))?;
        let tunnel = Arc::new(Tunnel {
            id: network.0,
            destination,
            buffers: Mutex::new(Buffers::default()),
            readable: AtomicWaker::new(),
            writable: AtomicWaker::new(),
        });
        network.1 = Some(tunnel.clone());
        Ok(ApduBio(tunnel))
    }

    pub fn command(&self, command: &Command<'_>) -> Option<Result<(Vec<u8>, u16), u16>> {
        match command.ins {
            NET_STATUS | NET_RESULT | NET_READ | NET_WRITE => Some(self.dispatch(command)),
            _ => None,
        }
    }

    fn dispatch(&self, command: &Command<'_>) -> Result<(Vec<u8>, u16), u16> {
        let network = self.slot.lock().map_err(|_| BAD_STATE)?;
        if command.ins == NET_STATUS && command.sequence != 0 {
            return Err(BAD_SEQUENCE);
        }
        let Some(tunnel) = &network.1 else {
            return if command.ins == NET_STATUS {
                Ok((Vec::new(), OK))
            } else {
                Err(BAD_STATE)
            };
        };
        let mut buffers = tunnel.buffers().map_err(|_| BAD_STATE)?;
        if buffers.closed {
            return if command.ins == NET_STATUS {
                Ok((Vec::new(), OK))
            } else {
                Err(BAD_STATE)
            };
        }
        if command.ins == NET_STATUS {
            let credit = if buffers.eof || buffers.failed {
                0
            } else {
                BUFFER - buffers.from_server.len()
            };
            let flags = u8::from(buffers.opened) | (u8::from(!buffers.to_server.is_empty()) << 1);
            let [id_high, id_low] = tunnel.id.to_be_bytes();
            let [credit_high, credit_low] = (credit as u16).to_be_bytes();
            return Ok((
                vec![
                    id_high,
                    id_low,
                    tunnel.destination as u8,
                    flags,
                    credit_high,
                    credit_low,
                ],
                OK,
            ));
        }
        let [high, low, data @ ..] = command.data else {
            return Err(BAD_LENGTH);
        };
        if u16::from_be_bytes([*high, *low]) != tunnel.id {
            return Err(BAD_STATE);
        }
        match command.ins {
            NET_RESULT if command.sequence == 0 => {
                match data {
                    [0] if !buffers.opened && !buffers.failed => buffers.opened = true,
                    [1] => buffers.failed = true,
                    [2] if buffers.opened => buffers.eof = true,
                    _ => return Err(BAD_DATA),
                }
                drop(buffers);
                tunnel.readable.wake();
                tunnel.writable.wake();
                Ok((Vec::new(), OK))
            }
            NET_READ if data.is_empty() && buffers.opened && !buffers.failed => {
                if command.sequence != buffers.outbound_sequence {
                    return Err(BAD_SEQUENCE);
                }
                let count = buffers.to_server.len().min(FRAGMENT);
                if count == 0 {
                    return Ok((Vec::new(), OK));
                }
                buffers.outbound_sequence = buffers.outbound_sequence.wrapping_add(1);
                let data = buffers.to_server.drain(..count).collect();
                drop(buffers);
                tunnel.writable.wake();
                Ok((data, OK))
            }
            NET_WRITE if !data.is_empty() && buffers.opened && !buffers.eof && !buffers.failed => {
                if command.sequence != buffers.inbound_sequence {
                    return Err(BAD_SEQUENCE);
                }
                if buffers.from_server.len() + data.len() > BUFFER {
                    return Err(BAD_LENGTH);
                }
                buffers.from_server.extend(data);
                buffers.inbound_sequence = buffers.inbound_sequence.wrapping_add(1);
                drop(buffers);
                tunnel.readable.wake();
                Ok((Vec::new(), OK))
            }
            _ => Err(BAD_STATE),
        }
    }
}

impl Drop for ApduBio {
    fn drop(&mut self) {
        if let Ok(mut buffers) = self.0.buffers() {
            buffers.closed = true;
        }
    }
}

impl Bio for ApduBio {
    fn try_write(&self, bytes: &[u8]) -> io::Result<usize> {
        let mut buffers = self.0.buffers()?;
        if buffers.failed {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let count = bytes.len().min(BUFFER - buffers.to_server.len());
        if !buffers.opened || count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        buffers.to_server.extend(&bytes[..count]);
        Ok(count)
    }

    fn try_read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut buffers = self.0.buffers()?;
        if buffers.failed {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        let count = bytes.len().min(buffers.from_server.len());
        if count == 0 && !buffers.eof {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        for (output, byte) in bytes.iter_mut().zip(buffers.from_server.drain(..count)) {
            *output = byte;
        }
        Ok(count)
    }

    fn poll_read_ready(&self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.readable.register(context.waker());
        let buffers = self.0.buffers()?;
        if buffers.eof || buffers.failed || !buffers.from_server.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn poll_write_ready(&self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.writable.register(context.waker());
        let buffers = self.0.buffers()?;
        if buffers.failed || (buffers.opened && buffers.to_server.len() < BUFFER) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn capacity_and_connection_errors_are_applied_to_the_tls_bio() {
        let network = Network::default();
        let bio = network.open(Destination::Auth).unwrap();
        let exchange = |ins, sequence, data| {
            network.dispatch(&Command {
                ins,
                sequence,
                data,
            })
        };
        assert_eq!(
            bio.try_write(b"one").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        exchange(NET_RESULT, 0, &[0, 1, 0]).unwrap();
        assert_eq!(bio.try_write(&vec![7; BUFFER + 1]).unwrap(), BUFFER);
        assert_eq!(
            bio.try_write(b"one").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(exchange(NET_READ, 1, &[0, 1]), Err(BAD_SEQUENCE));
        assert_eq!(exchange(NET_READ, 0, &[0, 1]).unwrap().0.len(), FRAGMENT);
        assert_eq!(bio.try_write(&vec![7; FRAGMENT + 1]).unwrap(), FRAGMENT);
        assert_eq!(exchange(NET_WRITE, 0, &[0, 2, 0]), Err(BAD_STATE));
        exchange(NET_RESULT, 0, &[0, 1, 1]).unwrap();
        assert_eq!(
            bio.try_write(b"one").unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(
            bio.try_read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
