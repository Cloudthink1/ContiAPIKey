use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::FRAGMENT;
use crate::protocol::*;

pub(crate) struct FixtureRelay {
    addresses: Vec<(u8, SocketAddr)>,
    connection: Option<(u16, TcpStream, u16, u16)>,
    pub(crate) packets: usize,
}

impl FixtureRelay {
    pub(crate) fn new(addresses: Vec<(u8, SocketAddr)>) -> Self {
        Self {
            addresses,
            connection: None,
            packets: 0,
        }
    }

    async fn pump(
        &mut self,
        mut exchange: impl AsyncFnMut(u8, u16, &[u8]) -> Result<(Vec<u8>, u16), u16>,
    ) {
        let (descriptor, _) = exchange(NET_STATUS, 0, &[]).await.unwrap();
        let [high, low, target, flags, credit_high, credit_low] = descriptor.as_slice() else {
            self.connection = None;
            return;
        };
        let id = u16::from_be_bytes([*high, *low]);
        if self
            .connection
            .as_ref()
            .is_none_or(|connection| connection.0 != id)
        {
            let socket = TcpStream::connect(
                self.addresses
                    .iter()
                    .find(|(id, _)| id == target)
                    .unwrap()
                    .1,
            )
            .await
            .unwrap();
            match exchange(NET_RESULT, 0, &[*high, *low, 0]).await {
                Err(BAD_STATE) => return,
                result => result.unwrap(),
            };
            self.connection = Some((id, socket, 0, 0));
        }
        let (_, socket, outgoing, incoming) = self.connection.as_mut().unwrap();
        if flags & 2 != 0 {
            let (data, _) = match exchange(NET_READ, *outgoing, &[*high, *low]).await {
                Err(BAD_STATE) => return,
                result => result.unwrap(),
            };
            if !data.is_empty() {
                *outgoing = outgoing.wrapping_add(1);
                let _ = socket.write_all(&data).await;
                self.packets += 1;
            }
        }
        let credit = usize::from(u16::from_be_bytes([*credit_high, *credit_low])).min(FRAGMENT);
        if credit == 0 {
            return;
        }
        let mut data = [0; CHUNK];
        data[..2].copy_from_slice(&[*high, *low]);
        match socket.try_read(&mut data[2..credit + 2]) {
            Ok(0) => {
                let _ = exchange(NET_RESULT, 0, &[*high, *low, 2]).await;
            }
            Ok(count) => {
                match exchange(NET_WRITE, *incoming, &data[..count + 2]).await {
                    Err(BAD_STATE) => return,
                    result => result.unwrap(),
                };
                *incoming = incoming.wrapping_add(1);
                self.packets += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(_) => {
                let _ = exchange(NET_RESULT, 0, &[*high, *low, 1]).await;
            }
        }
    }

    pub(crate) async fn read(
        &mut self,
        mut exchange: impl AsyncFnMut(u8, u16, &[u8]) -> Result<(Vec<u8>, u16), u16>,
    ) -> Result<Vec<u8>, u16> {
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            let mut data = Vec::new();
            let mut sequence = 0;
            loop {
                let (chunk, status) = exchange(READ, sequence, &[]).await?;
                data.extend_from_slice(&chunk);
                match status {
                    LAST => return Ok(data),
                    MORE => sequence += 1,
                    PENDING => {
                        self.pump(&mut exchange).await;
                        tokio::task::yield_now().await;
                    }
                    status => return Err(status),
                }
            }
        })
        .await
        .expect("mock operation timed out");
        self.connection = None;
        result
    }
}
