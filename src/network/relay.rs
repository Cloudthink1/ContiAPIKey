use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use super::Destination;
use super::FRAGMENT;
use super::proxy;
use crate::host::Session;
use crate::protocol::*;

const RELAY_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy)]
enum Route {
    ChatGpt,
    DeepSeek,
}

struct Tunnel {
    id: u16,
    socket: Option<TcpStream>,
    inbound: u16,
    outbound: u16,
}

pub(crate) struct Relay {
    route: Route,
    tunnel: Option<Tunnel>,
}

impl Relay {
    pub(crate) fn chatgpt() -> Self {
        Self {
            route: Route::ChatGpt,
            tunnel: None,
        }
    }

    pub(crate) fn deepseek() -> Self {
        Self {
            route: Route::DeepSeek,
            tunnel: None,
        }
    }

    fn accepts(&self, destination: Destination) -> bool {
        match self.route {
            Route::ChatGpt => matches!(destination, Destination::Auth | Destination::Chat),
            Route::DeepSeek => destination == Destination::DeepSeek,
        }
    }

    async fn connect(&self, destination: Destination) -> Result<TcpStream> {
        match self.route {
            Route::ChatGpt => proxy::connect(destination).await,
            Route::DeepSeek => Ok(tokio::time::timeout(
                CONNECT_TIMEOUT,
                TcpStream::connect((destination.hostname(), 443)),
            )
            .await??),
        }
    }

    async fn pump(&mut self, session: &mut Session) -> Result<bool> {
        let report = session.checked(NET_STATUS, 0, &[]).await?;
        let [high, low, destination, flags, credit_high, credit_low] = report.as_slice() else {
            ensure!(report.is_empty(), "invalid APDU connection status");
            self.tunnel = None;
            return Ok(false);
        };
        let id = u16::from_be_bytes([*high, *low]);
        if self.tunnel.as_ref().is_none_or(|tunnel| tunnel.id != id) {
            let destination = Destination::decode(*destination)
                .context("unsupported APDU network destination")?;
            ensure!(
                self.accepts(destination),
                "APDU network destination is disabled for this mode"
            );
            let socket = self.connect(destination).await.ok();
            let mut result = id.to_be_bytes().to_vec();
            result.push(if socket.is_some() { 0 } else { 1 });
            let status = session.exchange(NET_RESULT, 0, &result).await?.1;
            if status != BAD_STATE {
                ensure!(
                    status == OK,
                    "APDU simulator refused network connection result"
                );
                self.tunnel = Some(Tunnel {
                    id,
                    socket,
                    inbound: 0,
                    outbound: 0,
                });
            }
            return Ok(true);
        }
        let tunnel = self
            .tunnel
            .as_mut()
            .context("missing APDU network connection")?;
        let Some(socket) = tunnel.socket.as_mut() else {
            return Ok(false);
        };
        let mut progressed = false;
        let id = id.to_be_bytes();
        if flags & 2 != 0 {
            let (data, status) = session.exchange(NET_READ, tunnel.outbound, &id).await?;
            if status == BAD_STATE {
                return Ok(true);
            }
            ensure!(
                status == OK && data.len() <= FRAGMENT,
                "APDU simulator supplied invalid TLS data"
            );
            if !data.is_empty() {
                tunnel.outbound = tunnel.outbound.wrapping_add(1);
                if !matches!(
                    tokio::time::timeout(RELAY_TIMEOUT, socket.write_all(&data)).await,
                    Ok(Ok(()))
                ) {
                    let _ = session.exchange(NET_RESULT, 0, &[id[0], id[1], 1]).await?;
                    tunnel.socket = None;
                    return Ok(true);
                }
                progressed = true;
            }
        }
        let credit = usize::from(u16::from_be_bytes([*credit_high, *credit_low])).min(FRAGMENT);
        if credit != 0 {
            let mut data = [0; CHUNK];
            data[..2].copy_from_slice(&id);
            match socket.try_read(&mut data[2..2 + credit]) {
                Ok(0) => {
                    let _ = session.exchange(NET_RESULT, 0, &[id[0], id[1], 2]).await?;
                    progressed = true;
                }
                Ok(count) => {
                    let status = session
                        .exchange(NET_WRITE, tunnel.inbound, &data[..count + 2])
                        .await?
                        .1;
                    if status == BAD_STATE {
                        return Ok(true);
                    }
                    ensure!(status == OK, "APDU simulator refused input TLS data");
                    tunnel.inbound = tunnel.inbound.wrapping_add(1);
                    progressed = true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(_) => {
                    let _ = session.exchange(NET_RESULT, 0, &[id[0], id[1], 1]).await?;
                    tunnel.socket = None;
                    progressed = true;
                }
            }
        }
        Ok(progressed)
    }

    pub(crate) async fn next(
        &mut self,
        session: &mut Session,
        sequence: &mut u16,
    ) -> Result<Result<(Bytes, bool), u16>> {
        loop {
            let (data, status) = session.exchange(READ, *sequence, &[]).await?;
            match status {
                LAST => {
                    self.tunnel = None;
                    return Ok(Ok((Bytes::from(data), true)));
                }
                MORE if !data.is_empty() => {
                    *sequence = sequence
                        .checked_add(1)
                        .context("APDU response sequence exhausted")?;
                    return Ok(Ok((Bytes::from(data), false)));
                }
                PENDING if data.is_empty() => {
                    if !self.pump(session).await? {
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
                status => {
                    self.tunnel = None;
                    return Ok(Err(status));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_only_accepts_destinations_for_its_mode() {
        let targets = [Destination::Auth, Destination::Chat, Destination::DeepSeek];
        assert_eq!(
            targets.map(|destination| Relay::chatgpt().accepts(destination)),
            [true, true, false]
        );
        assert_eq!(
            targets.map(|destination| Relay::deepseek().accepts(destination)),
            [false, false, true]
        );
    }
}
