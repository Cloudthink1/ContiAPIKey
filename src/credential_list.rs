use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;

use crate::host::Session;
use crate::protocol::*;

const MAX_ALIASES: usize = 4096;

#[derive(Default)]
pub(crate) struct CredentialList {
    remaining: std::vec::IntoIter<String>,
    next: u16,
}

impl CredentialList {
    pub(crate) fn page(
        &mut self,
        sequence: u16,
        load: impl FnOnce() -> Result<Vec<String>, u16>,
    ) -> Result<(Vec<u8>, u16), u16> {
        if sequence == 0 {
            *self = Self::default();
            let aliases = load()?;
            if aliases.len() > MAX_ALIASES {
                return Err(TOO_LARGE);
            }
            self.remaining = aliases.into_iter();
        } else if sequence != self.next {
            return Err(BAD_SEQUENCE);
        }
        let alias = self
            .remaining
            .next()
            .map_or_else(Vec::new, String::into_bytes);
        if self.remaining.len() == 0 {
            self.next = 0;
            Ok((alias, LAST))
        } else {
            self.next = sequence + 1;
            Ok((alias, MORE))
        }
    }
}

pub(crate) async fn receive(session: &mut Session) -> Result<Vec<String>> {
    let mut aliases = Vec::new();
    for sequence in 0..MAX_ALIASES as u16 {
        let (bytes, status) = session.exchange(LIST_CREDENTIALS, sequence, &[]).await?;
        ensure!(
            matches!(status, MORE | LAST),
            "Could not list APDU credentials ({status:04X})."
        );
        if bytes.is_empty() {
            ensure!(
                sequence == 0 && status == LAST,
                "Invalid empty APDU credential entry."
            );
        } else {
            let alias = String::from_utf8(bytes)?;
            crate::validate_alias(&alias)?;
            aliases.push(alias);
        }
        if status == LAST {
            return Ok(aliases);
        }
    }
    bail!("APDU credential list exceeded the size limit.")
}
