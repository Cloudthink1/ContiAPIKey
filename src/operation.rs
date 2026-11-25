use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::protocol::*;

const OPERATION_TIMEOUT: Duration = Duration::from_secs(180);
pub(crate) const TURN_TIMEOUT: Duration = Duration::from_secs(185);

pub(crate) struct Output {
    pub bytes: Bytes,
    pub last: bool,
}

pub(crate) struct Operation {
    task: JoinHandle<Result<(), u16>>,
    output: mpsc::Receiver<Output>,
    pending: Bytes,
    next: u16,
    last: bool,
}

impl Drop for Operation {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Operation {
    pub(crate) fn launch<F, Fut>(run: F) -> Self
    where
        F: FnOnce(mpsc::Sender<Output>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), u16>> + Send + 'static,
    {
        let (sender, output) = mpsc::channel(2);
        let task = tokio::spawn(async move {
            tokio::time::timeout(OPERATION_TIMEOUT, run(sender))
                .await
                .unwrap_or(Err(UPSTREAM_FAILED))
        });
        Self {
            task,
            output,
            pending: Bytes::new(),
            next: 0,
            last: false,
        }
    }

    pub(crate) async fn read(
        operation: &mut Option<Self>,
        sequence: u16,
    ) -> Result<(Vec<u8>, u16), u16> {
        let op = operation.as_mut().ok_or(BAD_STATE)?;
        if sequence != op.next {
            return Err(BAD_SEQUENCE);
        }
        let finished = op.task.is_finished();
        if op.pending.is_empty()
            && let Ok(output) = op.output.try_recv()
        {
            op.pending = output.bytes;
            op.last = output.last;
        }
        if !op.pending.is_empty() {
            let fragment = op.pending.split_to(op.pending.len().min(CHUNK));
            if op.last && op.pending.is_empty() {
                *operation = None;
                return Ok((fragment.to_vec(), LAST));
            }
            op.next = op.next.checked_add(1).ok_or(TOO_LARGE)?;
            return Ok((fragment.to_vec(), MORE));
        }
        if !finished {
            return Ok((Vec::new(), PENDING));
        }
        let mut op = operation.take().ok_or(BAD_STATE)?;
        (&mut op.task).await.map_err(|_| UPSTREAM_FAILED)??;
        Ok((Vec::new(), LAST))
    }
}
