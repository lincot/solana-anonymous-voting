use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, error::SendError, unbounded_channel};
use tracing::warn;

#[derive(Clone)]
pub struct Broadcaster<T: Clone> {
    senders: Vec<UnboundedSender<T>>,
}

impl<T: Clone> Broadcaster<T> {
    pub fn new() -> Self {
        Self {
            senders: Vec::new(),
        }
    }

    pub fn subscribe(&mut self) -> UnboundedReceiver<T> {
        let (tx, rx) = unbounded_channel();
        self.senders.push(tx);
        rx
    }

    pub fn send(&self, msg: T) -> Result<(), SendError<T>> {
        for sender in &self.senders {
            if let Err(err) = sender.send(msg.clone()) {
                warn!("Broadcaster: failed to send over a channel: {err}");
            }
        }
        Ok(())
    }
}
