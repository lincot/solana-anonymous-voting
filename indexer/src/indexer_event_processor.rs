use anon_vote::events::{CreatePollEvent, FinishTallyEvent, VoteEvent};
use solana_client::rpc_client::SerializableTransaction;
use solana_tools::solana_logs::solana_event_listener::LogsBunch;
use solana_transaction_status::option_serializer::OptionSerializer;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{error, warn};

use super::solana_reader::Tx;
use crate::{event_processor::EventListener, parse_logs::Event};

#[derive(Clone, Debug)]
pub(crate) enum IndexerEvent {
    CreatePoll(CreatePollEvent),
    Vote(VoteEvent),
    FinishTally(FinishTallyEvent),
}

impl Event for IndexerEvent {
    fn deserialize(log: &str) -> Option<Self> {
        if let Some(event) = VoteEvent::deserialize(log) {
            Some(Self::Vote(event))
        } else if let Some(event) = CreatePollEvent::deserialize(log) {
            Some(Self::CreatePoll(event))
        } else if let Some(event) = FinishTallyEvent::deserialize(log) {
            Some(Self::FinishTally(event))
        } else {
            warn!("Unknown event {log}");
            None
        }
    }
}

pub(crate) struct EventProcessor<T: Event> {
    logs_receiver: UnboundedReceiver<Arc<Tx>>,
    event_sender: UnboundedSender<(String, Vec<T>)>,
}

impl<T: Event> EventProcessor<T> {
    pub(crate) fn new(
        logs_receiver: UnboundedReceiver<Arc<Tx>>,
        event_sender: UnboundedSender<(String, Vec<T>)>,
    ) -> Self {
        Self {
            logs_receiver,
            event_sender,
        }
    }

    pub(crate) async fn execute(&mut self) {
        while let Some(tx) = self.logs_receiver.recv().await {
            let meta = &tx.meta;

            if meta.err.is_some() {
                continue;
            }

            let OptionSerializer::Some(logs) = &meta.log_messages else {
                error!(tx_id = %tx.transaction.get_signature(), "Tx has no logs");
                continue;
            };

            let logs_bunch = LogsBunch {
                need_check: false,
                tx_signature: tx.transaction.get_signature().to_string(),
                logs: logs.clone(),
                slot: tx.slot,
            };
            self.on_logs(logs_bunch, anon_vote::ID);
        }
    }
}

impl<T: Event> EventListener for EventProcessor<T> {
    type Event = T;

    fn on_events(&self, events: Vec<Self::Event>, signature: &str, _slot: u64, _need_check: bool) {
        if let Err(err) = self.event_sender.send((signature.into(), events)) {
            error!("Failed to send event through the channel: {}", err);
        }
    }
}
