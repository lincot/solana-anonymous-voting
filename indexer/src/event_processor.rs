use solana_sdk::pubkey::Pubkey;
use solana_tools::solana_logs::LogsBunch;

use crate::parse_logs;

pub trait EventListener {
    type Event: parse_logs::Event;

    fn on_logs(&self, logs_bunch: LogsBunch, program: Pubkey) {
        let logs = &logs_bunch.logs[..];
        let logs: Vec<&str> = logs.iter().by_ref().map(String::as_str).collect();
        let Ok(events) =
            parse_logs::parse_logs::<Self::Event>(logs.as_slice(), program.to_string().as_str())
        else {
            tracing::error!("Failed to parse logs: {:?}", logs);
            return;
        };
        // if !events.is_empty() {
        //     debug!(
        //         "Logs intercepted, tx_signature: {}, events: {}, need_check: {}",
        //         logs_bunch.tx_signature,
        //         events.len(),
        //         logs_bunch.need_check
        //     );
        // }

        if !events.is_empty() {
            self.on_events(
                events,
                &logs_bunch.tx_signature,
                logs_bunch.slot,
                logs_bunch.need_check,
            );
        }
    }

    fn on_events(&self, events: Vec<Self::Event>, signature: &str, slot: u64, need_check: bool);
}
