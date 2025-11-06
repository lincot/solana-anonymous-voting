// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024 Entangle Technologies Ltd.
// SPDX-FileCopyrightText: 2025 lincot
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::stream::{self, StreamExt};
use solana_client::{
    rpc_client::{GetConfirmedSignaturesForAddress2Config, SerializableTransaction},
    rpc_config::{RpcBlockConfig, RpcTransactionConfig},
    rpc_request::MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT,
    rpc_response::RpcConfirmedTransactionStatusWithSignature,
};
use solana_sdk::{
    clock::Slot, commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature,
    transaction::VersionedTransaction,
};
use solana_tools::solana_transactor::{RpcPool, TransactorError};
use solana_transaction_status::{
    EncodedConfirmedTransactionWithStatusMeta, EncodedTransaction, TransactionBinaryEncoding,
    TransactionConfirmationStatus, TransactionDetails, UiTransactionEncoding,
    UiTransactionStatusMeta,
};
use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};
use tracing::debug;

use super::utils::Broadcaster;

#[derive(Clone, Debug)]
pub struct Tx {
    pub transaction: VersionedTransaction,
    pub meta: UiTransactionStatusMeta,
    pub slot: Slot,
    #[allow(dead_code)]
    pub block_time: i64,
}

pub struct SolanaReader {
    rpc_pool: RpcPool,
    program: Pubkey,
    tx_read_from: Signature,
    concurrency: usize,
    polling_interval: Duration,
    confirmed_tx_sender: Broadcaster<Arc<Tx>>,
    finalized_tx_sender: Broadcaster<Arc<Tx>>,
    /// Transactions that were confirmed but not yet finalized.
    confirmed_txs: HashMap<Signature, Arc<Tx>>,
}

impl SolanaReader {
    pub fn new(
        rpc_pool: RpcPool,
        program: Pubkey,
        tx_read_from: Signature,
        concurrency: usize,
        polling_interval: Duration,
        confirmed_tx_sender: Broadcaster<Arc<Tx>>,
        finalized_tx_sender: Broadcaster<Arc<Tx>>,
    ) -> Self {
        Self {
            rpc_pool,
            concurrency,
            program,
            tx_read_from,
            confirmed_tx_sender,
            finalized_tx_sender,
            polling_interval,
            confirmed_txs: HashMap::new(),
        }
    }

    pub async fn listen_to_solana(mut self) -> Result<(), TransactorError> {
        debug!(
            "Starting listening to Solana program {} since tx {}",
            self.program, self.tx_read_from,
        );

        let mut tx_read_from = Some(self.tx_read_from);
        let mut until: Option<Signature> = None;
        let mut next_until: Option<Signature> = None;
        loop {
            let mut before = None;
            until = if tx_read_from.is_some() {
                tx_read_from.take()
            } else if next_until.is_some() {
                next_until
            } else {
                until
            };
            next_until = None;

            let mut sig_chunks = Vec::new();
            loop {
                let signatures_backward = self.fetch_signature_chunk(until, before).await;
                let signatures_len = signatures_backward.len();

                if next_until.is_none() {
                    next_until = signatures_backward
                        .iter()
                        .find(|sig| {
                            sig.confirmation_status
                                .clone()
                                .expect("Expected confirmation status to be present")
                                == TransactionConfirmationStatus::Finalized
                        })
                        .map(|newest_finalized_sig| {
                            Signature::from_str(&newest_finalized_sig.signature)
                                .expect("Expected signature to be parsed")
                        });
                }

                if let Some(oldest_sig) = signatures_backward.last() {
                    before.replace(
                        Signature::from_str(&oldest_sig.signature)
                            .expect("Failed to parse signature"),
                    );
                }
                sig_chunks.push(signatures_backward);

                if signatures_len < MAX_GET_CONFIRMED_SIGNATURES_FOR_ADDRESS2_LIMIT {
                    break;
                }
            }

            let mut blocks_to_fetch =
                Vec::<(Slot, Vec<(Signature, TransactionConfirmationStatus)>)>::new();

            let mut add_sig_to_fetch = |slot, signature, confirmation_status| {
                if let Ok(i) = blocks_to_fetch.binary_search_by_key(&slot, |&(slot, _)| slot) {
                    blocks_to_fetch[i].1.push((signature, confirmation_status));
                } else {
                    blocks_to_fetch.push((slot, vec![(signature, confirmation_status)]))
                }
            };

            for sig_chunk in sig_chunks.into_iter().rev() {
                for sig in sig_chunk.into_iter().rev() {
                    let confirmation_status = sig
                        .confirmation_status
                        .clone()
                        .expect("Expected confirmation status to be present");

                    let signature = sig
                        .signature
                        .parse()
                        .expect("Expected signature to be parsed");

                    match confirmation_status {
                        TransactionConfirmationStatus::Confirmed => {
                            if !self.confirmed_txs.contains_key(&signature) {
                                add_sig_to_fetch(sig.slot, signature, confirmation_status);
                            }
                        }
                        TransactionConfirmationStatus::Finalized => {
                            if let Some(tx) = self.confirmed_txs.remove(&signature) {
                                self.finalized_tx_sender
                                    .send(tx)
                                    .expect("Failed to send tx over a channel");
                            } else {
                                add_sig_to_fetch(sig.slot, signature, confirmation_status);
                            }
                        }
                        TransactionConfirmationStatus::Processed => {
                            panic!("Unexpected confirmation status")
                        }
                    }
                }
            }

            if blocks_to_fetch.is_empty() {
                tokio::time::sleep(self.polling_interval).await;
                continue;
            }
            if blocks_to_fetch.len() >= 50 {
                debug!("Many blocks to fetch: {}", blocks_to_fetch.len());
            }

            let mut tx_stream = stream::iter(blocks_to_fetch.into_iter().map(|(slot, sigs)| {
                let rpc_pool = self.rpc_pool.clone();
                async move {
                    if sigs.len() == 1 {
                        let (sig, confirmation_status) = sigs.into_iter().next().unwrap();
                        let tx_full = Self::fetch_tx(rpc_pool, sig).await;
                        let EncodedTransaction::Binary(tx, encoding) =
                            &tx_full.transaction.transaction
                        else {
                            panic!("Unexpected transaction encoding");
                        };
                        assert_eq!(encoding, &TransactionBinaryEncoding::Base64);
                        let tx = Self::decode_base64_transaction(tx);
                        let tx = Tx {
                            transaction: tx,
                            meta: tx_full
                                .transaction
                                .meta
                                .expect("Expected meta to be present"),
                            slot,
                            block_time: tx_full
                                .block_time
                                .expect("Expected block time to be present"),
                        };
                        vec![(tx, confirmation_status)]
                    } else {
                        let txs = Self::fetch_txs_in_block(
                            rpc_pool,
                            slot,
                            sigs.iter().map(|(sig, _)| sig).collect::<Vec<_>>(),
                        )
                        .await;
                        txs.into_iter()
                            .zip(sigs)
                            .map(|(tx, (_, confirmation_status))| (tx, confirmation_status))
                            .collect()
                    }
                }
            }))
            .buffered(self.concurrency);

            while let Some(txs) = tx_stream.next().await {
                for (tx, confirmation_status) in txs {
                    match confirmation_status {
                        TransactionConfirmationStatus::Confirmed => {
                            let sig = *tx.transaction.get_signature();
                            let tx = Arc::new(tx);
                            self.confirmed_txs.insert(sig, tx.clone());
                            self.confirmed_tx_sender
                                .send(tx)
                                .expect("Failed to send tx over a channel");
                        }
                        TransactionConfirmationStatus::Finalized => {
                            let tx = Arc::new(tx);
                            self.confirmed_tx_sender
                                .send(tx.clone())
                                .expect("Failed to send tx over a channel");
                            self.finalized_tx_sender
                                .send(tx)
                                .expect("Failed to send tx over a channel")
                        }
                        TransactionConfirmationStatus::Processed => {
                            panic!("Unexpected confirmation status")
                        }
                    }
                }
            }
        }
    }

    async fn fetch_tx(
        rpc_pool: RpcPool,
        signature: Signature,
    ) -> EncodedConfirmedTransactionWithStatusMeta {
        rpc_pool
            .with_read_rpc_loop(
                |rpc| async move {
                    rpc.get_transaction_with_config(
                        &signature,
                        RpcTransactionConfig {
                            encoding: Some(UiTransactionEncoding::Base64),
                            commitment: Some(CommitmentConfig::confirmed()),
                            max_supported_transaction_version: Some(0),
                        },
                    )
                    .await
                },
                CommitmentConfig::confirmed(),
            )
            .await
    }

    async fn fetch_signature_chunk(
        &self,
        until: Option<Signature>,
        before: Option<Signature>,
    ) -> Vec<RpcConfirmedTransactionStatusWithSignature> {
        self.rpc_pool
            .with_read_rpc_loop(
                |rpc| async move {
                    let args = GetConfirmedSignaturesForAddress2Config {
                        before,
                        until,
                        limit: None,
                        commitment: Some(CommitmentConfig::confirmed()),
                    };

                    rpc.get_signatures_for_address_with_config(&self.program, args)
                        .await
                },
                CommitmentConfig::confirmed(),
            )
            .await
    }

    async fn fetch_txs_in_block(
        rpc_pool: RpcPool,
        slot: Slot,
        signatures: impl IntoIterator<Item = &Signature>,
    ) -> Vec<Tx> {
        let block = rpc_pool
            .with_read_rpc_loop(
                |rpc| async move {
                    // oldest first
                    rpc.get_block_with_config(
                        slot,
                        RpcBlockConfig {
                            // Base64 is most efficient
                            encoding: Some(UiTransactionEncoding::Base64),
                            transaction_details: Some(TransactionDetails::Full),
                            max_supported_transaction_version: Some(0),
                            commitment: Some(CommitmentConfig::confirmed()),
                            ..Default::default()
                        },
                    )
                    .await
                },
                CommitmentConfig::confirmed(),
            )
            .await;
        let mut unseen_transactions = &block
            .transactions
            .expect("Expected transactions to be fetched")[..];

        let mut res = vec![];
        let mut sig_count = 0;
        for sig in signatures.into_iter() {
            sig_count += 1;
            let (pos, tx) = unseen_transactions
                .iter()
                .map(|tx| {
                    let EncodedTransaction::Binary(tx, encoding) = &tx.transaction else {
                        panic!("Unexpected transaction encoding");
                    };
                    assert_eq!(encoding, &TransactionBinaryEncoding::Base64);
                    Self::decode_base64_transaction(tx)
                })
                .enumerate()
                .find(|(_, tx)| sig == tx.get_signature())
                .expect("Expected transaction to be found in block");
            res.push(Tx {
                transaction: tx,
                meta: unseen_transactions[pos]
                    .meta
                    .clone()
                    .expect("Expected meta to be present"),
                slot,
                block_time: block.block_time.expect("Expected block time to be present"),
            });
            unseen_transactions = &unseen_transactions[pos + 1..];
        }
        if sig_count >= 50 {
            debug!(
                "Fetched block with many program transactions: {}",
                sig_count
            );
        }
        res
    }

    fn decode_base64_transaction(base64_str: &str) -> VersionedTransaction {
        let bytes = BASE64
            .decode(base64_str)
            .expect("Expected transaction to be base64 encoded");
        bincode::deserialize(&bytes).expect("Expected transaction to be deserialized")
    }
}

#[cfg(test)]
mod tests {
    use solana_sdk::message::VersionedMessage;

    use super::*;

    #[test]
    fn test_decode_base64_transaction() {
        let legacy_str = "AZ5+tBdn9BxSM5DVDsImFpZ3pvP+7YdhQpZbopFLSRJmTvHVjYpScV5+VxiN1iYE0PY7R+er3rs1tDs41J3z1gcBAAEDi90/vt77Q6PQZiKNTSjv6rNsrdFDl6WyBBfgZR8uWf7yuFzH4AWjuSFI1yDGOL/jso0lAW5/zR8FTddr3bRdnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYTYW0iJUpty2LHfslmuNpqvP4n3Y2bkDS4GHa5E8N+sBAgIAAQwCAAAAR3qRAAAAAAA=";
        let tx = SolanaReader::decode_base64_transaction(legacy_str);
        assert!(matches!(tx.message, VersionedMessage::Legacy(_)));

        let v0_str = "AeAYmm5ARjCwPzFL9vQXulsq78PHV4ac19ML20K3bEj79br3VrhUF6Ctt+lhKqVoK6ffYrJEEB7TY7c/cCyvQwyAAQAKEAeTCjQL26xEhbEOBHOvvNcKkQ0MWyqy+yYMcCcG1PQG+jqbEhI/mP9oeJoxMmYTZadz2pfWRUWyFrAmZ0X5Y8RD857XhWM7o8YhktD+8jdeqxM65OGhRItyrjSyPUya0EbDQxsPhg1mrn1PGFrWUpo/5kLmEu3g1CrN+CtDA7z+/bMJw6u5gydXlKG+YD8dciPwBJuCIERgo01fRJrJe8+n0KEwixIW+uOfQYKfNd+nzmKv8yO7BZvpGyRdH4YWj4yXJY9OJInxuz0QKRSODYMLWhOZ2v8QhASOe9jb6fhZcWh0TbXdiF7CEP4UpaU7GHhj2ehcQpuruO3AFBXjtp4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpDQUmct/XBjxcxrUBdUwcxV2gPhr6Iq83q2aTj87J/3yRXyvWfshElS+FrJxNBA/VmkRcXaGqPSy8tKhFsqDCml1tRurHN33YrF6zjJWdkB+GWNf8GqRpF1XYqhnD6g7Ipnfs7EEirVpqtxOGK0/bRozVLILd+Ipo+aW/4Tqf6ZkNxbHTttZ1ODAdOlComWfDcrMZJcEfuRwg9xG7A2xJ7gan1RcZLFxRIYzJTD1K8X9Y2u4Im6H9ROPb2YoAAAAAi4nPX9pmSRXJDb+p6uKpoosQsScHKcKI9uQVU2EDNeQCBgYAAQAHCAkACg4ACwwNBw4CAQMEBQgJDxhmBj0SAdrr6mtCkeh6AAAA8WStAAAAAAAA";
        let tx = SolanaReader::decode_base64_transaction(v0_str);
        assert!(matches!(tx.message, VersionedMessage::V0(_)));
    }
}
