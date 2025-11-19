use actix_cors::Cors;
use actix_web::{post, web, App, HttpResponse, HttpServer};
use anchor_lang::{system_program, InstructionData, ToAccountMetas};
use core::mem::transmute;
use dashmap::DashMap;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use serde_with::{hex::Hex, serde_as, DisplayFromStr};
use smt_circom::{
    store::{NodeStore, RocksStore},
    CircomProof,
};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
    transaction::TransactionError,
};
use solana_tools::solana_transactor::{
    ix_compiler::InstructionBundle, SolanaTransactor, TransactorError,
};
use std::{cell::RefCell, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::{
    config::SslConfig,
    prover::{compress_proof, prove_relay, RelayInputs, RelayPublicInputs, STATE_DEPTH},
    rocks::{StateKey, StateStore},
};

// TODO delete nodes on tally finish

const MSG_LIMIT: u64 = 3; // const for now
const RELAY_CU: u32 = 200_000;

/// Relayer config PDA. Address derivation is tested below.
const RELAYER_CONFIG: Pubkey = pubkey!("HdeFrMkEy82nL3F9udVPtu4uPshdU3EaAKNgSYH7yS7n");

#[derive(Clone)]
struct AppState {
    relayer: Arc<Keypair>,
    transactor: SolanaTransactor,
    store: Arc<StateStore>,
    locks: Arc<DashMap<StateKey, Arc<Mutex<()>>>>,
}

pub struct Server {
    app_state: AppState,
}

impl Server {
    pub fn new(relayer: Keypair, transactor: SolanaTransactor, rocksdb_path: &str) -> Self {
        Self {
            app_state: AppState {
                relayer: Arc::new(relayer),
                transactor,
                store: Arc::new(StateStore::open(rocksdb_path).unwrap()),
                locks: Arc::new(DashMap::new()),
            },
        }
    }

    pub async fn execute(
        self,
        addrs: &str,
        ssl_config: SslConfig,
        workers: usize,
    ) -> std::io::Result<()> {
        let state = self.app_state;

        let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        ssl_builder.set_private_key_file(ssl_config.key, SslFiletype::PEM)?;
        ssl_builder.set_certificate_chain_file(ssl_config.cert)?;

        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(state.clone()))
                .wrap(Cors::permissive())
                .wrap(actix_web::middleware::Compress::default())
                .service(relay)
        })
        .bind_openssl(addrs, ssl_builder)?
        .workers(workers)
        .run()
        .await
    }
}

#[serde_as]
#[allow(dead_code)]
#[repr(C)]
#[derive(Debug, Deserialize)]
pub struct AccountMetaFromStr {
    #[serde_as(as = "DisplayFromStr")]
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[serde_as]
#[derive(Debug, Deserialize)]
struct RelayRequest {
    #[serde_as(as = "Hex")]
    msg_hash: [u8; 32],
    #[serde_as(as = "Hex")]
    nu: [u8; 32],
    discriminator: u8,
    #[serde_as(as = "Hex")]
    data: Vec<u8>,
    #[serde_as(as = "DisplayFromStr")]
    target_program: Pubkey,
    #[serde_as(as = "DisplayFromStr")]
    state_id: u64,
    cu_limit: Option<u32>,
    accounts: Vec<AccountMetaFromStr>,
}

#[post("/relay")]
async fn relay(
    app: web::Data<AppState>,
    req: web::Json<RelayRequest>,
) -> actix_web::Result<HttpResponse> {
    let msg_hash = req.msg_hash;
    match relay_inner(app.get_ref(), req.into_inner()).await {
        Ok(resp) => {
            debug!("executed message {}", hex::encode(msg_hash));
            Ok(HttpResponse::Ok().json(resp))
        }
        Err(err) => {
            warn!("relay error: {}", err);
            Ok(HttpResponse::BadRequest().body(err.to_string()))
        }
    }
}

#[derive(Debug, Serialize)]
struct RelayResponse {
    signature: String,
}

#[derive(Debug, Error)]
enum RelayError {
    #[error("The message has already been processed")]
    MessageDuplicated,
    #[error("Relayer message limit exceeded")]
    MessageLimitExceeded,
    #[error("Solana transaction error: {0}")]
    TransactionError(#[from] TransactionError),
    #[error("Solana transactor error: {0}")]
    TransactorError(#[from] TransactorError),
    #[error("Merkle tree error: {0}")]
    Smt(#[from] smt_circom::Error<<RocksStore<'static, [u8; 0]> as NodeStore>::Error>),
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),
    #[error("Prover error: {0}")]
    Prover(#[from] anyhow::Error),
}

async fn relay_inner(app: &AppState, req: RelayRequest) -> Result<RelayResponse, RelayError> {
    let skey = StateKey {
        program: req.target_program,
        state_id: req.state_id,
    };
    let lock = app
        .locks
        .entry(skey.clone())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let batch = RefCell::new(WriteBatch::new());
    let mut state = app.store.load_state(&skey, &batch)?;

    const {
        assert!(STATE_DEPTH.is_multiple_of(8));
    }
    let mut idx = req.nu;
    idx[..32 - STATE_DEPTH / 8].fill(0);

    let CircomProof {
        siblings: siblings_quota,
        is_old0: no_aux_quota,
        old_key: aux_key_quota,
        old_value: aux_value_quota,
        membership: membership_quota,
    } = state.quota_tree.get_proof(idx)?;
    let CircomProof {
        siblings: siblings_uniq,
        is_old0: no_aux_uniq,
        old_key: aux_key_uniq,
        old_value: aux_value_uniq,
        membership: membership_uniq,
    } = state.uniq_tree.get_proof(req.msg_hash)?;

    if membership_uniq {
        return Err(RelayError::MessageDuplicated);
    }

    let prev_count = if membership_quota {
        u64::from_be_bytes(aux_value_quota[24..].try_into().unwrap())
    } else {
        0
    };

    if prev_count >= MSG_LIMIT {
        return Err(RelayError::MessageLimitExceeded);
    }

    let root_quota_before = state.quota_tree.root()?;
    let root_uniq_before = state.uniq_tree.root()?;

    let inputs = RelayInputs {
        RootQuota_before: root_quota_before,
        RootUniq_before: root_uniq_before,
        MsgHash: req.msg_hash,
        MsgLimit: MSG_LIMIT,
        Nu: req.nu,
        PrevCount: prev_count,
        SiblingsQuota: siblings_quota,
        NoAuxQuota: no_aux_quota,
        AuxKeyQuota: aux_key_quota,
        AuxValueQuota: aux_value_quota,
        SiblingsUniq: siblings_uniq,
        NoAuxUniq: no_aux_uniq,
        AuxKeyUniq: aux_key_uniq,
        AuxValueUniq: aux_value_uniq,
    };

    let circom = prove_relay(&inputs).map_err(RelayError::Prover)?;
    let proof = compress_proof(circom.proof);
    let pub_inputs = RelayPublicInputs::from(&circom.pub_inputs);

    let mut accounts = zk_relayer::accounts::Relay {
        relayer: app.relayer.pubkey(),
        relayer_config: RELAYER_CONFIG,
        relayer_state: find_relayer_state(req.target_program, req.state_id),
        target_program: req.target_program,
        system_program: system_program::ID,
    }
    .to_account_metas(None);

    let req_accounts =
        unsafe { transmute::<Vec<AccountMetaFromStr>, Vec<AccountMeta>>(req.accounts) };
    accounts.extend(req_accounts);

    let data = zk_relayer::instruction::Relay {
        state_id: req.state_id,
        proof,
        root_state_after: pub_inputs.root_state_after,
        msg_hash: req.msg_hash,
        discriminator: req.discriminator,
        nu_hash: pub_inputs.nu_hash,
        data: req.data,
    }
    .data();

    let instruction = Instruction::new_with_bytes(zk_relayer::ID, &data, accounts);
    let ix = InstructionBundle::new(
        instruction,
        RELAY_CU + req.cu_limit.unwrap_or(0),
        None,
        vec![],
    );

    // TODO preflight...

    let tx_results = app
        .transactor
        .send_all_instructions(
            Option::<&str>::None,
            &[ix],
            &[&app.relayer],
            app.relayer.pubkey(),
            1,
            None,
            false,
        )
        .await?;

    // TODO persist if exited here but transaction succeeded...

    let signature = tx_results.last().unwrap().signature;
    for tx_result in tx_results {
        tx_result.status?;
    }

    let new_count = u64_to_u256_be(prev_count + 1);
    if prev_count == 0 {
        state.quota_tree.add(idx, new_count)?;
    } else {
        state.quota_tree.update(idx, new_count)?;
    }
    state.uniq_tree.add(req.msg_hash, one_be())?;
    app.store.db.write(batch.take())?;

    Ok(RelayResponse {
        signature: signature.to_string(),
    })
}

fn find_relayer_state(target_program: Pubkey, state_id: u64) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"RELAYER_STATE",
            &target_program.to_bytes(),
            &state_id.to_le_bytes(),
        ],
        &zk_relayer::ID,
    )
    .0
}

fn one_be() -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
}

fn u64_to_u256_be(x: u64) -> [u8; 32] {
    let mut res = [0; 32];
    res[32 - 8..].copy_from_slice(&x.to_be_bytes());
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relayer_config_pda() {
        assert_eq!(
            RELAYER_CONFIG,
            Pubkey::find_program_address(&[b"RELAYER_CONFIG"], &zk_relayer::ID).0
        );
    }
}
