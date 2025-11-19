use clap::Parser;
use solana_sdk::signer::Signer;
use solana_tools::solana_transactor::{RpcPool, SolanaTransactor};
use std::{env, path::PathBuf};
use tracing::{debug, error};

use crate::{config::RelayerConfig, server::Server};

mod config;
mod prover;
mod rocks;
mod server;
mod utils;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(long, short, help = "Common config path")]
    config: PathBuf,
}

#[actix_web::main]
async fn main() {
    dotenvy::dotenv().unwrap();
    tracing_subscriber::fmt::init();

    let cli = Cli::parse_from(env::args());
    let config = RelayerConfig::from_path(cli.config);
    debug!("Public key {}", config.solana.keypair.pubkey());

    let rpc_pool = RpcPool::new(&config.solana.read_rpcs, &config.solana.write_rpcs)
        .expect("RPC pool failed to initialize");

    let transactor = SolanaTransactor::start(rpc_pool)
        .await
        .expect("Failed to start solana transactor");
    let server = Server::new(config.solana.keypair, transactor, &config.rocksdb_path);

    let res = server
        .execute(
            &config.addrs,
            config.ssl,
            std::thread::available_parallelism()
                .unwrap()
                .get()
                .saturating_sub(1)
                .min(1),
        )
        .await;
    if let Err(err) = res {
        error!("Server finished with {err}");
    }
}
