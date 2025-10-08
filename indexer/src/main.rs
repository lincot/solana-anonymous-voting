use clap::Parser;
use core::time::Duration;
use db::DbManager;
use indexer_event_processor::IndexerEvent;
use solana_tools::solana_transactor::RpcPool;
use sqlx::postgres::PgPoolOptions;
use std::{env, path::PathBuf};
use tokio::sync::mpsc::unbounded_channel;
use tracing::error;

use crate::{
    config::IndexerConfig, indexer_event_processor::EventProcessor, server::Server,
    solana_reader::SolanaReader, utils::Broadcaster,
};

mod config;
mod db;
mod event_processor;
mod indexer_event_processor;
mod parse_logs;
mod server;
mod solana_reader;
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
    let config = IndexerConfig::from_path(cli.config);

    let rpc_pool = RpcPool::new(&config.solana.read_rpcs, &config.solana.write_rpcs)
        .expect("RPC pool failed to initialize");

    let (event_sender, event_receiver) = unbounded_channel();

    let url = std::env::var("DATABASE_URL").expect("expected DATABASE_URL to be set");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    // sqlx::migrate!().run(&pool).await?;
    let mut db_manager = DbManager::new(pool.clone(), event_receiver).await.unwrap();

    let tx_read_from = db_manager
        .get_cursor()
        .await
        .unwrap()
        .map_or(Default::default(), |s| s.parse().unwrap());

    let mut confirmed_tx_sender = Broadcaster::new();
    let finalized_tx_sender = Broadcaster::new();

    let logs_receiver = confirmed_tx_sender.subscribe();

    let solana_reader = SolanaReader::new(
        rpc_pool,
        anon_vote::ID,
        tx_read_from,
        config.solana.reader_concurrency,
        Duration::from_secs(3),
        confirmed_tx_sender,
        finalized_tx_sender,
    );

    let mut event_processor = EventProcessor::<IndexerEvent>::new(logs_receiver, event_sender);

    let server = Server::new(pool);

    // let mut tasks = JoinSet::new();
    tokio::spawn(async move {
        let res = solana_reader.listen_to_solana().await;
        error!("Solana reader finished with {res:?}");
    });
    tokio::spawn(async move {
        let res = db_manager.execute().await;
        error!("Database manager finished with {res:?}");
    });
    tokio::spawn(async move {
        event_processor.execute().await;
        error!("Event processor finished");
    });
    // tokio::spawn(async move {
    let res = server
        .execute(
            config.ssl,
            std::thread::available_parallelism()
                .unwrap()
                .get()
                .saturating_sub(4)
                .min(1),
        )
        .await;
    error!("Server finished with {res:?}");
    // });
    // tasks.join_all().await;
}
