use clap::Parser;
use core::time::Duration;
use db::DbManager;
use description_manager::DescriptionManager;
use indexer_event_processor::IndexerEvent;
use solana_tools::solana_transactor::RpcPool;
use sqlx::postgres::PgPoolOptions;
use std::{env, path::PathBuf};
use tokio::sync::mpsc::unbounded_channel;
use tracing::error;

use crate::{
    census_manager::CensusManager, config::IndexerConfig, indexer_event_processor::EventProcessor,
    server::Server, solana_reader::SolanaReader, utils::Broadcaster,
};

mod census_manager;
mod config;
mod db;
mod description_manager;
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
    let (census_sender, census_receiver) = unbounded_channel();
    let (description_sender, description_receiver) = unbounded_channel();

    let url = std::env::var("DATABASE_URL").expect("expected DATABASE_URL to be set");
    let pg_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("Expected postgres to connect");
    CensusManager::enqueue_unfinished(&pg_pool, &census_sender)
        .await
        .unwrap();
    DescriptionManager::enqueue_unfinished(&pg_pool, &description_sender)
        .await
        .unwrap();
    let mut db_manager = DbManager::new(
        pg_pool.clone(),
        event_receiver,
        census_sender,
        description_sender,
    )
    .await
    .unwrap();

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
    let reqwest_client = reqwest::Client::new();
    let census_manager =
        CensusManager::new(pg_pool.clone(), reqwest_client.clone(), census_receiver, 3);
    let description_manager =
        DescriptionManager::new(pg_pool.clone(), reqwest_client, description_receiver, 3);

    let server = Server::new(pg_pool);

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
    tokio::spawn(async move {
        census_manager.execute().await;
        error!("Census manager finished");
    });
    tokio::spawn(async move {
        description_manager.execute().await;
        error!("Description manager finished");
    });
    let res = server
        .execute(
            config.ssl,
            std::thread::available_parallelism()
                .unwrap()
                .get()
                .saturating_sub(5)
                .min(1),
        )
        .await;
    if let Err(err) = res {
        error!("Server finished with {err}");
    }
}
