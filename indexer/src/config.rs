use config::{Config, File};
use serde::Deserialize;
use solana_tools::solana_transactor::RpcEntry;
use std::path::PathBuf;
use tracing::debug;

#[derive(Debug, Deserialize)]
pub(crate) struct IndexerConfig {
    pub solana: SolanaReaderConfig,
    pub ssl: SslConfig,
}

impl IndexerConfig {
    pub(super) fn from_path(config_path: PathBuf) -> Self {
        debug!("Reading config from path {:?}", config_path);
        let config = Config::builder()
            .add_source(File::from(config_path))
            .add_source(config::Environment::with_prefix("AV").separator("_"))
            .build()
            .expect("Failed to build envs");

        config
            .try_deserialize()
            .expect("Failed to deserialize config")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SolanaReaderConfig {
    pub read_rpcs: Vec<RpcEntry>,
    pub write_rpcs: Vec<RpcEntry>,
    pub reader_concurrency: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SslConfig {
    pub key: PathBuf,
    pub cert: PathBuf,
}
