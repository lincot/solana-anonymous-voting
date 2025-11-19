use config::{Config, File};
use serde::Deserialize;
use solana_sdk::signature::Keypair;
use solana_tools::solana_transactor::RpcEntry;
use solana_tools::utils::deserialize_keypair;
use std::path::PathBuf;
use tracing::debug;

#[derive(Debug, Deserialize)]
pub(crate) struct RelayerConfig {
    pub addrs: String,
    pub solana: SolanaConfig,
    pub ssl: SslConfig,
    pub rocksdb_path: String,
}

impl RelayerConfig {
    pub(super) fn from_path(config_path: PathBuf) -> Self {
        debug!("Reading config from path {:?}", config_path);
        let config = Config::builder()
            .add_source(File::from(config_path))
            .add_source(config::Environment::with_prefix("RELAYER").separator("_"))
            .build()
            .expect("Failed to build envs");

        config
            .try_deserialize()
            .expect("Failed to deserialize config")
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct SolanaConfig {
    #[serde(deserialize_with = "deserialize_keypair")]
    pub keypair: Keypair,
    pub read_rpcs: Vec<RpcEntry>,
    pub write_rpcs: Vec<RpcEntry>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SslConfig {
    pub key: PathBuf,
    pub cert: PathBuf,
}
