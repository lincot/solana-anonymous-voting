use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use smt_circom::{store::RocksStore, SparseMerkleTree};
use solana_sdk::pubkey::Pubkey;
use std::cell::RefCell;

use crate::prover::STATE_DEPTH;

pub struct StateStore {
    pub db: DB,
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub struct StateKey {
    pub program: Pubkey,
    pub state_id: u64,
}

impl StateKey {
    fn serialize(&self) -> [u8; 40] {
        let mut res = [0u8; 40];
        res[..32].copy_from_slice(self.program.as_ref());
        res[32..].copy_from_slice(&self.state_id.to_be_bytes());
        res
    }
}

pub struct LoadedState<'a> {
    pub quota_tree: SparseMerkleTree<STATE_DEPTH, RocksStore<'a, [u8; 40]>>,
    pub uniq_tree: SparseMerkleTree<STATE_DEPTH, RocksStore<'a, [u8; 40]>>,
}

impl StateStore {
    pub fn open(path: &str) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = [
            ColumnFamilyDescriptor::new("nodes:quota", Options::default()),
            ColumnFamilyDescriptor::new("nodes:uniq", Options::default()),
        ];
        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db })
    }

    pub fn load_state<'a>(
        &'a self,
        key: &StateKey,
        batch: &'a RefCell<WriteBatch>,
    ) -> Result<LoadedState<'a>, rocksdb::Error> {
        let cf_quota = self.db.cf_handle("nodes:quota").unwrap();
        let cf_uniq = self.db.cf_handle("nodes:uniq").unwrap();

        let key = key.serialize();
        let q_store = RocksStore::new(&self.db, cf_quota, batch, key)?;
        let quota_tree = SparseMerkleTree::<STATE_DEPTH, _>::new(q_store)?;

        let u_store = RocksStore::new(&self.db, cf_uniq, batch, key)?;
        let uniq_tree = SparseMerkleTree::<STATE_DEPTH, _>::new(u_store)?;

        Ok(LoadedState {
            quota_tree,
            uniq_tree,
        })
    }
}
