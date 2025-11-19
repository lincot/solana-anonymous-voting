use rocksdb::{ColumnFamily, DB, WriteBatch};
use std::cell::RefCell;

use super::NodeStore;
use crate::Node;

pub struct RocksStore<'a, P: AsRef<[u8]>> {
    db: &'a DB,
    cf: &'a ColumnFamily,
    batch: &'a RefCell<WriteBatch>,
    key_prefix: P,
    cached_root: [u8; 32],
}

impl<'a, P: AsRef<[u8]>> RocksStore<'a, P> {
    pub fn new(
        db: &'a DB,
        cf: &'a ColumnFamily,
        batch: &'a RefCell<WriteBatch>,
        key_prefix: P,
    ) -> Result<Self, rocksdb::Error> {
        Ok(Self {
            db,
            cf,
            batch,
            cached_root: get_root(db, cf, key_prefix.as_ref())?,
            key_prefix,
        })
    }
}

impl<P: AsRef<[u8]>> RocksStore<'_, P> {
    fn prefix_key(&self, key: [u8; 32]) -> Vec<u8> {
        prefix_key(self.key_prefix.as_ref(), key)
    }
}

impl<P: AsRef<[u8]>> NodeStore for RocksStore<'_, P> {
    type Error = rocksdb::Error;

    fn get(&self, key: [u8; 32]) -> Result<Option<Node>, Self::Error> {
        Ok(self
            .db
            .get_cf(self.cf, self.prefix_key(key))?
            .and_then(|v| Node::decode(&v)))
    }

    fn put(&mut self, key: [u8; 32], node: [u8; 65]) -> Result<(), Self::Error> {
        self.batch
            .borrow_mut()
            .put_cf(self.cf, self.prefix_key(key), node);
        Ok(())
    }

    fn get_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(self.cached_root)
    }

    fn set_root(&mut self, root: [u8; 32]) -> Result<(), Self::Error> {
        self.batch
            .borrow_mut()
            .put_cf(self.cf, self.prefix_key([0; 32]), root);
        self.cached_root = root;
        Ok(())
    }
}

fn get_root(db: &DB, cf: &ColumnFamily, key_prefix: &[u8]) -> Result<[u8; 32], rocksdb::Error> {
    Ok(db
        .get_cf(cf, prefix_key(key_prefix, [0; 32]))?
        .map_or([0; 32], |x| x.try_into().unwrap()))
}

fn prefix_key(key_prefix: &[u8], key: [u8; 32]) -> Vec<u8> {
    let mut res = Vec::with_capacity(key_prefix.len() + 32);
    res.extend(key_prefix);
    res.extend(&key);
    res
}
