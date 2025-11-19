pub use self::mem::MemStore;
#[cfg(feature = "rocksdb")]
pub use self::rocksdb::RocksStore;
use crate::Node;

mod mem;
#[cfg(feature = "rocksdb")]
mod rocksdb;

pub trait NodeStore {
    type Error: core::fmt::Debug;

    fn get(&self, key: [u8; 32]) -> Result<Option<Node>, Self::Error>;
    fn put(&mut self, key: [u8; 32], node: [u8; 65]) -> Result<(), Self::Error>;
    fn get_root(&self) -> Result<[u8; 32], Self::Error>;
    fn set_root(&mut self, root: [u8; 32]) -> Result<(), Self::Error>;
}
