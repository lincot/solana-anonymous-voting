use core::convert::Infallible;
use std::collections::HashMap;

use super::NodeStore;
use crate::Node;

#[derive(Clone, Default)]
pub struct MemStore {
    map: HashMap<[u8; 32], [u8; 65]>,
    root: [u8; 32],
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NodeStore for MemStore {
    type Error = Infallible;

    fn get(&self, k: [u8; 32]) -> Result<Option<Node>, Self::Error> {
        Ok(self.map.get(&k).and_then(|v| Node::decode(v)))
    }

    fn put(&mut self, k: [u8; 32], n: [u8; 65]) -> Result<(), Self::Error> {
        self.map.insert(k, n);
        Ok(())
    }

    fn get_root(&self) -> Result<[u8; 32], Self::Error> {
        Ok(self.root)
    }

    fn set_root(&mut self, root: [u8; 32]) -> Result<(), Self::Error> {
        self.root = root;
        Ok(())
    }
}
