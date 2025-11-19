use ark_bn254::Fr;
use core::array;
use light_poseidon::{Poseidon, PoseidonBytesHasher};

use crate::store::NodeStore;

pub mod store;

#[inline]
fn poseidon_hash(inputs: &[&[u8]]) -> [u8; 32] {
    let mut p = Poseidon::<Fr>::new_circom(inputs.len()).expect("poseidon init");
    p.hash_bytes_be(inputs).expect("poseidon hash")
}

#[inline]
fn leaf_key(k: [u8; 32], v: [u8; 32]) -> [u8; 32] {
    let mut one = [0u8; 32];
    one[31] = 1;
    poseidon_hash(&[&k, &v, &one])
}

#[inline]
fn mid_key(l: [u8; 32], r: [u8; 32]) -> [u8; 32] {
    poseidon_hash(&[&l, &r])
}

#[derive(Clone, Copy, Debug)]
pub enum Node {
    Middle { l: [u8; 32], r: [u8; 32] },
    Leaf { k: [u8; 32], v: [u8; 32] },
}

impl Node {
    pub fn encode(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        match self {
            Node::Middle { l: left, r: right } => {
                out[0] = 0;
                out[1..33].copy_from_slice(left);
                out[33..65].copy_from_slice(right);
            }
            Node::Leaf { k: index, v: value } => {
                out[0] = 1;
                out[1..33].copy_from_slice(index);
                out[33..65].copy_from_slice(value);
            }
        }
        out
    }

    pub fn decode(bs: &[u8]) -> Option<Self> {
        if bs.len() != 65 {
            return None;
        }
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a.copy_from_slice(&bs[1..33]);
        b.copy_from_slice(&bs[33..65]);
        Some(match bs[0] {
            0 => Node::Middle { l: a, r: b },
            1 => Node::Leaf { k: a, v: b },
            _ => return None,
        })
    }

    fn key(&self) -> [u8; 32] {
        match *self {
            Node::Leaf { k, v } => leaf_key(k, v),
            Node::Middle { l, r } => mid_key(l, r),
        }
    }
}

#[inline]
fn get_path<const D: usize>(key: &[u8; 32]) -> [bool; D] {
    array::from_fn(|i| {
        let byte = i / 8;
        let bit = i % 8;
        (key[31 - byte] & (1 << bit)) != 0
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircomProof<const D: usize> {
    pub siblings: [[u8; 32]; D],
    pub is_old0: bool,
    pub old_key: [u8; 32],
    pub old_value: [u8; 32],
    pub membership: bool,
}

pub struct SparseMerkleTree<const D: usize, S: NodeStore> {
    store: S,
}

#[derive(Debug, thiserror::Error)]
pub enum Error<E> {
    #[error("The key is already present")]
    AlreadyPresent,
    #[error("Key wasn't found")]
    KeyNotFound,
    #[error("Store error: {0}")]
    Store(E),
}

pub struct LookupResult<const D: usize> {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub siblings: [[u8; 32]; D],
    pub membership: bool,
}

impl<const D: usize, S: NodeStore> SparseMerkleTree<D, S> {
    pub fn new(store: S) -> Result<Self, S::Error> {
        Ok(Self { store })
    }

    pub fn root(&self) -> Result<[u8; 32], S::Error> {
        self.store.get_root()
    }

    fn put(&mut self, node: &Node) -> Result<[u8; 32], S::Error> {
        let k = node.key();
        self.store.put(k, node.encode())?;
        Ok(k)
    }

    fn set_root(&mut self, root: [u8; 32]) -> Result<(), S::Error> {
        self.store.set_root(root)
    }

    pub fn lookup(&self, key: [u8; 32]) -> Result<LookupResult<D>, S::Error> {
        let k = key;
        let mut siblings = [[0; 32]; D];
        let mut sibling_i = 0;
        let mut cur = self.root()?;

        for (i, go_right) in get_path::<D>(&k).into_iter().enumerate() {
            match self.store.get(cur).expect("node exists") {
                None => {
                    return Ok(LookupResult {
                        key: [0; 32],
                        value: [0; 32],
                        siblings,
                        membership: false,
                    });
                }
                Some(Node::Leaf {
                    k: leaf_k,
                    v: leaf_v,
                }) => {
                    let exists = leaf_k == k;
                    return Ok(LookupResult {
                        key: leaf_k,
                        value: leaf_v,
                        siblings,
                        membership: exists,
                    });
                }
                Some(Node::Middle { l, r }) => {
                    if go_right {
                        siblings[sibling_i] = l;
                        cur = r;
                    } else {
                        siblings[sibling_i] = r;
                        cur = l;
                    }
                    sibling_i += 1;
                }
            }
            if i == D - 1 {
                return Ok(LookupResult {
                    key: [0; 32],
                    value: [0; 32],
                    siblings,
                    membership: false,
                });
            }
        }
        unreachable!();
    }

    fn add_leaf(
        &mut self,
        new_leaf: Node,
        cur_key: [u8; 32],
        lvl: usize,
        path_new: &[bool],
    ) -> Result<[u8; 32], Error<S::Error>> {
        let n = self.store.get(cur_key).expect("node exists");
        match n {
            None => Ok(self.put(&new_leaf).map_err(Error::Store)?),
            Some(Node::Leaf { k: old_k, v: old_v }) => {
                if let Node::Leaf { k: new_k, .. } = new_leaf {
                    if new_k == old_k {
                        return Err(Error::AlreadyPresent);
                    }
                } else {
                    unreachable!();
                }
                let path_old = get_path::<D>(&old_k);
                self.push_leaf(
                    new_leaf,
                    Node::Leaf { k: old_k, v: old_v },
                    lvl,
                    path_new,
                    &path_old,
                )
                .map_err(Error::Store)
            }
            Some(Node::Middle { l, r }) => {
                if path_new[lvl] {
                    let next = self.add_leaf(new_leaf, r, lvl + 1, path_new)?;
                    Ok(self
                        .put(&Node::Middle { l, r: next })
                        .map_err(Error::Store)?)
                } else {
                    let next = self.add_leaf(new_leaf, l, lvl + 1, path_new)?;
                    Ok(self
                        .put(&Node::Middle { l: next, r })
                        .map_err(Error::Store)?)
                }
            }
        }
    }

    fn push_leaf(
        &mut self,
        new_leaf: Node,
        old_leaf: Node,
        lvl: usize,
        path_new: &[bool],
        path_old: &[bool],
    ) -> Result<[u8; 32], S::Error> {
        if path_new[lvl] == path_old[lvl] {
            let next_key = self.push_leaf(new_leaf, old_leaf, lvl + 1, path_new, path_old)?;
            let mid = if path_new[lvl] {
                Node::Middle {
                    l: [0; 32],
                    r: next_key,
                }
            } else {
                Node::Middle {
                    l: next_key,
                    r: [0; 32],
                }
            };
            return self.put(&mid);
        }

        let Node::Leaf { k: old_k, v: old_v } = old_leaf else {
            unreachable!()
        };

        let new_leaf_key = self.put(&new_leaf)?;
        let old_leaf_key = leaf_key(old_k, old_v);

        let mid = if path_new[lvl] {
            Node::Middle {
                l: old_leaf_key,
                r: new_leaf_key,
            }
        } else {
            Node::Middle {
                l: new_leaf_key,
                r: old_leaf_key,
            }
        };
        self.put(&mid)
    }

    pub fn add(&mut self, key: [u8; 32], val: [u8; 32]) -> Result<(), Error<S::Error>> {
        let kh = key;
        let vh = val;
        let new_leaf = Node::Leaf { k: kh, v: vh };

        let path_new = get_path::<D>(&kh);
        let new_root = self.add_leaf(new_leaf, self.root().map_err(Error::Store)?, 0, &path_new)?;
        self.set_root(new_root).map_err(Error::Store)?;
        Ok(())
    }

    pub fn update(&mut self, key: [u8; 32], val: [u8; 32]) -> Result<[u8; 32], Error<S::Error>> {
        let kh = key;
        let vh = val;
        let mut cur = self.root().map_err(Error::Store)?;
        let mut siblings = heapless::Vec::<[u8; 32], D>::new();
        let path = get_path::<D>(&kh);
        let old_v;

        for go_right in path.iter().copied() {
            match self.store.get(cur).expect("node exists") {
                None => return Err(Error::KeyNotFound),
                Some(Node::Leaf { k, v }) => {
                    if k != kh {
                        return Err(Error::KeyNotFound);
                    }
                    old_v = Some(v);

                    let mut node = Node::Leaf { k: kh, v: vh };
                    let mut node_h = self.put(&node).map_err(Error::Store)?;

                    for (lvl, sib) in siblings.into_iter().enumerate().rev() {
                        let bit = path[lvl];
                        node = if bit {
                            Node::Middle { l: sib, r: node_h }
                        } else {
                            Node::Middle { l: node_h, r: sib }
                        };
                        node_h = self.put(&node).map_err(Error::Store)?;
                    }
                    self.set_root(node_h).map_err(Error::Store)?;
                    return Ok(old_v.unwrap());
                }
                Some(Node::Middle { l, r }) => {
                    if go_right {
                        siblings.push(l).unwrap();
                        cur = r;
                    } else {
                        siblings.push(r).unwrap();
                        cur = l;
                    }
                }
            }
        }
        Err(Error::KeyNotFound)
    }

    pub fn get_leaf(&self, key: [u8; 32]) -> Result<Option<[u8; 32]>, S::Error> {
        let res = self.lookup(key)?;
        if res.membership {
            Ok(Some(res.value))
        } else {
            Ok(None)
        }
    }

    pub fn get_proof(&self, key: [u8; 32]) -> Result<CircomProof<D>, S::Error> {
        let LookupResult {
            key: found_k,
            value: found_v,
            siblings,
            membership,
        } = self.lookup(key)?;

        let is_old0 = found_v == [0u8; 32];

        Ok(CircomProof {
            siblings,
            is_old0,
            old_key: if is_old0 { [0u8; 32] } else { found_k },
            old_value: if is_old0 { [0u8; 32] } else { found_v },
            membership,
        })
    }

    pub fn add_or_update(&mut self, key: [u8; 32], val: [u8; 32]) -> Result<(), Error<S::Error>> {
        match self.add(key, val) {
            Err(Error::AlreadyPresent) => self.update(key, val).map(|_| ()),
            x => x,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

    const DEPTH: usize = 64;

    #[test]
    fn test_smt() {
        let mut t = SparseMerkleTree::<DEPTH, _>::new(MemStore::new()).unwrap();
        assert_eq!(t.root().unwrap(), [0; 32]);

        let k1 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 43, 127, 78,
            51, 93, 159, 92, 71,
        ];
        let v1 = [
            16, 232, 248, 117, 61, 208, 169, 22, 163, 170, 44, 57, 210, 21, 42, 219, 91, 147, 79,
            94, 181, 31, 210, 205, 159, 82, 222, 81, 110, 255, 37, 198,
        ];

        let p1 = t.get_proof(k1).unwrap();
        t.add_or_update(k1, v1).unwrap();
        assert!(!p1.membership);
        assert!(p1.is_old0);
        assert_eq!(p1.old_key, [0; 32]);
        assert_eq!(p1.old_value, [0; 32]);
        assert_eq!(p1.siblings.len(), DEPTH);
        assert!(p1.siblings.iter().all(|&b| b == [0; 32]));

        let root1 = t.root().unwrap();
        let root1_js = [
            37, 18, 9, 85, 224, 252, 133, 154, 45, 120, 67, 166, 143, 180, 254, 196, 219, 139, 9,
            229, 191, 47, 36, 89, 138, 111, 104, 170, 242, 127, 191, 38,
        ];
        assert_eq!(root1, root1_js);

        let k2 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 211, 160, 91,
            130, 253, 193, 133, 52,
        ];
        let v2 = [
            2, 135, 56, 32, 251, 187, 59, 31, 232, 236, 204, 116, 101, 171, 47, 15, 159, 138, 139,
            231, 61, 78, 108, 10, 70, 133, 200, 198, 187, 100, 85, 178,
        ];
        let p2 = t.get_proof(k2).unwrap();
        t.add_or_update(k2, v2).unwrap();
        assert!(!p2.membership);
        assert!(!p2.is_old0);
        assert_eq!(p2.old_key, k1);
        assert_eq!(p2.old_value, v1);
        assert_eq!(p2.siblings.len(), DEPTH);
        assert!(p2.siblings.iter().all(|&b| b == [0; 32]));

        let k3 = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 74, 181, 123,
            89, 155, 208, 255, 114,
        ];
        let v3 = [
            16, 46, 63, 228, 134, 35, 92, 132, 114, 153, 57, 23, 154, 224, 217, 112, 131, 208, 134,
            232, 218, 170, 173, 245, 178, 128, 151, 223, 2, 64, 114, 19,
        ];
        let p3 = t.get_proof(k3).unwrap();
        t.add_or_update(k3, v3).unwrap();
        assert!(!p3.membership);
        assert!(!p3.is_old0);
        assert_eq!(p3.old_key, k2);
        assert_eq!(p3.old_value, v2);
        assert_eq!(p3.siblings.len(), DEPTH);
        assert_eq!(p3.siblings[0], root1_js);
        assert!(p3.siblings[1..].iter().all(|&b| b == [0; 32]));

        let v4 = [
            34, 105, 95, 86, 39, 160, 123, 45, 219, 68, 91, 94, 55, 161, 223, 203, 206, 164, 203,
            253, 33, 59, 150, 111, 108, 74, 20, 17, 62, 214, 104, 58,
        ];
        let p4 = t.get_proof(k3).unwrap();
        t.add_or_update(k3, v4).unwrap();
        assert!(p4.membership);
        assert!(!p4.is_old0);
        assert_eq!(p4.old_key, k3);
        assert_eq!(p4.old_value, v3);
        assert_eq!(p4.siblings.len(), DEPTH);
        assert_eq!(p4.siblings[0], root1_js);
        assert_eq!(
            p4.siblings[1],
            [
                39, 2, 121, 120, 126, 69, 90, 96, 220, 95, 224, 252, 255, 197, 106, 214, 4, 22,
                155, 164, 67, 176, 180, 82, 34, 37, 226, 17, 201, 250, 187, 58
            ],
        );
        assert!(p4.siblings[2..].iter().all(|&b| b == [0; 32]));
    }
}
