//! Domain-separated SHA-384 commitments (whitepaper §3.1, Lemma 9″).
//!
//! Every hash input begins with a one-byte domain tag, so an input of one kind can never be read as another.
//! Merkle roots follow RFC 6962: leaves are `H(leaf_tag ‖ data)`, nodes `H(node_tag ‖ left ‖ right)`, and a
//! list of m items splits at the largest power of two strictly below m (no padding).
#![forbid(unsafe_code)]

use rayon::prelude::*;
use sha2::{Digest, Sha384};

pub type Hash = [u8; 48];

/// Domain registry (whitepaper Lemma 9″ table).
pub mod domain {
    pub const BATCH_LEAF: u8 = 0x00;
    pub const BATCH_NODE: u8 = 0x01;
    pub const HEADER: u8 = 0x02;
    pub const SKIP: u8 = 0x03;
    pub const HISTORY_LEAF: u8 = 0x04;
    pub const HISTORY_NODE: u8 = 0x05;
    pub const STATE_LEAF: u8 = 0x06;
    pub const STATE_NODE: u8 = 0x07;
    pub const TIMEOUT: u8 = 0x08;
}

/// A leaf/node tag pair selecting one Merkle domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tree {
    pub leaf: u8,
    pub node: u8,
}
pub const BATCH: Tree = Tree {
    leaf: domain::BATCH_LEAF,
    node: domain::BATCH_NODE,
};
pub const HISTORY: Tree = Tree {
    leaf: domain::HISTORY_LEAF,
    node: domain::HISTORY_NODE,
};
pub const STATE: Tree = Tree {
    leaf: domain::STATE_LEAF,
    node: domain::STATE_NODE,
};

/// `H(tag ‖ parts…)`.
#[inline]
pub fn hash_tagged(tag: u8, parts: &[&[u8]]) -> Hash {
    let mut h = Sha384::new();
    h.update([tag]);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

#[inline]
pub fn leaf_hash(t: Tree, data: &[u8]) -> Hash {
    hash_tagged(t.leaf, &[data])
}

#[inline]
pub fn node_hash(t: Tree, left: &Hash, right: &Hash) -> Hash {
    hash_tagged(t.node, &[left, right])
}

/// Root of the empty list: `H(node_tag)`.
pub fn empty_root(t: Tree) -> Hash {
    hash_tagged(t.node, &[])
}

#[inline]
fn split_point(m: usize) -> usize {
    debug_assert!(m >= 2);
    1usize << (usize::BITS - 1 - (m - 1).leading_zeros())
}

/// Reference RFC 6962 root over leaf *digests* (already leaf-hashed).
pub fn root_from_leaf_hashes(t: Tree, leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(t),
        1 => leaves[0],
        m => {
            let k = split_point(m);
            node_hash(
                t,
                &root_from_leaf_hashes(t, &leaves[..k]),
                &root_from_leaf_hashes(t, &leaves[k..]),
            )
        }
    }
}

/// Reference RFC 6962 root over raw items.
pub fn merkle_root<D: AsRef<[u8]>>(t: Tree, items: &[D]) -> Hash {
    let leaves: Vec<Hash> = items.iter().map(|d| leaf_hash(t, d.as_ref())).collect();
    root_from_leaf_hashes(t, &leaves)
}

/// Parallel RFC 6962 root: leaf hashing and large subtrees run on all cores (rayon). Same result as `merkle_root`.
pub fn par_merkle_root<D: AsRef<[u8]> + Sync>(t: Tree, items: &[D]) -> Hash {
    let leaves: Vec<Hash> = items
        .par_iter()
        .with_min_len(256)
        .map(|d| leaf_hash(t, d.as_ref()))
        .collect();
    par_root_from_leaf_hashes(t, &leaves)
}

pub fn par_root_from_leaf_hashes(t: Tree, leaves: &[Hash]) -> Hash {
    const SERIAL_BELOW: usize = 1024;
    match leaves.len() {
        0 => empty_root(t),
        1 => leaves[0],
        m if m < SERIAL_BELOW => root_from_leaf_hashes(t, leaves),
        m => {
            let k = split_point(m);
            let (l, r) = rayon::join(
                || par_root_from_leaf_hashes(t, &leaves[..k]),
                || par_root_from_leaf_hashes(t, &leaves[k..]),
            );
            node_hash(t, &l, &r)
        }
    }
}

/// Streaming (frontier) Merkle root — Proposition R. Items are absorbed as they arrive; after the last one, at most
/// ⌊log₂ m⌋ + 1 hashes remain. Total work is exactly 2m − 1 hashes.
#[derive(Clone, Debug)]
pub struct Frontier {
    t: Tree,
    stack: Vec<(u32, Hash)>,
    count: u64,
    hashes: u64,
}

impl Frontier {
    pub fn new(t: Tree) -> Self {
        Frontier {
            t,
            stack: Vec::with_capacity(64),
            count: 0,
            hashes: 0,
        }
    }
    pub fn push(&mut self, item: &[u8]) {
        let mut x = leaf_hash(self.t, item);
        self.hashes += 1;
        let mut height = 0u32;
        while let Some(&(h, y)) = self.stack.last() {
            if h != height {
                break;
            }
            self.stack.pop();
            x = node_hash(self.t, &y, &x);
            self.hashes += 1;
            height += 1;
        }
        self.stack.push((height, x));
        self.count += 1;
    }
    /// Root of everything absorbed so far (does not consume the frontier).
    pub fn root(&self) -> Hash {
        let mut it = self.stack.iter().rev();
        match it.next() {
            None => empty_root(self.t),
            Some(&(_, top)) => it.fold(top, |acc, &(_, y)| node_hash(self.t, &y, &acc)),
        }
    }
    pub fn len(&self) -> u64 {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    /// Hashes spent so far in `push` (the fold in `root` adds popcount(len) − 1 more).
    pub fn hashes(&self) -> u64 {
        self.hashes
    }
}

/// A materialised RFC 6962 tree: every level is kept, so an audit path costs O(log n) instead of the O(n) of the
/// recursive `audit_path` — needed when every order in a batch gets its own inclusion proof. Pairing bottom-up and
/// promoting an odd last node unchanged yields exactly the RFC 6962 (split at the largest power of two) shape.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    t: Tree,
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build from leaf digests; levels with ≥ 1024 nodes are hashed in parallel.
    pub fn from_leaf_hashes(t: Tree, leaves: Vec<Hash>) -> MerkleTree {
        const SERIAL_BELOW: usize = 1024;
        let mut levels = vec![leaves];
        while levels[levels.len() - 1].len() > 1 {
            let prev = &levels[levels.len() - 1];
            let pair = |c: &[Hash]| {
                if c.len() == 2 {
                    node_hash(t, &c[0], &c[1])
                } else {
                    c[0]
                }
            };
            let next: Vec<Hash> = if prev.len() < SERIAL_BELOW {
                prev.chunks(2).map(pair).collect()
            } else {
                prev.par_chunks(2).with_min_len(128).map(pair).collect()
            };
            levels.push(next);
        }
        MerkleTree { t, levels }
    }

    /// Leaf-hash `items` in parallel and build the tree.
    pub fn from_items<D: AsRef<[u8]> + Sync>(t: Tree, items: &[D]) -> MerkleTree {
        let leaves = items
            .par_iter()
            .with_min_len(256)
            .map(|d| leaf_hash(t, d.as_ref()))
            .collect();
        MerkleTree::from_leaf_hashes(t, leaves)
    }

    pub fn root(&self) -> Hash {
        match self.levels[self.levels.len() - 1].first() {
            Some(r) => *r,
            None => empty_root(self.t),
        }
    }
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }
    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }
    pub fn leaf(&self, index: usize) -> Hash {
        self.levels[0][index]
    }

    /// Audit path for leaf `index`, identical to `audit_path` on the same leaves.
    pub fn path(&self, index: usize) -> Vec<Hash> {
        assert!(index < self.len());
        let mut out = Vec::with_capacity(self.levels.len());
        let mut i = index;
        for lvl in &self.levels[..self.levels.len() - 1] {
            if let Some(sib) = lvl.get(i ^ 1) {
                out.push(*sib);
            }
            i >>= 1;
        }
        out
    }
}

/// RFC 6962 audit path for leaf `index`: sibling digests from the leaf upward.
pub fn audit_path(t: Tree, leaves: &[Hash], index: usize) -> Vec<Hash> {
    fn rec(t: Tree, leaves: &[Hash], i: usize, out: &mut Vec<Hash>) {
        if leaves.len() <= 1 {
            return;
        }
        let k = split_point(leaves.len());
        if i < k {
            rec(t, &leaves[..k], i, out);
            out.push(root_from_leaf_hashes(t, &leaves[k..]));
        } else {
            rec(t, &leaves[k..], i - k, out);
            out.push(root_from_leaf_hashes(t, &leaves[..k]));
        }
    }
    assert!(index < leaves.len());
    let mut out = Vec::new();
    rec(t, leaves, index, &mut out);
    out
}

/// Verify an RFC 6962 audit path (RFC 9162 §2.1.3.2 algorithm).
pub fn verify_audit_path(
    t: Tree,
    leaf: &Hash,
    index: u64,
    size: u64,
    path: &[Hash],
    root: &Hash,
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(t, p, &r);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(t, &r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && &r == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn items(m: usize, seed: u8) -> Vec<Vec<u8>> {
        (0..m)
            .map(|i| vec![seed, (i & 0xff) as u8, (i >> 8) as u8, 7])
            .collect()
    }

    #[test]
    fn streaming_equals_reference_equals_parallel() {
        for m in (0..=1100).chain([2047, 2048, 2049, 4096, 5000]) {
            let xs = items(m, 3);
            let r = merkle_root(BATCH, &xs);
            let mut f = Frontier::new(BATCH);
            xs.iter().for_each(|x| f.push(x));
            assert_eq!(f.root(), r, "frontier m={m}");
            assert_eq!(par_merkle_root(BATCH, &xs), r, "parallel m={m}");
            if m > 0 {
                let fold = (m as u64).count_ones() as u64 - 1;
                assert_eq!(f.hashes() + fold, 2 * m as u64 - 1, "2m-1 hashes, m={m}");
            }
        }
    }

    #[test]
    fn domains_separate_trees() {
        let xs = items(9, 1);
        assert_ne!(merkle_root(BATCH, &xs), merkle_root(STATE, &xs));
        assert_ne!(merkle_root(BATCH, &xs), merkle_root(HISTORY, &xs));
        // a leaf and a node over the same bytes differ
        let a = leaf_hash(BATCH, &[0u8; 96]);
        let n = node_hash(BATCH, &[0u8; 48], &[0u8; 48]);
        assert_ne!(a, n);
    }

    #[test]
    fn depth_confusion_is_blocked() {
        // The pre-v3.3 attack: a 2-leaf batch whose leaves are the concatenated digests of a 4-leaf batch.
        let xs = items(4, 9);
        let lh: Vec<Hash> = xs.iter().map(|x| leaf_hash(BATCH, x)).collect();
        let forged = vec![[lh[0], lh[1]].concat(), [lh[2], lh[3]].concat()];
        assert_ne!(merkle_root(BATCH, &xs), merkle_root(BATCH, &forged));
    }

    #[test]
    fn materialised_tree_matches_reference_paths() {
        for m in (0..=300).chain([1023, 1024, 1025, 2049, 5000]) {
            let xs = items(m, 7);
            let leaves: Vec<Hash> = xs.iter().map(|x| leaf_hash(BATCH, x)).collect();
            let tree = MerkleTree::from_items(BATCH, &xs);
            assert_eq!(
                tree.root(),
                root_from_leaf_hashes(BATCH, &leaves),
                "root m={m}"
            );
            let step = if m > 400 { 97 } else { 1 };
            for i in (0..m).step_by(step) {
                let p = tree.path(i);
                assert_eq!(p, audit_path(BATCH, &leaves, i), "path m={m} i={i}");
                assert!(verify_audit_path(
                    BATCH,
                    &leaves[i],
                    i as u64,
                    m as u64,
                    &p,
                    &tree.root()
                ));
            }
        }
    }

    proptest! {
        #[test]
        fn audit_paths_verify_and_reject(m in 1usize..600, pick in 0usize..600, flip in 0usize..48) {
            let i = pick % m;
            let xs = items(m, 5);
            let leaves: Vec<Hash> = xs.iter().map(|x| leaf_hash(BATCH, x)).collect();
            let root = root_from_leaf_hashes(BATCH, &leaves);
            let path = audit_path(BATCH, &leaves, i);
            prop_assert!(path.len() <= 64 - (m as u64).leading_zeros() as usize);
            prop_assert!(verify_audit_path(BATCH, &leaves[i], i as u64, m as u64, &path, &root));
            let mut bad = leaves[i]; bad[flip] ^= 1;
            prop_assert!(!verify_audit_path(BATCH, &bad, i as u64, m as u64, &path, &root));
            if m > 1 {
                prop_assert!(!verify_audit_path(BATCH, &leaves[i], ((i + 1) % m) as u64, m as u64, &path, &root)
                    || leaves[i] == leaves[(i + 1) % m]);
            }
        }
    }
}

/// Big-endian reader for the fixed-layout encodings hashed under the domain registry; every read is bounds-checked
/// and `end` requires the input to be consumed exactly, so a parser built on it never panics and accepts one
/// encoding per value.
pub struct Reader<'a> {
    buf: &'a [u8],
}

/// The input ended early or had bytes left over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Truncated;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        if self.buf.len() < n {
            return Err(Truncated);
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    pub fn u8(&mut self) -> Result<u8, Truncated> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Truncated> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, Truncated> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, Truncated> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn u128(&mut self) -> Result<u128, Truncated> {
        Ok(u128::from_be_bytes(self.array()?))
    }
    /// A u32 element count, refused if the remaining input cannot hold `count × min_len` bytes (so a forged count
    /// cannot force a large allocation).
    pub fn count(&mut self, min_len: usize) -> Result<usize, Truncated> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_len) > self.buf.len() {
            return Err(Truncated);
        }
        Ok(n)
    }
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }
    pub fn end(&self) -> Result<(), Truncated> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Truncated)
        }
    }
}
