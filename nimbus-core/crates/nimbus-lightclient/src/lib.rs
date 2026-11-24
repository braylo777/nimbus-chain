//! Light-client verification of a finality proof (whitepaper Proposition V).
//!
//! A proof that operation `x` is final at (height, rank) carries: the operation bytes, its index and the batch size,
//! the RFC 6962 audit path, the 154-byte header, and a certificate of ⌈0.8n⌉ validator signatures on SHA-384(header).
//! Acceptance of a false proof requires a hash collision / second preimage (Proposition Q) or a signature forgery
//! (Theorem A*).
#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use nimbus_hash::{domain, hash_tagged, leaf_hash, verify_audit_path, Hash, BATCH};
use nimbus_sig::{CheckedKey, Item};

pub const HEADER_LEN: usize = 154;

/// Parsed header: 0x02 ‖ height(8) ‖ rank(1) ‖ batch_root(48) ‖ prev(48) ‖ history_acc(48).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub height: u64,
    pub rank: u8,
    pub batch_root: Hash,
    pub prev: Hash,
    pub history: Hash,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0] = domain::HEADER;
        b[1..9].copy_from_slice(&self.height.to_be_bytes());
        b[9] = self.rank;
        b[10..58].copy_from_slice(&self.batch_root);
        b[58..106].copy_from_slice(&self.prev);
        b[106..154].copy_from_slice(&self.history);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Header, Error> {
        if b.len() != HEADER_LEN {
            return Err(Error::HeaderLength);
        }
        if b[0] != domain::HEADER {
            return Err(Error::HeaderDomain);
        }
        let h = |r: std::ops::Range<usize>| -> Hash { b[r].try_into().expect("48 bytes") };
        Ok(Header {
            height: u64::from_be_bytes(b[1..9].try_into().expect("8")),
            rank: b[9],
            batch_root: h(10..58),
            prev: h(58..106),
            history: h(106..154),
        })
    }
}

/// SHA-384 of the full header bytes (the tag byte is inside the header, domain 0x02).
pub fn header_digest(header_bytes: &[u8]) -> Hash {
    hash_tagged(header_bytes[0], &[&header_bytes[1..]])
}

#[derive(Clone, Debug)]
pub struct Certificate {
    /// (validator index, signature over header_digest)
    pub sigs: Vec<(u16, [u8; 64])>,
}

#[derive(Clone, Debug)]
pub struct FinalityProof {
    pub op: Vec<u8>,
    pub index: u64,
    pub batch_size: u64,
    pub path: Vec<Hash>,
    pub header: Vec<u8>,
    pub cert: Certificate,
}

/// Upper bounds a decoder enforces before allocating (a light client must not be made to allocate by a peer).
pub const MAX_OP_LEN: usize = 1 << 16;
pub const MAX_PATH_LEN: usize = 64;
pub const MAX_SIGS: usize = 1 << 12;

impl FinalityProof {
    /// Wire format (big-endian): op_len (4) ‖ op ‖ index (8) ‖ batch_size (8) ‖ path_len (1) ‖ path (48 each) ‖
    /// header (154) ‖ sig_count (2) ‖ (validator (2) ‖ signature (64))*.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            4 + self.op.len()
                + 17
                + 48 * self.path.len()
                + HEADER_LEN
                + 2
                + 66 * self.cert.sigs.len(),
        );
        v.extend_from_slice(&(self.op.len() as u32).to_be_bytes());
        v.extend_from_slice(&self.op);
        v.extend_from_slice(&self.index.to_be_bytes());
        v.extend_from_slice(&self.batch_size.to_be_bytes());
        v.push(self.path.len() as u8);
        for h in &self.path {
            v.extend_from_slice(h);
        }
        v.extend_from_slice(&self.header);
        v.extend_from_slice(&(self.cert.sigs.len() as u16).to_be_bytes());
        for (i, s) in &self.cert.sigs {
            v.extend_from_slice(&i.to_be_bytes());
            v.extend_from_slice(s);
        }
        v
    }

    /// Parse untrusted bytes (exact length). Never panics; allocates at most what the input length allows.
    pub fn decode(b: &[u8]) -> Result<FinalityProof, Error> {
        let mut r = b;
        fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
            if r.len() < n {
                return Err(Error::Encoding);
            }
            let (a, rest) = r.split_at(n);
            *r = rest;
            Ok(a)
        }
        let op_len = u32::from_be_bytes(take(&mut r, 4)?.try_into().expect("4")) as usize;
        if op_len > MAX_OP_LEN {
            return Err(Error::Encoding);
        }
        let op = take(&mut r, op_len)?.to_vec();
        let index = u64::from_be_bytes(take(&mut r, 8)?.try_into().expect("8"));
        let batch_size = u64::from_be_bytes(take(&mut r, 8)?.try_into().expect("8"));
        let path_len = take(&mut r, 1)?[0] as usize;
        if path_len > MAX_PATH_LEN {
            return Err(Error::Encoding);
        }
        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            path.push(take(&mut r, 48)?.try_into().expect("48"));
        }
        let header = take(&mut r, HEADER_LEN)?.to_vec();
        let n = u16::from_be_bytes(take(&mut r, 2)?.try_into().expect("2")) as usize;
        if n > MAX_SIGS || r.len() != 66 * n {
            return Err(Error::Encoding);
        }
        let sigs = r
            .as_chunks::<66>()
            .0
            .iter()
            .map(|c| {
                (
                    u16::from_be_bytes([c[0], c[1]]),
                    c[2..].try_into().expect("64"),
                )
            })
            .collect();
        Ok(FinalityProof {
            op,
            index,
            batch_size,
            path,
            header,
            cert: Certificate { sigs },
        })
    }
}

/// Decode and verify in one step (the entry point a browser or embedded light client calls).
pub fn verify_bytes(set: &ValidatorSet, proof: &[u8]) -> Result<Header, Error> {
    set.verify(&FinalityProof::decode(proof)?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The proof bytes do not parse (wrong length, over a bound).
    Encoding,
    HeaderLength,
    HeaderDomain,
    Inclusion,
    UnknownValidator,
    DuplicateSigner,
    Quorum {
        have: usize,
        need: usize,
    },
    Signature,
    /// A small-order validator key: anyone can produce signatures that verify under it.
    WeakKey,
}

/// The validator set a light client trusts (from genesis or a verified epoch change).
pub struct ValidatorSet {
    /// `CheckedKey`s: a weak key cannot be part of a set.
    pub keys: Vec<CheckedKey>,
}

impl ValidatorSet {
    pub fn new(keys: &[VerifyingKey]) -> Result<ValidatorSet, Error> {
        Ok(ValidatorSet {
            keys: keys
                .iter()
                .map(|k| CheckedKey::new(k.to_bytes()).ok_or(Error::WeakKey))
                .collect::<Result<_, _>>()?,
        })
    }

    pub fn quorum(&self) -> usize {
        (4 * self.keys.len()).div_ceil(5)
    } // ceil(0.8 n)

    pub fn verify(&self, p: &FinalityProof) -> Result<Header, Error> {
        let header = Header::decode(&p.header)?;
        let leaf = leaf_hash(BATCH, &p.op);
        if !verify_audit_path(
            BATCH,
            &leaf,
            p.index,
            p.batch_size,
            &p.path,
            &header.batch_root,
        ) {
            return Err(Error::Inclusion);
        }
        let need = self.quorum();
        if p.cert.sigs.len() < need {
            return Err(Error::Quorum {
                have: p.cert.sigs.len(),
                need,
            });
        }
        let mut seen = vec![false; self.keys.len()];
        let digest = header_digest(&p.header);
        let mut items = Vec::with_capacity(p.cert.sigs.len());
        for (i, s) in &p.cert.sigs {
            let i = *i as usize;
            let k = self.keys.get(i).ok_or(Error::UnknownValidator)?;
            if std::mem::replace(&mut seen[i], true) {
                return Err(Error::DuplicateSigner);
            }
            items.push(Item {
                key: *k,
                msg: digest,
                sig: *s,
            });
        }
        // One ZIP-215 batch: accepts exactly when every vote would verify singly (the rule full nodes use too).
        if !nimbus_sig::verify_batch(&items) {
            return Err(Error::Signature);
        }
        Ok(header)
    }
}

/// Test/benchmark helper: build a valid proof for `ops[index]` signed by validators `signers`.
pub mod testkit {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use nimbus_hash::{audit_path, root_from_leaf_hashes};

    pub fn build(
        ops: &[Vec<u8>],
        index: usize,
        height: u64,
        keys: &[SigningKey],
        signers: &[usize],
    ) -> FinalityProof {
        let leaves: Vec<Hash> = ops.iter().map(|o| leaf_hash(BATCH, o)).collect();
        let root = root_from_leaf_hashes(BATCH, &leaves);
        let header = Header {
            height,
            rank: 0,
            batch_root: root,
            prev: [7u8; 48],
            history: [9u8; 48],
        }
        .encode()
        .to_vec();
        let d = header_digest(&header);
        let sigs = signers
            .iter()
            .map(|&i| (i as u16, keys[i].sign(&d).to_bytes()))
            .collect();
        FinalityProof {
            op: ops[index].clone(),
            index: index as u64,
            batch_size: ops.len() as u64,
            path: audit_path(BATCH, &leaves, index),
            header,
            cert: Certificate { sigs },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::build;
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn setup(n: usize, m: usize) -> (Vec<SigningKey>, ValidatorSet, Vec<Vec<u8>>) {
        let mut rng = StdRng::seed_from_u64(1);
        let keys: Vec<SigningKey> = (0..n).map(|_| SigningKey::generate(&mut rng)).collect();
        let vs =
            ValidatorSet::new(&keys.iter().map(|k| k.verifying_key()).collect::<Vec<_>>()).unwrap();
        let ops = (0..m)
            .map(|i| {
                let mut v = vec![0u8; 96];
                rng.fill(&mut v[..]);
                v[0] = i as u8;
                v
            })
            .collect();
        (keys, vs, ops)
    }

    #[test]
    fn valid_proofs_verify() {
        let (keys, vs, ops) = setup(21, 1366);
        for idx in [0, 1, 683, 1365] {
            let p = build(&ops, idx, 42, &keys, &(0..17).collect::<Vec<_>>());
            assert_eq!(vs.verify(&p).unwrap().height, 42);
        }
    }

    #[test]
    fn mutations_are_rejected() {
        let (keys, vs, ops) = setup(21, 1366);
        let signers: Vec<usize> = (2..19).collect();
        let base = build(&ops, 500, 7, &keys, &signers);
        let mut rng = StdRng::seed_from_u64(9);
        let mut rejected = 0;
        let trials = 3000;
        for t in 0..trials {
            let mut p = base.clone();
            match t % 9 {
                0 => {
                    let i = rng.gen_range(0..p.op.len());
                    p.op[i] ^= 1 << rng.gen_range(0..8);
                }
                1 => {
                    let j = rng.gen_range(0..p.path.len());
                    p.path[j][rng.gen_range(0..48)] ^= 1;
                }
                2 => {
                    let i = rng.gen_range(0..HEADER_LEN);
                    p.header[i] ^= 1 << rng.gen_range(0..8);
                }
                3 => {
                    let j = rng.gen_range(0..p.cert.sigs.len());
                    p.cert.sigs[j].1[rng.gen_range(0..64)] ^= 1;
                }
                4 => {
                    p.cert.sigs.pop();
                }
                5 => {
                    let s = p.cert.sigs[0];
                    p.cert.sigs[1] = s;
                } // duplicate signer
                6 => {
                    p.cert.sigs[0].0 = 0;
                } // signature under wrong key
                7 => {
                    p.index = (p.index + 1) % p.batch_size;
                } // wrong position
                _ => {
                    p.header[0] = domain::BATCH_NODE;
                } // cross-domain header
            }
            if vs.verify(&p).is_err() {
                rejected += 1;
            }
        }
        assert_eq!(rejected, trials, "every mutated proof must be rejected");
    }

    #[test]
    fn encode_decode_roundtrip_and_verify_bytes() {
        let (keys, vs, ops) = setup(7, 33);
        for idx in [0usize, 16, 32] {
            let p = build(&ops, idx, 5, &keys, &(0..6).collect::<Vec<_>>());
            let b = p.encode();
            let q = FinalityProof::decode(&b).unwrap();
            assert_eq!(q.encode(), b);
            assert_eq!(q.op, p.op);
            assert_eq!(q.path, p.path);
            assert_eq!(verify_bytes(&vs, &b).unwrap().height, 5);
        }
    }

    #[test]
    fn decode_rejects_every_truncation_and_extension() {
        let (keys, _, ops) = setup(4, 9);
        let b = build(&ops, 4, 1, &keys, &[0, 1, 2, 3]).encode();
        for n in 0..b.len() {
            assert_eq!(FinalityProof::decode(&b[..n]).err(), Some(Error::Encoding));
        }
        let mut longer = b.clone();
        longer.push(0);
        assert_eq!(FinalityProof::decode(&longer).err(), Some(Error::Encoding));
    }

    #[test]
    fn decode_enforces_bounds_before_allocating() {
        let mut b = ((MAX_OP_LEN + 1) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(&[0u8; 64]);
        assert_eq!(FinalityProof::decode(&b).err(), Some(Error::Encoding));
        let mut b = 0u32.to_be_bytes().to_vec();
        b.extend_from_slice(&[0u8; 16]);
        b.push((MAX_PATH_LEN + 1) as u8);
        assert_eq!(FinalityProof::decode(&b).err(), Some(Error::Encoding));
    }

    #[test]
    fn quorum_is_ceil_four_fifths() {
        for (n, q) in [(1, 1), (4, 4), (5, 4), (10, 8), (21, 17), (100, 80)] {
            let (_, vs, _) = setup(n, 1);
            assert_eq!(vs.quorum(), q, "n = {n}");
        }
    }

    #[test]
    fn header_codec_rejects_bad_length_and_domain() {
        let h = Header {
            height: 3,
            rank: 1,
            batch_root: [1; 48],
            prev: [2; 48],
            history: [3; 48],
        };
        let b = h.encode();
        assert_eq!(Header::decode(&b).unwrap(), h);
        assert_eq!(Header::decode(&b[..153]).err(), Some(Error::HeaderLength));
        let mut c = b;
        c[0] ^= 0xff;
        assert_eq!(Header::decode(&c).err(), Some(Error::HeaderDomain));
    }

    #[test]
    fn short_certificate_reports_have_and_need() {
        let (keys, vs, ops) = setup(10, 4);
        let p = build(&ops, 0, 1, &keys, &[0, 1, 2]);
        assert_eq!(
            vs.verify(&p).err(),
            Some(Error::Quorum { have: 3, need: 8 })
        );
        let mut p = build(&ops, 0, 1, &keys, &(0..8).collect::<Vec<_>>());
        p.cert.sigs[7].0 = 99;
        assert_eq!(vs.verify(&p).err(), Some(Error::UnknownValidator));
    }

    /// v0.4 regression: batch verification, like non-strict single verification, accepts R = identity, s = 0 under
    /// a small-order key, so a weak key in the set would let anyone cast that validator's vote.
    #[test]
    fn weak_validator_key_cannot_be_counted() {
        let (keys, _, ops) = setup(21, 64);
        let mut id = [0u8; 32];
        id[0] = 1;
        let weak = VerifyingKey::from_bytes(&id).unwrap();
        let p = build(&ops, 3, 1, &keys, &(0..16).collect::<Vec<_>>());
        let mut forged = [0u8; 64];
        forged[0] = 1;
        let d = header_digest(&p.header);
        let msgs: Vec<&[u8]> = vec![&d[..]; 1];
        assert!(
            ed25519_dalek::verify_batch(
                &msgs,
                &[ed25519_dalek::Signature::from_bytes(&forged)],
                &[weak]
            )
            .is_ok(),
            "the hazard: the keyless signature passes batch verification"
        );
        let mut vks: Vec<VerifyingKey> = keys.iter().map(|k| k.verifying_key()).collect();
        vks[20] = weak;
        assert_eq!(ValidatorSet::new(&vks).err(), Some(Error::WeakKey));
    }
}
