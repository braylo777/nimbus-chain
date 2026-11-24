//! The one Ed25519 rule used everywhere in nimbus — orders, account actions, bridge operations, feed attestations,
//! validator votes and engine checkpoints.
//!
//! * **Keys** must decode to a curve point, be canonically encoded, and not be of small order. A `CheckedKey` can only
//!   be made by passing these checks, so hot paths never re-check. (Under a small-order key, signatures verify
//!   without any private key.)
//! * **Signatures** are verified with the ZIP-215 cofactored equation `[8][s]B = [8]R + [8][k]A` (s canonical),
//!   implemented by `ed25519-zebra`. Under this rule batch verification accepts a set of signatures exactly when each
//!   would be accepted alone (up to probability 2⁻¹²⁸), so batching is safe on every path, including replay. The
//!   cofactorless rule used by default elsewhere does not have this property.
//! * **`verify_all`** checks many signatures on all cores: items are grouped by key (coalescing their terms), split
//!   into one batch per thread, and a failing batch is bisected; when both halves of a failed batch fail again the
//!   failures are dense and the remainder is checked one by one, bounding the cost of an invalid-signature flood at
//!   roughly 1.6× plain single verification.
//! * **`SpinPool`** is for sub-millisecond slots: dedicated worker threads spin on a generation counter instead of
//!   sleeping, so dispatching a handful of signatures costs no thread wake-up. Results are those of `verify_all`.
#![forbid(unsafe_code)]

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_zebra::{batch, Signature, VerificationKey, VerificationKeyBytes};
use rayon::prelude::*;

/// Batches smaller than this are not bisected further; their members are verified singly.
const SINGLE_BELOW: usize = 32;
/// Smallest per-thread batch. Small slots (≈ 1 ms of traffic) are split across all cores for latency; large ones get
/// n / threads per batch, where batching is most efficient.
const MIN_CHUNK: usize = 16;

/// A public key that decodes, is canonically encoded and is not of small order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckedKey([u8; 32]);

impl CheckedKey {
    pub fn new(bytes: [u8; 32]) -> Option<CheckedKey> {
        let p = CompressedEdwardsY(bytes).decompress()?;
        (p.compress().to_bytes() == bytes && !p.is_small_order()).then_some(CheckedKey(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Why `CheckedKey::new` refused a key (for error messages).
pub fn key_problem(bytes: &[u8; 32]) -> Option<&'static str> {
    match CompressedEdwardsY(*bytes).decompress() {
        None => Some("not a curve point"),
        Some(p) if p.compress().to_bytes() != *bytes => Some("non-canonical encoding"),
        Some(p) if p.is_small_order() => Some("small-order (weak) key"),
        Some(_) => None,
    }
}

/// One signature to check: key, message (all nimbus signed messages are 48-byte SHA-384 digests), signature.
#[derive(Clone, Copy, Debug)]
pub struct Item {
    pub key: CheckedKey,
    pub msg: [u8; 48],
    pub sig: [u8; 64],
}

/// Single verification under the rule.
pub fn verify(key: &CheckedKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    VerificationKey::try_from(key.0)
        .map(|vk| vk.verify(&Signature::from_bytes(sig), msg).is_ok())
        .unwrap_or(false)
}

fn batch_ok(items: &[Item], idx: &[u32]) -> bool {
    let mut v = batch::Verifier::new();
    for &i in idx {
        let it = &items[i as usize];
        v.queue((
            VerificationKeyBytes::from(it.key.0),
            Signature::from_bytes(&it.sig),
            &it.msg[..],
        ));
    }
    v.verify(rand::thread_rng()).is_ok()
}

/// Is every item valid? One batch; equivalent to checking each singly (up to 2⁻¹²⁸).
pub fn verify_batch(items: &[Item]) -> bool {
    let idx: Vec<u32> = (0..items.len() as u32).collect();
    items.is_empty() || batch_ok(items, &idx)
}

/// Results for `idx`, given whether the batch over `idx` is already known to have failed.
fn check(items: &[Item], idx: &[u32], known_bad: bool) -> Vec<bool> {
    if !known_bad && batch_ok(items, idx) {
        return vec![true; idx.len()];
    }
    let singly = |idx: &[u32]| -> Vec<bool> {
        idx.iter()
            .map(|&i| {
                let it = &items[i as usize];
                verify(&it.key, &it.msg, &it.sig)
            })
            .collect()
    };
    if idx.len() <= SINGLE_BELOW {
        return singly(idx);
    }
    let (l, r) = idx.split_at(idx.len() / 2);
    match (batch_ok(items, l), batch_ok(items, r)) {
        // Both halves fail: failures are dense, so batching no longer pays — check one by one.
        (false, false) => singly(idx),
        (lok, rok) => {
            let mut out = if lok {
                vec![true; l.len()]
            } else {
                check(items, l, true)
            };
            out.extend(if rok {
                vec![true; r.len()]
            } else {
                check(items, r, true)
            });
            out
        }
    }
}

/// Verify every item; result `i` is `verify(items[i])`. Uses all rayon threads; batches of at least 16.
pub fn verify_all(items: &[Item]) -> Vec<bool> {
    verify_all_with(items, MIN_CHUNK)
}

/// `verify_all` with a chosen minimum batch per thread. `min_batch = 1` is latency mode: small slots are spread over
/// every core even when that forgoes most of the batching gain (a lone signature costs ≈ 2× its share of a
/// 16-signature batch), which is what a sub-millisecond slot needs.
pub fn verify_all_with(items: &[Item], min_batch: usize) -> Vec<bool> {
    let n = items.len();
    if n == 0 {
        return Vec::new();
    }
    // Group by key so each batch coalesces a key's terms and decompresses it once.
    let parts = split(items, rayon::current_num_threads(), min_batch);
    let results: Vec<Vec<bool>> = parts.par_iter().map(|c| check(items, c, false)).collect();
    let mut out = vec![false; n];
    for (c, ok) in parts.iter().zip(results) {
        for (&i, v) in c.iter().zip(ok) {
            out[i as usize] = v;
        }
    }
    out
}

/// Key-grouped split of `0..n` into at most `parts` chunks of at least `min` items.
fn split(items: &[Item], parts: usize, min: usize) -> Vec<Vec<u32>> {
    let n = items.len();
    let mut order: Vec<u32> = (0..n as u32).collect();
    order.sort_unstable_by_key(|&i| items[i as usize].key);
    let chunk = n.div_ceil(parts.max(1)).max(min.max(1));
    order.chunks(chunk).map(|c| c.to_vec()).collect()
}

/// A job: the items and, per participant, the indices it checks (participant 0 is the caller).
type Job = (std::sync::Arc<Vec<Item>>, Vec<Vec<u32>>);

struct Shared {
    /// Bumped once per job; workers start when they see a new value.
    generation: std::sync::atomic::AtomicU64,
    finished: std::sync::atomic::AtomicUsize,
    stop: std::sync::atomic::AtomicBool,
    job: std::sync::Mutex<Job>,
    out: std::sync::Mutex<Vec<Vec<bool>>>,
}

/// Verification workers that busy-wait for work. Each owns a core while the pool lives (drop it to stop them), so
/// a job of a few signatures starts on every worker within nanoseconds rather than after a thread wake-up. Use it
/// only with cores set aside for verification.
pub struct SpinPool {
    shared: std::sync::Arc<Shared>,
    workers: Vec<std::thread::JoinHandle<()>>,
    /// One job at a time.
    call: std::sync::Mutex<()>,
}

impl SpinPool {
    /// `workers` spinning threads; the calling thread takes a share of every job as well.
    pub fn new(workers: usize) -> SpinPool {
        use std::sync::atomic::Ordering;
        let shared = std::sync::Arc::new(Shared {
            generation: 0.into(),
            finished: 0.into(),
            stop: false.into(),
            job: std::sync::Mutex::new((std::sync::Arc::new(Vec::new()), Vec::new())),
            out: std::sync::Mutex::new(Vec::new()),
        });
        let workers = (0..workers)
            .map(|w| {
                let sh = shared.clone();
                std::thread::spawn(move || {
                    let mut seen = 0;
                    loop {
                        let g = sh.generation.load(Ordering::Acquire);
                        if g == seen {
                            std::hint::spin_loop();
                            continue;
                        }
                        seen = g;
                        if sh.stop.load(Ordering::Acquire) {
                            return;
                        }
                        let (items, part) = {
                            let j = sh.job.lock().expect("job lock");
                            (j.0.clone(), j.1.get(w + 1).cloned())
                        };
                        if let Some(idx) = part {
                            let ok = check(&items, &idx, false);
                            sh.out.lock().expect("out lock")[w + 1] = ok;
                        }
                        sh.finished.fetch_add(1, Ordering::AcqRel);
                    }
                })
            })
            .collect();
        SpinPool {
            shared,
            workers,
            call: std::sync::Mutex::new(()),
        }
    }

    /// Same result as `verify_all_with(items, 1)`.
    pub fn verify_all(&self, items: &[Item]) -> Vec<bool> {
        use std::sync::atomic::Ordering;
        let n = items.len();
        if n == 0 {
            return Vec::new();
        }
        let _one = self.call.lock().expect("call lock");
        let parts = split(items, self.workers.len() + 1, 1);
        let arc = std::sync::Arc::new(items.to_vec());
        *self.shared.out.lock().expect("out lock") = vec![Vec::new(); parts.len().max(1)];
        *self.shared.job.lock().expect("job lock") = (arc.clone(), parts.clone());
        self.shared.finished.store(0, Ordering::Release);
        self.shared.generation.fetch_add(1, Ordering::AcqRel);
        let mine = check(&arc, &parts[0], false);
        while self.shared.finished.load(Ordering::Acquire) < self.workers.len() {
            std::hint::spin_loop();
        }
        let mut res = std::mem::take(&mut *self.shared.out.lock().expect("out lock"));
        res[0] = mine;
        let mut out = vec![false; n];
        for (c, ok) in parts.iter().zip(res) {
            for (&i, v) in c.iter().zip(ok) {
                out[i as usize] = v;
            }
        }
        out
    }
}

impl Drop for SpinPool {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.shared.stop.store(true, Ordering::Release);
        self.shared.generation.fetch_add(1, Ordering::AcqRel);
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{constants, EdwardsPoint, Scalar};
    use ed25519_dalek::{Signer, SigningKey};
    use proptest::prelude::*;
    use sha2::{Digest, Sha512};

    fn key(i: u8) -> SigningKey {
        SigningKey::from_bytes(&[i; 32])
    }
    fn msg(i: u32) -> [u8; 48] {
        let mut m = [0u8; 48];
        m[..4].copy_from_slice(&i.to_be_bytes());
        m
    }
    fn item(k: &SigningKey, m: [u8; 48]) -> Item {
        Item {
            key: CheckedKey::new(k.verifying_key().to_bytes()).unwrap(),
            msg: m,
            sig: k.sign(&m).to_bytes(),
        }
    }

    /// A signature the key holder can make that passes the cofactored equation but not the cofactorless one:
    /// R' = rB + T with T of order 8, s = r + k·a. (s·B − R' − k·A = −T, killed by the cofactor.)
    fn torsion_signed(m: &[u8; 48], seed: u8) -> ([u8; 32], [u8; 64]) {
        let a = Scalar::from_bytes_mod_order([seed; 32]);
        let big_a = (a * constants::ED25519_BASEPOINT_POINT).compress();
        let r = Scalar::from_bytes_mod_order([seed.wrapping_add(77); 32]);
        let r_pt: EdwardsPoint =
            r * constants::ED25519_BASEPOINT_POINT + constants::EIGHT_TORSION[1];
        let r_enc = r_pt.compress();
        let k = Scalar::from_hash(
            Sha512::new()
                .chain_update(r_enc.as_bytes())
                .chain_update(big_a.as_bytes())
                .chain_update(m),
        );
        let s = r + k * a;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r_enc.as_bytes());
        sig[32..].copy_from_slice(s.as_bytes());
        (big_a.to_bytes(), sig)
    }

    #[test]
    fn keys_are_checked() {
        let mut id = [0u8; 32];
        id[0] = 1;
        assert_eq!(key_problem(&id), Some("small-order (weak) key"));
        assert!(CheckedKey::new(id).is_none());
        // Non-canonical: y = p + 1 encodes the same point as y = 1 (identity), and y ≥ p in general.
        let mut nc = [0xffu8; 32];
        nc[0] = 0xee;
        nc[31] = 0x7f;
        assert!(CheckedKey::new(nc).is_none());
        let good = key(3).verifying_key().to_bytes();
        assert!(CheckedKey::new(good).is_some());
        assert_eq!(key_problem(&good), None);
    }

    /// v0.5 regression for audit F6: with the previous rule, single and batch verification could disagree on a
    /// signature crafted by a key holder. Under ZIP-215 they agree.
    #[test]
    fn single_and_batch_agree_where_the_old_rule_did_not() {
        let m = msg(1);
        let (a, sig) = torsion_signed(&m, 9);
        let dk = ed25519_dalek::VerifyingKey::from_bytes(&a).unwrap();
        let dsig = ed25519_dalek::Signature::from_bytes(&sig);
        use ed25519_dalek::Verifier;
        assert!(dk.verify(&m, &dsig).is_err(), "cofactorless single rejects");
        // The old batch equation accepts it whenever its derived coefficient is ≡ 0 mod 8 (≈ 1 in 8 batches).
        let honest: Vec<(
            ed25519_dalek::VerifyingKey,
            [u8; 48],
            ed25519_dalek::Signature,
        )> = (0..40u32)
            .map(|i| {
                let k = key(i as u8 + 20);
                let mm = msg(100 + i);
                (k.verifying_key(), mm, k.sign(&mm))
            })
            .collect();
        let accepted_by_some_old_batch = (0..40).any(|j| {
            let mut ks = vec![dk];
            let mut ms: Vec<&[u8]> = vec![&m[..]];
            let mut ss = vec![dsig];
            ks.push(honest[j].0);
            ms.push(&honest[j].1[..]);
            ss.push(honest[j].2);
            ed25519_dalek::verify_batch(&ms, &ss, &ks).is_ok()
        });
        assert!(
            accepted_by_some_old_batch,
            "old batch/single disagreement not reproduced"
        );
        // New rule: single accepts (the key holder made it), and every batch containing it agrees.
        let ck = CheckedKey::new(a).unwrap();
        assert!(verify(&ck, &m, &sig));
        let mut items: Vec<Item> = (0..300u32)
            .map(|i| item(&key((i % 50) as u8 + 20), msg(i)))
            .collect();
        items.push(Item {
            key: ck,
            msg: m,
            sig,
        });
        assert!(verify_all(&items).iter().all(|&b| b));
        assert!(verify_batch(&items));
    }

    #[test]
    fn verify_all_finds_exactly_the_bad_signatures() {
        let ks: Vec<SigningKey> = (1..=40u8).map(key).collect();
        for pattern in 0..6 {
            let mut items: Vec<Item> = (0..3000u32)
                .map(|i| item(&ks[(i % 40) as usize], msg(i)))
                .collect();
            let mut want = vec![true; items.len()];
            for (i, it) in items.iter_mut().enumerate() {
                let bad = match pattern {
                    0 => false,
                    1 => i == 1777,
                    2 => i % 97 == 3,
                    3 => i % 2 == 0,
                    4 => true,
                    _ => i < 64,
                };
                if bad {
                    it.sig[40] ^= 1;
                    want[i] = false;
                }
            }
            assert_eq!(verify_all(&items), want, "pattern {pattern}");
            assert_eq!(
                verify_all_with(&items[..200], 1),
                want[..200],
                "latency mode, pattern {pattern}"
            );
            assert_eq!(verify_batch(&items), pattern == 0);
            let pool = SpinPool::new(3);
            for n in [0usize, 1, 3, 8, 200] {
                assert_eq!(
                    pool.verify_all(&items[..n]),
                    want[..n],
                    "spin pool, pattern {pattern}, {n} items"
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).map(|c: u32| c / 20).unwrap_or(100).max(10), .. ProptestConfig::default() })]

        /// verify_all = per-item single verification, for any mix of valid, corrupted, wrong-message, wrong-key and
        /// torsion-crafted signatures.
        #[test]
        fn verify_all_equals_single(kinds in prop::collection::vec(0u8..6, 1..700)) {
            let items: Vec<Item> = kinds.iter().enumerate().map(|(i, k)| {
                let sk = key((i % 13) as u8 + 1);
                let mut it = item(&sk, msg(i as u32));
                match k {
                    1 => it.sig[(i * 7) % 64] ^= 1 << (i % 8),
                    2 => it.msg[0] ^= 1,
                    3 => it.key = CheckedKey::new(key(99).verifying_key().to_bytes()).unwrap(),
                    4 => { let (a, s) = torsion_signed(&it.msg, (i % 50) as u8 + 1); it.key = CheckedKey::new(a).unwrap(); it.sig = s; }
                    5 => it.sig[63] |= 0xf0, // non-canonical s
                    _ => {}
                }
                it
            }).collect();
            let single: Vec<bool> = items.iter().map(|it| verify(&it.key, &it.msg, &it.sig)).collect();
            prop_assert_eq!(verify_all(&items), single.clone());
            prop_assert_eq!(SpinPool::new(2).verify_all(&items), single.clone());
            prop_assert_eq!(verify_batch(&items), single.iter().all(|&b| b));
        }
    }
}
