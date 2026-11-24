//! Price/slot attestations signed by a k-of-m feed quorum.
//!
//! Body (28 bytes): market ‖ price ‖ slot ‖ time_ms, signed as H(0x0A ‖ body) by feed keys. A verifier accepts
//! an attestation only if ≥ k distinct known feed keys signed it, it is fresh (`now − time_ms ≤ max_age_ms`, and
//! not from the future beyond `max_skew_ms`), and its slot does not go backwards (`FeedTracker`).
//! Wire: body (28) ‖ count (1) ‖ count × (signer index u16 ‖ signature 64).
#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nimbus_hash::{hash_tagged, Hash};
use nimbus_sig::{CheckedKey, Item};

pub const FEED_TAG: u8 = 0x0A;
pub const BODY_LEN: usize = 28;
pub const MAX_SIGNERS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub market: u32,
    pub price: u64,
    pub slot: u64,
    pub time_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation {
    pub obs: Observation,
    pub sigs: Vec<(u16, [u8; 64])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedError {
    Length,
    TooManySigners,
    ZeroPrice,
    UnknownSigner(u16),
    DuplicateSigner(u16),
    Quorum {
        have: usize,
        need: usize,
    },
    BadSignature,
    Stale {
        age_ms: u64,
        max_ms: u64,
    },
    FromFuture {
        ahead_ms: u64,
    },
    SlotRegressed {
        slot: u64,
        last: u64,
    },
    WrongMarket {
        expected: u32,
        got: u32,
    },
    /// Two different quorum-signed observations for the same market and slot (evidence of feed misbehaviour).
    Conflict {
        slot: u64,
    },
    /// A small-order feed key: anyone can produce signatures that verify under it.
    WeakKey(u16),
    Threshold,
}

impl Observation {
    pub fn encode(&self) -> [u8; BODY_LEN] {
        let mut b = [0u8; BODY_LEN];
        b[0..4].copy_from_slice(&self.market.to_be_bytes());
        b[4..12].copy_from_slice(&self.price.to_be_bytes());
        b[12..20].copy_from_slice(&self.slot.to_be_bytes());
        b[20..28].copy_from_slice(&self.time_ms.to_be_bytes());
        b
    }
    pub fn digest(&self) -> Hash {
        hash_tagged(FEED_TAG, &[&self.encode()])
    }
}

impl Attestation {
    /// Sign `obs` with the feed keys at `indices` (feed operator side).
    pub fn sign(obs: Observation, keys: &[SigningKey], indices: &[usize]) -> Attestation {
        let d = obs.digest();
        Attestation {
            obs,
            sigs: indices
                .iter()
                .map(|&i| (i as u16, keys[i].sign(&d).to_bytes()))
                .collect(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.obs.encode().to_vec();
        v.push(self.sigs.len() as u8);
        for (i, s) in &self.sigs {
            v.extend_from_slice(&i.to_be_bytes());
            v.extend_from_slice(s);
        }
        v
    }

    /// Parse untrusted bytes; never panics.
    pub fn from_bytes(b: &[u8]) -> Result<Attestation, FeedError> {
        if b.len() < BODY_LEN + 1 {
            return Err(FeedError::Length);
        }
        let n = b[BODY_LEN] as usize;
        if n > MAX_SIGNERS {
            return Err(FeedError::TooManySigners);
        }
        if b.len() != BODY_LEN + 1 + n * 66 {
            return Err(FeedError::Length);
        }
        let u32_at = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().expect("4"));
        let u64_at = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().expect("8"));
        let obs = Observation {
            market: u32_at(0),
            price: u64_at(4),
            slot: u64_at(12),
            time_ms: u64_at(20),
        };
        if obs.price == 0 {
            return Err(FeedError::ZeroPrice);
        }
        let sigs = (0..n)
            .map(|k| {
                let o = BODY_LEN + 1 + k * 66;
                (
                    u16::from_be_bytes([b[o], b[o + 1]]),
                    b[o + 2..o + 66].try_into().expect("64"),
                )
            })
            .collect();
        Ok(Attestation { obs, sigs })
    }
}

/// The feed keys a signer trusts, the quorum, and the freshness window. Keys are `CheckedKey`s, so a weak key cannot
/// be part of a set.
#[derive(Clone, Debug)]
pub struct FeedSet {
    pub keys: Vec<CheckedKey>,
    pub threshold: usize,
    pub max_age_ms: u64,
    pub max_skew_ms: u64,
}

impl FeedSet {
    /// Validated constructor: 1 ≤ threshold ≤ keys, no weak keys, at most `MAX_SIGNERS` keys.
    pub fn new(
        keys: Vec<VerifyingKey>,
        threshold: usize,
        max_age_ms: u64,
        max_skew_ms: u64,
    ) -> Result<FeedSet, FeedError> {
        if keys.len() > MAX_SIGNERS {
            return Err(FeedError::TooManySigners);
        }
        if threshold == 0 || threshold > keys.len() {
            return Err(FeedError::Threshold);
        }
        let keys = keys
            .iter()
            .enumerate()
            .map(|(i, k)| CheckedKey::new(k.to_bytes()).ok_or(FeedError::WeakKey(i as u16)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FeedSet {
            keys,
            threshold,
            max_age_ms,
            max_skew_ms,
        })
    }

    pub fn verify(&self, a: &Attestation, now_ms: u64) -> Result<(), FeedError> {
        if a.obs.price == 0 {
            return Err(FeedError::ZeroPrice);
        }
        if a.obs.time_ms > now_ms + self.max_skew_ms {
            return Err(FeedError::FromFuture {
                ahead_ms: a.obs.time_ms - now_ms,
            });
        }
        let age = now_ms.saturating_sub(a.obs.time_ms);
        if age > self.max_age_ms {
            return Err(FeedError::Stale {
                age_ms: age,
                max_ms: self.max_age_ms,
            });
        }
        if a.sigs.len() < self.threshold {
            return Err(FeedError::Quorum {
                have: a.sigs.len(),
                need: self.threshold,
            });
        }
        let mut seen = vec![false; self.keys.len()];
        let d = a.obs.digest();
        let mut items = Vec::with_capacity(a.sigs.len());
        for (i, s) in &a.sigs {
            let k = self
                .keys
                .get(*i as usize)
                .ok_or(FeedError::UnknownSigner(*i))?;
            if std::mem::replace(&mut seen[*i as usize], true) {
                return Err(FeedError::DuplicateSigner(*i));
            }
            items.push(Item {
                key: *k,
                msg: d,
                sig: *s,
            });
        }
        // One ZIP-215 batch: accepts exactly when every signature would verify singly.
        if nimbus_sig::verify_batch(&items) {
            Ok(())
        } else {
            Err(FeedError::BadSignature)
        }
    }
}

/// Per-market monotonic slot tracking: an attestation older (in slots) than one already accepted is refused, so a
/// client cannot swap in an older, more convenient price; a *different* observation for an already-accepted slot is
/// refused too (re-presenting the identical one is harmless and accepted).
#[derive(Clone, Debug, Default)]
pub struct FeedTracker {
    last: std::collections::BTreeMap<u32, Observation>,
}

impl FeedTracker {
    /// Restore from persisted observations (so monotonicity survives a restart).
    pub fn restore(obs: impl IntoIterator<Item = Observation>) -> FeedTracker {
        FeedTracker {
            last: obs.into_iter().map(|o| (o.market, o)).collect(),
        }
    }

    /// Latest accepted observation per market.
    pub fn latest(&self, market: u32) -> Option<Observation> {
        self.last.get(&market).copied()
    }

    pub fn all(&self) -> impl Iterator<Item = &Observation> {
        self.last.values()
    }

    pub fn accept(
        &mut self,
        set: &FeedSet,
        a: &Attestation,
        market: u32,
        now_ms: u64,
    ) -> Result<Observation, FeedError> {
        if a.obs.market != market {
            return Err(FeedError::WrongMarket {
                expected: market,
                got: a.obs.market,
            });
        }
        set.verify(a, now_ms)?;
        if let Some(prev) = self.last.get(&market) {
            if a.obs.slot < prev.slot {
                return Err(FeedError::SlotRegressed {
                    slot: a.obs.slot,
                    last: prev.slot,
                });
            }
            if a.obs.slot == prev.slot && a.obs != *prev {
                return Err(FeedError::Conflict { slot: a.obs.slot });
            }
        }
        self.last.insert(market, a.obs);
        Ok(a.obs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn setup() -> (Vec<SigningKey>, FeedSet) {
        let mut r = StdRng::seed_from_u64(5);
        let keys: Vec<SigningKey> = (0..5).map(|_| SigningKey::generate(&mut r)).collect();
        let set = FeedSet::new(
            keys.iter().map(|k| k.verifying_key()).collect(),
            3,
            500,
            100,
        )
        .unwrap();
        (keys, set)
    }
    fn obs(slot: u64, t: u64) -> Observation {
        Observation {
            market: 1,
            price: 1000,
            slot,
            time_ms: t,
        }
    }

    #[test]
    fn quorum_freshness_and_monotonicity() {
        let (k, set) = setup();
        let mut tr = FeedTracker::default();
        let a = Attestation::sign(obs(10, 1_000), &k, &[0, 2, 4]);
        let back = Attestation::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(back, a);
        assert!(tr.accept(&set, &back, 1, 1_200).is_ok());
        assert!(matches!(
            set.verify(&Attestation::sign(obs(10, 1_000), &k, &[0, 1]), 1_200),
            Err(FeedError::Quorum { .. })
        ));
        assert!(matches!(
            set.verify(&a, 1_600),
            Err(FeedError::Stale { .. })
        ));
        assert!(matches!(
            set.verify(&Attestation::sign(obs(10, 2_000), &k, &[0, 1, 2]), 1_000),
            Err(FeedError::FromFuture { .. })
        ));
        assert!(matches!(
            tr.accept(
                &set,
                &Attestation::sign(obs(9, 1_100), &k, &[1, 2, 3]),
                1,
                1_200
            ),
            Err(FeedError::SlotRegressed { .. })
        ));
        assert!(matches!(
            tr.accept(&set, &a, 2, 1_200),
            Err(FeedError::WrongMarket { .. })
        ));
        let mut dup = Attestation::sign(obs(11, 1_100), &k, &[0, 1, 2]);
        dup.sigs[2] = dup.sigs[0];
        assert!(matches!(
            set.verify(&dup, 1_200),
            Err(FeedError::DuplicateSigner(0))
        ));
    }

    #[test]
    fn same_slot_conflict_and_weak_keys_are_refused() {
        let (k, set) = setup();
        let mut tr = FeedTracker::default();
        let a = Attestation::sign(obs(10, 1_000), &k, &[0, 1, 2]);
        assert!(tr.accept(&set, &a, 1, 1_100).is_ok());
        assert!(
            tr.accept(&set, &a, 1, 1_100).is_ok(),
            "identical re-presentation is harmless"
        );
        let other = Observation {
            price: 1_010,
            ..obs(10, 1_000)
        };
        assert_eq!(
            tr.accept(&set, &Attestation::sign(other, &k, &[2, 3, 4]), 1, 1_100),
            Err(FeedError::Conflict { slot: 10 })
        );
        assert_eq!(tr.latest(1), Some(obs(10, 1_000)));
        let restored = FeedTracker::restore(tr.all().copied());
        assert_eq!(restored.latest(1), tr.latest(1));
        // Weak key: with R = identity and s = 0 the keyless signature would pass verification, so a weak key can
        // never enter a set (FeedSet holds CheckedKeys).
        let mut id = [0u8; 32];
        id[0] = 1;
        let mut keys: Vec<VerifyingKey> = k.iter().map(|k| k.verifying_key()).collect();
        keys[4] = VerifyingKey::from_bytes(&id).unwrap();
        assert_eq!(
            FeedSet::new(keys.clone(), 3, 500, 100).unwrap_err(),
            FeedError::WeakKey(4)
        );
        keys[4] = k[4].verifying_key();
        assert_eq!(
            FeedSet::new(keys, 0, 1, 1).unwrap_err(),
            FeedError::Threshold
        );
    }

    #[test]
    fn cross_domain_signature_is_rejected() {
        let (k, set) = setup();
        let o = obs(10, 1_000);
        let wrong = hash_tagged(0x09, &[&o.encode()]); // same bytes, order domain
        let a = Attestation {
            obs: o,
            sigs: (0..3)
                .map(|i| (i as u16, k[i].sign(&wrong).to_bytes()))
                .collect(),
        };
        assert_eq!(set.verify(&a, 1_000), Err(FeedError::BadSignature));
    }

    proptest! {
        #[test]
        fn parser_never_panics(b in prop::collection::vec(any::<u8>(), 0..600)) {
            let _ = Attestation::from_bytes(&b);
        }

        #[test]
        fn any_bit_flip_is_rejected(byte in 0usize..(BODY_LEN + 1 + 3 * 66), bit in 0u8..8) {
            let (k, set) = setup();
            let mut w = Attestation::sign(obs(10, 1_000), &k, &[0, 2, 4]).to_bytes();
            w[byte] ^= 1 << bit;
            let ok = Attestation::from_bytes(&w).map(|a| set.verify(&a, 1_100).is_ok()).unwrap_or(false);
            // Flipping the time or slot can still yield a structurally valid observation, but the signatures then fail.
            prop_assert!(!ok, "tampered attestation accepted (byte {byte}, bit {bit})");
        }
    }
}
