//! Replication: a replica that applies the primary's shipped batches holds a byte-identical journal, and accepts
//! nothing that does not continue its own chain.
use ed25519_dalek::SigningKey;
use nimbus_journal::*;
use nimbus_match::{Side, Tif};
use nimbus_order::{Entry, Intent, SignedOrder};
use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::path::PathBuf;

fn path(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "nimbus-repl-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn batches(seed: u64, slots: u64) -> Vec<(u64, Vec<Entry>)> {
    let mut rng = StdRng::seed_from_u64(seed);
    let key = SigningKey::generate(&mut rng);
    let mut nonce = 0;
    (1..=slots)
        .map(|slot| {
            let n = rng.gen_range(0..12);
            let mut v: Vec<Entry> = (0..n)
                .map(|_| {
                    nonce += 1;
                    Entry::Order(SignedOrder::sign(
                        Intent {
                            market: rng.gen_range(0..3),
                            acct: 1,
                            side: if rng.gen_bool(0.5) {
                                Side::Bid
                            } else {
                                Side::Ask
                            },
                            price: rng.gen_range(90..110),
                            qty: rng.gen_range(1..50),
                            tif: Tif::Gtc,
                            nonce,
                            expiry_slot: 1_000,
                        },
                        &key,
                    ))
                })
                .collect();
            if v.is_empty() {
                v.push(Entry::Tick);
            }
            (slot, v)
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).map(|n: u32| n / 50).unwrap_or(24).max(8)
    ))]
    #[test]
    fn replicas_hold_the_primary_journal_and_refuse_anything_else(
        seed in any::<u64>(), bad_batch in 0usize..20, byte in any::<usize>(), bit in 0u8..8
    ) {
        let (pp, rp) = (path("p"), path("r"));
        let (mut primary, _) = Journal::open(&pp, usize::MAX).unwrap();
        let (mut replica, _) = Journal::open(&rp, usize::MAX).unwrap();
        for (i, (slot, entries)) in batches(seed, 20).iter().enumerate() {
            let from = primary.anchor();
            let refs: Vec<&Entry> = entries.iter().collect();
            primary.append_batch(*slot, &refs).unwrap();
            primary.sync().unwrap();
            let shipped = primary.last_write().to_vec();
            if i == bad_batch {
                let before = (replica.anchor(), std::fs::read(&rp).unwrap());
                // A flipped bit, a cut record, a gap and a replayed batch are all refused, and change nothing.
                let mut flipped = shipped.clone();
                let at = byte % flipped.len();
                flipped[at] ^= 1 << bit;
                prop_assert!(replica.replicate(&from, &flipped).is_err());
                prop_assert!(replica.replicate(&from, &shipped[..shipped.len() - 1]).is_err());
                let gap = replica.replicate(&primary.anchor(), &shipped);
                let gap_refused = matches!(gap, Err(JournalError::NotContiguous { .. }));
                prop_assert!(gap_refused);
                // Records that verify but end somewhere other than the signed anchor are refused too.
                let mut wrong_end = primary.anchor();
                wrong_end.head[0] ^= 1;
                let refused = matches!(replica.replicate_to(&from, &wrong_end, &shipped), Err(JournalError::EndMismatch));
                prop_assert!(refused);
                prop_assert_eq!(&before, &(replica.anchor(), std::fs::read(&rp).unwrap()));
            }
            prop_assert_eq!(replica.replicate_to(&from, &primary.anchor(), &shipped).unwrap(), primary.anchor());
            prop_assert_eq!(replica.durable_len(), primary.durable_len());
            if i == 0 {
                let again = replica.replicate(&from, &shipped);
                let replay_refused = matches!(again, Err(JournalError::NotContiguous { .. }));
                prop_assert!(replay_refused, "the same batch twice");
            }
        }
        prop_assert_eq!(std::fs::read(&pp).unwrap(), std::fs::read(&rp).unwrap());
        drop(replica);
        let (_, rec) = Journal::open(&rp, usize::MAX).unwrap();
        prop_assert_eq!(rec.head, primary.head());
        let _ = (std::fs::remove_file(&pp), std::fs::remove_file(&rp));
    }
}
