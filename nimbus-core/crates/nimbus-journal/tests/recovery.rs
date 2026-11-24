use ed25519_dalek::SigningKey;
use nimbus_journal::*;
use nimbus_match::{Exchange, Op, Side, Tif};
use nimbus_order::{Admission, Entry, Intent, SignedOrder};
use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::path::{Path, PathBuf};

fn path(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "nimbus-journal-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// Admit `n` random signed orders across 3 markets, journal them, and return the final engine hash.
fn live_run(p: &Path, n: usize, seed: u64) -> ([u8; 48], Vec<SigningKey>) {
    let mut rng = StdRng::seed_from_u64(seed);
    let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut rng)).collect();
    let mut adm = Admission::new();
    let mut ex = Exchange::new(3);
    for (a, k) in keys.iter().enumerate() {
        adm.register(a as u32, k.verifying_key()).unwrap();
        for m in ex.markets.iter_mut() {
            m.apply(&Op::Deposit {
                acct: a as u32,
                base: 1_000_000,
                quote: 1_000_000_000,
            });
        }
    }
    let (mut j, rec) = Journal::open(p, 64).unwrap();
    assert!(rec.records.is_empty());
    for i in 0..n {
        let a = rng.gen_range(0..4u32);
        let market = rng.gen_range(0..3u32);
        let it = Intent {
            market,
            acct: a,
            side: if rng.gen_bool(0.5) {
                Side::Bid
            } else {
                Side::Ask
            },
            price: rng.gen_range(95..106),
            qty: rng.gen_range(1..20),
            tif: if rng.gen_bool(0.2) {
                Tif::Ioc
            } else {
                Tif::Gtc
            },
            nonce: adm.next_nonce(a),
            expiry_slot: 1_000,
        };
        let o = SignedOrder::sign(it, &keys[a as usize]);
        let op = adm.admit(&o, i as u64 / 10).unwrap();
        j.append(i as u64 / 10, &Entry::Order(o)).unwrap();
        ex.markets[market as usize].apply(&op);
    }
    j.sync().unwrap();
    (ex.state_hash(), keys)
}

fn replay(records: &[Record], keys: &[SigningKey]) -> [u8; 48] {
    let mut adm = Admission::new();
    let mut ex = Exchange::new(3);
    for (a, k) in keys.iter().enumerate() {
        adm.register(a as u32, k.verifying_key()).unwrap();
        for m in ex.markets.iter_mut() {
            m.apply(&Op::Deposit {
                acct: a as u32,
                base: 1_000_000,
                quote: 1_000_000_000,
            });
        }
    }
    for r in records {
        let Entry::Order(o) = &r.entry else {
            panic!("unexpected entry")
        };
        let op = adm
            .admit(o, r.slot)
            .expect("journaled orders must re-admit");
        ex.markets[o.intent.market as usize].apply(&op);
    }
    ex.state_hash()
}

#[test]
fn replay_reconstructs_the_exact_engine_state() {
    let p = path("replay");
    let (live, keys) = live_run(&p, 5_000, 1);
    let (_, rec) = Journal::open(&p, 64).unwrap();
    assert_eq!(rec.records.len(), 5_000);
    assert_eq!(rec.truncated_bytes, 0);
    assert_eq!(replay(&rec.records, &keys), live);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(64), .. ProptestConfig::default() })]

    #[test]
    fn crash_at_any_byte_recovers_the_complete_prefix(cut in 0usize..(300 * ORDER_RECORD_LEN)) {
        let p = path("crash");
        let (_, keys) = live_run(&p, 300, 2);
        let full = std::fs::read(&p).unwrap();
        std::fs::write(&p, &full[..cut.min(full.len())]).unwrap();
        let (j, rec) = Journal::open(&p, 1).unwrap();
        let whole = cut / ORDER_RECORD_LEN;
        prop_assert_eq!(rec.records.len(), whole);
        prop_assert_eq!(rec.truncated_bytes as usize, cut % ORDER_RECORD_LEN);
        prop_assert_eq!(std::fs::metadata(&p).unwrap().len() as usize, whole * ORDER_RECORD_LEN);
        prop_assert_eq!(j.len() as usize, whole);
        let _ = replay(&rec.records, &keys); // prefix must re-admit cleanly
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn any_modified_byte_is_detected(byte in 0usize..(200 * ORDER_RECORD_LEN), bit in 0u8..8) {
        let p = path("tamper");
        let _ = live_run(&p, 200, 3);
        let full = Journal::open(&p, 1).unwrap().0.anchor();
        let mut b = std::fs::read(&p).unwrap();
        b[byte] ^= 1 << bit;
        std::fs::write(&p, &b).unwrap();
        // Detected as tampering/corruption, or — only for a length field inside the final record's span — seen as a
        // torn tail, which the published anchor then exposes.
        match Journal::open(&p, 1) {
            Err(JournalError::Tampered { .. } | JournalError::Corrupt { .. }) => {}
            Ok((_, rec)) => {
                prop_assert!(rec.records.len() < 200, "modification at byte {byte} not detected");
                prop_assert!(byte >= 199 * ORDER_RECORD_LEN, "only the last record may read as a torn tail");
                let behind = matches!(Journal::open_anchored(&p, 1, &full), Err(JournalError::BehindAnchor { .. }));
                prop_assert!(behind, "the anchor must expose the shortened journal");
            }
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
        let _ = std::fs::remove_file(&p);
    }
}

#[test]
fn removed_or_reordered_records_are_detected() {
    let p = path("reorder");
    let _ = live_run(&p, 50, 4);
    let b = std::fs::read(&p).unwrap();
    // remove record 10
    let mut cut = b[..10 * ORDER_RECORD_LEN].to_vec();
    cut.extend_from_slice(&b[11 * ORDER_RECORD_LEN..]);
    std::fs::write(&p, &cut).unwrap();
    assert!(matches!(
        Journal::open(&p, 1),
        Err(JournalError::Tampered { seq: 10 })
    ));
    // swap records 20 and 21
    let mut sw = b.clone();
    let (r20, r21) = (
        b[20 * ORDER_RECORD_LEN..21 * ORDER_RECORD_LEN].to_vec(),
        b[21 * ORDER_RECORD_LEN..22 * ORDER_RECORD_LEN].to_vec(),
    );
    sw[20 * ORDER_RECORD_LEN..21 * ORDER_RECORD_LEN].copy_from_slice(&r21);
    sw[21 * ORDER_RECORD_LEN..22 * ORDER_RECORD_LEN].copy_from_slice(&r20);
    std::fs::write(&p, &sw).unwrap();
    assert!(matches!(
        Journal::open(&p, 1),
        Err(JournalError::Tampered { seq: 20 })
    ));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn anchors_detect_records_cut_from_the_end() {
    let p = path("anchor");
    let _ = live_run(&p, 100, 5);
    let (j, rec) = Journal::open(&p, 1).unwrap();
    let full = j.anchor();
    let mid = Anchor {
        len: 60,
        head: rec.chain[59],
    };
    drop(j);
    // Without an anchor, cutting whole records from the end is undetectable: the shorter chain is valid.
    let b = std::fs::read(&p).unwrap();
    std::fs::write(&p, &b[..80 * ORDER_RECORD_LEN]).unwrap();
    assert_eq!(Journal::open(&p, 1).unwrap().1.records.len(), 80);
    // With the published anchor it is caught; an older anchor inside the remaining prefix still verifies.
    assert!(matches!(
        Journal::open_anchored(&p, 1, &full),
        Err(JournalError::BehindAnchor {
            have: 80,
            anchored: 100
        })
    ));
    assert!(Journal::open_anchored(&p, 1, &mid).is_ok());
    // A different history of the same length does not match the anchor.
    let q = path("anchor-other");
    let _ = live_run(&q, 100, 6);
    assert!(matches!(
        Journal::open_anchored(&q, 1, &full),
        Err(JournalError::AnchorMismatch { len: 100 })
    ));
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(&q);
}

#[test]
fn group_commit_matches_single_appends_and_tracks_durability() {
    let k = SigningKey::from_bytes(&[3; 32]);
    let orders: Vec<SignedOrder> = (0..50u64)
        .map(|n| {
            SignedOrder::sign(
                Intent {
                    market: (n % 3) as u32,
                    acct: 1,
                    side: Side::Bid,
                    price: 100 + n,
                    qty: 1 + n,
                    tif: Tif::Gtc,
                    nonce: n,
                    expiry_slot: 99,
                },
                &k,
            )
        })
        .collect();
    let (a, b) = (path("single"), path("batch"));
    let (mut ja, _) = Journal::open(&a, 1_000).unwrap();
    for (i, o) in orders.iter().enumerate() {
        ja.append(i as u64 / 10, &Entry::Order(o.clone())).unwrap();
    }
    ja.sync().unwrap();
    let (mut jb, _) = Journal::open(&b, 1_000).unwrap();
    for (s, chunk) in orders.chunks(10).enumerate() {
        let owned: Vec<Entry> = chunk.iter().cloned().map(Entry::Order).collect();
        let entries: Vec<&Entry> = owned.iter().collect();
        let before = jb.durable_len();
        let r = jb.append_batch(s as u64, &entries).unwrap();
        assert_eq!(r, before..before + 10);
        assert_eq!(jb.durable_len(), before, "nothing is durable before sync");
        jb.sync().unwrap();
        assert_eq!(jb.durable_len(), before + 10);
    }
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    assert_eq!(ja.head(), jb.head());
    assert!(matches!(
        jb.append_batch(2, &[&Entry::Tick]),
        Err(JournalError::SlotOrder { .. })
    ));
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
}
