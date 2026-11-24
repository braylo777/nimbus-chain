//! Deterministic replay: the same submissions give the same journal and the same checkpoints, whatever the batching
//! mode, and any replica that re-executes the shipped journal derives exactly the engine's checkpoints.
mod common;
use common::*;
use nimbus_bridge::Certifier;
use nimbus_pipeline::Replayer;
use proptest::prelude::*;

fn replay(ships: &[Shipment], min_batch: usize) -> Vec<nimbus_pipeline::Checkpoint> {
    let d = dir("replay-j");
    let (mut j, _) = nimbus_journal::Journal::open(&d.join("r.bin"), usize::MAX).unwrap();
    let mut r = Replayer::new(cfg(min_batch), &genesis()).unwrap();
    let out = ships
        .iter()
        .map(|s| {
            let (after, records) = j.replicate_records(&s.from, &s.bytes).unwrap();
            assert_eq!(after, s.to);
            r.apply_slot(&records, after).unwrap()
        })
        .collect();
    let _ = std::fs::remove_dir_all(&d);
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, .. ProptestConfig::default() })]

    /// Two engines fed the same traffic — one in throughput mode (min_batch 16), one in latency mode (min_batch 1) —
    /// write byte-identical journals and sign identical checkpoints; a replayer reproduces every one of them.
    #[test]
    fn same_input_same_history(seed in 1u64..u64::MAX, slots in 2u64..10, per_slot in 1usize..40) {
        let (da, db) = (dir("det-a"), dir("det-b"));
        let (ca, sa) = run_engine(&da, seed, slots, per_slot, 16);
        let (cb, sb) = run_engine(&db, seed, slots, per_slot, 1);
        prop_assert_eq!(ca.len(), cb.len());
        for (a, b) in ca.iter().zip(&cb) {
            prop_assert_eq!(a, b);
        }
        prop_assert_eq!(sa.len(), sb.len());
        for (a, b) in sa.iter().zip(&sb) {
            prop_assert_eq!(&a.bytes, &b.bytes);
            prop_assert_eq!(a.to, b.to);
        }
        let ja = std::fs::read(da.join("journal.bin")).unwrap();
        prop_assert_eq!(&ja, &std::fs::read(db.join("journal.bin")).unwrap());
        let r = replay(&sa, 16);
        prop_assert_eq!(r.len(), ca.len());
        for (x, y) in r.iter().zip(&ca) {
            prop_assert!(x.same_body(y), "slot {}", y.slot);
        }
        for d in [&da, &db] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// Different traffic gives different checkpoints (the checkpoint commits to the history).
    #[test]
    fn different_input_different_checkpoint(seed in 1u64..u64::MAX) {
        let (da, db) = (dir("diff-a"), dir("diff-b"));
        let (ca, _) = run_engine(&da, seed, 2, 10, 16);
        let (cb, _) = run_engine(&db, seed ^ 0xdead_beef_0000, 2, 10, 16);
        prop_assert!(!ca[0].same_body(&cb[0]));
        for d in [&da, &db] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// A certifier restarted at any point resumes with the same derivations (crash-restart determinism).
#[test]
fn certifier_restart_reproduces_derivations() {
    let (de, dc) = (dir("restart-e"), dir("restart-c"));
    let (cks, ships) = run_engine(&de, 77, 12, 20, 16);
    let open = || {
        Certifier::open(
            &dc,
            cfg(16),
            &genesis(),
            operator().verifying_key(),
            validator(0),
            0,
        )
        .unwrap()
    };
    for cut in [0, 1, 5, ships.len()] {
        let _ = std::fs::remove_dir_all(&dc);
        let mut c = open();
        for s in &ships[..cut] {
            c.replicate_shipment(&s.from, &s.bytes).unwrap();
        }
        drop(c);
        let mut c = open();
        assert_eq!(c.anchor(), ships[..cut].last().map_or(c.anchor(), |s| s.to));
        for s in &ships[cut..] {
            c.replicate_shipment(&s.from, &s.bytes).unwrap();
        }
        for ck in &cks {
            assert!(c.derived(ck.slot).unwrap().same_body(ck), "cut {cut}");
        }
    }
    for d in [&de, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// A shipment that skips ahead, repeats, or carries two slots is refused and changes nothing.
#[test]
fn out_of_order_and_multi_slot_shipments_are_refused() {
    let (de, dc) = (dir("ooo-e"), dir("ooo-c"));
    let (_, ships) = run_engine(&de, 5, 4, 10, 16);
    let mut c = Certifier::open(
        &dc,
        cfg(16),
        &genesis(),
        operator().verifying_key(),
        validator(1),
        1,
    )
    .unwrap();
    let a0 = c.anchor();
    assert!(c
        .replicate_shipment(&ships[1].from, &ships[1].bytes)
        .is_err());
    assert_eq!(c.anchor(), a0);
    let mut two = ships[0].bytes.clone();
    two.extend_from_slice(&ships[1].bytes);
    assert!(c.replicate_shipment(&ships[0].from, &two).is_err());
    assert_eq!(c.anchor(), a0);
    c.replicate_shipment(&ships[0].from, &ships[0].bytes)
        .unwrap();
    assert!(c
        .replicate_shipment(&ships[0].from, &ships[0].bytes)
        .is_err());
    for d in [&de, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}
