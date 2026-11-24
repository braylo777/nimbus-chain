//! `open_from`: resuming at a snapshot's anchor returns exactly the suffix `open` would, and refuses a file that was
//! replaced or cut below the anchor.
use ed25519_dalek::SigningKey;
use nimbus_journal::*;
use nimbus_match::{Side, Tif};
use nimbus_order::{Entry, Intent, SignedOrder};
use std::path::PathBuf;

fn path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nimbus-journal-resume-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ))
}

fn entry(k: &SigningKey, nonce: u64, qty: u64) -> Entry {
    Entry::Order(SignedOrder::sign(
        Intent {
            market: 0,
            acct: 1,
            side: Side::Bid,
            price: 100,
            qty,
            tif: Tif::Gtc,
            nonce,
            expiry_slot: 1_000,
        },
        k,
    ))
}

/// 40 slots of 1–3 records; returns (anchor, bytes, last slot) after `cut` slots.
fn write(p: &PathBuf, seed: u64, cut: u64) -> (Anchor, u64, u64) {
    let _ = std::fs::remove_file(p);
    let k = SigningKey::from_bytes(&[seed as u8; 32]);
    let (mut j, _) = Journal::open(p, 1).unwrap();
    let mut at = None;
    let mut nonce = 0;
    for slot in 1..=40u64 {
        let n = 1 + (slot * seed) % 3;
        let es: Vec<Entry> = (0..n)
            .map(|i| {
                nonce += 1;
                entry(&k, nonce, 1 + i + seed)
            })
            .collect();
        j.append_batch(slot, &es.iter().collect::<Vec<_>>())
            .unwrap();
        j.sync().unwrap();
        if slot == cut {
            at = Some((j.anchor(), j.byte_len().unwrap(), slot));
        }
    }
    at.unwrap_or((
        Anchor {
            len: 0,
            head: genesis_chain(),
        },
        0,
        0,
    ))
}

#[test]
fn resuming_returns_the_suffix_open_returns() {
    for cut in [0, 1, 17, 40] {
        let p = path("suffix");
        let (a, bytes, last) = write(&p, 1, cut);
        let (_, full) = Journal::open(&p, 1).unwrap();
        let (mut j, rec) = Journal::open_from(&p, 1, &a, bytes, last).unwrap();
        let k = a.len as usize;
        assert_eq!(rec.records, full.records[k..], "cut {cut}");
        assert_eq!(rec.chain, full.chain[k..]);
        assert_eq!(rec.offsets, full.offsets[k..]);
        assert_eq!(rec.head, full.head);
        assert_eq!(j.len(), full.records.len() as u64);
        // Appending after a resume continues the same chain: a full open still verifies.
        let e = entry(&SigningKey::from_bytes(&[1; 32]), 999, 5);
        j.append_batch(41, &[&e]).unwrap();
        j.sync().unwrap();
        drop(j);
        assert_eq!(
            Journal::open(&p, 1).unwrap().1.records.len(),
            full.records.len() + 1
        );
        let _ = std::fs::remove_file(&p);
    }
}

#[test]
fn a_replaced_or_cut_journal_is_refused_and_a_torn_tail_is_cut() {
    let p = path("replaced");
    let (a, bytes, last) = write(&p, 1, 17);
    // Another history of the same shape.
    let q = path("other");
    write(&q, 2, 17);
    std::fs::copy(&q, &p).unwrap();
    assert!(matches!(
        Journal::open_from(&p, 1, &a, bytes, last),
        Err(JournalError::AnchorMismatch { .. }) | Err(JournalError::BehindAnchor { .. })
    ));
    // Cut below the anchor.
    write(&p, 1, 17);
    let full_len = std::fs::metadata(&p).unwrap().len();
    let cut = |len: u64| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .unwrap()
            .set_len(len)
            .unwrap()
    };
    cut(bytes - 1);
    assert!(Journal::open_from(&p, 1, &a, bytes, last).is_err());
    // A torn tail after the anchor is cut exactly as `open` cuts it.
    write(&p, 1, 17);
    cut(full_len - 10);
    let (_, rec) = Journal::open_from(&p, 1, &a, bytes, last).unwrap();
    assert!(rec.truncated_bytes > 0);
    let (_, full) = Journal::open(&p, 1).unwrap();
    assert_eq!(rec.records, full.records[a.len as usize..]);
    for x in [&p, &q] {
        let _ = std::fs::remove_file(x);
    }
}
