//! Journal damage, record by record: a cut inside the last record is a torn tail (truncated, earlier records kept);
//! a changed byte in any record is reported at that record; anchors pin a prefix.
use ed25519_dalek::SigningKey;
use nimbus_journal::*;
use nimbus_match::{Side, Tif};
use nimbus_order::{Entry, Intent, SignedOrder};
use std::path::PathBuf;

const N: usize = 8;

fn path(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "nimbus-damage-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn entries() -> Vec<Entry> {
    let k = SigningKey::from_bytes(&[5; 32]);
    (0..N as u64)
        .map(|i| {
            if i == 4 {
                Entry::Tick
            } else {
                Entry::Order(SignedOrder::sign(
                    Intent {
                        market: 0,
                        acct: 1,
                        side: Side::Bid,
                        price: 100 + i,
                        qty: 1,
                        tif: Tif::Gtc,
                        nonce: i,
                        expiry_slot: 99,
                    },
                    &k,
                ))
            }
        })
        .collect()
}

/// Write the journal; return its bytes and the byte offset just past each record.
fn write(p: &PathBuf) -> (Vec<u8>, Vec<u64>) {
    let (mut j, _) = Journal::open(p, 1).unwrap();
    for (i, e) in entries().iter().enumerate() {
        j.append(i as u64 / 3, e).unwrap();
    }
    j.sync().unwrap();
    drop(j);
    let (_, rec) = Journal::open(p, 1).unwrap();
    (std::fs::read(p).unwrap(), rec.offsets)
}

macro_rules! tamper_record {
    ($($name:ident: $k:expr,)*) => {$(
        #[test]
        fn $name() {
            let p = path("tamper");
            let (mut b, off) = write(&p);
            let start = if $k == 0 { 0 } else { off[$k - 1] as usize };
            // A byte inside the entry body of record k.
            b[start + HEADER_LEN + 1] ^= 0x40;
            std::fs::write(&p, &b).unwrap();
            match Journal::open(&p, 1) {
                Err(JournalError::Tampered { seq }) | Err(JournalError::Corrupt { seq }) => {
                    assert_eq!(seq, $k as u64)
                }
                Err(e) => panic!("unexpected {e:?}"),
                Ok(_) => panic!("a modified record {} was accepted", $k),
            }
            let _ = std::fs::remove_file(&p);
        }
    )*};
}

tamper_record! {
    tamper_record_0: 0, tamper_record_1: 1, tamper_record_2: 2, tamper_record_3: 3,
    tamper_record_4_tick: 4, tamper_record_5: 5, tamper_record_6: 6, tamper_record_7: 7,
}

macro_rules! torn_tail {
    ($($name:ident: $keep:expr,)*) => {$(
        #[test]
        fn $name() {
            let p = path("torn");
            let (b, off) = write(&p);
            let last = off[N - 2] as usize;
            let cut = last + $keep;
            assert!(cut < b.len());
            std::fs::write(&p, &b[..cut]).unwrap();
            let (j, rec) = Journal::open(&p, 1).unwrap();
            assert_eq!(rec.records.len(), N - 1);
            assert_eq!(rec.truncated_bytes, $keep as u64);
            assert_eq!(j.len(), (N - 1) as u64);
            assert_eq!(std::fs::metadata(&p).unwrap().len(), last as u64, "tail truncated on disk");
            let _ = std::fs::remove_file(&p);
        }
    )*};
}

torn_tail! {
    torn_after_1_byte: 1, torn_after_2_bytes: 2, torn_inside_header: 10, torn_inside_entry: 60,
    torn_inside_chain_hash: 200,
}

#[test]
fn cut_at_every_record_boundary_keeps_that_prefix() {
    let p = path("bound");
    let (b, off) = write(&p);
    let all = entries();
    for (k, &o) in off.iter().enumerate() {
        std::fs::write(&p, &b[..o as usize]).unwrap();
        let (_, rec) = Journal::open(&p, 1).unwrap();
        assert_eq!(rec.records.len(), k + 1);
        assert_eq!(rec.truncated_bytes, 0);
        for (r, e) in rec.records.iter().zip(&all) {
            assert_eq!(&r.entry, e);
        }
    }
    let _ = std::fs::remove_file(&p);
}

#[test]
fn an_anchor_detects_whole_records_cut_from_the_end() {
    let p = path("anchor");
    let (b, off) = write(&p);
    let (j, _) = Journal::open(&p, 1).unwrap();
    let a = j.anchor();
    drop(j);
    std::fs::write(&p, &b[..off[N - 3] as usize]).unwrap();
    assert!(
        Journal::open(&p, 1).is_ok(),
        "the chain alone cannot see it"
    );
    assert!(
        Journal::open_anchored(&p, 1, &a).is_err(),
        "the anchor does"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn swapped_records_are_refused() {
    let p = path("swap");
    let (b, off) = write(&p);
    let (r1, r2) = (
        b[off[0] as usize..off[1] as usize].to_vec(),
        b[off[1] as usize..off[2] as usize].to_vec(),
    );
    let mut s = b[..off[0] as usize].to_vec();
    s.extend_from_slice(&r2);
    s.extend_from_slice(&r1);
    s.extend_from_slice(&b[off[2] as usize..]);
    std::fs::write(&p, &s).unwrap();
    assert!(Journal::open(&p, 1).is_err());
    let _ = std::fs::remove_file(&p);
}

#[test]
fn record_lengths_match_the_format() {
    assert_eq!(ORDER_RECORD_LEN, 207);
    assert_eq!(record_len(1), HEADER_LEN + 1 + 48);
    let p = path("len");
    let (_, off) = write(&p);
    assert_eq!(off[0] as usize, ORDER_RECORD_LEN);
    assert_eq!(
        (off[4] - off[3]) as usize,
        record_len(1),
        "a tick is one byte"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn genesis_chain_is_the_empty_anchor() {
    let p = path("empty");
    let (j, rec) = Journal::open(&p, 1).unwrap();
    assert!(j.is_empty() && rec.records.is_empty());
    assert_eq!(j.head(), genesis_chain());
    assert_eq!(j.anchor().len, 0);
    let _ = std::fs::remove_file(&p);
}
