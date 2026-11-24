//! A valid journal is damaged by fuzzer-chosen edits (overwrite / truncate / append) and re-opened:
//! open and replicate never panic, and whatever `open` accepts is a prefix of the records actually written —
//! the hash chain lets no altered record through.
#![no_main]
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use nimbus_journal::{Anchor, Journal};
use nimbus_match::{Side, Tif};
use nimbus_order::{Entry, Intent, SignedOrder};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::OnceLock;

fn original() -> &'static (Vec<u8>, Vec<Entry>) {
    static O: OnceLock<(Vec<u8>, Vec<Entry>)> = OnceLock::new();
    O.get_or_init(|| {
        let key = SigningKey::generate(&mut StdRng::seed_from_u64(7));
        let entries: Vec<Entry> = (0..6u64)
            .map(|i| {
                if i == 3 {
                    return Entry::Tick;
                }
                Entry::Order(SignedOrder::sign(
                    Intent {
                        market: 0,
                        acct: 0,
                        side: if i % 2 == 0 { Side::Bid } else { Side::Ask },
                        price: 100 + i,
                        qty: 1 + i,
                        tif: Tif::Gtc,
                        nonce: i,
                        expiry_slot: 100,
                    },
                    &key,
                ))
            })
            .collect();
        let p =
            std::env::temp_dir().join(format!("nimbus-fuzz-journal-src-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let (mut j, _) = Journal::open(&p, 1).unwrap();
        for (i, e) in entries.iter().enumerate() {
            j.append(i as u64 / 2, e).unwrap();
        }
        j.sync().unwrap();
        drop(j);
        let bytes = std::fs::read(&p).unwrap();
        let _ = std::fs::remove_file(&p);
        (bytes, entries)
    })
}

fuzz_target!(|data: &[u8]| {
    let (bytes, entries) = original();
    let mut b = bytes.clone();
    for c in data.chunks_exact(4) {
        let at = u16::from_le_bytes([c[1], c[2]]) as usize;
        match c[0] % 3 {
            0 if !b.is_empty() => {
                let i = at % b.len();
                b[i] ^= c[3] | 1;
            }
            1 => b.truncate(at % (b.len() + 1)),
            _ => b.push(c[3]),
        }
    }
    let p = std::env::temp_dir().join(format!("nimbus-fuzz-journal-{}", std::process::id()));
    std::fs::write(&p, &b).unwrap();
    if let Ok((_, rec)) = Journal::open(&p, 1) {
        assert!(rec.records.len() <= entries.len());
        for (r, e) in rec.records.iter().zip(entries) {
            assert_eq!(&r.entry, e, "a damaged record was accepted");
        }
    }
    // Shipping the damaged bytes to an empty replica: accepted only if they are a clean prefix.
    let q = std::env::temp_dir().join(format!("nimbus-fuzz-replica-{}", std::process::id()));
    let _ = std::fs::remove_file(&q);
    let (mut r, _) = Journal::open(&q, 1).unwrap();
    let from: Anchor = r.anchor();
    if r.replicate_records(&from, &b).is_ok() {
        assert!(
            bytes.starts_with(&b),
            "replica accepted bytes the primary never wrote"
        );
    }
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_file(&q);
});
