//! Checkpoints and receipt proofs from a real engine run: codec, operator signature, and every single-field
//! mutation of a receipt proof refused.
use ed25519_dalek::{Signer, SigningKey};
use nimbus_journal::Anchor;
use nimbus_match::{Fees, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;

fn key(a: u32) -> SigningKey {
    let mut s = [21u8; 32];
    s[..4].copy_from_slice(&a.to_be_bytes());
    SigningKey::from_bytes(&s)
}
fn operator() -> SigningKey {
    SigningKey::from_bytes(&[3; 32])
}

fn run() -> (Vec<SlotResult>, std::path::PathBuf) {
    let d = std::env::temp_dir().join(format!(
        "nimbus-ckpt-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let g = Genesis {
        accounts: (0..4).map(|a| (a, key(a).verifying_key())).collect(),
        deposits: (0..4).map(|a| (0, a, 1_000, 1_000_000)).collect(),
        fees: Fees::default(),
        ..Genesis::default()
    };
    let cfg = Config {
        markets: 1,
        max_life: 100,
        fsync: false,
        min_batch: 16,
    };
    let (mut p, _) = Pipeline::open(&d, cfg, &g, operator(), None).unwrap();
    let mut out = Vec::new();
    for slot in 1..=3u64 {
        let subs: Vec<Vec<u8>> = (0..4u32)
            .map(|a| {
                Entry::Order(SignedOrder::sign(
                    Intent {
                        market: 0,
                        acct: a,
                        side: if a % 2 == 0 { Side::Bid } else { Side::Ask },
                        price: 100,
                        qty: 2,
                        tif: Tif::Gtc,
                        nonce: slot - 1,
                        expiry_slot: 50,
                    },
                    &key(a),
                ))
                .to_bytes()
            })
            .collect();
        out.push(p.process_slot(slot, &subs).unwrap());
    }
    (out, d)
}

#[test]
fn checkpoint_bytes_roundtrip_and_verify() {
    let (rs, d) = run();
    for r in &rs {
        let ck = r.checkpoint.unwrap();
        assert_eq!(ck.slot, r.slot);
        let b = ck.to_bytes();
        assert_eq!(b.len(), CHECKPOINT_LEN);
        assert_eq!(Checkpoint::from_bytes(&b), Some(ck));
        assert!(ck.verify(&operator().verifying_key()));
        assert!(!ck.verify(&key(0).verifying_key()));
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn checkpoint_from_bytes_wrong_length() {
    assert_eq!(Checkpoint::from_bytes(&[0u8; CHECKPOINT_LEN - 1]), None);
    assert_eq!(Checkpoint::from_bytes(&[0u8; CHECKPOINT_LEN + 1]), None);
}

#[test]
fn checkpoint_body_ignores_the_signature() {
    let ck = Checkpoint {
        slot: 4,
        journal: Anchor {
            len: 9,
            head: [1; 48],
        },
        receipts_root: [2; 48],
        receipts: 3,
        sig: [0; 64],
    };
    let mut b = [0u8; CHECKPOINT_BODY];
    b.copy_from_slice(&ck.to_bytes()[..CHECKPOINT_BODY]);
    assert_eq!(Checkpoint::from_body(&b), ck);
    let mut s = ck;
    s.sig = operator().sign(&ck.digest()).to_bytes();
    assert!(s.same_body(&ck));
    assert_eq!(s.digest(), ck.digest());
}

#[test]
fn every_checkpoint_field_changes_the_digest() {
    let base = Checkpoint {
        slot: 4,
        journal: Anchor {
            len: 9,
            head: [1; 48],
        },
        receipts_root: [2; 48],
        receipts: 3,
        sig: [0; 64],
    };
    let mut v = vec![base; 5];
    v[0].slot += 1;
    v[1].journal.len += 1;
    v[2].journal.head[47] ^= 1;
    v[3].receipts_root[0] ^= 1;
    v[4].receipts += 1;
    for (i, c) in v.iter().enumerate() {
        assert_ne!(c.digest(), base.digest(), "field {i}");
        assert!(!c.same_body(&base));
    }
}

#[test]
fn every_receipt_has_a_valid_proof() {
    let (rs, d) = run();
    let pk = operator().verifying_key();
    let mut n = 0;
    for r in &rs {
        for k in 0..r.receipts.len() {
            assert!(r.proof(k).unwrap().verify(&pk));
            n += 1;
        }
    }
    assert!(n >= 12);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn receipt_proof_mutations_are_refused() {
    let (rs, d) = run();
    let pk = operator().verifying_key();
    let p = rs[1].proof(1).unwrap();
    let mut a = p.clone();
    a.index ^= 1;
    let mut b = p.clone();
    b.path[0][0] ^= 1;
    let mut c = p.clone();
    c.receipt.slot += 1;
    let mut e = p.clone();
    e.checkpoint.sig[0] ^= 1;
    let mut f = p.clone();
    f.checkpoint.receipts += 1;
    let mut g = p.clone();
    g.path.pop();
    for (i, m) in [a, b, c, e, f, g].iter().enumerate() {
        assert!(!m.verify(&pk), "mutation {i} accepted");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn proof_out_of_range_is_none() {
    let (rs, d) = run();
    assert!(rs[0].proof(rs[0].receipts.len()).is_none());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn seal_appends_a_tagged_digest() {
    let s = seal(b"body".to_vec());
    assert_eq!(s.len(), 4 + 48);
    assert_eq!(
        &s[4..],
        &nimbus_hash::hash_tagged(SNAPSHOT_TAG, &[b"body"])[..]
    );
}
