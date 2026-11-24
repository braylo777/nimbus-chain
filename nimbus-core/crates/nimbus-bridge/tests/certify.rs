//! Certifiers: replicas that re-execute the journal and co-sign only checkpoints they reproduce, once per slot.
use ed25519_dalek::{Signer, SigningKey};
use nimbus_bridge::*;
use nimbus_match::{Fees, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use std::path::PathBuf;

const ACCOUNTS: u32 = 8;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nimbus-cert-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn key(a: u32) -> SigningKey {
    let mut s = [11u8; 32];
    s[..4].copy_from_slice(&a.to_be_bytes());
    SigningKey::from_bytes(&s)
}
fn operator() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}
fn validator(i: u16) -> SigningKey {
    SigningKey::from_bytes(&[70 + i as u8; 32])
}
fn genesis() -> Genesis {
    Genesis {
        accounts: (0..ACCOUNTS).map(|a| (a, key(a).verifying_key())).collect(),
        deposits: (0..2)
            .flat_map(|m| (0..ACCOUNTS).map(move |a| (m, a, 1 << 20, 1 << 32)))
            .collect(),
        fees: Fees {
            maker_bps: 2,
            taker_bps: 5,
            collector: 99,
            maker_rebate_bps: 0,
        },
        ..Genesis::default()
    }
}
fn cfg() -> Config {
    Config {
        markets: 2,
        max_life: 1_000,
        fsync: true,
        min_batch: 16,
    }
}

/// Mixed traffic: orders on two markets with crossing prices, a cancel and a withdrawal now and then.
struct Traffic {
    nonce: Vec<u64>,
    seed: u64,
}
impl Traffic {
    fn new(seed: u64) -> Self {
        Traffic {
            nonce: vec![0; ACCOUNTS as usize],
            seed,
        }
    }
    fn next(&mut self) -> u64 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed
    }
    fn slot(&mut self, slot: u64, n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|_| {
                let a = (self.next() % ACCOUNTS as u64) as u32;
                let nonce = self.nonce[a as usize];
                self.nonce[a as usize] += 1;
                let market = (self.next() % 2) as u32;
                let e = match self.next() % 20 {
                    0 => Entry::Action(SignedAction::sign(
                        Action {
                            market,
                            acct: a,
                            nonce,
                            expiry_slot: slot + 50,
                            kind: ActionKind::Withdraw {
                                base: 0,
                                quote: 1_000,
                            },
                        },
                        &key(a),
                    )),
                    1 => Entry::Action(SignedAction::sign(
                        Action {
                            market,
                            acct: a,
                            nonce,
                            expiry_slot: slot + 50,
                            kind: ActionKind::Cancel {
                                order_id: 1 + self.next() % 20,
                            },
                        },
                        &key(a),
                    )),
                    _ => Entry::Order(SignedOrder::sign(
                        Intent {
                            market,
                            acct: a,
                            side: if self.next().is_multiple_of(2) {
                                Side::Bid
                            } else {
                                Side::Ask
                            },
                            price: 995 + self.next() % 11,
                            qty: 1 + self.next() % 30,
                            tif: if self.next().is_multiple_of(5) {
                                Tif::Ioc
                            } else {
                                Tif::Gtc
                            },
                            nonce,
                            expiry_slot: slot + 3 + self.next() % 10,
                        },
                        &key(a),
                    )),
                };
                e.to_bytes()
            })
            .collect()
    }
}

#[test]
fn the_replayer_reproduces_every_engine_checkpoint() {
    let d = dir("replay");
    let (mut p, _) = Pipeline::open(&d, cfg(), &genesis(), operator(), None).unwrap();
    let mut t = Traffic::new(7);
    let mut cks = Vec::new();
    for slot in 1..=60 {
        let n = if slot % 9 == 0 { 0 } else { 40 };
        cks.extend(p.process_slot(slot, &t.slot(slot, n)).unwrap().checkpoint);
    }
    drop(p);
    let (_, rec) = nimbus_journal::Journal::open(&d.join("journal.bin"), usize::MAX).unwrap();
    let mut r = Replayer::new(cfg(), &genesis()).unwrap();
    let mut got = Vec::new();
    let mut i = 0;
    while i < rec.records.len() {
        let slot = rec.records[i].slot;
        let end = i + rec.records[i..]
            .iter()
            .take_while(|x| x.slot == slot)
            .count();
        let after = nimbus_journal::Anchor {
            len: end as u64,
            head: rec.chain[end - 1],
        };
        got.push(r.apply_slot(&rec.records[i..end], after).unwrap());
        i = end;
    }
    assert_eq!(got.len(), cks.len());
    for (a, b) in got.iter().zip(&cks) {
        assert!(a.same_body(b), "slot {}", b.slot);
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn certifiers_certify_what_they_reproduce_and_the_bridge_pays_only_that() {
    let (de, dc) = (dir("engine"), dir("certs"));
    let g = genesis();
    let (mut p, _) = Pipeline::open(&de, cfg(), &g, operator(), None).unwrap();
    let certs: Vec<SharedCertifier> = (0..4u16)
        .map(|i| {
            let c = Certifier::open(
                &dc.join(format!("v{i}")),
                cfg(),
                &g,
                operator().verifying_key(),
                validator(i),
                i,
            )
            .unwrap();
            SharedCertifier::new(c)
        })
        .collect();
    p.attach_replicas(
        certs
            .iter()
            .map(|c| Box::new(c.clone()) as Box<dyn Replica>)
            .collect(),
        4,
    )
    .unwrap();
    let mut t = Traffic::new(11);
    let mut withdrawal = None;
    for slot in 1..=30 {
        let r = p.process_slot(slot, &t.slot(slot, 30)).unwrap();
        for (k, rc) in r.receipts.iter().enumerate() {
            if withdrawal.is_none() && matches!(rc.status, Status::Withdrawn { .. }) {
                withdrawal = r.proof(k);
            }
        }
    }
    let proof = withdrawal.expect("the traffic contains a completed withdrawal");
    // 3 of 4 (3q > 2n): any three certifiers suffice.
    let vals = Validators::new(
        &(0..4)
            .map(|i| validator(i).verifying_key())
            .collect::<Vec<_>>(),
        3,
    )
    .unwrap();
    let mut bridge =
        Settlement::open_certified(&dc.join("settled.bin"), operator().verifying_key(), vals)
            .unwrap();
    let (cert, refusals) = certify_with(&certs, &proof.checkpoint, 3);
    assert!(refusals.is_empty(), "{refusals:?}");
    let cert = cert.expect("three co-signatures");
    assert!(matches!(
        bridge.pay_certified(&proof, &cert),
        Ok(Instruction::Pay { .. })
    ));

    // The operator fabricates a validly signed checkpoint for the same slot with an inflated withdrawal.
    let mut fake = proof.clone();
    fake.receipt.status = Status::Withdrawn {
        base: 0,
        quote: 1 << 30,
    };
    fake.index = 0;
    fake.path.clear();
    fake.checkpoint.receipts = 1;
    fake.checkpoint.receipts_root = fake.receipt.leaf();
    fake.checkpoint.sig = operator().sign(&fake.checkpoint.digest()).to_bytes();
    assert!(fake.verify(&operator().verifying_key()));
    let (cert, refusals) = certify_with(&certs, &fake.checkpoint, 3);
    assert!(cert.is_none());
    assert!(
        refusals
            .iter()
            .all(|e| matches!(e, CertifyError::Mismatch { .. })),
        "{refusals:?}"
    );
    // … for a slot nobody has replicated, and without the operator's signature.
    let mut future = proof.checkpoint;
    future.slot = 10_000;
    future.sig = operator().sign(&future.digest()).to_bytes();
    assert!(matches!(
        certs[0].certify(&future),
        Err(CertifyError::NotYetReplicated { slot: 10_000 })
    ));
    let mut unsigned = proof.checkpoint;
    unsigned.sig = [7; 64];
    assert!(matches!(
        certs[0].certify(&unsigned),
        Err(CertifyError::NotOperatorSigned)
    ));
    for d in [&de, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn a_certifier_signs_one_checkpoint_per_slot_across_restarts() {
    let (da, db, dc) = (dir("a"), dir("b"), dir("c"));
    let g = genesis();
    // Two different histories under the same operator key: the operator equivocates.
    let run = |d: &PathBuf, seed: u64| {
        let (mut p, _) = Pipeline::open(d, cfg(), &g, operator(), None).unwrap();
        let mut t = Traffic::new(seed);
        (1..=5)
            .filter_map(|s| p.process_slot(s, &t.slot(s, 20)).unwrap().checkpoint)
            .collect::<Vec<_>>()
    };
    let (ca, cb) = (run(&da, 3), run(&db, 4));
    assert!(!ca[0].same_body(&cb[0]));
    // The certifier holds history A and signs slot 1.
    std::fs::copy(da.join("journal.bin"), dc.join("journal.bin")).unwrap();
    let open =
        || Certifier::open(&dc, cfg(), &g, operator().verifying_key(), validator(0), 0).unwrap();
    let mut c = open();
    let s1 = c.certify(&ca[0]).unwrap();
    assert!(matches!(
        c.certify(&cb[0]),
        Err(CertifyError::Mismatch { slot: 1 })
    ));
    drop(c);
    // Restart: the same derivation, the same signature (Ed25519 is deterministic).
    let mut c = open();
    assert_eq!(c.derived(1).map(|x| x.digest()), Some(ca[0].digest()));
    assert_eq!(c.certify(&ca[0]).unwrap(), s1);
    drop(c);
    // Its journal is replaced by history B (a corrupted or substituted replica): it now reproduces B's slot 1, but it
    // has already signed A's slot 1 and refuses a second checkpoint for that slot.
    std::fs::copy(db.join("journal.bin"), dc.join("journal.bin")).unwrap();
    let mut c = open();
    assert!(c.derived(1).unwrap().same_body(&cb[0]));
    assert!(matches!(
        c.certify(&cb[0]),
        Err(CertifyError::AlreadySignedOther { slot: 1 })
    ));
    assert!(c.certify(&cb[1]).is_ok(), "other slots are unaffected");
    for d in [&da, &db, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn a_certifier_refuses_a_journal_with_a_forged_entry() {
    // A journal that chains correctly but carries an order whose signature does not verify: a certifier must not
    // derive (and so never sign) any checkpoint from it.
    let d = dir("forged");
    let (mut j, _) = nimbus_journal::Journal::open(&d.join("journal.bin"), usize::MAX).unwrap();
    let mut o = SignedOrder::sign(
        Intent {
            market: 0,
            acct: 1,
            side: Side::Bid,
            price: 1_000,
            qty: 5,
            tif: Tif::Gtc,
            nonce: 0,
            expiry_slot: 50,
        },
        &key(1),
    );
    o.sig[10] ^= 1;
    j.append_batch(1, &[&Entry::Order(o)]).unwrap();
    j.sync().unwrap();
    drop(j);
    let r = Certifier::open(
        &d,
        cfg(),
        &genesis(),
        operator().verifying_key(),
        validator(0),
        0,
    );
    assert!(r.is_err(), "forged entry accepted");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_retaining_certifier_stays_bounded_and_never_signs_below_its_floor() {
    const RETAIN: u64 = 8;
    let (de, dc, db) = (dir("ret-engine"), dir("ret-cert"), dir("ret-b"));
    let g = genesis();
    let open = || {
        Certifier::open_retaining(
            &dc,
            cfg(),
            &g,
            operator().verifying_key(),
            validator(0),
            0,
            RETAIN,
        )
        .unwrap()
    };
    let cert = SharedCertifier::new(open());
    let (mut p, _) = Pipeline::open(&de, cfg(), &g, operator(), None).unwrap();
    p.attach_replicas(vec![Box::new(cert.clone())], 1).unwrap();
    let mut t = Traffic::new(5);
    let mut cks = Vec::new();
    for slot in 1..=200 {
        let ck = p
            .process_slot(slot, &t.slot(slot, 10))
            .unwrap()
            .checkpoint
            .unwrap();
        cert.certify(&ck).unwrap();
        cks.push(ck);
        let c = cert.0.lock().unwrap();
        assert!(c.retained() as u64 <= RETAIN);
        assert_eq!(c.floor(), (slot + 1).saturating_sub(RETAIN));
        let disk = std::fs::metadata(dc.join("signed.bin")).unwrap().len();
        assert!(
            disk <= (2 * RETAIN + 64 + 1) * 56,
            "signed.bin {disk} B at slot {slot}"
        );
    }
    drop(p);
    assert!(matches!(
        cert.certify(&cks[0]),
        Err(CertifyError::Pruned {
            slot: 1,
            floor: 193
        })
    ));
    let last = cert.certify(&cks[199]).unwrap();
    drop(cert);
    // Restart: the same window, the same signature for a retained slot.
    let mut c = open();
    assert_eq!((c.floor(), c.retained() as u64), (193, RETAIN));
    assert_eq!(c.certify(&cks[199]).unwrap(), last);
    drop(c);
    // The journal is replaced by a 5-slot history B (substituted replica). Its slots lie below the durable floor:
    // refused, although their signing records were compacted away and B's bodies are re-derived.
    let (mut pb, _) = Pipeline::open(&db, cfg(), &g, operator(), None).unwrap();
    let mut tb = Traffic::new(6);
    let cb: Vec<_> = (1..=5)
        .filter_map(|s| pb.process_slot(s, &tb.slot(s, 10)).unwrap().checkpoint)
        .collect();
    drop(pb);
    std::fs::copy(db.join("journal.bin"), dc.join("journal.bin")).unwrap();
    let mut c = open();
    assert!(c.floor() > 5, "the floor did not fall with the journal");
    for ck in &cb {
        assert!(matches!(c.certify(ck), Err(CertifyError::Pruned { .. })));
    }
    for d in [&de, &dc, &db] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn retained_signing_records_survive_compaction_and_restart() {
    const RETAIN: u64 = 8;
    let (de, db, dc) = (dir("cmp-engine"), dir("cmp-b"), dir("cmp-cert"));
    let g = genesis();
    let open = || {
        Certifier::open_retaining(
            &dc,
            cfg(),
            &g,
            operator().verifying_key(),
            validator(0),
            0,
            RETAIN,
        )
        .unwrap()
    };
    let records = || std::fs::metadata(dc.join("signed.bin")).map_or(0, |m| m.len() / 56);
    // Live: the certifier replicates history A and signs every slot, until the first slot whose replication
    // compacted signed.bin (more than 2 × 8 + 64 records): the retained records then come from the compacted file.
    let cert = SharedCertifier::new(open());
    let (mut p, _) = Pipeline::open(&de, cfg(), &g, operator(), None).unwrap();
    p.attach_replicas(vec![Box::new(cert.clone())], 1).unwrap();
    let mut t = Traffic::new(21);
    let mut n = 0;
    for slot in 1..=200 {
        let before = records();
        let ck = p
            .process_slot(slot, &t.slot(slot, 10))
            .unwrap()
            .checkpoint
            .unwrap();
        cert.certify(&ck).unwrap();
        if records() < before {
            n = slot;
            break;
        }
    }
    assert!(n > 0, "signed.bin was never compacted");
    assert_eq!(
        records(),
        RETAIN,
        "the compacted file holds the retained records"
    );
    drop((p, cert));
    // History B: an equivocating n-slot history under the same operator key replaces the certifier's journal.
    let (mut pb, _) = Pipeline::open(&db, cfg(), &g, operator(), None).unwrap();
    let mut tb = Traffic::new(22);
    let cb: Vec<_> = (1..=n)
        .map(|s| {
            pb.process_slot(s, &tb.slot(s, 10))
                .unwrap()
                .checkpoint
                .unwrap()
        })
        .collect();
    drop(pb);
    std::fs::copy(db.join("journal.bin"), dc.join("journal.bin")).unwrap();
    let mut c = open();
    assert_eq!(c.floor(), n - RETAIN + 1);
    // Every retained slot of A was signed and its record kept through compaction: B's checkpoints are refused.
    for ck in &cb[(n - RETAIN) as usize..] {
        assert!(c.derived(ck.slot).unwrap().same_body(ck));
        assert!(
            matches!(c.certify(ck), Err(CertifyError::AlreadySignedOther { .. })),
            "slot {}",
            ck.slot
        );
    }
    for d in [&de, &db, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn a_certifier_resumes_from_its_snapshot_and_keeps_certifying() {
    const RETAIN: u64 = 32;
    let (de, dc, df) = (dir("snap-engine"), dir("snap-cert"), dir("snap-full"));
    let g = genesis();
    let open = |d: &PathBuf| {
        Certifier::open_retaining(
            d,
            cfg(),
            &g,
            operator().verifying_key(),
            validator(0),
            0,
            RETAIN,
        )
        .unwrap()
    };
    let mut c = open(&dc);
    c.set_snapshot_every(16);
    let cert = SharedCertifier::new(c);
    let (mut p, _) = Pipeline::open(&de, cfg(), &g, operator(), None).unwrap();
    p.attach_replicas(vec![Box::new(cert.clone())], 1).unwrap();
    let mut t = Traffic::new(31);
    let mut cks = Vec::new();
    for slot in 1..=100 {
        let ck = p
            .process_slot(slot, &t.slot(slot, 20))
            .unwrap()
            .checkpoint
            .unwrap();
        cert.certify(&ck).unwrap();
        cks.push(ck);
    }
    let last = cert.certify(&cks[99]).unwrap();
    drop((p, cert));

    // Restart: resumes at the newest snapshot (slots 16, 32, …, 96), not from genesis, and re-derives exactly what
    // a certifier replaying the whole journal derives.
    std::fs::copy(dc.join("journal.bin"), df.join("journal.bin")).unwrap();
    let full = open(&df);
    assert_eq!(full.resumed_from(), None);
    let mut c = open(&dc);
    assert_eq!(c.resumed_from(), Some(96));
    for ck in &cks[(100 - RETAIN as usize)..] {
        assert_eq!(
            c.derived(ck.slot),
            full.derived(ck.slot),
            "slot {}",
            ck.slot
        );
        assert!(c.derived(ck.slot).unwrap().same_body(ck));
    }
    assert_eq!(c.certify(&cks[99]).unwrap(), last);
    c.set_snapshot_every(16);

    // It keeps replicating from the resumed journal: the restarted engine ships 30 more slots, all certified.
    let cert = SharedCertifier::new(c);
    let (mut p, _) = Pipeline::open(&de, cfg(), &g, operator(), Some(&cks[99])).unwrap();
    p.attach_replicas(vec![Box::new(cert.clone())], 1).unwrap();
    let mut t = Traffic::new(32);
    t.nonce = (0..ACCOUNTS).map(|a| p.next_nonce(a)).collect();
    for slot in 101..=130 {
        let ck = p
            .process_slot(slot, &t.slot(slot, 20))
            .unwrap()
            .checkpoint
            .unwrap();
        cert.certify(&ck).unwrap();
        cks.push(ck);
    }
    drop((p, cert));
    let c = open(&dc);
    assert_eq!(c.resumed_from(), Some(128));
    assert!(c.derived(130).unwrap().same_body(&cks[129]));
    drop(c);

    // A damaged snapshot is ignored: full replay, same derivations.
    let mut b = std::fs::read(dc.join("snapshot.bin")).unwrap();
    let n = b.len();
    b[n / 3] ^= 0x40;
    std::fs::write(dc.join("snapshot.bin"), &b).unwrap();
    let c = open(&dc);
    assert_eq!(c.resumed_from(), None);
    assert!(c.derived(130).unwrap().same_body(&cks[129]));
    for d in [&de, &dc, &df] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn a_snapshot_does_not_survive_a_substituted_journal() {
    let (da, db, dc) = (dir("sub-a"), dir("sub-b"), dir("sub-c"));
    let g = genesis();
    let run = |d: &PathBuf, seed: u64| {
        let (mut p, _) = Pipeline::open(d, cfg(), &g, operator(), None).unwrap();
        let mut t = Traffic::new(seed);
        (1..=20)
            .map(|s| {
                p.process_slot(s, &t.slot(s, 20))
                    .unwrap()
                    .checkpoint
                    .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let (ca, cb) = (run(&da, 41), run(&db, 42));
    std::fs::copy(da.join("journal.bin"), dc.join("journal.bin")).unwrap();
    let open =
        || Certifier::open(&dc, cfg(), &g, operator().verifying_key(), validator(0), 0).unwrap();
    let mut c = open();
    c.snapshot_now().unwrap();
    c.certify(&ca[19]).unwrap();
    drop(c);
    // History B of the same shape replaces the journal: the snapshot (of A) no longer matches and is not used; the
    // signing record still refuses B's checkpoint for slot 20.
    std::fs::copy(db.join("journal.bin"), dc.join("journal.bin")).unwrap();
    let mut c = open();
    assert_eq!(c.resumed_from(), None);
    assert!(c.derived(20).unwrap().same_body(&cb[19]));
    assert!(matches!(
        c.certify(&cb[19]),
        Err(CertifyError::AlreadySignedOther { slot: 20 })
    ));
    for d in [&da, &db, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}
