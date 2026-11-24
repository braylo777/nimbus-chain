//! Domain-registry vectors for the paper's Lemma 9″ table (domains 0x09–0x11): for each message type the exact hash
//! input the code produces and its SHA-384 digest, plus a real journal file. Written as JSON to $REGISTRY_VECTORS
//! (if set) so an independent checker can parse every input with the paper's layout table alone.
use ed25519_dalek::SigningKey;
use nimbus_feed::Observation;
use nimbus_hash::{hash_tagged, node_hash};
use nimbus_journal::Journal;
use nimbus_match::{Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use sha2::{Digest, Sha384};

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn registry_vectors_match_the_layout_table() {
    let k = SigningKey::from_bytes(&[5; 32]);
    let intent = Intent {
        market: 3,
        acct: 7,
        side: Side::Ask,
        price: 1_001,
        qty: 25,
        tif: Tif::Ioc,
        nonce: 9,
        expiry_slot: 40,
    };
    let cancel = Action {
        market: 3,
        acct: 7,
        nonce: 10,
        expiry_slot: 41,
        kind: ActionKind::Cancel { order_id: 12 },
    };
    let withdraw = Action {
        market: 3,
        acct: 7,
        nonce: 11,
        expiry_slot: 42,
        kind: ActionKind::Withdraw { base: 5, quote: 6 },
    };
    let deposit = BridgeOp {
        reference: [8; 32],
        expiry_slot: 43,
        kind: BridgeKind::Deposit {
            market: 3,
            acct: 7,
            base: 1,
            quote: 2,
        },
    };
    let register = BridgeOp {
        reference: [9; 32],
        expiry_slot: 44,
        kind: BridgeKind::Register {
            acct: 8,
            key: k.verifying_key().to_bytes(),
        },
    };
    let obs = Observation {
        market: 3,
        price: 1_000,
        slot: 45,
        time_ms: 1_700_000_000_000,
    };
    let mut vectors = Vec::new();
    let mut push = |tag: u8, name: &str, body: Vec<u8>| {
        let digest = hash_tagged(tag, &[&body]);
        let mut input = vec![tag];
        input.extend_from_slice(&body);
        assert_eq!(
            Sha384::digest(&input).as_slice(),
            &digest[..],
            "H(tag ‖ body) is plain SHA-384 of the input"
        );
        vectors.push(format!(
            "{{\"tag\":{tag},\"name\":\"{name}\",\"input\":\"{}\",\"digest\":\"{}\"}}",
            hexs(&input),
            hexs(&digest)
        ));
    };
    push(0x09, "order intent", intent.encode().to_vec());
    push(0x0A, "feed observation", obs.encode().to_vec());
    push(0x0F, "action: cancel", cancel.encode().to_vec());
    push(0x0F, "action: withdraw", withdraw.encode().to_vec());
    push(0x10, "bridge: deposit", deposit.encode().to_vec());
    push(0x10, "bridge: register", register.encode().to_vec());
    assert_eq!(intent.digest(), hash_tagged(0x09, &[&intent.encode()]));
    assert_eq!(cancel.digest(), hash_tagged(0x0F, &[&cancel.encode()]));
    assert_eq!(deposit.digest(), hash_tagged(0x10, &[&deposit.encode()]));
    assert_eq!(obs.digest(), hash_tagged(0x0A, &[&obs.encode()]));

    // Run a short pipeline to obtain real receipts, a checkpoint and a journal.
    let dir = std::env::temp_dir().join(format!("nimbus-registry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let bridge: Vec<SigningKey> = (60..63u8)
        .map(|b| SigningKey::from_bytes(&[b; 32]))
        .collect();
    let g = Genesis {
        accounts: vec![
            (7, k.verifying_key()),
            (1, SigningKey::from_bytes(&[6; 32]).verifying_key()),
        ],
        deposits: vec![(3, 7, 1_000, 100_000), (3, 1, 1_000, 100_000)],
        bridge: bridge.iter().map(|b| b.verifying_key()).collect(),
        bridge_threshold: 2,
        deposit_cap: None,
        fees: nimbus_match::Fees {
            maker_bps: 0,
            taker_bps: 5,
            collector: 99,
            maker_rebate_bps: 2,
        },
    };
    let cfg = Config {
        markets: 4,
        max_life: 100,
        fsync: true,
        min_batch: 16,
    };
    let (mut p, _) = Pipeline::open(
        &dir,
        cfg.clone(),
        &g,
        SigningKey::from_bytes(&[4; 32]),
        None,
    )
    .unwrap();
    let bid = Intent {
        acct: 1,
        side: Side::Bid,
        tif: Tif::Gtc,
        nonce: 0,
        qty: 10,
        ..intent
    };
    let subs = vec![
        Entry::Order(SignedOrder::sign(bid, &SigningKey::from_bytes(&[6; 32]))).to_bytes(),
        Entry::Order(SignedOrder::sign(Intent { nonce: 0, ..intent }, &k)).to_bytes(),
        Entry::Bridge(SignedBridge::sign(
            deposit,
            &[(0, &bridge[0]), (2, &bridge[2])],
        ))
        .to_bytes(),
    ];
    let r = p.process_slot(5, &subs).unwrap();
    assert!(r.decisions.iter().all(|d| d.is_ok()));
    for (i, rc) in r.receipts.iter().enumerate() {
        push(0x0D, &format!("receipt leaf {i}"), rc.encode());
        assert_eq!(rc.leaf(), hash_tagged(0x0D, &[&rc.encode()]));
    }
    let (l, rr) = (r.receipts[0].leaf(), r.receipts[1].leaf());
    let node = node_hash(RECEIPTS, &l, &rr);
    let mut body = l.to_vec();
    body.extend_from_slice(&rr);
    assert_eq!(node, hash_tagged(0x0E, &[&body]));
    push(0x0E, "receipt node", body);
    let ck = r.checkpoint.unwrap();
    push(
        0x0C,
        "checkpoint",
        ck.to_bytes()[..CHECKPOINT_BODY].to_vec(),
    );
    assert_eq!(
        ck.digest(),
        hash_tagged(0x0C, &[&ck.to_bytes()[..CHECKPOINT_BODY]])
    );
    // Replication statements (0x11) over the real anchors of this slot.
    let from = nimbus_journal::Anchor {
        len: 0,
        head: nimbus_journal::genesis_chain(),
    };
    for (role, name) in [
        (nimbus_journal::ROLE_SHIP, "replication: ship"),
        (nimbus_journal::ROLE_ACK, "replication: ack"),
        (nimbus_journal::ROLE_HELLO, "replication: hello"),
    ] {
        let to = if role == nimbus_journal::ROLE_HELLO {
            from
        } else {
            ck.journal
        };
        let body = nimbus_journal::replication_body(role, 3, &from, &to);
        assert_eq!(
            nimbus_journal::replication_digest(role, 3, &from, &to),
            hash_tagged(0x11, &[&body])
        );
        push(0x11, name, body.to_vec());
    }
    drop(p);
    let journal = std::fs::read(dir.join("journal.bin")).unwrap();
    let (_, rec) = Journal::open(&dir.join("journal.bin"), 1).unwrap();
    assert_eq!(rec.records.len(), 3);
    // Replay-state snapshot (0x12) after slot 5, carrying the slot's checkpoint body as its window.
    let mut rp = Replayer::new(cfg, &g).unwrap();
    let derived = rp.apply_slot(&rec.records, ck.journal).unwrap();
    assert!(derived.same_body(&ck));
    let snap = rp.snapshot(journal.len() as u64, &[derived]);
    let (body, digest) = snap.split_at(snap.len() - 48);
    assert_eq!(hash_tagged(0x12, &[body]).as_slice(), digest);
    push(0x12, "replay snapshot", body.to_vec());
    if let Ok(path) = std::env::var("REGISTRY_VECTORS") {
        let json = format!(
            "{{\"vectors\":[{}],\"journal_hex\":\"{}\",\"journal_head\":\"{}\",\"checkpoint_journal_head\":\"{}\"}}",
            vectors.join(","),
            hexs(&journal),
            hexs(&rec.head),
            hexs(&ck.journal.head)
        );
        std::fs::write(path, json).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
