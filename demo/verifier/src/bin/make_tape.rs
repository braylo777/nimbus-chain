//! Replay a small trading tape through the real engine (`nimbus-pipeline`: verify → admit → journal → match →
//! receipts → checkpoint), then certify each slot's batch with a 21-validator quorum and emit, for every journaled
//! entry, a light-client finality proof. Output: JSON on stdout (the demo's `tape.json`). Deterministic keys, so the
//! tape is reproducible byte for byte.
use ed25519_dalek::{Signer, SigningKey};
use nimbus_hash::{
    audit_path, leaf_hash, merkle_root, root_from_leaf_hashes, Hash, BATCH, HISTORY,
};
use nimbus_lightclient::{header_digest, Certificate, FinalityProof, Header, ValidatorSet};
use nimbus_match::{Fees, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use std::fmt::Write as _;

const N_VALIDATORS: usize = 21;

fn key(a: u32) -> SigningKey {
    let mut s = [42u8; 32];
    s[..4].copy_from_slice(&a.to_be_bytes());
    SigningKey::from_bytes(&s)
}
fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}
fn js(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn order(a: u32, side: Side, price: u64, qty: u64, tif: Tif, nonce: u64) -> Entry {
    Entry::Order(SignedOrder::sign(
        Intent {
            market: 0,
            acct: a,
            side,
            price,
            qty,
            tif,
            nonce,
            expiry_slot: 50,
        },
        &key(a),
    ))
}
fn action(a: u32, kind: ActionKind, nonce: u64) -> Entry {
    Entry::Action(SignedAction::sign(
        Action {
            market: 0,
            acct: a,
            nonce,
            expiry_slot: 50,
            kind,
        },
        &key(a),
    ))
}

fn describe(e: &Entry) -> String {
    match e {
        Entry::Order(o) => {
            let i = o.intent;
            format!(
                "agent {} {} {} @ {} {:?}",
                i.acct,
                if i.side == Side::Bid { "bids" } else { "asks" },
                i.qty,
                i.price,
                i.tif
            )
        }
        Entry::Action(a) => match a.action.kind {
            ActionKind::Cancel { order_id } => {
                format!("agent {} cancels order #{order_id}", a.action.acct)
            }
            ActionKind::Withdraw { base, quote } => format!(
                "agent {} withdraws {base} base, {quote} quote",
                a.action.acct
            ),
        },
        Entry::Bridge(_) => "bridge operation".into(),
        Entry::Tick => "tick".into(),
    }
}

fn receipt_text(r: &Receipt) -> String {
    match &r.status {
        Status::Executed {
            id,
            filled,
            notional,
            resting,
            ..
        } => format!(
            "agent {}: order #{id} filled {filled} (notional {notional}), resting {resting}",
            r.acct
        ),
        Status::MakerFill {
            order_id,
            price,
            qty,
            ..
        } => format!("agent {}: maker #{order_id} traded {qty} @ {price}", r.acct),
        Status::Cancelled { id, released } => {
            format!(
                "agent {}: order #{id} cancelled, {released} released",
                r.acct
            )
        }
        Status::Withdrawn { base, quote } => {
            format!("agent {}: withdrew {base} base, {quote} quote", r.acct)
        }
        Status::Deposited { base, quote } => {
            format!("agent {}: deposited {base} base, {quote} quote", r.acct)
        }
        Status::Registered => format!("agent {}: registered", r.acct),
        Status::Rejected(x) => format!("agent {}: rejected {x:?}", r.acct),
    }
}

fn main() {
    let dir = std::env::temp_dir().join(format!("nimbus-tape-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let operator = SigningKey::from_bytes(&[1; 32]);
    let g = Genesis {
        accounts: (0..4).map(|a| (a, key(a).verifying_key())).collect(),
        deposits: (0..4).map(|a| (0, a, 1_000, 1_000_000)).collect(),
        fees: Fees {
            maker_bps: 0,
            taker_bps: 10,
            collector: 99,
            maker_rebate_bps: 2,
        },
        ..Genesis::default()
    };
    let cfg = Config {
        markets: 1,
        max_life: 100,
        fsync: true,
        min_batch: 1,
    };
    let (mut p, _) = Pipeline::open(&dir, cfg, &g, operator.clone(), None).expect("engine");
    let slots: Vec<Vec<Entry>> = vec![
        vec![
            order(0, Side::Ask, 101, 10, Tif::Gtc, 0),
            order(1, Side::Ask, 100, 5, Tif::Gtc, 0),
            order(2, Side::Bid, 99, 3, Tif::Gtc, 0),
        ],
        vec![
            order(3, Side::Bid, 101, 8, Tif::Ioc, 0),
            order(2, Side::Bid, 98, 4, Tif::PostOnly, 1),
        ],
        vec![
            action(2, ActionKind::Cancel { order_id: 3 }, 2),
            order(1, Side::Bid, 102, 20, Tif::Fok, 1),
            action(
                1,
                ActionKind::Withdraw {
                    base: 0,
                    quote: 500,
                },
                2,
            ),
        ],
        vec![
            order(3, Side::Ask, 98, 6, Tif::Gtc, 1),
            order(0, Side::Bid, 101, 2, Tif::Gtc, 1),
        ],
    ];

    let validators: Vec<SigningKey> = (0..N_VALIDATORS as u8)
        .map(|i| SigningKey::from_bytes(&[200u8.wrapping_add(i); 32]))
        .collect();
    let set = ValidatorSet::new(
        &validators
            .iter()
            .map(|k| k.verifying_key())
            .collect::<Vec<_>>(),
    )
    .expect("set");
    let q = set.quorum();

    let mut prev: Hash = [0; 48];
    let mut certified: Vec<Hash> = Vec::new();
    let mut out = String::from("{\n");
    let _ = writeln!(
        out,
        " \"about\": {},",
        js("Replayed through nimbus-pipeline v0.18 (verify, admit, journal + fsync, match, receipts, checkpoint); each slot's journaled entries certified by 17 of 21 validators. Deterministic keys: demo only.")
    );
    let _ = writeln!(out, " \"quorum\": {q},");
    let _ = writeln!(
        out,
        " \"validators\": [{}],",
        validators
            .iter()
            .map(|k| js(&hex(&k.verifying_key().to_bytes())))
            .collect::<Vec<_>>()
            .join(",")
    );
    out.push_str(" \"slots\": [\n");
    let mut first = true;
    let mut journal_seen = 0usize;
    for (s, entries) in slots.iter().enumerate() {
        let slot = s as u64 + 1;
        let subs: Vec<Vec<u8>> = entries.iter().map(|e| e.to_bytes()).collect();
        let r = p.process_slot(slot, &subs).expect("slot");
        let ck = r.checkpoint.expect("checkpoint");
        // Every receipt's proof checks against the operator key (what an agent does offline).
        for k in 0..r.receipts.len() {
            assert!(r.proof(k).unwrap().verify(&operator.verifying_key()));
        }
        // The batch = this slot's journaled entries, in journal order.
        let (_, rec) =
            nimbus_journal::Journal::open(&dir.join("journal.bin"), usize::MAX).expect("journal");
        let ops: Vec<Vec<u8>> = rec.records[journal_seen..]
            .iter()
            .map(|x| x.entry.to_bytes())
            .collect();
        let descs: Vec<String> = rec.records[journal_seen..]
            .iter()
            .map(|x| describe(&x.entry))
            .collect();
        journal_seen = rec.records.len();
        let leaves: Vec<Hash> = ops.iter().map(|o| leaf_hash(BATCH, o)).collect();
        let header = Header {
            height: slot,
            rank: 0,
            batch_root: root_from_leaf_hashes(BATCH, &leaves),
            prev,
            history: merkle_root(HISTORY, &certified),
        }
        .encode()
        .to_vec();
        let d = header_digest(&header);
        prev = d;
        certified.push(d);
        let sigs: Vec<(u16, [u8; 64])> = (0..q)
            .map(|i| (i as u16, validators[i].sign(&d).to_bytes()))
            .collect();
        if !first {
            out.push_str(",\n");
        }
        first = false;
        let _ = write!(
            out,
            "  {{\"slot\": {slot}, \"checkpoint\": {{\"journal_len\": {}, \"receipts\": {}, \"receipts_root\": {}}},\n   \"receipts\": [{}],\n   \"entries\": [",
            ck.journal.len,
            ck.receipts,
            js(&hex(&ck.receipts_root[..12])),
            r.receipts.iter().map(|x| js(&receipt_text(x))).collect::<Vec<_>>().join(", ")
        );
        for (i, op) in ops.iter().enumerate() {
            let proof = FinalityProof {
                op: op.clone(),
                index: i as u64,
                batch_size: ops.len() as u64,
                path: audit_path(BATCH, &leaves, i),
                header: header.clone(),
                cert: Certificate { sigs: sigs.clone() },
            };
            assert_eq!(set.verify(&proof).expect("native verify").height, slot);
            let b = proof.encode();
            let _ = write!(
                out,
                "{}\n    {{\"text\": {}, \"bytes\": {}, \"proof\": {}}}",
                if i == 0 { "" } else { "," },
                js(&descs[i]),
                b.len(),
                js(&hex(&b))
            );
        }
        out.push_str("]}");
    }
    out.push_str("\n ]\n}\n");
    print!("{out}");
    let _ = std::fs::remove_dir_all(&dir);
}
