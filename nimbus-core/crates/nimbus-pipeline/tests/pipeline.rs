//! Pipeline tests: the parallel batch-verifying pipeline against an independent sequential reference (single
//! verification, one market at a time, expiry by sorting a Vec), receipt proofs, recovery and anchoring.
use ed25519_dalek::SigningKey;
use nimbus_hash::Hash;
use nimbus_match::{Balance, Exchange, Op, Outcome, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::path::{Path, PathBuf};

const MARKETS: u32 = 4;
const ACCOUNTS: u32 = 12;
const MAX_LIFE: u64 = 40;
/// Receives every fee (not a trading account).
const COLLECTOR: u32 = 900;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nimbus-pipeline-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn acct_key(a: u32) -> SigningKey {
    let mut s = [0u8; 32];
    s[..4].copy_from_slice(&a.to_be_bytes());
    s[31] = 1;
    SigningKey::from_bytes(&s)
}
fn operator() -> SigningKey {
    SigningKey::from_bytes(&[200; 32])
}
/// Three bridge keys; operations need two of them.
fn bridge_keys() -> Vec<SigningKey> {
    (201..204u8)
        .map(|b| SigningKey::from_bytes(&[b; 32]))
        .collect()
}
fn bsign(op: BridgeOp) -> SignedBridge {
    let ks = bridge_keys();
    SignedBridge::sign(op, &[(0, &ks[0]), (2, &ks[2])])
}

fn genesis(quote: u128) -> Genesis {
    Genesis {
        accounts: (0..ACCOUNTS)
            .map(|a| (a, acct_key(a).verifying_key()))
            .collect(),
        deposits: (0..MARKETS)
            .flat_map(|m| (0..ACCOUNTS).map(move |a| (m, a, 5_000u128, quote)))
            .collect(),
        bridge: bridge_keys().iter().map(|k| k.verifying_key()).collect(),
        bridge_threshold: 2,
        deposit_cap: None,
        fees: nimbus_match::Fees {
            maker_bps: 0,
            taker_bps: 5,
            collector: COLLECTOR,
            maker_rebate_bps: 2,
        },
    }
}

fn cfg() -> Config {
    Config {
        markets: MARKETS,
        max_life: MAX_LIFE,
        fsync: true,
        min_batch: 16,
    }
}

fn order_bytes(i: Intent) -> Vec<u8> {
    Entry::Order(SignedOrder::sign(i, &acct_key(i.acct))).to_bytes()
}

/// Client-side view used to generate plausible traffic: known accounts and their next nonces.
struct Clients {
    accounts: Vec<u32>,
    nonces: std::collections::HashMap<u32, u64>,
    next_account: u32,
    refs: u64,
    used_refs: Vec<[u8; 32]>,
    last_valid: Option<Vec<u8>>,
    /// Resting orders learned from receipts, as agents would: (account, market, order id).
    resting: Vec<(u32, u32, u64)>,
}

impl Clients {
    fn new() -> Self {
        Clients {
            accounts: (0..ACCOUNTS).collect(),
            nonces: (0..ACCOUNTS).map(|a| (a, 0)).collect(),
            next_account: 1_000,
            refs: 0,
            used_refs: Vec::new(),
            last_valid: None,
            resting: Vec::new(),
        }
    }
    fn learn(&mut self, receipts: &[Receipt]) {
        for r in receipts {
            if let (Status::Executed { id, resting, .. }, Some(m)) = (&r.status, r.market) {
                if *resting > 0 {
                    self.resting.push((r.acct, m, *id));
                }
            }
        }
        if self.resting.len() > 2_000 {
            self.resting.drain(..1_000);
        }
    }
    fn fresh_ref(&mut self) -> [u8; 32] {
        self.refs += 1;
        let mut r = [0u8; 32];
        r[..8].copy_from_slice(&self.refs.to_be_bytes());
        self.used_refs.push(r);
        r
    }
    fn take_nonce(&mut self, a: u32) -> u64 {
        let n = self.nonces.entry(a).or_insert(0);
        *n += 1;
        *n - 1
    }

    /// One slot of mixed traffic, including refused input of every kind.
    fn slot(&mut self, rng: &mut StdRng, slot: u64, n: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            // Mostly funded genesis accounts; cancels usually target an order learned from receipts.
            let kind = rng.gen_range(0..100);
            let known = (13..=20).contains(&kind) && !self.resting.is_empty() && rng.gen_bool(0.8);
            let (a, market, cancel_id) = if known {
                let (a, m, id) = self
                    .resting
                    .swap_remove(rng.gen_range(0..self.resting.len()));
                (a, m, id)
            } else if rng.gen_bool(0.85) {
                (
                    rng.gen_range(0..ACCOUNTS),
                    rng.gen_range(0..MARKETS),
                    rng.gen_range(1..80),
                )
            } else {
                (
                    self.accounts[rng.gen_range(0..self.accounts.len())],
                    rng.gen_range(0..MARKETS),
                    rng.gen_range(1..80),
                )
            };
            let peek = self.nonces[&a];
            let intent = Intent {
                market,
                acct: a,
                side: if rng.gen_bool(0.5) {
                    Side::Bid
                } else {
                    Side::Ask
                },
                price: rng.gen_range(95..106),
                qty: rng.gen_range(1..400),
                tif: match rng.gen_range(0..8) {
                    0 | 1 => Tif::Ioc,
                    2 => Tif::Fok,
                    3 => Tif::PostOnly,
                    _ => Tif::Gtc,
                },
                nonce: peek,
                expiry_slot: slot + rng.gen_range(0..8),
            };
            let action = |kind| Action {
                market: intent.market,
                acct: a,
                nonce: peek,
                expiry_slot: slot + 5,
                kind,
            };
            let deposit = |r: [u8; 32], to: u32| BridgeOp {
                reference: r,
                expiry_slot: slot + 5,
                kind: BridgeKind::Deposit {
                    market: intent.market,
                    acct: to,
                    base: 50,
                    quote: 20_000,
                },
            };
            let bytes = match kind {
                0..=3 => {
                    let mut o = SignedOrder::sign(intent, &acct_key(a));
                    o.sig[10] ^= 1; // bad signature
                    Entry::Order(o).to_bytes()
                }
                4..=6 => self.last_valid.clone().unwrap_or_else(|| vec![0, 1, 2]), // replay
                7 => order_bytes(Intent {
                    market: MARKETS + 2,
                    ..intent
                }), // unknown market
                8 => order_bytes(Intent {
                    expiry_slot: slot.saturating_sub(1),
                    ..intent
                }),
                9 => order_bytes(Intent {
                    expiry_slot: slot + MAX_LIFE + 1,
                    ..intent
                }),
                10 => (0..rng.gen_range(0..200)).map(|_| rng.gen()).collect(), // garbage
                11 => Entry::Order(SignedOrder::sign(intent, &acct_key(a + 1))).to_bytes(), // wrong key
                12 => Entry::Tick.to_bytes(), // ticks are engine-internal
                13..=20 => {
                    self.take_nonce(a);
                    Entry::Action(SignedAction::sign(
                        action(ActionKind::Cancel {
                            order_id: cancel_id,
                        }),
                        &acct_key(a),
                    ))
                    .to_bytes()
                }
                21..=24 => {
                    self.take_nonce(a);
                    let k = ActionKind::Withdraw {
                        base: rng.gen_range(0..40),
                        quote: rng.gen_range(1..9_000),
                    };
                    Entry::Action(SignedAction::sign(action(k), &acct_key(a))).to_bytes()
                }
                25..=28 => {
                    let r = self.fresh_ref();
                    Entry::Bridge(bsign(deposit(r, a))).to_bytes()
                }
                29 => {
                    // Duplicate reference (refused), unless none exists yet.
                    let r = self.used_refs.first().copied().unwrap_or([0xAB; 32]);
                    Entry::Bridge(bsign(deposit(r, a))).to_bytes()
                }
                30 => {
                    let r = [0xEE; 32];
                    Entry::Bridge(SignedBridge::sign(
                        deposit(r, a),
                        &[(0, &acct_key(a)), (1, &acct_key(a + 1))],
                    ))
                    .to_bytes()
                    // not the bridge key
                }
                31..=32 => {
                    // Register a new account; it may trade later in this very slot.
                    let new = self.next_account;
                    self.next_account += 1;
                    self.accounts.push(new);
                    self.nonces.insert(new, 0);
                    let r = self.fresh_ref();
                    let op = BridgeOp {
                        reference: r,
                        expiry_slot: slot + 5,
                        kind: BridgeKind::Register {
                            acct: new,
                            key: acct_key(new).verifying_key().to_bytes(),
                        },
                    };
                    Entry::Bridge(bsign(op)).to_bytes()
                }
                33 => {
                    // Re-registering an existing account: refused at admission, reference not consumed.
                    let r = self.fresh_ref();
                    let op = BridgeOp {
                        reference: r,
                        expiry_slot: slot + 5,
                        kind: BridgeKind::Register {
                            acct: a,
                            key: acct_key(a + 7).verifying_key().to_bytes(),
                        },
                    };
                    Entry::Bridge(bsign(op)).to_bytes()
                }
                _ => {
                    self.take_nonce(a);
                    let b = order_bytes(intent);
                    self.last_valid = Some(b.clone());
                    b
                }
            };
            out.push(bytes);
        }
        out
    }
}

/// Independent sequential reference.
struct Reference {
    adm: Admission,
    ex: Exchange,
    resting: Vec<(u64, u32, u64, u32)>, // (expiry, market, id, acct)
}

type Expired = Vec<(u32, u64, u32, u64, Balance)>;
/// Per submission: the status and post-trade balance, or None if refused.
/// Maker side of each fill: (maker account, maker order, price, qty, maker fee, maker balance after the taker's
/// order).
type Makers = Vec<(u32, u64, u64, u64, u128, u128, Balance)>;
type Want = Option<(Status, Option<Balance>, Makers)>;

impl Reference {
    fn new(g: &Genesis) -> Self {
        let mut adm = Admission::new();
        adm.set_max_life(MAX_LIFE);
        for (a, k) in &g.accounts {
            adm.register(*a, *k).unwrap();
        }
        let bk: Vec<[u8; 32]> = g.bridge.iter().map(|k| k.to_bytes()).collect();
        adm.set_bridge(&bk, g.bridge_threshold).unwrap();
        let mut ex = Exchange::new(MARKETS as usize);
        ex.set_fees(g.fees).unwrap();
        for &(m, a, b, q) in &g.deposits {
            ex.markets[m as usize].apply(&Op::Deposit {
                acct: a,
                base: b,
                quote: q,
            });
        }
        Reference {
            adm,
            ex,
            resting: Vec::new(),
        }
    }

    /// (expired orders as (market, id, acct, released, balance after), per-submission (status, balance after) or
    /// None if refused)
    fn slot(&mut self, slot: u64, subs: &[Vec<u8>]) -> (Expired, Vec<Want>) {
        self.resting.sort();
        let (due, keep): (Vec<_>, Vec<_>) = self.resting.iter().partition(|r| r.0 < slot);
        self.resting = keep;
        let mut expired = Vec::new();
        for (_, m, id, acct) in due {
            let mkt = &mut self.ex.markets[m as usize];
            if let Outcome::Cancelled { released, .. } = mkt.apply(&Op::Cancel { acct, id }) {
                expired.push((m, id, acct, released, mkt.balance(acct)));
            }
        }
        let statuses = subs
            .iter()
            .map(|b| {
                let e = Entry::from_bytes(b).ok()?;
                if e == Entry::Tick || e.subject().1.is_some_and(|m| m >= MARKETS) {
                    return None;
                }
                let items = self.adm.items_for(&e).ok()?;
                let v = verify_entry(e.clone(), &items).ok()?; // single verification
                let eff = self.adm.admit_verified(&v, slot).ok()?;
                let Effect::Market { market, op } = eff else {
                    return Some((Status::Registered, None, Vec::new()));
                };
                let mkt = &mut self.ex.markets[market as usize];
                let out = mkt.apply(&op);
                let balance = Some(mkt.balance(op.acct()));
                let makers: Makers = match &out {
                    Outcome::Placed { fills, .. } => fills
                        .iter()
                        .map(|f| {
                            (
                                f.maker_acct,
                                f.maker,
                                f.price,
                                f.qty,
                                f.maker_fee,
                                f.maker_rebate,
                                mkt.balance(f.maker_acct),
                            )
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                let status = match (op, out) {
                    (_, Outcome::Rejected(r)) => Status::Rejected(r),
                    (
                        _,
                        Outcome::Placed {
                            id,
                            fills,
                            resting,
                            self_trade_cancels,
                        },
                    ) => {
                        let Entry::Order(o) = &e else { unreachable!() };
                        if resting > 0 && o.intent.tif.rests() {
                            self.resting
                                .push((o.intent.expiry_slot, market, id, o.intent.acct));
                        }
                        let filled = fills.iter().map(|f| f.qty).sum();
                        let notional = fills.iter().map(|f| f.price as u128 * f.qty as u128).sum();
                        Status::Executed {
                            id,
                            filled,
                            notional,
                            fees: fills.iter().map(|f| f.taker_fee).sum(),
                            resting,
                            self_trade_cancels,
                            fills,
                        }
                    }
                    (_, Outcome::Cancelled { id, released }) => Status::Cancelled { id, released },
                    (Op::Deposit { base, quote, .. }, Outcome::Ok) => {
                        Status::Deposited { base, quote }
                    }
                    (Op::Withdraw { base, quote, .. }, Outcome::Ok) => {
                        Status::Withdrawn { base, quote }
                    }
                    (op, o) => panic!("{op:?} → {o:?}"),
                };
                Some((status, balance, makers))
            })
            .collect();
        (expired, statuses)
    }
}

#[derive(Default, Debug)]
struct Stats {
    admitted: usize,
    refused: usize,
    fills: usize,
    expired: usize,
    cancels: usize,
    deposits: usize,
    withdrawals: usize,
    registrations: usize,
    engine_rejects: usize,
    maker_receipts: usize,
    fees: u128,
}

fn run(
    d: &Path,
    slots: u64,
    per_slot: usize,
    seed: u64,
) -> (Pipeline, Vec<Checkpoint>, Vec<ReceiptProof>, Stats) {
    let g = genesis(600_000);
    let (mut p, rep) = Pipeline::open(d, cfg(), &g, operator(), None).unwrap();
    assert_eq!(rep.records, 0);
    let mut reference = Reference::new(&g);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut clients = Clients::new();
    let (mut cks, mut proofs, mut st) = (Vec::new(), Vec::new(), Stats::default());
    let mut fee_sum = vec![0u128; MARKETS as usize];
    for slot in 1..=slots {
        // Every seventh slot sends nothing: expiries alone must still be journaled (as a tick) and replay identically.
        let n = if slot % 7 == 0 { 0 } else { per_slot };
        let subs = clients.slot(&mut rng, slot, n);
        let r = p.process_slot(slot, &subs).unwrap();
        clients.learn(&r.receipts);
        let (want_expired, want) = reference.slot(slot, &subs);
        assert_eq!(r.decisions.len(), subs.len());
        let got_expired: Expired = r.receipts[..r.expired as usize]
            .iter()
            .map(|rc| match (rc.source, &rc.status) {
                (Source::Expiry { order_id }, Status::Cancelled { id, released }) => {
                    assert_eq!(order_id, *id);
                    (
                        rc.market.unwrap(),
                        *id,
                        rc.acct,
                        *released,
                        rc.balance.unwrap(),
                    )
                }
                other => panic!("unexpected expiry receipt {other:?}"),
            })
            .collect();
        assert_eq!(got_expired, want_expired, "expiries differ at slot {slot}");
        st.expired += got_expired.len();
        for (dcs, w) in r.decisions.iter().zip(&want) {
            match (dcs, w) {
                (Ok(i), Some((status, balance, makers))) => {
                    st.admitted += 1;
                    assert_eq!(&r.receipts[*i].status, status, "slot {slot}");
                    // The maker receipts follow the taker's, one per fill.
                    for (j, &(acct, order, price, qty, fee, rebate, bal)) in
                        makers.iter().enumerate()
                    {
                        let m = &r.receipts[*i + 1 + j];
                        assert_eq!(m.acct, acct, "maker account, slot {slot}");
                        assert_eq!(
                            m.status,
                            Status::MakerFill {
                                order_id: order,
                                price,
                                qty,
                                fee,
                                rebate
                            }
                        );
                        assert_eq!(m.balance, Some(bal), "maker balance, slot {slot}");
                        assert!(
                            matches!(m.source, Source::Fill { maker_order, .. } if maker_order == order)
                        );
                    }
                    st.maker_receipts += makers.len();
                    assert_eq!(
                        &r.receipts[*i].balance, balance,
                        "post-trade balance, slot {slot}"
                    );
                    match status {
                        Status::Executed { fills, .. } => {
                            st.fills += fills.len();
                            let m = r.receipts[*i].market.unwrap() as usize;
                            fee_sum[m] += fills
                                .iter()
                                .map(|f| f.taker_fee + f.maker_fee - f.maker_rebate)
                                .sum::<u128>();
                            st.fees += fills
                                .iter()
                                .map(|f| f.taker_fee + f.maker_fee - f.maker_rebate)
                                .sum::<u128>();
                        }
                        Status::Cancelled { .. } => st.cancels += 1,
                        Status::Deposited { .. } => st.deposits += 1,
                        Status::Withdrawn { .. } => st.withdrawals += 1,
                        Status::Registered => st.registrations += 1,
                        Status::Rejected(_) => st.engine_rejects += 1,
                        Status::MakerFill { .. } => {
                            unreachable!("maker receipts are not entry receipts")
                        }
                    }
                }
                (Err(_), None) => st.refused += 1,
                (a, b) => panic!("slot {slot}: pipeline {a:?} vs reference {b:?}"),
            }
        }
        assert_eq!(
            p.exchange().state_hash(),
            reference.ex.state_hash(),
            "state diverged at slot {slot}"
        );
        if let Some(ck) = r.checkpoint {
            assert!(
                p.journal_durable_len() >= ck.journal.len,
                "checkpoint issued before the journal was durable"
            );
            cks.push(ck);
            for i in (0..r.receipts.len()).step_by(7) {
                proofs.push(r.proof(i).unwrap());
            }
        }
    }
    for (k, m) in p.exchange().markets.iter().enumerate() {
        m.check_invariants().unwrap();
        // Conservation of fees: the collector holds exactly the fees stated in the receipts, nothing more or less.
        assert_eq!(
            m.balance(COLLECTOR).quote_free,
            fee_sum[k],
            "collector balance vs Σ receipt fees, market {k}"
        );
    }
    println!("{slots} slots: {st:?}");
    assert!(
        st.fills > 0
            && st.expired > 0
            && st.cancels > 0
            && st.deposits > 0
            && st.withdrawals > 0
            && st.registrations > 0
            && st.engine_rejects > 0
            && st.refused > 0
            && st.fees > 0,
        "workload too tame: {st:?}"
    );
    (p, cks, proofs, st)
}

#[test]
fn pipeline_equals_sequential_reference_and_every_receipt_proves() {
    let d = dir("ref");
    let slots = std::env::var("PIPELINE_SLOTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    let (p, cks, proofs, _) = run(&d, slots, 300, 1);
    let pk = p.operator_key();
    assert!(!proofs.is_empty());
    for pr in &proofs {
        assert!(pr.verify(&pk), "valid receipt proof rejected");
    }
    let mut rng = StdRng::seed_from_u64(9);
    for (n, pr) in proofs.iter().enumerate().take(600) {
        let mut bad = pr.clone();
        match n % 6 {
            0 => bad.receipt.acct ^= 1,
            1 => bad.receipt.slot += 1,
            2 => match &mut bad.receipt.status {
                Status::Executed { filled, .. } => *filled += 1,
                Status::Cancelled { released, .. } => *released += 1,
                Status::Deposited { base, .. } | Status::Withdrawn { base, .. } => *base += 1,
                _ => bad.receipt.market = Some(bad.receipt.market.unwrap_or(0) ^ 1),
            },
            3 => bad.index = (bad.index + 1) % bad.checkpoint.receipts.max(2),
            4 => {
                if bad.path.is_empty() {
                    bad.receipt.slot += 1;
                } else {
                    let j = rng.gen_range(0..bad.path.len());
                    bad.path[j][rng.gen_range(0..48)] ^= 1;
                }
            }
            _ => bad.checkpoint.receipts_root[rng.gen_range(0..48)] ^= 1,
        }
        assert!(!bad.verify(&pk), "tampered proof accepted (case {})", n % 6);
    }
    assert!(!proofs[0].verify(&SigningKey::from_bytes(&[1; 32]).verifying_key()));
    assert!(cks
        .windows(2)
        .all(|w| w[0].slot < w[1].slot && w[0].journal.len < w[1].journal.len));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn recovery_replays_to_identical_state_and_checkpoints() {
    let d = dir("recover");
    let (p, cks, proofs, _) = run(&d, 30, 200, 2);
    let hash: Hash = p.exchange().state_hash();
    let n1000 = p.next_nonce(1_000);
    drop(p);
    let last = *cks.last().unwrap();
    let (mut q, rep) =
        Pipeline::open(&d, cfg(), &genesis(600_000), operator(), Some(&last)).unwrap();
    assert_eq!(rep.checkpoints_matched, cks.len() as u64);
    assert_eq!(rep.checkpoints_rederived, 0);
    assert!(rep.external_matched);
    assert_eq!(q.exchange().state_hash(), hash);
    assert_eq!(
        q.next_nonce(1_000),
        n1000,
        "accounts registered through the bridge survive recovery"
    );
    assert!(q.admission().key(1_000).is_some());
    assert_eq!(q.latest_checkpoint(), Some(last));
    assert!(proofs[0].verify(&q.operator_key()));
    assert!(matches!(
        q.process_slot(last.slot, &[[0u8; 1]]),
        Err(PipelineError::SlotNotIncreasing { .. })
    ));
    let o = order_bytes(Intent {
        market: 0,
        acct: 3,
        side: Side::Bid,
        price: 100,
        qty: 1,
        tif: Tif::Ioc,
        nonce: q.next_nonce(3),
        expiry_slot: 999,
    });
    let r = q.process_slot(999, &[o]).unwrap();
    assert!(r.decisions[0].is_ok());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn torn_or_missing_checkpoints_are_rederived_bit_identically() {
    let d = dir("torn");
    let (p, cks, _, _) = run(&d, 20, 150, 3);
    drop(p);
    let f = d.join("checkpoints.bin");
    let b = std::fs::read(&f).unwrap();
    std::fs::write(&f, &b[..12 * CHECKPOINT_LEN + CHECKPOINT_LEN / 2]).unwrap();
    let (q, rep) = Pipeline::open(&d, cfg(), &genesis(600_000), operator(), None).unwrap();
    assert_eq!(rep.checkpoints_matched, 12);
    assert_eq!(rep.checkpoints_rederived, cks.len() as u64 - 12);
    assert_eq!(rep.checkpoints_discarded, 1);
    assert_eq!(
        std::fs::read(&f).unwrap(),
        b,
        "re-derived checkpoints must be byte-identical"
    );
    drop(q);
    let mut forged = b.clone();
    forged[5 * CHECKPOINT_LEN + 70] ^= 1;
    std::fs::write(&f, &forged).unwrap();
    let (_, rep) = Pipeline::open(&d, cfg(), &genesis(600_000), operator(), None).unwrap();
    assert_eq!(
        (rep.checkpoints_discarded, rep.checkpoints_rederived),
        (1, 1)
    );
    assert_eq!(std::fs::read(&f).unwrap(), b);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn records_cut_from_the_end_are_caught_by_an_agents_checkpoint() {
    let d = dir("cut");
    let (p, cks, _, _) = run(&d, 20, 150, 4);
    drop(p);
    let last = *cks.last().unwrap();
    let j = d.join("journal.bin");
    let b = std::fs::read(&j).unwrap();
    let offsets = nimbus_journal::Journal::open(&j, 1).unwrap().1.offsets;
    let keep = offsets[cks[10].journal.len as usize - 1] as usize;
    std::fs::write(&j, &b[..keep]).unwrap();
    assert!(matches!(
        Pipeline::open(&d, cfg(), &genesis(600_000), operator(), None),
        Err(PipelineError::Truncated { .. })
    ));
    std::fs::write(d.join("checkpoints.bin"), b"").unwrap();
    assert!(Pipeline::open(&d, cfg(), &genesis(600_000), operator(), None).is_ok());
    std::fs::write(&j, &b[..keep]).unwrap();
    std::fs::write(d.join("checkpoints.bin"), b"").unwrap();
    match Pipeline::open(&d, cfg(), &genesis(600_000), operator(), Some(&last)) {
        Err(PipelineError::Truncated { have, need, slot }) => {
            assert_eq!(
                (have, need, slot),
                (cks[10].journal.len, last.journal.len, last.slot)
            )
        }
        Err(e) => panic!("expected Truncated, got {e:?}"),
        Ok(_) => panic!("expected Truncated, got Ok"),
    }
    let mut fake = last;
    fake.sig = [7; 64];
    assert!(matches!(
        Pipeline::open(&d, cfg(), &genesis(600_000), operator(), Some(&fake)),
        Err(PipelineError::CheckpointInvalid)
    ));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_different_genesis_is_reported_as_divergence() {
    let d = dir("div");
    let (p, _, _, _) = run(&d, 15, 150, 5);
    drop(p);
    assert!(matches!(
        Pipeline::open(&d, cfg(), &genesis(1_000), operator(), None),
        Err(PipelineError::Diverged { .. } | PipelineError::ReplayRejected { .. })
    ));
    // Without the bridge key, journaled bridge operations no longer re-admit.
    let mut g = genesis(600_000);
    g.bridge.clear();
    assert!(matches!(
        Pipeline::open(&d, cfg(), &g, operator(), None),
        Err(PipelineError::ReplayRejected { .. })
    ));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn signed_cancels_withdrawals_and_expiry_ticks() {
    let d = dir("actions");
    let (mut p, _) = Pipeline::open(&d, cfg(), &genesis(600_000), operator(), None).unwrap();
    let k0 = acct_key(0);
    let ask = |nonce, expiry| {
        order_bytes(Intent {
            market: 1,
            acct: 0,
            side: Side::Ask,
            price: 100,
            qty: 10,
            tif: Tif::Gtc,
            nonce,
            expiry_slot: expiry,
        })
    };
    let act = |nonce, kind| {
        Entry::Action(SignedAction::sign(
            Action {
                market: 1,
                acct: 0,
                nonce,
                expiry_slot: 30,
                kind,
            },
            &k0,
        ))
        .to_bytes()
    };
    let r = p.process_slot(1, &[ask(0, 20), ask(1, 5)]).unwrap();
    let Status::Executed {
        id: id0,
        resting: 10,
        ..
    } = r.receipts[0].status
    else {
        panic!("{:?}", r.receipts[0])
    };
    assert_eq!(p.exchange().markets[1].balance(0).base_locked, 20);
    // Cancel the first order by signed action; cancelling it again consumes a nonce but is rejected by the engine;
    // another account cannot cancel it.
    let other = Entry::Action(SignedAction::sign(
        Action {
            market: 1,
            acct: 1,
            nonce: 0,
            expiry_slot: 30,
            kind: ActionKind::Cancel { order_id: 2 },
        },
        &acct_key(1),
    ))
    .to_bytes();
    let r = p
        .process_slot(
            2,
            &[
                act(2, ActionKind::Cancel { order_id: id0 }),
                act(3, ActionKind::Cancel { order_id: id0 }),
                other,
            ],
        )
        .unwrap();
    assert_eq!(
        r.receipts[0].status,
        Status::Cancelled {
            id: id0,
            released: 10
        }
    );
    assert_eq!(
        r.receipts[1].status,
        Status::Rejected(nimbus_match::Reject::UnknownOrder)
    );
    assert_eq!(
        r.receipts[2].status,
        Status::Rejected(nimbus_match::Reject::NotOwner)
    );
    assert_eq!(p.exchange().markets[1].balance(0).base_locked, 10);
    // Withdraw: more than free is rejected (nonce consumed), within free succeeds.
    let free = p.exchange().markets[1].balance(0).quote_free;
    let r = p
        .process_slot(
            3,
            &[
                act(
                    4,
                    ActionKind::Withdraw {
                        base: 0,
                        quote: free + 1,
                    },
                ),
                act(
                    5,
                    ActionKind::Withdraw {
                        base: 0,
                        quote: 1_000,
                    },
                ),
            ],
        )
        .unwrap();
    assert_eq!(
        r.receipts[0].status,
        Status::Rejected(nimbus_match::Reject::InsufficientBalance)
    );
    assert_eq!(
        r.receipts[1].status,
        Status::Withdrawn {
            base: 0,
            quote: 1_000
        }
    );
    assert_eq!(p.exchange().markets[1].balance(0).quote_free, free - 1_000);
    // Slot 9: no submissions, but the second order (expiry 5) expires → journaled as a tick, with a receipt.
    let before = p.journal_durable_len();
    let r = p.process_slot(9, &[] as &[Vec<u8>]).unwrap();
    assert_eq!(r.expired, 1);
    assert!(matches!(r.receipts[0].source, Source::Expiry { .. }));
    let ck = r.checkpoint.expect("an expiry-only slot is checkpointed");
    assert_eq!(p.journal_durable_len(), before + 1, "one tick record");
    assert!(r.proof(0).unwrap().verify(&p.operator_key()));
    // Nothing happens at slot 10: no journal record, no checkpoint.
    assert!(p
        .process_slot(10, &[] as &[Vec<u8>])
        .unwrap()
        .checkpoint
        .is_none());
    let hash = p.exchange().state_hash();
    drop(p);
    let (q, rep) = Pipeline::open(&d, cfg(), &genesis(600_000), operator(), Some(&ck)).unwrap();
    assert_eq!(q.exchange().state_hash(), hash);
    assert_eq!(rep.checkpoints_matched, 4);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn bridge_deposits_apply_once_and_new_accounts_trade_in_the_same_slot() {
    let d = dir("bridge");
    let (mut p, _) = Pipeline::open(&d, cfg(), &genesis(600_000), operator(), None).unwrap();
    let newbie = acct_key(5_000);
    let reg = Entry::Bridge(bsign(BridgeOp {
        reference: [1; 32],
        expiry_slot: 20,
        kind: BridgeKind::Register {
            acct: 5_000,
            key: newbie.verifying_key().to_bytes(),
        },
    }))
    .to_bytes();
    let dep = |r: u8| {
        Entry::Bridge(bsign(BridgeOp {
            reference: [r; 32],
            expiry_slot: 20,
            kind: BridgeKind::Deposit {
                market: 2,
                acct: 5_000,
                base: 0,
                quote: 10_000,
            },
        }))
        .to_bytes()
    };
    let bid = Entry::Order(SignedOrder::sign(
        Intent {
            market: 2,
            acct: 5_000,
            side: Side::Bid,
            price: 100,
            qty: 50,
            tif: Tif::Gtc,
            nonce: 0,
            expiry_slot: 20,
        },
        &newbie,
    ))
    .to_bytes();
    let r = p.process_slot(1, &[reg, dep(2), dep(2), bid]).unwrap();
    assert_eq!(r.receipts[0].status, Status::Registered);
    assert_eq!(
        r.receipts[1].status,
        Status::Deposited {
            base: 0,
            quote: 10_000
        }
    );
    assert_eq!(
        r.decisions[2],
        Err(Refusal::Entry(OrderError::DuplicateReference))
    );
    assert!(
        matches!(r.receipts[2].status, Status::Executed { .. }),
        "the new account traded in its registration slot"
    );
    // L(100, 50) = 5,000 + ⌈5,000 · 5 / 10⁴⌉ + 50 under the test's fee schedule (taker 5 bps, maker rebate 2 bps).
    assert_eq!(p.exchange().markets[2].balance(5_000).quote_locked, 5_053);
    // A reference used in an earlier slot is refused in the screen.
    let r = p.process_slot(2, &[dep(2)]).unwrap();
    assert_eq!(
        r.decisions[0],
        Err(Refusal::Entry(OrderError::DuplicateReference))
    );
    assert!(r.checkpoint.is_none());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn weak_genesis_keys_are_refused() {
    let d = dir("weak");
    let mut id = [0u8; 32];
    id[0] = 1;
    let weak = ed25519_dalek::VerifyingKey::from_bytes(&id).unwrap();
    let mut g = genesis(1);
    g.accounts[0].1 = weak;
    assert!(matches!(
        Pipeline::open(&d, cfg(), &g, operator(), None),
        Err(PipelineError::Genesis(_))
    ));
    let mut g = genesis(1);
    g.bridge = vec![weak];
    g.bridge_threshold = 1;
    assert!(matches!(
        Pipeline::open(&d, cfg(), &g, operator(), None),
        Err(PipelineError::Genesis(_))
    ));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn bridge_quorum_caps_and_post_trade_balances() {
    let d = dir("quorum");
    let mut g = genesis(600_000);
    g.deposit_cap = Some((0, 25_000));
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    let ks = bridge_keys();
    let dep = |r: u8, q: u128| BridgeOp {
        reference: [r; 32],
        expiry_slot: 20,
        kind: BridgeKind::Deposit {
            market: 1,
            acct: 3,
            base: 0,
            quote: q,
        },
    };
    let one = Entry::Bridge(SignedBridge::sign(dep(1, 10_000), &[(1, &ks[1])])).to_bytes();
    let ok = Entry::Bridge(bsign(dep(2, 20_000))).to_bytes();
    let over = Entry::Bridge(bsign(dep(3, 10_000))).to_bytes(); // 30,000 > 25,000 this slot
    let r = p.process_slot(1, &[one, ok, over.clone()]).unwrap();
    assert_eq!(
        r.decisions[0],
        Err(Refusal::Entry(OrderError::BridgeQuorum {
            have: 1,
            need: 2
        }))
    );
    assert_eq!(r.decisions[2], Err(Refusal::Entry(OrderError::DepositCap)));
    let rc = &r.receipts[0];
    assert_eq!(
        rc.status,
        Status::Deposited {
            base: 0,
            quote: 20_000
        }
    );
    assert_eq!(
        rc.balance,
        Some(p.exchange().markets[1].balance(3)),
        "receipt carries the post-trade balance"
    );
    // Next slot the cap has room again, and the refused deposit (reference unused) goes through.
    let r = p.process_slot(2, &[over]).unwrap();
    assert!(r.decisions[0].is_ok());
    assert_eq!(
        r.receipts[0].balance.unwrap().quote_free,
        p.exchange().markets[1].balance(3).quote_free
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn latency_mode_and_spin_pool_give_identical_results() {
    let (d1, d2) = (dir("thru"), dir("lat"));
    let g = genesis(600_000);
    let (mut a, _) = Pipeline::open(&d1, cfg(), &g, operator(), None).unwrap();
    let (mut b, _) = Pipeline::open(
        &d2,
        Config {
            min_batch: 1,
            ..cfg()
        },
        &g,
        operator(),
        None,
    )
    .unwrap();
    let d3 = dir("spin");
    let (mut c, _) = Pipeline::open(&d3, cfg(), &g, operator(), None).unwrap();
    c.use_spin_pool(2);
    let mut rng = StdRng::seed_from_u64(77);
    let mut clients = Clients::new();
    for slot in 1..=25 {
        let subs = clients.slot(&mut rng, slot, 120);
        let (ra, rb, rc) = (
            a.process_slot(slot, &subs).unwrap(),
            b.process_slot(slot, &subs).unwrap(),
            c.process_slot(slot, &subs).unwrap(),
        );
        clients.learn(&ra.receipts);
        assert_eq!(ra.decisions, rb.decisions);
        assert_eq!(ra.checkpoint, rb.checkpoint, "slot {slot}");
        assert_eq!(ra.decisions, rc.decisions, "spin pool");
        assert_eq!(ra.checkpoint, rc.checkpoint, "spin pool, slot {slot}");
    }
    for d in [&d1, &d2, &d3] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn pipelined_slots_equal_slot_by_slot() {
    let (d1, d2) = (dir("seq"), dir("piped"));
    let g = genesis(600_000);
    let (mut a, _) = Pipeline::open(&d1, cfg(), &g, operator(), None).unwrap();
    let (mut b, _) = Pipeline::open(&d2, cfg(), &g, operator(), None).unwrap();
    let mut rng = StdRng::seed_from_u64(99);
    let mut clients = Clients::new();
    // Generate traffic slot by slot (clients learn from the sequential run's receipts), then replay it pipelined.
    let mut slots = Vec::new();
    let mut want = Vec::new();
    for slot in 1..=40u64 {
        let subs = clients.slot(&mut rng, slot, if slot % 9 == 0 { 0 } else { 200 });
        let r = a.process_slot(slot, &subs).unwrap();
        clients.learn(&r.receipts);
        want.push((
            r.decisions.iter().map(|d| d.is_ok()).collect::<Vec<_>>(),
            r.checkpoint,
        ));
        slots.push((slot, subs));
    }
    let refs: Vec<(u64, &[Vec<u8>])> = slots.iter().map(|(s, v)| (*s, v.as_slice())).collect();
    let got = b.process_slots(&refs).unwrap();
    for (i, (r, (ok, ck))) in got.iter().zip(&want).enumerate() {
        assert_eq!(
            &r.decisions.iter().map(|d| d.is_ok()).collect::<Vec<_>>(),
            ok,
            "slot {}",
            i + 1
        );
        assert_eq!(&r.checkpoint, ck, "slot {}", i + 1);
    }
    assert_eq!(a.exchange().state_hash(), b.exchange().state_hash());
    assert!(matches!(
        b.process_slots(&refs[..1]),
        Err(PipelineError::SlotNotIncreasing { .. })
    ));
    let _ = std::fs::remove_dir_all(&d1);
    let _ = std::fs::remove_dir_all(&d2);
}

/// Accepts every batch but reports a wrong anchor: a replica that lost or altered data.
struct Diverging(nimbus_journal::Anchor);
impl Replica for Diverging {
    fn anchor(&self) -> nimbus_journal::Anchor {
        self.0
    }
    fn replicate(
        &mut self,
        _: &nimbus_journal::Anchor,
        _: &[u8],
    ) -> Result<nimbus_journal::Anchor, String> {
        self.0.len += 1;
        Ok(self.0)
    }
}

#[test]
fn replicated_journal_enforces_the_quorum_and_supports_failover() {
    use nimbus_journal::Journal;
    let (d, r0, r1) = (dir("prim"), dir("rep0"), dir("rep1"));
    let g = genesis(600_000);
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    let replica = |dd: &Path| -> Box<dyn Replica> {
        std::fs::create_dir_all(dd).unwrap();
        Box::new(
            Journal::open(&dd.join("journal.bin"), usize::MAX)
                .unwrap()
                .0,
        )
    };
    assert!(matches!(
        p.attach_replicas(vec![replica(&r0)], 2),
        Err(PipelineError::ReplicaSetup { .. })
    ));
    let bad = Diverging(p.journal_anchor());
    p.attach_replicas(vec![replica(&r0), replica(&r1), Box::new(bad)], 2)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(5);
    let mut clients = Clients::new();
    let mut last = None;
    for slot in 1..=30u64 {
        let subs = clients.slot(&mut rng, slot, if slot % 7 == 0 { 0 } else { 150 });
        let r = p.process_slot(slot, &subs).unwrap();
        clients.learn(&r.receipts);
        last = r.checkpoint.or(last);
    }
    assert_eq!(p.live_replicas(), 2, "the diverging replica was dropped");
    let last = last.unwrap();
    // Failover: either replica, opened as the engine, reproduces the latest signed checkpoint and the book.
    for rd in [&r0, &r1] {
        let (q, rep) = Pipeline::open(rd, cfg(), &g, operator(), Some(&last)).unwrap();
        assert!(rep.external_matched);
        assert_eq!(q.latest_checkpoint(), Some(last));
        assert_eq!(q.exchange().state_hash(), p.exchange().state_hash());
    }
    // A quorum of all three cannot be met once one replica diverges: the slot is not acknowledged.
    let (d2, r2) = (dir("prim2"), dir("rep2"));
    let (mut p2, _) = Pipeline::open(&d2, cfg(), &g, operator(), None).unwrap();
    let bad = Diverging(p2.journal_anchor());
    p2.attach_replicas(vec![replica(&r2), Box::new(bad)], 2)
        .unwrap();
    let subs = Clients::new().slot(&mut rng, 1, 50);
    assert!(matches!(
        p2.process_slot(1, &subs),
        Err(PipelineError::Replication { acks: 1, need: 2 })
    ));
    assert!(matches!(
        p2.process_slot(2, &subs),
        Err(PipelineError::Poisoned)
    ));
    for x in [&d, &r0, &r1, &d2, &r2] {
        let _ = std::fs::remove_dir_all(x);
    }
}

/// A replica behind a slow link: each batch takes `0` longer before it is applied and acknowledged.
struct Delayed(nimbus_journal::Journal, std::time::Duration);
impl Replica for Delayed {
    fn anchor(&self) -> nimbus_journal::Anchor {
        self.0.anchor()
    }
    fn replicate(
        &mut self,
        from: &nimbus_journal::Anchor,
        bytes: &[u8],
    ) -> Result<nimbus_journal::Anchor, String> {
        std::thread::sleep(self.1);
        self.0.replicate(from, bytes).map_err(|e| format!("{e:?}"))
    }
}

#[test]
fn windowed_replication_releases_the_blocking_results_in_order() {
    use nimbus_journal::Journal;
    use std::time::Duration;
    let (da, db, r0, r1) = (dir("wa"), dir("wb"), dir("wr0"), dir("wr1"));
    let g = genesis(600_000);
    let (mut a, _) = Pipeline::open(&da, cfg(), &g, operator(), None).unwrap();
    let (mut b, _) = Pipeline::open(&db, cfg(), &g, operator(), None).unwrap();
    let journal = |dd: &Path| {
        std::fs::create_dir_all(dd).unwrap();
        Journal::open(&dd.join("journal.bin"), usize::MAX)
            .unwrap()
            .0
    };
    assert!(matches!(
        b.submit_slot(1, &Vec::<Vec<u8>>::new()),
        Err(PipelineError::WrongMode)
    ));
    // One fast replica and one 3 ms replica; both required; at most 3 slots unreleased.
    b.attach_replicas_windowed(
        vec![
            Box::new(journal(&r0)),
            Box::new(Delayed(journal(&r1), Duration::from_millis(3))),
        ],
        2,
        3,
    )
    .unwrap();
    assert!(matches!(
        b.process_slot(1, &Vec::<Vec<u8>>::new()),
        Err(PipelineError::WrongMode)
    ));
    let mut rng = StdRng::seed_from_u64(17);
    let mut clients = Clients::new();
    let (mut want, mut got) = (Vec::new(), Vec::new());
    let mut batch = Vec::new();
    for slot in 1..=40u64 {
        let subs = clients.slot(&mut rng, slot, if slot % 11 == 0 { 0 } else { 120 });
        let r = a.process_slot(slot, &subs).unwrap();
        clients.learn(&r.receipts);
        want.push((
            slot,
            r.decisions.iter().map(|d| d.is_ok()).collect::<Vec<_>>(),
            r.checkpoint,
        ));
        if slot <= 20 {
            got.extend(b.submit_slot(slot, &subs).unwrap());
            assert!(b.unreleased() <= 3, "the window bounds unreleased slots");
        } else {
            batch.push((slot, subs));
        }
    }
    // The second half goes through cross-slot pipelining.
    let refs: Vec<(u64, &[Vec<u8>])> = batch.iter().map(|(s, v)| (*s, v.as_slice())).collect();
    got.extend(b.submit_slots(&refs).unwrap());
    got.extend(b.drain().unwrap());
    assert_eq!(b.unreleased(), 0);
    assert_eq!(got.len(), want.len(), "every slot released exactly once");
    for (r, (slot, ok, ck)) in got.iter().zip(&want) {
        assert_eq!(r.slot, *slot, "released in slot order");
        assert_eq!(
            &r.decisions.iter().map(|d| d.is_ok()).collect::<Vec<_>>(),
            ok
        );
        assert_eq!(&r.checkpoint, ck, "slot {slot}");
    }
    assert_eq!(a.exchange().state_hash(), b.exchange().state_hash());
    // Every released checkpoint was durable on both replicas: either one fails over to the same state.
    let last = want.iter().rev().find_map(|w| w.2).unwrap();
    drop(b);
    for rd in [&r0, &r1] {
        let (q, _) = Pipeline::open(rd, cfg(), &g, operator(), Some(&last)).unwrap();
        assert_eq!(q.latest_checkpoint(), Some(last));
    }
    for x in [&da, &db, &r0, &r1] {
        let _ = std::fs::remove_dir_all(x);
    }
}

#[test]
fn windowed_replication_enforces_the_quorum() {
    use nimbus_journal::Journal;
    let g = genesis(600_000);
    let mut rng = StdRng::seed_from_u64(23);
    let slots: Vec<Vec<Vec<u8>>> = {
        let mut c = Clients::new();
        (1..=12u64).map(|s| c.slot(&mut rng, s, 60)).collect()
    };
    for need in [1usize, 2] {
        let (d, r0) = (dir("wq"), dir("wqr"));
        let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
        std::fs::create_dir_all(&r0).unwrap();
        let good = Journal::open(&r0.join("journal.bin"), usize::MAX)
            .unwrap()
            .0;
        let bad = Diverging(p.journal_anchor());
        p.attach_replicas_windowed(vec![Box::new(good), Box::new(bad)], need, 2)
            .unwrap();
        let mut released = 0;
        let mut failed = None;
        for (i, subs) in slots.iter().enumerate() {
            match p.submit_slot(i as u64 + 1, subs) {
                Ok(rs) => released += rs.len(),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if need == 1 {
            assert!(failed.is_none());
            released += p.drain().unwrap().len();
            assert_eq!(released, slots.len());
            assert_eq!(p.live_replicas(), 1, "the diverging replica was dropped");
        } else {
            assert!(
                matches!(failed, Some(PipelineError::Replication { need: 2, .. })),
                "{failed:?}"
            );
            assert_eq!(released, 0, "nothing released without the quorum");
            assert!(matches!(
                p.drain(),
                Err(PipelineError::Poisoned) | Err(PipelineError::Replication { .. })
            ));
        }
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&r0);
    }
}

/// Records how long its journal is after every batch it has made durable.
struct Tracked<R: Replica>(R, std::sync::Arc<std::sync::atomic::AtomicU64>);
impl<R: Replica> Replica for Tracked<R> {
    fn anchor(&self) -> nimbus_journal::Anchor {
        self.0.anchor()
    }
    fn replicate(
        &mut self,
        from: &nimbus_journal::Anchor,
        bytes: &[u8],
    ) -> Result<nimbus_journal::Anchor, String> {
        let a = self.0.replicate(from, bytes)?;
        self.1.store(a.len, std::sync::atomic::Ordering::SeqCst);
        Ok(a)
    }
}

#[test]
fn windowed_release_waits_until_every_record_is_durable_on_the_quorum() {
    use nimbus_journal::Journal;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let (d, r0, r1) = (dir("wd"), dir("wd0"), dir("wd1"));
    let g = genesis(600_000);
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    let journal = |dd: &Path| {
        std::fs::create_dir_all(dd).unwrap();
        Journal::open(&dd.join("journal.bin"), usize::MAX)
            .unwrap()
            .0
    };
    let (fast, slow) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    p.attach_replicas_windowed(
        vec![
            Box::new(Tracked(journal(&r0), fast.clone())),
            Box::new(Tracked(
                Delayed(journal(&r1), std::time::Duration::from_millis(2)),
                slow.clone(),
            )),
        ],
        2,
        8,
    )
    .unwrap();
    // One order per slot: each slot adds exactly one journal record, so a replica one record behind is visible.
    let mut released = Vec::new();
    for slot in 1..=30u64 {
        let o = order_bytes(Intent {
            market: 0,
            acct: (slot % ACCOUNTS as u64) as u32,
            side: if slot % 2 == 0 { Side::Bid } else { Side::Ask },
            price: 100,
            qty: 1,
            tif: Tif::Gtc,
            nonce: slot / ACCOUNTS as u64,
            expiry_slot: slot + 20,
        });
        let rs = p.submit_slot(slot, &[o]).unwrap();
        for r in &rs {
            let len = r.checkpoint.map_or(0, |c| c.journal.len);
            assert!(
                fast.load(Ordering::SeqCst) >= len && slow.load(Ordering::SeqCst) >= len,
                "slot {} released before both replicas held its {len} records",
                r.slot
            );
        }
        released.extend(rs);
    }
    released.extend(p.drain().unwrap());
    assert_eq!(released.len(), 30);
    for x in [&d, &r0, &r1] {
        let _ = std::fs::remove_dir_all(x);
    }
}

/// Replay split by a snapshot at slot k equals replay without one, for every k: the snapshot carries the complete
/// replay state (books, balances, next order ids, supply, keys, nonces, bridge references, deposit caps, expiries).
#[test]
fn a_replayer_restored_from_a_snapshot_continues_identically() {
    let d = dir("snapshot");
    let (p, cks, _, st) = run(&d, 40, 200, 9);
    assert!(st.fills > 0 && st.deposits > 0 && st.registrations > 0 && st.expired > 0);
    drop(p);
    let (_, rec) = nimbus_journal::Journal::open(&d.join("journal.bin"), usize::MAX).unwrap();
    // Group the journal into slots: (records, anchor after, byte length after).
    let mut slots = Vec::new();
    let mut i = 0;
    while i < rec.records.len() {
        let s = rec.records[i].slot;
        let end = i + rec.records[i..].iter().take_while(|r| r.slot == s).count();
        let after = nimbus_journal::Anchor {
            len: end as u64,
            head: rec.chain[end - 1],
        };
        slots.push((i..end, after, rec.offsets[end - 1]));
        i = end;
    }
    assert_eq!(slots.len(), cks.len());
    for k in 0..=slots.len() {
        let mut a = Replayer::new(cfg(), &genesis(600_000)).unwrap();
        let mut window = Vec::new();
        for (range, after, _) in &slots[..k] {
            window.push(a.apply_slot(&rec.records[range.clone()], *after).unwrap());
        }
        let bytes = slots.get(k.wrapping_sub(1)).map_or(0, |s| s.2);
        let snap = a.snapshot(bytes, &window[window.len().saturating_sub(4)..]);
        let (mut b, got_bytes, got_window) = Replayer::restore(cfg(), &snap).unwrap();
        assert_eq!(got_bytes, bytes);
        assert_eq!(got_window, window[window.len().saturating_sub(4)..]);
        assert_eq!(
            b.snapshot(bytes, &got_window),
            snap,
            "canonical at slot {k}"
        );
        for (j, (range, after, _)) in slots[k..].iter().enumerate() {
            let c = b.apply_slot(&rec.records[range.clone()], *after).unwrap();
            assert!(
                c.same_body(&cks[k + j]),
                "slot {} after a snapshot at {k}",
                cks[k + j].slot
            );
        }
        // A damaged snapshot is refused.
        let mut bad = snap.clone();
        bad[snap.len() / 2] ^= 1;
        assert!(Replayer::restore(cfg(), &bad).is_err());
    }
    let _ = std::fs::remove_dir_all(&d);
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// The engine resumes from its own snapshot: same state and checkpoints as full replay, and identical results on
/// every later slot; snapshots are written in the background while it runs.
#[test]
fn the_engine_restarts_from_its_snapshot() {
    let (d, full) = (dir("eng-snap"), dir("eng-full"));
    let g = genesis(600_000);
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    p.set_snapshot_every(8);
    let mut rng = StdRng::seed_from_u64(77);
    let mut clients = Clients::new();
    let mut last = None;
    for slot in 1..=45 {
        let n = if slot % 7 == 0 { 0 } else { 150 };
        let r = p
            .process_slot(slot, &clients.slot(&mut rng, slot, n))
            .unwrap();
        clients.learn(&r.receipts);
        last = r.checkpoint.or(last);
    }
    let last = last.unwrap();
    drop(p); // waits for the background writer
    copy_dir(&d, &full);
    std::fs::remove_file(full.join("snapshot.bin")).unwrap();

    let (mut a, ra) = Pipeline::open(&d, cfg(), &g, operator(), Some(&last)).unwrap();
    let (mut b, rb) = Pipeline::open(&full, cfg(), &g, operator(), Some(&last)).unwrap();
    // Snapshots at slots 8, 16, …, 40 (slot 42 and 35 are empty; checkpointed slots only).
    assert_eq!(ra.resumed_from, Some(40));
    assert_eq!(rb.resumed_from, None);
    assert!(
        ra.records < rb.records / 5,
        "{} vs {} records re-executed",
        ra.records,
        rb.records
    );
    assert!(ra.external_matched && rb.external_matched);
    assert_eq!(a.latest_checkpoint(), b.latest_checkpoint());
    for (m, (x, y)) in a
        .exchange()
        .markets
        .iter()
        .zip(&b.exchange().markets)
        .enumerate()
    {
        assert_eq!(x.state_hash(), y.state_hash(), "market {m}");
    }
    // Both continue identically.
    for slot in 46..=60 {
        let subs = clients.slot(&mut rng, slot, 150);
        let (x, y) = (
            a.process_slot(slot, &subs).unwrap(),
            b.process_slot(slot, &subs).unwrap(),
        );
        assert_eq!(x.checkpoint, y.checkpoint, "slot {slot}");
        assert_eq!(x.decisions, y.decisions);
        clients.learn(&x.receipts);
    }
    for x in [&d, &full] {
        let _ = std::fs::remove_dir_all(x);
    }
}

/// Recovery never trusts a snapshot over the journal or a signed checkpoint: a damaged snapshot, a checkpoint at or
/// before the snapshot that the engine did not store, or records cut after the snapshot all fall back to replay
/// from genesis, which then reports exactly what it reported without snapshots.
#[test]
fn engine_recovery_falls_back_when_the_snapshot_does_not_fit() {
    let d = dir("eng-fallback");
    let g = genesis(600_000);
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    let mut rng = StdRng::seed_from_u64(78);
    let mut clients = Clients::new();
    let mut cks = Vec::new();
    for slot in 1..=20 {
        let r = p
            .process_slot(slot, &clients.slot(&mut rng, slot, 100))
            .unwrap();
        clients.learn(&r.receipts);
        cks.extend(r.checkpoint);
        if slot == 12 {
            p.snapshot_now().unwrap();
        }
    }
    drop(p);
    let reopen = |ext: Option<&Checkpoint>| Pipeline::open(&d, cfg(), &g, operator(), ext);
    assert_eq!(reopen(Some(&cks[19])).unwrap().1.resumed_from, Some(12));
    let good = std::fs::read(d.join("snapshot.bin")).unwrap();
    // An agent's checkpoint for slot 5 (before the snapshot) that the engine no longer has on disk: full replay.
    std::fs::remove_file(d.join("checkpoints.bin")).unwrap();
    let (_, r) = reopen(Some(&cks[4])).unwrap();
    assert_eq!((r.resumed_from, r.external_matched), (None, true));
    // Damaged snapshot: full replay.
    let mut b = good.clone();
    b[good.len() / 2] ^= 1;
    std::fs::write(d.join("snapshot.bin"), &b).unwrap();
    assert_eq!(reopen(None).unwrap().1.resumed_from, None);
    // The slot-12 snapshot again, and the journal's last record (slot 20) cut: an agent's checkpoint for slot 20
    // reports the truncation, exactly as without snapshots.
    std::fs::write(d.join("snapshot.bin"), &good).unwrap();
    let (_, rec) = nimbus_journal::Journal::open(&d.join("journal.bin"), usize::MAX).unwrap();
    let cut = rec.offsets[rec.records.len() - 2];
    std::fs::OpenOptions::new()
        .write(true)
        .open(d.join("journal.bin"))
        .unwrap()
        .set_len(cut)
        .unwrap();
    assert!(matches!(
        reopen(Some(&cks[19])),
        Err(PipelineError::Truncated { .. })
    ));
    let _ = std::fs::remove_dir_all(&d);
}

/// A snapshot follower runs alongside a live engine (its own thread, reading the journal read-only); the engine
/// later resumes from the follower's snapshot with the state and checkpoints of full replay.
#[test]
fn a_follower_snapshots_a_live_engine_off_its_critical_path() {
    let (d, full) = (dir("follow"), dir("follow-full"));
    let g = genesis(600_000);
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let follower = {
        let (d, g, stop) = (d.clone(), g.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut f = SnapshotFollower::new(&d, cfg(), &g).unwrap();
            let mut rounds = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                if f.catch_up().unwrap() > 0 {
                    f.snapshot().unwrap();
                    rounds += 1;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            f.catch_up().unwrap();
            f.snapshot().unwrap();
            (f.last_slot(), rounds)
        })
    };
    let mut rng = StdRng::seed_from_u64(79);
    let mut clients = Clients::new();
    let mut last = None;
    for slot in 1..=60 {
        let n = if slot % 7 == 0 { 0 } else { 150 };
        let r = p
            .process_slot(slot, &clients.slot(&mut rng, slot, n))
            .unwrap();
        clients.learn(&r.receipts);
        last = r.checkpoint.or(last);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (followed, rounds) = follower.join().unwrap();
    let last = last.unwrap();
    assert_eq!(
        followed,
        Some(last.slot),
        "the follower reached the engine's last checkpointed slot"
    );
    assert!(
        rounds > 1,
        "snapshots were written while the engine ran ({rounds})"
    );
    drop(p);
    copy_dir(&d, &full);
    std::fs::remove_file(full.join("snapshot.bin")).unwrap();
    let (mut a, ra) = Pipeline::open(&d, cfg(), &g, operator(), Some(&last)).unwrap();
    let (mut b, rb) = Pipeline::open(&full, cfg(), &g, operator(), Some(&last)).unwrap();
    assert_eq!(
        (ra.resumed_from, ra.records, rb.resumed_from),
        (Some(last.slot), 0, None)
    );
    assert_eq!(a.latest_checkpoint(), b.latest_checkpoint());
    for slot in 61..=70 {
        let subs = clients.slot(&mut rng, slot, 150);
        let (x, y) = (
            a.process_slot(slot, &subs).unwrap(),
            b.process_slot(slot, &subs).unwrap(),
        );
        assert_eq!(x.checkpoint, y.checkpoint, "slot {slot}");
        clients.learn(&x.receipts);
    }
    for x in [&d, &full] {
        let _ = std::fs::remove_dir_all(x);
    }
}

/// The follower re-derives every checkpoint and refuses to continue past one that differs from the engine's.
#[test]
fn a_follower_reports_divergence_from_the_engine() {
    let d = dir("follow-div");
    let g = genesis(600_000);
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    let mut rng = StdRng::seed_from_u64(80);
    let mut clients = Clients::new();
    for slot in 1..=10 {
        let r = p
            .process_slot(slot, &clients.slot(&mut rng, slot, 100))
            .unwrap();
        clients.learn(&r.receipts);
    }
    drop(p);
    // Alter the receipts root of the sixth stored checkpoint.
    let mut b = std::fs::read(d.join("checkpoints.bin")).unwrap();
    b[5 * CHECKPOINT_LEN + 70] ^= 1;
    std::fs::write(d.join("checkpoints.bin"), &b).unwrap();
    let mut f = SnapshotFollower::new(&d, cfg(), &g).unwrap();
    assert!(matches!(f.catch_up(), Err(PipelineError::Diverged { .. })));
    let _ = std::fs::remove_dir_all(&d);
}

/// With a snapshot, the engine's own stored checkpoints still guard the journal after it: records cut after the
/// snapshot are reported without any agent's checkpoint; and a resume that rewrites the checkpoint file keeps every
/// entry before the snapshot, so an agent's old checkpoint still matches later.
#[test]
fn resumed_recovery_keeps_the_checkpoint_guarantees() {
    use std::io::Write;
    let d = dir("eng-guard");
    let g = genesis(600_000);
    let (mut p, _) = Pipeline::open(&d, cfg(), &g, operator(), None).unwrap();
    let mut rng = StdRng::seed_from_u64(81);
    let mut clients = Clients::new();
    let mut cks = Vec::new();
    for slot in 1..=20 {
        let r = p
            .process_slot(slot, &clients.slot(&mut rng, slot, 100))
            .unwrap();
        clients.learn(&r.receipts);
        cks.extend(r.checkpoint);
        if slot == 12 {
            p.snapshot_now().unwrap();
        }
    }
    drop(p);
    let reopen = |ext: Option<&Checkpoint>| Pipeline::open(&d, cfg(), &g, operator(), ext);
    // A torn entry at the end of the checkpoint file: re-derived on a resumed open, the prefix kept.
    let ckpt = d.join("checkpoints.bin");
    let before = std::fs::read(&ckpt).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&ckpt)
        .unwrap()
        .write_all(&[7; 50])
        .unwrap();
    let (_, r) = reopen(None).unwrap();
    assert_eq!((r.resumed_from, r.checkpoints_discarded), (Some(12), 1));
    assert_eq!(
        std::fs::read(&ckpt).unwrap(),
        before,
        "every entry kept, the torn one removed"
    );
    let (_, r) = reopen(Some(&cks[4])).unwrap();
    assert_eq!((r.resumed_from, r.external_matched), (Some(12), true));
    // The last record cut from the journal, no agent's checkpoint: the stored checkpoint of slot 20 reports it.
    let (_, rec) = nimbus_journal::Journal::open(&d.join("journal.bin"), usize::MAX).unwrap();
    let cut = rec.offsets[rec.records.len() - 2];
    std::fs::OpenOptions::new()
        .write(true)
        .open(d.join("journal.bin"))
        .unwrap()
        .set_len(cut)
        .unwrap();
    assert!(matches!(reopen(None), Err(PipelineError::Truncated { .. })));
    let _ = std::fs::remove_dir_all(&d);
}
