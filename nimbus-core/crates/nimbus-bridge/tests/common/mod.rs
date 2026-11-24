//! Shared fixtures for the simulated-network and replay tests: deterministic keys, genesis, traffic, and a tap
//! replica that records every journal shipment the engine makes (the messages a network would carry).
#![allow(dead_code)]
use ed25519_dalek::SigningKey;
use nimbus_journal::{Anchor, Journal};
use nimbus_match::{Fees, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const ACCOUNTS: u32 = 8;

pub fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nimbus-sim-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
pub fn key(a: u32) -> SigningKey {
    let mut s = [11u8; 32];
    s[..4].copy_from_slice(&a.to_be_bytes());
    SigningKey::from_bytes(&s)
}
pub fn operator() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}
pub fn validator(i: u16) -> SigningKey {
    SigningKey::from_bytes(&[70 + i as u8; 32])
}
pub fn genesis() -> Genesis {
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
pub fn cfg(min_batch: usize) -> Config {
    Config {
        markets: 2,
        max_life: 1_000,
        fsync: false,
        min_batch,
    }
}

/// Mixed traffic from a seed: orders (GTC / IOC / FOK / post-only) on two markets, cancels and withdrawals.
pub struct Traffic {
    nonce: Vec<u64>,
    seed: u64,
}
impl Traffic {
    pub fn new(seed: u64) -> Self {
        Traffic {
            nonce: vec![0; ACCOUNTS as usize],
            seed: seed | 1,
        }
    }
    fn next(&mut self) -> u64 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed
    }
    pub fn slot(&mut self, slot: u64, n: usize) -> Vec<Vec<u8>> {
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
                            tif: match self.next() % 8 {
                                0 => Tif::Ioc,
                                1 => Tif::Fok,
                                2 => Tif::PostOnly,
                                _ => Tif::Gtc,
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

/// One journal shipment: the records taking a replica from `from` to `to`.
#[derive(Clone, Debug)]
pub struct Shipment {
    pub from: Anchor,
    pub to: Anchor,
    pub bytes: Vec<u8>,
}

/// A replica that keeps a journal and records every shipment (what the network carries to validators).
pub struct Tap {
    journal: Journal,
    pub log: Arc<Mutex<Vec<Shipment>>>,
}
impl Tap {
    pub fn new(path: &std::path::Path) -> (Tap, Arc<Mutex<Vec<Shipment>>>) {
        let (journal, _) = Journal::open(path, usize::MAX).unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        (
            Tap {
                journal,
                log: log.clone(),
            },
            log,
        )
    }
}
impl Replica for Tap {
    fn anchor(&self) -> Anchor {
        self.journal.anchor()
    }
    fn replicate(&mut self, from: &Anchor, bytes: &[u8]) -> Result<Anchor, String> {
        let to = self
            .journal
            .replicate(from, bytes)
            .map_err(|e| format!("{e:?}"))?;
        self.log.lock().unwrap().push(Shipment {
            from: *from,
            to,
            bytes: bytes.to_vec(),
        });
        Ok(to)
    }
}

/// Run the engine for `slots` slots of `per_slot` submissions; return its checkpoints and journal shipments.
pub fn run_engine(
    d: &std::path::Path,
    seed: u64,
    slots: u64,
    per_slot: usize,
    min_batch: usize,
) -> (Vec<Checkpoint>, Vec<Shipment>) {
    let g = genesis();
    let (mut p, _) = Pipeline::open(d, cfg(min_batch), &g, operator(), None).unwrap();
    let (tap, log) = Tap::new(&d.join("tap.bin"));
    p.attach_replicas(vec![Box::new(tap)], 1).unwrap();
    let mut t = Traffic::new(seed);
    let mut cks = Vec::new();
    for s in 1..=slots {
        cks.extend(p.process_slot(s, &t.slot(s, per_slot)).unwrap().checkpoint);
    }
    drop(p);
    let ships = log.lock().unwrap().clone();
    (cks, ships)
}
