//! BFT certification on a simulated network: n = 4 validators, quorum q = 3 (3q > 2n), f = 1 Byzantine.
//!
//! The engine's journal shipments travel to every validator over a lossy, reordering, duplicating network (a
//! deterministic simulation driven by proptest); honest validators are real `Certifier`s that replicate, re-execute
//! and co-sign. One validator is Byzantine (silent, equivocating, or sending garbage), and the operator may also
//! fabricate a second, validly operator-signed checkpoint for any slot and ask everyone to certify it.
//!
//! Safety: no slot ever has a valid certificate for any checkpoint other than the one the engine derived.
//! Liveness: once the network delivers (eventual delivery, retransmission), every genuine checkpoint is certified.
//! Simulated, not measured: these are model checks of the protocol logic on one machine.
mod common;
use common::*;
use ed25519_dalek::Signer;
use nimbus_bridge::*;
use nimbus_pipeline::Checkpoint;
use proptest::prelude::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap};

const N: u16 = 4;
const Q: usize = 3;

#[derive(Clone, Copy, Debug)]
enum Byz {
    /// Never answers (crash fault).
    Silent,
    /// Signs every checkpoint it is shown, genuine or fabricated.
    Equivocate,
    /// Answers with random bytes as signatures.
    Garbage,
}

struct Net {
    rng: StdRng,
    drop_p: f64,
    dup_p: f64,
}

/// One honest validator: a certifier plus its out-of-order buffer of shipments (keyed by journal length).
struct Honest {
    cert: Certifier,
    buf: BTreeMap<u64, Shipment>,
}

impl Honest {
    fn receive(&mut self, s: Shipment) {
        self.buf.entry(s.from.len).or_insert(s);
        // Apply every buffered shipment that continues the local journal; drop stale duplicates.
        loop {
            let at = self.cert.anchor();
            let Some(s) = self.buf.remove(&at.len) else {
                self.buf.retain(|k, _| *k > at.len);
                return;
            };
            assert_eq!(
                s.from, at,
                "honest replicas only ever see the engine's history"
            );
            replicate(&mut self.cert, &s);
        }
    }
}

fn replicate(c: &mut Certifier, s: &Shipment) {
    let got = c
        .replicate_shipment(&s.from, &s.bytes)
        .expect("valid shipment");
    assert_eq!(got, s.to);
}

struct Outcome {
    /// Every distinct certificate the aggregator could assemble, per slot: digest → signers.
    certified: HashMap<u64, Vec<[u8; 48]>>,
    genuine: Vec<Checkpoint>,
}

/// Run one simulated execution and return what got certified.
fn simulate(
    seed: u64,
    byz_index: Option<u16>,
    byz: Byz,
    fabricate_p: f64,
    drop_p: f64,
    slots: u64,
) -> Outcome {
    let (de, dc) = (dir("bft-engine"), dir("bft-certs"));
    let (genuine, ships) = run_engine(&de, seed, slots, 12, 16);
    let mut net = Net {
        rng: StdRng::seed_from_u64(seed ^ 0x5eed),
        drop_p,
        dup_p: 0.2,
    };
    let g = genesis();
    let mut honest: BTreeMap<u16, Honest> = (0..N)
        .filter(|i| Some(*i) != byz_index)
        .map(|i| {
            let cert = Certifier::open(
                &dc.join(format!("v{i}")),
                cfg(16),
                &g,
                operator().verifying_key(),
                validator(i),
                i,
            )
            .unwrap();
            (
                i,
                Honest {
                    cert,
                    buf: BTreeMap::new(),
                },
            )
        })
        .collect();

    // Requests: the genuine checkpoint of every slot, and with probability `fabricate_p` a forged one too.
    let mut requests: Vec<Checkpoint> = genuine.clone();
    for ck in &genuine {
        if net.rng.gen_bool(fabricate_p) {
            let mut f = *ck;
            f.receipts_root[net.rng.gen_range(0..48)] ^= 1 + net.rng.gen_range(0..255u8);
            f.sig = operator().sign(&f.digest()).to_bytes();
            requests.push(f);
        }
    }

    // Network rounds: every undelivered shipment is (re)sent to every honest validator each round, in random order,
    // possibly dropped or duplicated; then the aggregator asks everyone to sign every request.
    let mut sigs: HashMap<[u8; 48], BTreeMap<u16, [u8; 64]>> = HashMap::new();
    let total = ships.len() as u64;
    for _round in 0..200 {
        let mut msgs: Vec<(u16, Shipment)> = Vec::new();
        for (&i, h) in &honest {
            let have = h.cert.anchor().len;
            for s in ships.iter().filter(|s| s.to.len > have) {
                if net.rng.gen_bool(net.drop_p) {
                    continue;
                }
                msgs.push((i, s.clone()));
                if net.rng.gen_bool(net.dup_p) {
                    msgs.push((i, s.clone()));
                }
            }
        }
        // Shuffle: arbitrary reordering.
        for k in (1..msgs.len()).rev() {
            msgs.swap(k, net.rng.gen_range(0..=k));
        }
        for (i, s) in msgs {
            honest.get_mut(&i).unwrap().receive(s);
        }
        for ck in &requests {
            let d = ck.digest();
            for (&i, h) in honest.iter_mut() {
                if let Ok((idx, s)) = h.cert.certify(ck) {
                    assert_eq!(idx, i);
                    sigs.entry(d).or_default().insert(idx, s);
                }
            }
            if let Some(b) = byz_index {
                match byz {
                    Byz::Silent => {}
                    Byz::Equivocate => {
                        sigs.entry(d)
                            .or_default()
                            .insert(b, validator(b).sign(&d).to_bytes());
                    }
                    Byz::Garbage => {
                        let mut s = [0u8; 64];
                        net.rng.fill(&mut s[..]);
                        sigs.entry(d).or_default().insert(b, s);
                    }
                }
            }
        }
        let done = honest
            .values()
            .all(|h| h.cert.anchor().len == ships[ships.len() - 1].to.len);
        if done && total > 0 {
            break;
        }
    }

    // The aggregator / bridge: which checkpoints have a valid certificate?
    let vals = Validators::new(
        &(0..N)
            .map(|i| validator(i).verifying_key())
            .collect::<Vec<_>>(),
        Q,
    )
    .unwrap();
    let mut certified: HashMap<u64, Vec<[u8; 48]>> = HashMap::new();
    for ck in &requests {
        let d = ck.digest();
        let Some(s) = sigs.get(&d) else { continue };
        let good: Vec<(u16, [u8; 64])> = s
            .iter()
            .filter(|(i, sig)| single_ok(ck, **i, sig))
            .map(|(i, s)| (*i, *s))
            .collect();
        if good.len() >= Q {
            let cert = Certificate {
                sigs: good[..Q].to_vec(),
            };
            assert!(vals.verify(ck, &cert).is_ok());
            let e = certified.entry(ck.slot).or_default();
            if !e.contains(&d) {
                e.push(d);
            }
        }
    }
    for d in [&de, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
    Outcome { certified, genuine }
}

/// Whether validator `i`'s signature alone is valid (checked as a 1-of-1 batch under that key).
fn single_ok(ck: &Checkpoint, i: u16, sig: &[u8; 64]) -> bool {
    let one = Validators::new(&[validator(i).verifying_key()], 1).unwrap();
    one.verify(
        ck,
        &Certificate {
            sigs: vec![(0, *sig)],
        },
    )
    .is_ok()
}

fn byz_strategy() -> impl Strategy<Value = Byz> {
    prop_oneof![Just(Byz::Silent), Just(Byz::Equivocate), Just(Byz::Garbage)]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, .. ProptestConfig::default() })]

    /// Safety with f = 1 of 4 and a misbehaving operator: only the engine's own checkpoint is ever certified.
    #[test]
    fn safety_f1_of_4(seed in 1u64..u64::MAX, b in 0u16..N, byz in byz_strategy(),
                      fabricate in 0.0f64..1.0, drop in 0.0f64..0.6) {
        let o = simulate(seed, Some(b), byz, fabricate, drop, 8);
        for (slot, ds) in &o.certified {
            prop_assert_eq!(ds.len(), 1, "two certified checkpoints for slot {}", slot);
            let g = o.genuine.iter().find(|c| c.slot == *slot).expect("slot exists");
            prop_assert_eq!(ds[0], g.digest(), "a fabricated checkpoint was certified");
        }
    }

    /// Liveness with f = 1 of 4 (any fault mode) and a lossy, reordering network with retransmission:
    /// every genuine checkpoint ends up certified.
    #[test]
    fn liveness_f1_of_4(seed in 1u64..u64::MAX, b in 0u16..N, byz in byz_strategy(), drop in 0.0f64..0.6) {
        let o = simulate(seed, Some(b), byz, 0.3, drop, 8);
        for g in &o.genuine {
            prop_assert!(o.certified.get(&g.slot).is_some_and(|d| d == &vec![g.digest()]),
                "slot {} not certified", g.slot);
        }
    }
}

#[test]
fn all_honest_certify_every_slot() {
    let o = simulate(42, None, Byz::Silent, 0.5, 0.3, 10);
    assert!(!o.genuine.is_empty());
    for g in &o.genuine {
        assert_eq!(o.certified.get(&g.slot), Some(&vec![g.digest()]));
    }
}

/// The bound is tight for liveness: with two silent validators (f = 2 > (n − 1)/3) only two honest signers remain,
/// fewer than q = 3, and nothing is certified — but still nothing wrong is certified.
#[test]
fn two_silent_validators_stall_but_stay_safe() {
    let (de, dc) = (dir("stall-e"), dir("stall-c"));
    let (genuine, ships) = run_engine(&de, 9, 4, 10, 16);
    let g = genesis();
    let mut certs: Vec<Certifier> = (0..2u16)
        .map(|i| {
            Certifier::open(
                &dc.join(format!("v{i}")),
                cfg(16),
                &g,
                operator().verifying_key(),
                validator(i),
                i,
            )
            .unwrap()
        })
        .collect();
    for c in certs.iter_mut() {
        for s in &ships {
            replicate(c, s);
        }
    }
    let vals = Validators::new(
        &(0..N)
            .map(|i| validator(i).verifying_key())
            .collect::<Vec<_>>(),
        Q,
    )
    .unwrap();
    for ck in &genuine {
        let sigs: Vec<_> = certs.iter_mut().map(|c| c.certify(ck).unwrap()).collect();
        assert_eq!(
            vals.verify(ck, &Certificate { sigs }),
            Err(CertError::Quorum { have: 2, need: 3 })
        );
    }
    for d in [&de, &dc] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// The bound is tight for safety only at f ≥ q: three colluding validators can certify a fabricated checkpoint,
/// which is why the quorum must exceed 2n/3 and f must stay below n/3.
#[test]
fn three_colluding_validators_could_certify_a_fabrication() {
    let (de, _) = (dir("collude"), ());
    let (genuine, _) = run_engine(&de, 5, 2, 10, 16);
    let mut f = genuine[0];
    f.receipts_root[0] ^= 0xff;
    f.sig = operator().sign(&f.digest()).to_bytes();
    let d = f.digest();
    let vals = Validators::new(
        &(0..N)
            .map(|i| validator(i).verifying_key())
            .collect::<Vec<_>>(),
        Q,
    )
    .unwrap();
    let sigs = (0..3u16)
        .map(|i| (i, validator(i).sign(&d).to_bytes()))
        .collect();
    assert!(vals.verify(&f, &Certificate { sigs }).is_ok());
    let _ = std::fs::remove_dir_all(&de);
}
