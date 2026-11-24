//! Certifier memory per slot, executed (Linux: resident set size from /proc/self/statm). The engine ships S slots of
//! one signed order each to a certifier attached as its replica, and the certifier co-signs every checkpoint. The
//! growth of the resident set between slot S/4 and slot S is reported for three modes, each in its own process:
//! `engine` (no certifier: the control), `unbounded` (Certifier::open), `retain` (Certifier::open_retaining, 1,024
//! slots). Bytes per slot = (growth − control growth) / (3S/4). Env: MEM_SLOTS (200000).
use ed25519_dalek::SigningKey;
use nimbus_bridge::*;
use nimbus_match::{Fees, Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;

fn rss() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    Some(s.split_whitespace().nth(1)?.parse::<u64>().ok()? * 4096)
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if !["engine", "unbounded", "retain"].contains(&mode.as_str()) {
        // Driver: run the three modes in separate processes.
        let me = std::env::current_exe().unwrap();
        for m in ["engine", "unbounded", "retain"] {
            let out = std::process::Command::new(&me).arg(m).output().unwrap();
            print!("{}", String::from_utf8_lossy(&out.stdout));
        }
        return;
    }
    let slots: u64 = std::env::var("MEM_SLOTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);
    let key = SigningKey::from_bytes(&[5; 32]);
    let genesis = Genesis {
        accounts: vec![(0, key.verifying_key())],
        deposits: vec![(0, 0, 1u128 << 40, 1u128 << 60)],
        fees: Fees::default(),
        ..Genesis::default()
    };
    let cfg = Config {
        markets: 1,
        max_life: 1_000,
        fsync: false,
        min_batch: 16,
    };
    let base = std::env::temp_dir().join(format!("nimbus-certify-mem-{}", std::process::id()));
    let operator = SigningKey::from_bytes(&[9; 32]);
    let (mut p, _) = Pipeline::open(
        &base.join("engine"),
        cfg.clone(),
        &genesis,
        operator.clone(),
        None,
    )
    .unwrap();
    let cert = (mode != "engine").then(|| {
        let dir = base.join("cert");
        let (op, k) = (operator.verifying_key(), SigningKey::from_bytes(&[70; 32]));
        SharedCertifier::new(if mode == "retain" {
            Certifier::open_retaining(&dir, cfg.clone(), &genesis, op, k, 0, 1024).unwrap()
        } else {
            Certifier::open(&dir, cfg.clone(), &genesis, op, k, 0).unwrap()
        })
    });
    if let Some(c) = &cert {
        p.attach_replicas(vec![Box::new(c.clone())], 1).unwrap();
    }
    let mut mark = None;
    for slot in 1..=slots {
        // An IOC order on an empty book: it journals, matches nothing and leaves no state behind.
        let e = Entry::Order(SignedOrder::sign(
            Intent {
                market: 0,
                acct: 0,
                side: Side::Bid,
                price: 1_000,
                qty: 1,
                tif: Tif::Ioc,
                nonce: slot - 1,
                expiry_slot: slot + 10,
            },
            &key,
        ));
        let r = p.process_slot(slot, &[e.to_bytes()]).unwrap();
        if let (Some(c), Some(ck)) = (&cert, r.checkpoint) {
            c.certify(&ck).unwrap();
        }
        if slot == slots / 4 {
            mark = rss();
        }
        if std::env::var("MEM_TRACE").is_ok() && slot % (slots / 8) == 0 {
            println!(
                "{mode} slot {slot}: resident {} kB",
                rss().unwrap_or(0) / 1024
            );
        }
    }
    match (mark, rss()) {
        (Some(a), Some(b)) => println!(
            "{mode:<9} resident growth over {} slots: {:>10} B ({:.1} B/slot)",
            slots - slots / 4,
            b as i64 - a as i64,
            (b as f64 - a as f64) / (slots - slots / 4) as f64
        ),
        _ => println!("{mode:<9} resident set not available on this OS"),
    }
    let _ = std::fs::remove_dir_all(&base);
}
