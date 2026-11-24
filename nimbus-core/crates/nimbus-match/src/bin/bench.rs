//! Throughput benchmark: single-market ns/op and multi-market parallel ops/s.
use nimbus_match::*;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

fn gen(rng: &mut StdRng, mid: &mut i64) -> Op {
    let acct = rng.gen_range(0..64u32);
    let r: u32 = rng.gen_range(0..100);
    *mid = (*mid + rng.gen_range(-1..=1)).clamp(900, 1100);
    if r < 60 {
        let bid = rng.gen_bool(0.5);
        let off = rng.gen_range(0..20i64) - 2;
        let price = if bid { *mid - off } else { *mid + off } as u64;
        Op::Order {
            acct,
            side: if bid { Side::Bid } else { Side::Ask },
            price,
            qty: rng.gen_range(1..100),
            tif: Tif::Gtc,
        }
    } else if r < 90 {
        Op::Cancel {
            acct,
            id: rng.gen_range(1..200_000),
        }
    } else {
        let bid = rng.gen_bool(0.5);
        Op::Order {
            acct,
            side: if bid { Side::Bid } else { Side::Ask },
            price: if bid { 2000 } else { 1 },
            qty: rng.gen_range(1..50),
            tif: Tif::Ioc,
        }
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    // Single market
    let mut m = Market::new();
    for a in 0..64 {
        m.apply(&Op::Deposit {
            acct: a,
            base: 1 << 60,
            quote: 1 << 80,
        });
    }
    let mut mid = 1000i64;
    let ops: Vec<Op> = (0..2_000_000).map(|_| gen(&mut rng, &mut mid)).collect();
    if std::env::var("SPLIT").is_ok() {
        let mut mm = Market::new();
        for a in 0..64 {
            mm.apply(&Op::Deposit {
                acct: a,
                base: 1 << 60,
                quote: 1 << 80,
            });
        }
        let (mut tl, mut tc, mut ti, mut nl, mut nc, mut ni) = (0f64, 0f64, 0f64, 0u32, 0u32, 0u32);
        for op in &ops {
            let t = Instant::now();
            mm.apply(op);
            let d = t.elapsed().as_secs_f64();
            match op {
                Op::Order { tif: Tif::Gtc, .. } => {
                    tl += d;
                    nl += 1
                }
                Op::Cancel { .. } => {
                    tc += d;
                    nc += 1
                }
                _ => {
                    ti += d;
                    ni += 1
                }
            }
        }
        println!(
            "split: GTC {:.0} ns x{nl}, cancel {:.0} ns x{nc}, IOC {:.0} ns x{ni}",
            tl * 1e9 / nl as f64,
            tc * 1e9 / nc as f64,
            ti * 1e9 / ni as f64
        );
    }
    if std::env::var("TIF_SPLIT").is_ok() {
        // The same stream with every immediate-or-cancel order replaced by each order type in turn: time per
        // replaced order and the share refused (fill-or-kill: not fillable in full; post-only: would cross).
        for tif in [Tif::Ioc, Tif::Fok, Tif::PostOnly] {
            let mut mm = Market::new();
            for a in 0..64 {
                mm.apply(&Op::Deposit {
                    acct: a,
                    base: 1 << 60,
                    quote: 1 << 80,
                });
            }
            let (mut t_sum, mut n, mut refused) = (0f64, 0u32, 0u32);
            for op in &ops {
                match *op {
                    Op::Order {
                        acct,
                        side,
                        price,
                        qty,
                        tif: Tif::Ioc,
                    } => {
                        let o = Op::Order {
                            acct,
                            side,
                            price,
                            qty,
                            tif,
                        };
                        let t = Instant::now();
                        let r = mm.apply(&o);
                        t_sum += t.elapsed().as_secs_f64();
                        n += 1;
                        refused += matches!(r, Outcome::Rejected(_)) as u32;
                    }
                    _ => {
                        mm.apply(op);
                    }
                }
            }
            println!(
                "tif {:?}: {:.0} ns per order x{n}, refused {:.1}%",
                tif,
                t_sum * 1e9 / n as f64,
                100.0 * refused as f64 / n as f64
            );
        }
    }
    let t = Instant::now();
    let mut fills = 0usize;
    for op in &ops {
        if let Outcome::Placed { fills: f, .. } = m.apply(op) {
            fills += f.len();
        }
    }
    let dt = t.elapsed().as_secs_f64();
    println!(
        "single market : {} ops in {:.3} s = {:.1} ns/op ({:.2} M ops/s), {} fills, {} open orders",
        ops.len(),
        dt,
        dt * 1e9 / ops.len() as f64,
        ops.len() as f64 / dt / 1e6,
        fills,
        m.open_orders()
    );
    let t = Instant::now();
    let h = m.state_hash();
    let dh = t.elapsed().as_secs_f64();
    println!(
        "state hash    : {:.2} ms for {} open orders ({}…)",
        dh * 1e3,
        m.open_orders(),
        h[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    // Many markets in parallel
    let threads = rayon::current_num_threads();
    for markets in [threads, 4 * threads] {
        let mut ex = Exchange::new(markets);
        let dep: Vec<(usize, Op)> = (0..markets)
            .flat_map(|k| {
                (0..64).map(move |a| {
                    (
                        k,
                        Op::Deposit {
                            acct: a,
                            base: 1 << 60,
                            quote: 1 << 80,
                        },
                    )
                })
            })
            .collect();
        ex.apply_batch(&dep);
        let mut mids = vec![1000i64; markets];
        let per_batch = 4096 * markets;
        let batches: Vec<Vec<(usize, Op)>> = (0..40)
            .map(|_| {
                (0..per_batch)
                    .map(|i| {
                        let k = i % markets;
                        (k, gen(&mut rng, &mut mids[k]))
                    })
                    .collect()
            })
            .collect();
        let total: usize = batches.iter().map(|b| b.len()).sum();
        let t = Instant::now();
        for b in &batches {
            ex.apply_batch(b);
        }
        let dt = t.elapsed().as_secs_f64();
        println!("{markets:3} markets  : {} ops in {:.3} s = {:.2} M ops/s on {threads} threads ({:.1} ns/op/core)",
            total, dt, total as f64 / dt / 1e6, dt * 1e9 * threads as f64 / total as f64);
    }
}
