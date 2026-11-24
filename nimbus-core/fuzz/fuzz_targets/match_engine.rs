//! Arbitrary operation sequences against one market: no panic, invariants hold after every operation
//! (locks re-derived from the book, uncrossed book, supply conserved), and a re-run gives the same state hash.
#![no_main]
use libfuzzer_sys::fuzz_target;
use nimbus_match::{Market, Op, Side, Tif};

fn ops(data: &[u8]) -> Vec<Op> {
    data.chunks_exact(8)
        .map(|c| {
            let acct = (c[1] % 4) as u32;
            let price = 95 + (c[2] % 12) as u64;
            let qty = u16::from_le_bytes([c[3], c[4]]) as u64 % 64;
            let side = if c[5] & 1 == 0 { Side::Bid } else { Side::Ask };
            let tif = match c[6] % 4 {
                0 => Tif::Gtc,
                1 => Tif::Ioc,
                2 => Tif::Fok,
                _ => Tif::PostOnly,
            };
            match c[0] % 8 {
                0 => Op::Deposit {
                    acct,
                    base: c[7] as u128 * 10,
                    quote: c[7] as u128 * 1_000,
                },
                1 => Op::Withdraw {
                    acct,
                    base: c[7] as u128,
                    quote: c[7] as u128 * 50,
                },
                2 => Op::Cancel {
                    acct,
                    id: (c[7] % 32) as u64,
                },
                _ => Op::Order {
                    acct,
                    side,
                    price,
                    qty,
                    tif,
                },
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let ops = ops(data);
    let mut m = Market::new();
    for a in 0..4 {
        m.apply(&Op::Deposit {
            acct: a,
            base: 1_000,
            quote: 100_000,
        });
    }
    let mut again = m.clone();
    for op in &ops {
        m.apply(op);
        if let Err(e) = m.check_invariants() {
            panic!("invariant broken after {op:?}: {e}");
        }
    }
    for op in &ops {
        again.apply(op);
    }
    assert_eq!(
        m.state_hash(),
        again.state_hash(),
        "matching is not deterministic"
    );
});
