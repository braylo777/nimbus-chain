use nimbus_match::*;
use proptest::prelude::*;

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        1 => (0u32..4, 0u128..50, 0u128..2000).prop_map(|(a, b, q)| Op::Deposit { acct: a, base: b, quote: q }),
        1 => (0u32..4, 0u128..20, 0u128..400).prop_map(|(a, b, q)| Op::Withdraw { acct: a, base: b, quote: q }),
        8 => (0u32..4, any::<bool>(), 1u64..20, 0u64..12, any::<bool>()).prop_map(|(a, bid, p, q, ioc)| Op::Order {
            acct: a, side: if bid { Side::Bid } else { Side::Ask }, price: p, qty: q, tif: if ioc { Tif::Ioc } else { Tif::Gtc } }),
        2 => (0u32..4, 1u64..60).prop_map(|(a, id)| Op::Cancel { acct: a, id }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(2000), .. ProptestConfig::default() })]

    #[test]
    fn invariants_hold_after_every_op(ops in prop::collection::vec(op_strategy(), 1..200)) {
        let mut m = Market::new();
        let (mut base, mut quote) = (0u128, 0u128);
        for op in &ops {
            let before = m.state_hash();
            let out = m.apply(op);
            if let Outcome::Rejected(_) = out {
                prop_assert_eq!(before, m.state_hash(), "rejected op changed state: {:?}", op);
            } else {
                match op {
                    Op::Deposit { base: b, quote: q, .. } => { base += b; quote += q; }
                    Op::Withdraw { base: b, quote: q, .. } => { base -= b; quote -= q; }
                    _ => {}
                }
            }
            if let Outcome::Placed { fills, .. } = &out {
                for f in fills { prop_assert_ne!(f.maker_acct, f.taker_acct, "self-trade executed"); }
            }
            prop_assert_eq!(m.totals(), (base, quote), "conservation violated after {:?}", op);
            if let Err(e) = m.check_invariants() { return Err(TestCaseError::fail(format!("{e} after {op:?}"))); }
        }
    }

    #[test]
    fn replay_is_deterministic_and_parallel_equals_sequential(
        ops in prop::collection::vec((0usize..6, op_strategy()), 1..300)) {
        let mut a = Exchange::new(6);
        let mut b = Exchange::new(6);
        a.apply_batch(&ops);
        for (mkt, op) in &ops { b.markets[*mkt].apply(op); }
        prop_assert_eq!(a.state_hash(), b.state_hash());
        let mut c = Exchange::new(6);
        c.apply_batch(&ops);
        prop_assert_eq!(a.state_hash(), c.state_hash());
    }
}

#[test]
fn price_improvement_is_refunded_and_fill_is_at_maker_price() {
    let mut m = Market::new();
    m.apply(&Op::Deposit {
        acct: 1,
        base: 10,
        quote: 0,
    });
    m.apply(&Op::Deposit {
        acct: 2,
        base: 0,
        quote: 1_000,
    });
    m.apply(&Op::Order {
        acct: 1,
        side: Side::Ask,
        price: 40,
        qty: 10,
        tif: Tif::Gtc,
    });
    let out = m.apply(&Op::Order {
        acct: 2,
        side: Side::Bid,
        price: 50,
        qty: 4,
        tif: Tif::Ioc,
    });
    match out {
        Outcome::Placed { fills, resting, .. } => {
            assert_eq!(fills.len(), 1);
            assert_eq!((fills[0].price, fills[0].qty), (40, 4));
            assert_eq!(resting, 0);
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(
        m.balance(2),
        Balance {
            base_free: 4,
            base_locked: 0,
            quote_free: 1_000 - 160,
            quote_locked: 0
        }
    );
    assert_eq!(
        m.balance(1),
        Balance {
            base_free: 0,
            base_locked: 6,
            quote_free: 160,
            quote_locked: 0
        }
    );
    m.check_invariants().unwrap();
}

#[test]
fn self_trade_is_prevented() {
    let mut m = Market::new();
    m.apply(&Op::Deposit {
        acct: 7,
        base: 5,
        quote: 500,
    });
    m.apply(&Op::Order {
        acct: 7,
        side: Side::Ask,
        price: 10,
        qty: 5,
        tif: Tif::Gtc,
    });
    match m.apply(&Op::Order {
        acct: 7,
        side: Side::Bid,
        price: 10,
        qty: 5,
        tif: Tif::Gtc,
    }) {
        Outcome::Placed {
            fills,
            self_trade_cancels,
            resting,
            ..
        } => {
            assert!(fills.is_empty());
            assert_eq!((self_trade_cancels, resting), (1, 5));
        }
        o => panic!("{o:?}"),
    }
    m.check_invariants().unwrap();
}

#[test]
fn overdraft_and_foreign_cancel_are_rejected() {
    let mut m = Market::new();
    m.apply(&Op::Deposit {
        acct: 1,
        base: 0,
        quote: 100,
    });
    assert_eq!(
        m.apply(&Op::Order {
            acct: 1,
            side: Side::Bid,
            price: 11,
            qty: 10,
            tif: Tif::Gtc
        }),
        Outcome::Rejected(Reject::InsufficientBalance)
    );
    let id = match m.apply(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 10,
        qty: 10,
        tif: Tif::Gtc,
    }) {
        Outcome::Placed { id, .. } => id,
        o => panic!("{o:?}"),
    };
    assert_eq!(
        m.apply(&Op::Cancel { acct: 2, id }),
        Outcome::Rejected(Reject::NotOwner)
    );
    assert!(matches!(
        m.apply(&Op::Cancel { acct: 1, id }),
        Outcome::Cancelled { released: 10, .. }
    ));
    assert_eq!(m.balance(1).quote_free, 100);
}

/// v0.4 regression (M1): total deposits beyond u128::MAX used to be accepted, after which a cancel wrapped a balance
/// silently in release builds (2^128 − 1 units vanished). The supply cap rejects the deposit instead.
#[test]
fn deposits_beyond_the_supply_cap_are_rejected() {
    let mut m = Market::new();
    assert_eq!(
        m.apply(&Op::Deposit {
            acct: 1,
            base: 0,
            quote: u128::MAX
        }),
        Outcome::Ok
    );
    assert!(matches!(
        m.apply(&Op::Order {
            acct: 1,
            side: Side::Bid,
            price: 1 << 63,
            qty: 1 << 63,
            tif: Tif::Gtc
        }),
        Outcome::Placed { .. }
    ));
    let before = m.state_hash();
    assert_eq!(
        m.apply(&Op::Deposit {
            acct: 1,
            base: 0,
            quote: 1 << 126
        }),
        Outcome::Rejected(Reject::Overflow)
    );
    assert_eq!(
        m.apply(&Op::Deposit {
            acct: 2,
            base: 0,
            quote: 1
        }),
        Outcome::Rejected(Reject::Overflow)
    );
    assert_eq!(m.state_hash(), before, "rejected deposit changed state");
    assert!(matches!(
        m.apply(&Op::Cancel { acct: 1, id: 1 }),
        Outcome::Cancelled { .. }
    ));
    assert_eq!(m.balance(1).quote_free, u128::MAX);
    m.check_invariants().unwrap();
    // Withdrawing frees supply for others.
    assert_eq!(
        m.apply(&Op::Withdraw {
            acct: 1,
            base: 0,
            quote: 10
        }),
        Outcome::Ok
    );
    assert_eq!(
        m.apply(&Op::Deposit {
            acct: 2,
            base: 0,
            quote: 10
        }),
        Outcome::Ok
    );
    m.check_invariants().unwrap();
}
