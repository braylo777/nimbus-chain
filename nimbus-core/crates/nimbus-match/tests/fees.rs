//! Fees, worked by hand: who pays what on one fill, where the fee reserve goes, and when a schedule may change.
use nimbus_match::*;

fn market(maker_bps: u16, taker_bps: u16) -> Market {
    let mut m = Market::new();
    m.set_fees(Fees {
        maker_bps,
        taker_bps,
        collector: 9,
        maker_rebate_bps: 0,
    })
    .unwrap();
    for a in [1, 2] {
        m.apply(&Op::Deposit {
            acct: a,
            base: 1_000,
            quote: 1_000_000,
        });
    }
    m
}

#[test]
fn a_bid_taker_pays_notional_plus_fee_and_gets_the_unused_reserve_back() {
    // Maker 10 bps, taker 25 bps, so B = 25. Account 2 rests an ask of 30 at 997; account 1 bids 30 at 1,000.
    let mut m = market(10, 25);
    m.apply(&Op::Order {
        acct: 2,
        side: Side::Ask,
        price: 997,
        qty: 30,
        tif: Tif::Gtc,
    });
    let out = m.apply(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 1_000,
        qty: 30,
        tif: Tif::Gtc,
    });
    // n = 997 × 30 = 29,910; taker fee ⌈29,910 × 25 / 10⁴⌉ = ⌈74.775⌉ = 75; maker fee ⌈29.91⌉ = 30.
    let Outcome::Placed {
        fills, resting: 0, ..
    } = out
    else {
        panic!("{out:?}")
    };
    assert_eq!((fills[0].taker_fee, fills[0].maker_fee), (75, 30));
    let (b, s, c) = (m.balance(1), m.balance(2), m.balance(9));
    assert_eq!(
        b.quote_free,
        1_000_000 - 29_910 - 75,
        "buyer pays n + fee; price improvement and reserve refunded"
    );
    assert_eq!((b.quote_locked, b.base_free), (0, 1_030));
    assert_eq!(
        s.quote_free,
        1_000_000 + 29_910 - 30,
        "seller receives n − fee"
    );
    assert_eq!(c.quote_free, 105, "collector receives both fees");
    m.check_invariants().unwrap();
}

#[test]
fn a_resting_bid_locks_l_and_an_ask_taker_pays_its_fee_from_proceeds() {
    let mut m = market(10, 25);
    m.apply(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 500,
        qty: 40,
        tif: Tif::Gtc,
    });
    // L(500, 40) = 20,000 + ⌈20,000 × 25 / 10⁴⌉ + 40 = 20,000 + 50 + 40.
    assert_eq!(m.balance(1).quote_locked, 20_090);
    assert_eq!(m.bid_lock(500, 40), Ok(20_090));
    // Account 2 sells 15 into it: n = 7,500; taker (ask) fee ⌈18.75⌉ = 19; maker (bid) fee ⌈7.5⌉ = 8.
    m.apply(&Op::Order {
        acct: 2,
        side: Side::Ask,
        price: 450,
        qty: 15,
        tif: Tif::Ioc,
    });
    assert_eq!(m.balance(2).quote_free, 1_000_000 + 7_500 - 19);
    // The maker's lock falls to L(500, 25) = 12,500 + 32 + 25 = 12,557; it paid 7,500 + 8 out of the 7,533 released.
    let b = m.balance(1);
    assert_eq!(b.quote_locked, 12_557);
    assert_eq!(
        b.quote_free,
        1_000_000 - 20_090 + (20_090 - 12_557) - 7_500 - 8
    );
    assert_eq!(m.balance(9).quote_free, 27);
    // Cancelling releases exactly the remaining lock.
    let Outcome::Cancelled { .. } = m.apply(&Op::Cancel { acct: 1, id: 1 }) else {
        panic!()
    };
    assert_eq!(m.balance(1).quote_free, 1_000_000 - 7_500 - 8);
    m.check_invariants().unwrap();
    assert_eq!(
        m.totals(),
        (2_000, 2_000_000),
        "fees move quote between accounts; supply is unchanged"
    );
}

#[test]
fn fee_schedules_are_bounded_and_fixed_while_orders_rest() {
    let mut m = Market::new();
    assert!(m
        .set_fees(Fees {
            maker_bps: MAX_FEE_BPS + 1,
            taker_bps: 0,
            collector: 0,
            maker_rebate_bps: 0
        })
        .is_err());
    m.apply(&Op::Deposit {
        acct: 1,
        base: 10,
        quote: 10_000,
    });
    m.apply(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 10,
        qty: 5,
        tif: Tif::Gtc,
    });
    assert!(
        m.set_fees(Fees {
            maker_bps: 1,
            taker_bps: 1,
            collector: 0,
            maker_rebate_bps: 0
        })
        .is_err(),
        "resting bids' locks depend on the schedule"
    );
    // Without fees nothing changes: the lock is exactly p × r.
    assert_eq!(m.balance(1).quote_locked, 50);
}

#[test]
fn a_bid_can_afford_exactly_its_lock() {
    // L(1,000, 10) at B = 25 is 10,000 + 25 + 10 = 10,035: one unit less is refused, the exact amount admitted.
    let mut m = Market::new();
    m.set_fees(Fees {
        maker_bps: 25,
        taker_bps: 25,
        collector: 9,
        maker_rebate_bps: 0,
    })
    .unwrap();
    m.apply(&Op::Deposit {
        acct: 1,
        base: 0,
        quote: 10_034,
    });
    let bid = Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 1_000,
        qty: 10,
        tif: Tif::Gtc,
    };
    assert_eq!(
        m.apply(&bid),
        Outcome::Rejected(Reject::InsufficientBalance)
    );
    m.apply(&Op::Deposit {
        acct: 1,
        base: 0,
        quote: 1,
    });
    assert!(matches!(m.apply(&bid), Outcome::Placed { resting: 10, .. }));
    assert_eq!(m.balance(1).quote_free, 0);
}

#[test]
fn a_maker_rebate_is_paid_out_of_the_taker_fee_rounded_down() {
    let mut m = Market::new();
    let f = Fees {
        maker_bps: 0,
        taker_bps: 25,
        collector: 9,
        maker_rebate_bps: 10,
    };
    m.set_fees(f).unwrap();
    for a in [1, 2] {
        m.apply(&Op::Deposit {
            acct: a,
            base: 1_000,
            quote: 1_000_000,
        });
    }
    // Account 2 rests an ask (the maker); account 1 takes it.
    m.apply(&Op::Order {
        acct: 2,
        side: Side::Ask,
        price: 997,
        qty: 30,
        tif: Tif::Gtc,
    });
    let Outcome::Placed { fills, .. } = m.apply(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 1_000,
        qty: 30,
        tif: Tif::Gtc,
    }) else {
        panic!()
    };
    // n = 29,910: taker fee ⌈74.775⌉ = 75, rebate ⌊29.91⌋ = 29, the collector keeps 46.
    assert_eq!(
        (
            fills[0].taker_fee,
            fills[0].maker_fee,
            fills[0].maker_rebate
        ),
        (75, 0, 29)
    );
    assert_eq!(m.balance(2).quote_free, 1_000_000 + 29_910 + 29);
    assert_eq!(m.balance(1).quote_free, 1_000_000 - 29_910 - 75);
    assert_eq!(m.balance(9).quote_free, 46);
    // A resting bid as maker: its rebate returns with the refund of its lock.
    m.apply(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 500,
        qty: 10,
        tif: Tif::Gtc,
    });
    let before = m.balance(1);
    m.apply(&Op::Order {
        acct: 2,
        side: Side::Ask,
        price: 500,
        qty: 10,
        tif: Tif::Ioc,
    });
    // n = 5,000: the maker pays 5,000 − ⌊5⌋ = 4,995 net; the seller (taker) receives 5,000 − ⌈12.5⌉ = 4,987.
    let after = m.balance(1);
    assert_eq!(
        before.quote_free + before.quote_locked - after.quote_free - after.quote_locked,
        4_995
    );
    assert_eq!(m.balance(9).quote_free, 46 + 13 - 5);
    m.check_invariants().unwrap();
    assert_eq!(m.totals(), (2_000, 2_000_000));
}

#[test]
fn a_rebate_must_be_funded_by_the_taker_fee() {
    let mut m = Market::new();
    let bad = |maker_bps, taker_bps, maker_rebate_bps| Fees {
        maker_bps,
        taker_bps,
        collector: 0,
        maker_rebate_bps,
    };
    assert!(
        m.set_fees(bad(0, 10, 11)).is_err(),
        "rebate above the taker rate"
    );
    assert!(
        m.set_fees(bad(5, 10, 5)).is_err(),
        "a maker fee and a rebate at once"
    );
    assert!(m.set_fees(bad(0, 10, 10)).is_ok());
}
