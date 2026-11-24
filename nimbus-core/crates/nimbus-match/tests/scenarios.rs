//! Hand-worked matching scenarios without fees: one behaviour per test, each checked against exact balances and the
//! engine's own invariant check.
use nimbus_match::*;

fn m() -> Market {
    let mut m = Market::new();
    for a in 1..=4 {
        assert_eq!(
            m.apply(&Op::Deposit {
                acct: a,
                base: 100,
                quote: 100_000,
            }),
            Outcome::Ok
        );
    }
    m
}
fn gtc(acct: AccountId, side: Side, price: Price, qty: Qty) -> Op {
    Op::Order {
        acct,
        side,
        price,
        qty,
        tif: Tif::Gtc,
    }
}
fn place(m: &mut Market, op: Op) -> (OrderId, Vec<Fill>, Qty) {
    let out = m.apply(&op);
    m.check_invariants().unwrap();
    match out {
        Outcome::Placed {
            id, fills, resting, ..
        } => (id, fills, resting),
        o => panic!("expected Placed, got {o:?}"),
    }
}

#[test]
fn a_resting_bid_locks_price_times_qty() {
    let mut m = m();
    place(&mut m, gtc(1, Side::Bid, 100, 7));
    let b = m.balance(1);
    assert_eq!((b.quote_locked, b.quote_free), (700, 99_300));
    assert_eq!(m.best_bid(), Some(100));
}

#[test]
fn a_resting_ask_locks_base() {
    let mut m = m();
    place(&mut m, gtc(1, Side::Ask, 100, 7));
    let b = m.balance(1);
    assert_eq!((b.base_locked, b.base_free), (7, 93));
    assert_eq!(m.best_ask(), Some(100));
}

#[test]
fn crossing_orders_fill_at_the_maker_price_and_refund_the_bid() {
    let mut m = m();
    place(&mut m, gtc(1, Side::Ask, 95, 10));
    let (_, fills, resting) = place(&mut m, gtc(2, Side::Bid, 100, 10));
    assert_eq!(resting, 0);
    assert_eq!(fills.len(), 1);
    assert_eq!((fills[0].price, fills[0].qty), (95, 10));
    let b = m.balance(2);
    assert_eq!(
        (b.base_free, b.quote_free, b.quote_locked),
        (110, 100_000 - 950, 0)
    );
    let s = m.balance(1);
    assert_eq!((s.base_free, s.quote_free), (90, 100_950));
}

#[test]
fn price_priority_takes_the_best_ask_first() {
    let mut m = m();
    place(&mut m, gtc(1, Side::Ask, 102, 5));
    place(&mut m, gtc(2, Side::Ask, 101, 5));
    let (_, fills, _) = place(&mut m, gtc(3, Side::Bid, 102, 6));
    assert_eq!(
        fills.iter().map(|f| (f.price, f.qty)).collect::<Vec<_>>(),
        vec![(101, 5), (102, 1)]
    );
}

#[test]
fn time_priority_within_a_level() {
    let mut m = m();
    let (a, _, _) = place(&mut m, gtc(1, Side::Ask, 100, 5));
    let (b, _, _) = place(&mut m, gtc(2, Side::Ask, 100, 5));
    let (_, fills, _) = place(&mut m, gtc(3, Side::Bid, 100, 7));
    assert_eq!(
        fills.iter().map(|f| (f.maker, f.qty)).collect::<Vec<_>>(),
        vec![(a, 5), (b, 2)]
    );
}

#[test]
fn partial_fill_rests_the_remainder() {
    let mut m = m();
    place(&mut m, gtc(1, Side::Ask, 100, 3));
    let (id, _, resting) = place(&mut m, gtc(2, Side::Bid, 100, 8));
    assert_eq!(resting, 5);
    assert_eq!(m.owner(id), Some(2));
    assert_eq!(m.balance(2).quote_locked, 500);
}

#[test]
fn ioc_remainder_is_released_not_rested() {
    let mut m = m();
    place(&mut m, gtc(1, Side::Ask, 100, 3));
    let (id, fills, resting) = place(
        &mut m,
        Op::Order {
            acct: 2,
            side: Side::Bid,
            price: 100,
            qty: 8,
            tif: Tif::Ioc,
        },
    );
    assert_eq!((fills.len(), resting), (1, 0));
    assert_eq!(m.owner(id), None);
    assert_eq!(m.balance(2).quote_locked, 0);
}

#[test]
fn self_trade_cancels_the_resting_order() {
    let mut m = m();
    let (mine, _, _) = place(&mut m, gtc(1, Side::Ask, 100, 4));
    let out = m.apply(&gtc(1, Side::Bid, 100, 4));
    m.check_invariants().unwrap();
    match out {
        Outcome::Placed {
            fills,
            self_trade_cancels,
            ..
        } => {
            assert!(fills.is_empty());
            assert_eq!(self_trade_cancels, 1);
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(m.owner(mine), None);
    assert_eq!(m.balance(1).base_locked, 0);
}

#[test]
fn cancel_releases_the_lock() {
    let mut m = m();
    let (id, _, _) = place(&mut m, gtc(1, Side::Bid, 50, 10));
    assert_eq!(
        m.apply(&Op::Cancel { acct: 1, id }),
        Outcome::Cancelled { id, released: 10 }
    );
    assert_eq!(m.balance(1).quote_locked, 0);
    assert_eq!(m.open_orders(), 0);
    m.check_invariants().unwrap();
}

#[test]
fn cancel_by_another_account_is_refused() {
    let mut m = m();
    let (id, _, _) = place(&mut m, gtc(1, Side::Bid, 50, 10));
    assert_eq!(
        m.apply(&Op::Cancel { acct: 2, id }),
        Outcome::Rejected(Reject::NotOwner)
    );
    assert_eq!(m.owner(id), Some(1));
}

#[test]
fn cancel_of_unknown_order_is_refused() {
    let mut m = m();
    assert_eq!(
        m.apply(&Op::Cancel { acct: 1, id: 77 }),
        Outcome::Rejected(Reject::UnknownOrder)
    );
}

#[test]
fn zero_qty_or_price_is_refused() {
    let mut m = m();
    for (p, q) in [(0, 5), (5, 0), (0, 0)] {
        assert_eq!(
            m.apply(&gtc(1, Side::Bid, p, q)),
            Outcome::Rejected(Reject::ZeroQtyOrPrice)
        );
    }
}

#[test]
fn a_bid_beyond_free_quote_is_refused() {
    let mut m = m();
    assert_eq!(
        m.apply(&gtc(1, Side::Bid, 1_001, 100)),
        Outcome::Rejected(Reject::InsufficientBalance)
    );
    assert_eq!(m.balance(1).quote_free, 100_000);
}

#[test]
fn an_ask_beyond_free_base_is_refused() {
    let mut m = m();
    assert_eq!(
        m.apply(&gtc(1, Side::Ask, 1, 101)),
        Outcome::Rejected(Reject::InsufficientBalance)
    );
}

#[test]
fn withdraw_moves_only_free_funds() {
    let mut m = m();
    place(&mut m, gtc(1, Side::Ask, 100, 60));
    assert_eq!(
        m.apply(&Op::Withdraw {
            acct: 1,
            base: 41,
            quote: 0
        }),
        Outcome::Rejected(Reject::InsufficientBalance)
    );
    assert_eq!(
        m.apply(&Op::Withdraw {
            acct: 1,
            base: 40,
            quote: 1
        }),
        Outcome::Ok
    );
    assert_eq!(m.balance(1).base_free, 0);
    m.check_invariants().unwrap();
}

#[test]
fn deposits_above_the_supply_cap_are_refused() {
    let mut m = Market::new();
    assert_eq!(
        m.apply(&Op::Deposit {
            acct: 1,
            base: u128::MAX,
            quote: 0
        }),
        Outcome::Ok
    );
    assert_eq!(
        m.apply(&Op::Deposit {
            acct: 2,
            base: 1,
            quote: 0
        }),
        Outcome::Rejected(Reject::Overflow)
    );
    assert_eq!(m.totals(), (u128::MAX, 0));
}

#[test]
fn order_ids_increase_from_one() {
    let mut m = m();
    let ids: Vec<_> = (0..5)
        .map(|i| place(&mut m, gtc(1, Side::Bid, 10 + i, 1)).0)
        .collect();
    assert_eq!(ids, vec![1, 2, 3, 4, 5]);
}

#[test]
fn a_bid_sweeps_several_levels_and_stops_at_its_limit() {
    let mut m = m();
    for (p, q) in [(100, 2), (101, 2), (102, 2), (110, 2)] {
        place(&mut m, gtc(1, Side::Ask, p, q));
    }
    let (_, fills, resting) = place(&mut m, gtc(2, Side::Bid, 105, 10));
    assert_eq!(fills.iter().map(|f| f.qty).sum::<u64>(), 6);
    assert_eq!(resting, 4);
    assert_eq!((m.best_bid(), m.best_ask()), (Some(105), Some(110)));
}

#[test]
fn an_ask_sweeps_bids_from_the_top() {
    let mut m = m();
    for (p, q) in [(90, 1), (95, 1), (99, 1)] {
        place(&mut m, gtc(1, Side::Bid, p, q));
    }
    let (_, fills, _) = place(&mut m, gtc(2, Side::Ask, 94, 3));
    assert_eq!(
        fills.iter().map(|f| f.price).collect::<Vec<_>>(),
        vec![99, 95]
    );
}

#[test]
fn state_hash_is_deterministic_and_history_sensitive() {
    let run = |ops: &[Op]| {
        let mut x = m();
        for o in ops {
            x.apply(o);
        }
        x.state_hash()
    };
    let a = [gtc(1, Side::Bid, 10, 1), gtc(2, Side::Bid, 11, 1)];
    let b = [gtc(2, Side::Bid, 11, 1), gtc(1, Side::Bid, 10, 1)];
    assert_eq!(run(&a), run(&a));
    assert_ne!(run(&a), run(&b), "order ids differ, so state differs");
}

#[test]
fn rejected_operations_leave_the_state_hash_unchanged() {
    let mut x = m();
    place(&mut x, gtc(1, Side::Bid, 10, 1));
    let h = x.state_hash();
    x.apply(&gtc(1, Side::Bid, 0, 1));
    x.apply(&Op::Cancel { acct: 3, id: 1 });
    x.apply(&Op::Withdraw {
        acct: 4,
        base: 1_000,
        quote: 0,
    });
    assert_eq!(x.state_hash(), h);
}

#[test]
fn exchange_markets_are_independent() {
    let mut ex = Exchange::new(3);
    let dep: Vec<(usize, Op)> = (0..3)
        .map(|k| {
            (
                k,
                Op::Deposit {
                    acct: 1,
                    base: 10,
                    quote: 1_000,
                },
            )
        })
        .collect();
    ex.apply_batch(&dep);
    let out = ex.apply_batch(&[(1, gtc(1, Side::Bid, 5, 2))]);
    assert!(matches!(out[1][0], Outcome::Placed { .. }));
    assert!(out[0].is_empty() && out[2].is_empty());
    assert_eq!(ex.markets[0].balance(1).quote_locked, 0);
    assert_eq!(ex.markets[1].balance(1).quote_locked, 10);
}

#[test]
fn exchange_encoding_roundtrips() {
    let mut ex = Exchange::new(2);
    ex.apply_batch(&[
        (
            0,
            Op::Deposit {
                acct: 1,
                base: 10,
                quote: 1_000,
            },
        ),
        (0, gtc(1, Side::Bid, 5, 2)),
    ]);
    let mut b = Vec::new();
    ex.encode_into(&mut b);
    let mut r = nimbus_hash::Reader::new(&b);
    let back = Exchange::decode_from(&mut r).unwrap();
    assert_eq!(back.state_hash(), ex.state_hash());
}

#[test]
fn fee_and_rebate_rounding() {
    assert_eq!(fee(0, 25), 0);
    assert_eq!(fee(1, 25), 1, "fees round up");
    assert_eq!(fee(10_000, 25), 25);
    assert_eq!(fee(10_001, 25), 26);
    assert_eq!(rebate(1, 25), 0, "rebates round down");
    assert_eq!(rebate(10_000, 25), 25);
    assert_eq!(rebate(19_999, 10), 19);
    assert_eq!(fee(u128::MAX, 10_000), u128::MAX, "no overflow at the top");
}

#[test]
fn fee_schedule_validation() {
    let ok = Fees {
        maker_bps: 0,
        taker_bps: 30,
        collector: 9,
        maker_rebate_bps: 10,
    };
    assert!(ok.is_valid());
    assert!(!Fees {
        taker_bps: 1_001,
        ..ok
    }
    .is_valid());
    assert!(!Fees {
        maker_rebate_bps: 31,
        ..ok
    }
    .is_valid());
    assert!(
        !Fees { maker_bps: 1, ..ok }.is_valid(),
        "rebate needs maker 0"
    );
    assert!(Fees::default().is_zero());
}

#[test]
fn fees_cannot_change_while_orders_rest() {
    let mut x = m();
    place(&mut x, gtc(1, Side::Bid, 10, 1));
    assert!(x
        .set_fees(Fees {
            taker_bps: 5,
            ..Fees::default()
        })
        .is_err());
}

#[test]
fn tif_rests_only_for_gtc_and_post_only() {
    assert!(Tif::Gtc.rests() && Tif::PostOnly.rests());
    assert!(!Tif::Ioc.rests() && !Tif::Fok.rests());
    assert_eq!(Side::Bid.opposite(), Side::Ask);
    assert_eq!(gtc(7, Side::Bid, 1, 1).acct(), 7);
}
