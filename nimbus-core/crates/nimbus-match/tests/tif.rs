//! Fill-or-kill and post-only orders, worked by hand: when each is refused, that a refusal changes nothing, and
//! that the account's own resting orders are not counted as liquidity.
use nimbus_match::*;

fn market() -> Market {
    let mut m = Market::new();
    m.set_fees(Fees {
        maker_bps: 0,
        taker_bps: 25,
        collector: 9,
        maker_rebate_bps: 10,
    })
    .unwrap();
    for a in [1, 2, 3] {
        m.apply(&Op::Deposit {
            acct: a,
            base: 1_000,
            quote: 1_000_000,
        });
    }
    m
}

fn order(acct: AccountId, side: Side, price: Price, qty: Qty, tif: Tif) -> Op {
    Op::Order {
        acct,
        side,
        price,
        qty,
        tif,
    }
}

/// Account 2 asks 3 at 100 and 4 at 101; account 1 asks 5 at 100 (its own liquidity for the bids below).
fn book() -> Market {
    let mut m = market();
    m.apply(&order(2, Side::Ask, 100, 3, Tif::Gtc));
    m.apply(&order(2, Side::Ask, 101, 4, Tif::Gtc));
    m.apply(&order(1, Side::Ask, 100, 5, Tif::Gtc));
    m
}

#[test]
fn fill_or_kill_fills_in_full_exactly_as_immediate_or_cancel_would() {
    let (mut a, mut b) = (book(), book());
    let fok = a.apply(&order(3, Side::Bid, 101, 7, Tif::Fok));
    let ioc = b.apply(&order(3, Side::Bid, 101, 7, Tif::Ioc));
    assert_eq!(fok, ioc);
    let Outcome::Placed { fills, resting, .. } = fok else {
        panic!("{fok:?}")
    };
    assert_eq!(resting, 0);
    // Price-time priority: 3 at 100 (account 2), 4 more lots needed, account 1's 5 at 100 is next in time.
    let q: Vec<_> = fills
        .iter()
        .map(|f| (f.maker_acct, f.price, f.qty))
        .collect();
    assert_eq!(q, vec![(2, 100, 3), (1, 100, 4)]);
    assert_eq!(a.state_hash(), b.state_hash());
}

#[test]
fn fill_or_kill_short_of_liquidity_is_refused_and_changes_nothing() {
    let mut m = book();
    let before = m.state_hash();
    // 3 + 5 = 8 lots rest at 100 (12 at ≤ 101): a bid for 9 at 100 cannot fill in full.
    assert_eq!(
        m.apply(&order(3, Side::Bid, 100, 9, Tif::Fok)),
        Outcome::Rejected(Reject::NotFillable)
    );
    assert_eq!(
        m.state_hash(),
        before,
        "a refused fill-or-kill touches nothing"
    );
    assert_eq!(m.balance(3).quote_locked, 0);
}

#[test]
fn fill_or_kill_does_not_count_the_accounts_own_orders() {
    let mut m = book();
    let before = m.state_hash();
    // Account 1 bids 8 at 100: 8 lots rest at 100, but 5 are its own (self-trade prevention would cancel them).
    assert_eq!(
        m.apply(&order(1, Side::Bid, 100, 8, Tif::Fok)),
        Outcome::Rejected(Reject::NotFillable)
    );
    assert_eq!(
        m.state_hash(),
        before,
        "its own orders were not cancelled either"
    );
    // 3 lots at 100 are account 2's, ahead of account 1's own order in time: a fill-or-kill for 3 fills from them.
    let out = m.apply(&order(1, Side::Bid, 100, 3, Tif::Fok));
    let Outcome::Placed {
        fills,
        self_trade_cancels,
        ..
    } = out
    else {
        panic!("{out:?}")
    };
    assert_eq!((fills.len(), fills[0].qty, self_trade_cancels), (1, 3, 0));
}

#[test]
fn post_only_rests_as_a_maker_and_earns_the_rebate() {
    let mut m = book();
    let out = m.apply(&order(3, Side::Bid, 99, 200, Tif::PostOnly));
    let Outcome::Placed {
        id, fills, resting, ..
    } = out
    else {
        panic!("{out:?}")
    };
    assert_eq!((fills.len(), resting), (0, 200));
    // Account 2 sells 200 into it at 99: n = 19,800; the taker pays ⌈19,800 × 25 / 10⁴⌉ = ⌈49.5⌉ = 50 and the
    // post-only bid, the maker, receives ⌊19,800 × 10 / 10⁴⌋ = ⌊19.8⌋ = 19; the collector keeps 31.
    let out = m.apply(&order(2, Side::Ask, 99, 200, Tif::Ioc));
    let Outcome::Placed { fills, .. } = out else {
        panic!("{out:?}")
    };
    assert_eq!(
        (fills[0].maker, fills[0].taker_fee, fills[0].maker_rebate),
        (id, 50, 19)
    );
    assert_eq!(m.balance(9).quote_free, 31);
    // Account 3 locked L(99, 200) = 19,800 + ⌈49.5⌉ + 200 = 20,050, paid n = 19,800 and was rebated 19.
    let b = m.balance(3);
    assert_eq!(
        (b.quote_free, b.quote_locked, b.base_free),
        (1_000_000 - 19_800 + 19, 0, 1_200)
    );
}

#[test]
fn post_only_that_would_take_is_refused_and_changes_nothing() {
    let mut m = book();
    let before = m.state_hash();
    assert_eq!(
        m.apply(&order(3, Side::Bid, 100, 1, Tif::PostOnly)),
        Outcome::Rejected(Reject::WouldCross)
    );
    // Also against the account's own order: post-only never triggers self-trade prevention.
    assert_eq!(
        m.apply(&order(1, Side::Bid, 100, 1, Tif::PostOnly)),
        Outcome::Rejected(Reject::WouldCross)
    );
    // There are no bids, so a post-only ask at any price rests.
    assert!(matches!(
        m.apply(&order(3, Side::Ask, 1, 1, Tif::PostOnly)),
        Outcome::Placed { resting: 1, .. }
    ));
    assert_ne!(m.state_hash(), before);
}
