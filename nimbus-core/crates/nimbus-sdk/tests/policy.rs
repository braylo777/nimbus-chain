//! Agent risk policy, rate limiter and pre-trade simulator: each limit at its exact boundary.
use nimbus_match::{Op, Outcome, Side, Tif};
use nimbus_order::Intent;
use nimbus_sdk::*;

fn policy() -> RiskPolicy {
    RiskPolicy {
        markets: vec![1, 2],
        max_qty: 100,
        max_notional: 50_000,
        price_band_bps: 500,
        max_orders_per_sec: 5,
        max_expiry_slots: 20,
    }
}
fn intent(market: u32, price: u64, qty: u64, expiry: u64) -> Intent {
    Intent {
        market,
        acct: 1,
        side: Side::Bid,
        price,
        qty,
        tif: Tif::Gtc,
        nonce: 0,
        expiry_slot: expiry,
    }
}

#[test]
fn within_every_limit_passes() {
    assert_eq!(policy().check(&intent(1, 500, 100, 30), 500, 10), Ok(()));
}
#[test]
fn market_not_allowed() {
    assert_eq!(
        policy().check(&intent(3, 500, 1, 30), 500, 10),
        Err(RiskReject::Market(3))
    );
}
#[test]
fn qty_at_and_above_the_cap() {
    assert!(policy().check(&intent(1, 1, 100, 30), 1, 10).is_ok());
    assert_eq!(
        policy().check(&intent(1, 1, 101, 30), 1, 10),
        Err(RiskReject::Qty { qty: 101, max: 100 })
    );
}
#[test]
fn notional_at_and_above_the_cap() {
    assert!(policy().check(&intent(1, 500, 100, 30), 500, 10).is_ok());
    assert_eq!(
        policy().check(&intent(1, 501, 100, 30), 501, 10),
        Err(RiskReject::Notional {
            notional: 50_100,
            max: 50_000
        })
    );
}
#[test]
fn no_reference_price() {
    assert_eq!(
        policy().check(&intent(1, 500, 1, 30), 0, 10),
        Err(RiskReject::NoReference)
    );
}
#[test]
fn price_band_edges() {
    // 5 % of 1,000 = 50: 950 and 1,050 pass, 949 and 1,051 do not.
    for p in [950, 1_050] {
        assert!(policy().check(&intent(1, p, 1, 30), 1_000, 10).is_ok());
    }
    for p in [949, 1_051] {
        assert!(matches!(
            policy().check(&intent(1, p, 1, 30), 1_000, 10),
            Err(RiskReject::PriceBand { .. })
        ));
    }
}
#[test]
fn expiry_in_the_past() {
    assert!(matches!(
        policy().check(&intent(1, 500, 1, 9), 500, 10),
        Err(RiskReject::Expiry { .. })
    ));
}
#[test]
fn expiry_beyond_max_life() {
    assert!(policy().check(&intent(1, 500, 1, 30), 500, 10).is_ok());
    assert!(matches!(
        policy().check(&intent(1, 500, 1, 31), 500, 10),
        Err(RiskReject::Expiry { .. })
    ));
}
#[test]
fn policy_serializes() {
    let p = policy();
    let s = serde_json::to_string(&p).unwrap();
    assert_eq!(serde_json::from_str::<RiskPolicy>(&s).unwrap(), p);
}

#[test]
fn rate_limiter_burst_then_refill() {
    let mut r = RateLimiter::new(5, 0);
    assert!((0..5).all(|_| r.try_take(0)), "one second's burst");
    assert!(!r.try_take(0));
    assert!(!r.try_take(199), "0.995 tokens");
    assert!(r.try_take(200), "one token after 200 ms at 5/s");
    assert!(!r.try_take(200));
}
#[test]
fn rate_limiter_caps_at_one_second() {
    let mut r = RateLimiter::new(3, 0);
    assert!((0..3).all(|_| r.try_take(0)));
    let n = (0..10).filter(|_| r.try_take(60_000)).count();
    assert_eq!(n, 3, "a long idle period refills only to the burst size");
}
#[test]
fn rate_limiter_ignores_a_clock_going_backwards() {
    let mut r = RateLimiter::new(1, 1_000);
    assert!(r.try_take(1_000));
    assert!(!r.try_take(500));
    assert!(!r.try_take(1_999));
    assert!(r.try_take(2_000));
}
#[test]
fn rate_limiter_zero_rate_never_allows() {
    let mut r = RateLimiter::new(0, 0);
    assert!(!r.try_take(0) && !r.try_take(1_000_000));
}

fn sim() -> Simulator {
    let mut s = Simulator::new();
    for a in [1, 2] {
        s.apply(&Op::Deposit {
            acct: a,
            base: 100,
            quote: 100_000,
        });
    }
    s.apply(&Op::Order {
        acct: 2,
        side: Side::Ask,
        price: 100,
        qty: 4,
        tif: Tif::Gtc,
    });
    s.apply(&Op::Order {
        acct: 2,
        side: Side::Ask,
        price: 110,
        qty: 4,
        tif: Tif::Gtc,
    });
    s
}
#[test]
fn preview_reports_fill_and_average_price() {
    let s = sim();
    let p = s.preview(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 110,
        qty: 6,
        tif: Tif::Ioc,
    });
    assert_eq!(p.filled, 6);
    // (4·100 + 2·110) / 6 = 103.333…
    assert_eq!(p.avg_price_x1e6, Some(103_333_333));
    assert_eq!(p.balance_after.base_free, 106);
}
#[test]
fn preview_does_not_change_the_mirror() {
    let s = sim();
    let before = s.mirror.state_hash();
    s.preview(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 110,
        qty: 6,
        tif: Tif::Gtc,
    });
    assert_eq!(s.mirror.state_hash(), before);
}
#[test]
fn preview_equals_execution() {
    let mut s = sim();
    let op = Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 105,
        qty: 9,
        tif: Tif::Gtc,
    };
    let p = s.preview(&op);
    assert_eq!(s.apply(&op), p.outcome);
    assert_eq!(s.mirror.balance(1), p.balance_after);
}
#[test]
fn preview_of_a_refused_order() {
    let s = sim();
    let p = s.preview(&Op::Order {
        acct: 1,
        side: Side::Bid,
        price: 0,
        qty: 1,
        tif: Tif::Gtc,
    });
    assert!(matches!(p.outcome, Outcome::Rejected(_)));
    assert_eq!((p.filled, p.avg_price_x1e6), (0, None));
}
