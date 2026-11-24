//! Agent SDK: risk policy, rate limiting and exact pre-trade simulation.
//!
//! Accuracy per trade comes from `Simulator::preview`: it runs the order against an exact copy of the market
//! (same engine code), so the agent knows the fills, prices and resulting balances before it signs.
#![forbid(unsafe_code)]

use nimbus_match::{Balance, Market, Op, Outcome, Price};
use nimbus_order::Intent;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskPolicy {
    /// Markets the agent may trade.
    pub markets: Vec<u32>,
    /// Maximum lots per order.
    pub max_qty: u64,
    /// Maximum price × qty per order (quote units).
    pub max_notional: u64,
    /// Maximum distance of the limit price from the reference price, in basis points.
    pub price_band_bps: u32,
    /// Token-bucket rate: orders per second (burst = one second's worth).
    pub max_orders_per_sec: u32,
    /// Maximum lifetime of an order, in slots.
    pub max_expiry_slots: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RiskReject {
    Market(u32),
    Qty {
        qty: u64,
        max: u64,
    },
    Notional {
        notional: u128,
        max: u64,
    },
    PriceBand {
        price: Price,
        reference: Price,
        band_bps: u32,
    },
    Expiry {
        expiry: u64,
        now: u64,
        max_life: u64,
    },
    Rate,
    NoReference,
}

impl RiskPolicy {
    /// Stateless checks (everything except the rate limit).
    pub fn check(&self, i: &Intent, reference: Price, now_slot: u64) -> Result<(), RiskReject> {
        if !self.markets.contains(&i.market) {
            return Err(RiskReject::Market(i.market));
        }
        if i.qty > self.max_qty {
            return Err(RiskReject::Qty {
                qty: i.qty,
                max: self.max_qty,
            });
        }
        let notional = i.price as u128 * i.qty as u128;
        if notional > self.max_notional as u128 {
            return Err(RiskReject::Notional {
                notional,
                max: self.max_notional,
            });
        }
        if reference == 0 {
            return Err(RiskReject::NoReference);
        }
        let dist = (i.price as i128 - reference as i128).unsigned_abs();
        if dist * 10_000 > self.price_band_bps as u128 * reference as u128 {
            return Err(RiskReject::PriceBand {
                price: i.price,
                reference,
                band_bps: self.price_band_bps,
            });
        }
        if i.expiry_slot < now_slot || i.expiry_slot - now_slot > self.max_expiry_slots {
            return Err(RiskReject::Expiry {
                expiry: i.expiry_slot,
                now: now_slot,
                max_life: self.max_expiry_slots,
            });
        }
        Ok(())
    }
}

/// Deterministic token bucket driven by an explicit clock (milliseconds).
#[derive(Clone, Debug)]
pub struct RateLimiter {
    rate_per_sec: u64,
    tokens_milli: u64, // tokens × 1000
    last_ms: u64,
}

impl RateLimiter {
    pub fn new(rate_per_sec: u32, now_ms: u64) -> Self {
        RateLimiter {
            rate_per_sec: rate_per_sec as u64,
            tokens_milli: rate_per_sec as u64 * 1000,
            last_ms: now_ms,
        }
    }
    pub fn try_take(&mut self, now_ms: u64) -> bool {
        let cap = self.rate_per_sec * 1000;
        let dt = now_ms.saturating_sub(self.last_ms);
        self.tokens_milli = (self.tokens_milli + dt * self.rate_per_sec).min(cap);
        self.last_ms = self.last_ms.max(now_ms);
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// Expected result of an order, computed before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub outcome: Outcome,
    pub filled: u64,
    pub avg_price_x1e6: Option<u128>,
    pub balance_after: Balance,
}

/// A local mirror of one market, updated with the same operations the engine applies.
#[derive(Clone, Debug, Default)]
pub struct Simulator {
    pub mirror: Market,
}

impl Simulator {
    pub fn new() -> Self {
        Simulator {
            mirror: Market::new(),
        }
    }

    pub fn apply(&mut self, op: &Op) -> Outcome {
        self.mirror.apply(op)
    }

    /// Run `op` on a copy of the mirror and report what would happen to `acct`. Cost: one clone of the market.
    pub fn preview(&self, op: &Op) -> Preview {
        let acct = match op {
            Op::Order { acct, .. }
            | Op::Cancel { acct, .. }
            | Op::Deposit { acct, .. }
            | Op::Withdraw { acct, .. } => *acct,
        };
        let mut m = self.mirror.clone();
        let outcome = m.apply(op);
        let (filled, notional) = match &outcome {
            Outcome::Placed { fills, .. } => fills.iter().fold((0u64, 0u128), |(q, n), f| {
                (q + f.qty, n + f.price as u128 * f.qty as u128)
            }),
            _ => (0, 0),
        };
        Preview {
            avg_price_x1e6: (filled > 0).then(|| notional * 1_000_000 / filled as u128),
            filled,
            outcome,
            balance_after: m.balance(acct),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimbus_match::{Side, Tif};
    use proptest::prelude::*;

    fn policy() -> RiskPolicy {
        RiskPolicy {
            markets: vec![1],
            max_qty: 100,
            max_notional: 50_000,
            price_band_bps: 500,
            max_orders_per_sec: 10,
            max_expiry_slots: 100,
        }
    }
    fn intent(price: u64, qty: u64, market: u32, expiry: u64) -> Intent {
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
    fn policy_limits() {
        let p = policy();
        assert!(p.check(&intent(1000, 10, 1, 50), 1000, 10).is_ok());
        assert!(matches!(
            p.check(&intent(1000, 10, 2, 50), 1000, 10),
            Err(RiskReject::Market(2))
        ));
        assert!(matches!(
            p.check(&intent(1000, 101, 1, 50), 1000, 10),
            Err(RiskReject::Qty { .. })
        ));
        assert!(matches!(
            p.check(&intent(1000, 60, 1, 50), 1000, 10),
            Err(RiskReject::Notional { .. })
        ));
        assert!(matches!(
            p.check(&intent(1051, 10, 1, 50), 1000, 10),
            Err(RiskReject::PriceBand { .. })
        ));
        assert!(
            p.check(&intent(1050, 10, 1, 50), 1000, 10).is_ok(),
            "exactly at the band edge is allowed"
        );
        assert!(matches!(
            p.check(&intent(1000, 10, 1, 111), 1000, 10),
            Err(RiskReject::Expiry { .. })
        ));
        assert!(matches!(
            p.check(&intent(1000, 10, 1, 9), 1000, 10),
            Err(RiskReject::Expiry { .. })
        ));
    }

    #[test]
    fn rate_limiter_bursts_then_refills() {
        let mut r = RateLimiter::new(10, 0);
        assert_eq!((0..15).filter(|_| r.try_take(0)).count(), 10);
        assert!(!r.try_take(50));
        assert!(r.try_take(100), "one token per 100 ms at 10/s");
        assert_eq!(
            (0..20).filter(|_| r.try_take(10_000)).count(),
            10,
            "burst capped at one second"
        );
    }

    proptest! {
        #[test]
        fn policy_never_passes_out_of_limit_orders(price in 1u64..3000, qty in 1u64..300, market in 0u32..3,
                                                   reference in 1u64..3000, expiry in 0u64..300, now in 0u64..200) {
            let p = policy();
            let i = intent(price, qty, market, expiry);
            if p.check(&i, reference, now).is_ok() {
                prop_assert!(p.markets.contains(&market) && qty <= p.max_qty);
                prop_assert!(price as u128 * qty as u128 <= p.max_notional as u128);
                prop_assert!((price as i128 - reference as i128).unsigned_abs() * 10_000 <= p.price_band_bps as u128 * reference as u128);
                prop_assert!(expiry >= now && expiry - now <= p.max_expiry_slots);
            }
        }

        #[test]
        fn preview_equals_actual_execution(orders in prop::collection::vec((0u32..4, any::<bool>(), 90u64..110, 1u64..20, any::<bool>()), 1..120)) {
            let mut sim = Simulator::new();
            let mut engine = Market::new();
            for a in 0..4 {
                let d = Op::Deposit { acct: a, base: 1_000, quote: 1_000_000 };
                sim.apply(&d); engine.apply(&d);
            }
            for (a, bid, price, qty, ioc) in orders {
                let op = Op::Order { acct: a, side: if bid { Side::Bid } else { Side::Ask }, price, qty, tif: if ioc { Tif::Ioc } else { Tif::Gtc } };
                let predicted = sim.preview(&op);
                let actual = engine.apply(&op);
                sim.apply(&op);
                prop_assert_eq!(&predicted.outcome, &actual, "prediction differs from execution");
                prop_assert_eq!(predicted.balance_after, engine.balance(a));
            }
        }
    }
}
