//! Differential test: the optimised engine (slab, intrusive level lists, BTreeMap ladders, hash index) against a
//! deliberately naive reference (one Vec of resting orders, linear scans, checked arithmetic everywhere). After every
//! operation the outcome — every fill's maker, price, quantity and fees, order ids, resting quantity, self-trade
//! cancels — and every balance, the top of book and the open-order count must be identical.
//!
//! The reference is formulated differently from the engine: it keeps only each account's *total* base and quote and
//! the list of resting orders, and derives every lock from the book after each operation (a bid for r lots at p
//! locks L(p, r) = p·r + ⌈p·r·B/10⁴⌉ + r with fees, p·r without). Settlement therefore never touches a lock: the
//! buyer's total quote falls by notional + fee, the seller's rises by notional − fee, the collector's rises by both
//! fees. That every total stays ≥ its derived lock (checked subtraction) is the lock-coverage theorem, executed.
use nimbus_match::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
struct Resting {
    id: OrderId,
    acct: AccountId,
    side: Side,
    price: Price,
    qty: Qty,
    seq: u64,
}

#[derive(Default)]
struct Naive {
    book: Vec<Resting>,
    /// (base total, quote total) per account.
    total: BTreeMap<AccountId, (u128, u128)>,
    next_id: OrderId,
    seq: u64,
    supply: (u128, u128),
    fees: Fees,
}

fn mul(p: Price, q: Qty) -> u128 {
    (p as u128)
        .checked_mul(q as u128)
        .expect("u64 × u64 fits in u128")
}

/// ⌈n·bps/10⁴⌉ by exact rational arithmetic on (hi, lo) halves — written independently of the engine's formula.
fn ceil_fee(n: u128, bps: u16) -> u128 {
    let (hi, lo) = (n >> 64, n & u64::MAX as u128);
    // n·bps = hi·bps·2⁶⁴ + lo·bps; divide each part by 10⁴ keeping the remainders.
    let b = bps as u128;
    let (q1, r1) = ((hi * b) / 10_000, (hi * b) % 10_000);
    let carry = (r1 << 64) + lo * b; // < 10⁴·2⁶⁴ + 2⁶⁴·10⁴ fits in u128
    let (q2, r2) = (carry / 10_000, carry % 10_000);
    (q1 << 64) + q2 + u128::from(r2 > 0)
}

/// ⌊n·bps/10⁴⌋, from the same halves.
fn floor_rebate(n: u128, bps: u16) -> u128 {
    let c = ceil_fee(n, bps);
    // ⌈x⌉ − ⌊x⌋ is 1 exactly when 10⁴ does not divide n·bps.
    let exact = ((n % 10_000) * bps as u128).is_multiple_of(10_000);
    if exact {
        c
    } else {
        c - 1
    }
}

impl Naive {
    fn new(fees: Fees) -> Self {
        Naive {
            next_id: 1,
            fees,
            ..Default::default()
        }
    }

    fn lock_of(&self, side: Side, price: Price, qty: Qty) -> Option<u128> {
        match side {
            Side::Ask => Some(qty as u128),
            Side::Bid => {
                let n = mul(price, qty);
                if self.fees.maker_bps == 0 && self.fees.taker_bps == 0 {
                    return Some(n);
                }
                let b = self.fees.maker_bps.max(self.fees.taker_bps);
                n.checked_add(ceil_fee(n, b))?.checked_add(qty as u128)
            }
        }
    }

    fn locked(&self, a: AccountId) -> (u128, u128) {
        self.book
            .iter()
            .filter(|r| r.acct == a)
            .fold((0, 0), |(b, q), r| {
                let l = self.lock_of(r.side, r.price, r.qty).unwrap();
                match r.side {
                    Side::Ask => (b + l, q),
                    Side::Bid => (b, q + l),
                }
            })
    }

    fn balance(&self, a: AccountId) -> Balance {
        let Some(&(tb, tq)) = self.total.get(&a) else {
            return Balance::default();
        };
        let (lb, lq) = self.locked(a);
        Balance {
            base_free: tb.checked_sub(lb).expect("base total covers locks"),
            base_locked: lb,
            quote_free: tq.checked_sub(lq).expect("quote total covers locks"),
            quote_locked: lq,
        }
    }

    /// Index of the best resting order on `side` that crosses `limit`: best price, then earliest arrival.
    fn best(&self, side: Side, limit: Price) -> Option<usize> {
        let crosses = |r: &Resting| match side {
            Side::Ask => r.price <= limit,
            Side::Bid => r.price >= limit,
        };
        self.book
            .iter()
            .enumerate()
            .filter(|(_, r)| r.side == side && crosses(r))
            .min_by_key(|(_, r)| match side {
                Side::Ask => (r.price, r.seq),
                Side::Bid => (u64::MAX - r.price, r.seq),
            })
            .map(|(i, _)| i)
    }

    fn add(&mut self, a: AccountId, db: i8, base: u128, dq: i8, quote: u128) {
        let t = self.total.entry(a).or_default();
        t.0 = if db >= 0 {
            t.0.checked_add(base)
        } else {
            t.0.checked_sub(base)
        }
        .unwrap();
        t.1 = if dq >= 0 {
            t.1.checked_add(quote)
        } else {
            t.1.checked_sub(quote)
        }
        .unwrap();
    }

    fn apply(&mut self, op: &Op) -> Outcome {
        match *op {
            Op::Deposit { acct, base, quote } => {
                match (
                    self.supply.0.checked_add(base),
                    self.supply.1.checked_add(quote),
                ) {
                    (Some(sb), Some(sq)) => {
                        self.supply = (sb, sq);
                        self.add(acct, 1, base, 1, quote);
                        Outcome::Ok
                    }
                    _ => Outcome::Rejected(Reject::Overflow),
                }
            }
            Op::Withdraw { acct, base, quote } => {
                let b = self.balance(acct);
                if !self.total.contains_key(&acct) || b.base_free < base || b.quote_free < quote {
                    return Outcome::Rejected(Reject::InsufficientBalance);
                }
                self.add(acct, -1, base, -1, quote);
                self.supply.0 -= base;
                self.supply.1 -= quote;
                Outcome::Ok
            }
            Op::Cancel { acct, id } => {
                let Some(i) = self.book.iter().position(|r| r.id == id) else {
                    return Outcome::Rejected(Reject::UnknownOrder);
                };
                if self.book[i].acct != acct {
                    return Outcome::Rejected(Reject::NotOwner);
                }
                let r = self.book.remove(i);
                Outcome::Cancelled {
                    id,
                    released: r.qty,
                }
            }
            Op::Order {
                acct,
                side,
                price,
                qty,
                tif,
            } => {
                if qty == 0 || price == 0 {
                    return Outcome::Rejected(Reject::ZeroQtyOrPrice);
                }
                let maker_side = match side {
                    Side::Bid => Side::Ask,
                    Side::Ask => Side::Bid,
                };
                let crossing = |r: &&Resting| {
                    r.side == maker_side
                        && match side {
                            Side::Bid => r.price <= price,
                            Side::Ask => r.price >= price,
                        }
                };
                if tif == Tif::PostOnly && self.book.iter().any(|r| crossing(&r)) {
                    return Outcome::Rejected(Reject::WouldCross);
                }
                if tif == Tif::Fok {
                    let avail: u128 = self
                        .book
                        .iter()
                        .filter(crossing)
                        .filter(|r| r.acct != acct)
                        .map(|r| r.qty as u128)
                        .sum();
                    if avail < qty as u128 {
                        return Outcome::Rejected(Reject::NotFillable);
                    }
                }
                let Some(lock) = self.lock_of(side, price, qty) else {
                    return Outcome::Rejected(Reject::Overflow);
                };
                if !self.total.contains_key(&acct) {
                    return Outcome::Rejected(Reject::InsufficientBalance);
                }
                let b = self.balance(acct);
                let free = match side {
                    Side::Bid => b.quote_free,
                    Side::Ask => b.base_free,
                };
                if free < lock {
                    return Outcome::Rejected(Reject::InsufficientBalance);
                }
                let id = self.next_id;
                self.next_id += 1;
                let (mut remaining, mut fills, mut stp) = (qty, Vec::new(), 0u32);
                while remaining > 0 {
                    let Some(i) = self.best(maker_side, price) else {
                        break;
                    };
                    if self.book[i].acct == acct {
                        self.book.remove(i);
                        stp += 1;
                        continue;
                    }
                    let (m_id, m_acct, m_price) =
                        (self.book[i].id, self.book[i].acct, self.book[i].price);
                    let q = remaining.min(self.book[i].qty);
                    self.book[i].qty -= q;
                    if self.book[i].qty == 0 {
                        self.book.remove(i);
                    }
                    remaining -= q;
                    let n = mul(m_price, q);
                    let (tf, mf) = (
                        ceil_fee(n, self.fees.taker_bps),
                        ceil_fee(n, self.fees.maker_bps),
                    );
                    let rb = floor_rebate(n, self.fees.maker_rebate_bps);
                    let (buyer, bf, seller, sf) = match side {
                        Side::Bid => (acct, tf, m_acct, mf),
                        Side::Ask => (m_acct, mf, acct, tf),
                    };
                    self.add(buyer, 1, q as u128, -1, n + bf);
                    self.add(seller, -1, q as u128, 1, n - sf);
                    if rb > 0 {
                        // The maker's rebate, paid out of the taker's fee of the same fill.
                        self.add(m_acct, 1, 0, 1, rb);
                    }
                    let take = tf + mf - rb;
                    if take > 0 {
                        let c = self.fees.collector;
                        self.add(c, 1, 0, 1, take);
                    }
                    fills.push(Fill {
                        maker: m_id,
                        taker_acct: acct,
                        maker_acct: m_acct,
                        price: m_price,
                        qty: q,
                        taker_fee: tf,
                        maker_fee: mf,
                        maker_rebate: rb,
                    });
                }
                let resting = if remaining > 0 && matches!(tif, Tif::Gtc | Tif::PostOnly) {
                    self.seq += 1;
                    self.book.push(Resting {
                        id,
                        acct,
                        side,
                        price,
                        qty: remaining,
                        seq: self.seq,
                    });
                    remaining
                } else {
                    0
                };
                Outcome::Placed {
                    id,
                    fills,
                    resting,
                    self_trade_cancels: stp,
                }
            }
        }
    }

    fn best_bid(&self) -> Option<Price> {
        self.book
            .iter()
            .filter(|r| r.side == Side::Bid)
            .map(|r| r.price)
            .max()
    }
    fn best_ask(&self) -> Option<Price> {
        self.book
            .iter()
            .filter(|r| r.side == Side::Ask)
            .map(|r| r.price)
            .min()
    }
}

/// Half the orders rest (good-till-cancelled), the rest split between immediate-or-cancel, fill-or-kill and post-only.
fn tif_of(t: u8) -> Tif {
    match t {
        0..=3 => Tif::Gtc,
        4 | 5 => Tif::Ioc,
        6 => Tif::Fok,
        _ => Tif::PostOnly,
    }
}

fn small_ops() -> impl Strategy<Value = Op> {
    prop_oneof![
        1 => (0u32..4, 0u128..60, 0u128..3000).prop_map(|(a, b, q)| Op::Deposit { acct: a, base: b, quote: q }),
        1 => (0u32..4, 0u128..30, 0u128..600).prop_map(|(a, b, q)| Op::Withdraw { acct: a, base: b, quote: q }),
        9 => (0u32..4, any::<bool>(), 1u64..20, 0u64..14, 0u8..8).prop_map(|(a, bid, p, q, t)| Op::Order {
            acct: a, side: if bid { Side::Bid } else { Side::Ask }, price: p, qty: q, tif: tif_of(t) }),
        2 => (0u32..4, 0u64..90).prop_map(|(a, id)| Op::Cancel { acct: a, id }),
    ]
}

/// Extreme magnitudes: prices and quantities near u64::MAX, deposits near u128::MAX (overflow and cap edges).
fn big_ops() -> impl Strategy<Value = Op> {
    let price = prop_oneof![
        Just(1u64),
        Just(2),
        Just(1 << 32),
        Just(u64::MAX / 2),
        Just(u64::MAX - 1),
        Just(u64::MAX)
    ];
    let qty = prop_oneof![Just(0u64), Just(1), Just(3), Just(1 << 31), Just(u64::MAX)];
    let amt = prop_oneof![
        Just(0u128),
        Just(1),
        Just(u64::MAX as u128),
        Just(u128::MAX / 3),
        Just(u128::MAX - 1),
        Just(u128::MAX)
    ];
    prop_oneof![
        2 => (0u32..3, amt.clone(), amt.clone()).prop_map(|(a, b, q)| Op::Deposit { acct: a, base: b, quote: q }),
        1 => (0u32..3, amt.clone(), amt).prop_map(|(a, b, q)| Op::Withdraw { acct: a, base: b, quote: q }),
        6 => (0u32..3, any::<bool>(), price, qty, 0u8..8).prop_map(|(a, bid, p, q, t)| Op::Order {
            acct: a, side: if bid { Side::Bid } else { Side::Ask }, price: p, qty: q, tif: tif_of(t) }),
        1 => (0u32..3, 0u64..40).prop_map(|(a, id)| Op::Cancel { acct: a, id }),
    ]
}

/// Fee schedules exercised: none; taker only; both, with the collector also trading; both at the 10 % maximum;
/// a maker rebate paid to a collector that also trades; a rebate equal to the taker rate (collector nets ≈ 0).
fn schedules() -> [Fees; 6] {
    [
        Fees::default(),
        Fees {
            maker_bps: 0,
            taker_bps: 30,
            collector: 9,
            maker_rebate_bps: 0,
        },
        Fees {
            maker_bps: 10,
            taker_bps: 25,
            collector: 1,
            maker_rebate_bps: 0,
        },
        Fees {
            maker_bps: MAX_FEE_BPS,
            taker_bps: MAX_FEE_BPS,
            collector: 2,
            maker_rebate_bps: 0,
        },
        Fees {
            maker_bps: 0,
            taker_bps: 25,
            collector: 3,
            maker_rebate_bps: 10,
        },
        Fees {
            maker_bps: 0,
            taker_bps: 30,
            collector: 9,
            maker_rebate_bps: 30,
        },
    ]
}

fn compare(ops: &[Op], accounts: u32, fees: Fees) -> Result<(), TestCaseError> {
    let (mut e, mut n) = (Market::new(), Naive::new(fees));
    e.set_fees(fees).unwrap();
    for (k, op) in ops.iter().enumerate() {
        let (got, want) = (e.apply(op), n.apply(op));
        prop_assert_eq!(
            &got,
            &want,
            "outcome differs at op {} {:?} (fees {:?})",
            k,
            op,
            fees
        );
        for a in (0..accounts).chain([fees.collector]) {
            prop_assert_eq!(
                e.balance(a),
                n.balance(a),
                "balance of {} after op {}",
                a,
                k
            );
        }
        prop_assert_eq!(
            (e.best_bid(), e.best_ask()),
            (n.best_bid(), n.best_ask()),
            "top of book after op {}",
            k
        );
        prop_assert_eq!(e.open_orders(), n.book.len());
    }
    if let Err(msg) = e.check_invariants() {
        return Err(TestCaseError::fail(msg));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(2000), .. ProptestConfig::default() })]

    #[test]
    fn engine_equals_naive_reference(ops in prop::collection::vec(small_ops(), 1..400), f in 0usize..6) {
        compare(&ops, 4, schedules()[f])?;
    }

    #[test]
    fn engine_equals_naive_reference_at_extreme_magnitudes(ops in prop::collection::vec(big_ops(), 1..120), f in 0usize..6) {
        compare(&ops, 3, schedules()[f])?;
    }

    /// The two fee formulas agree everywhere, including at the top of the u128 range.
    #[test]
    fn fee_formulas_agree(n in any::<u128>(), bps in 0u16..=10_000) {
        prop_assert_eq!(fee(n, bps), ceil_fee(n, bps));
        prop_assert!(fee(n, bps) <= n);
        prop_assert_eq!(rebate(n, bps), floor_rebate(n, bps));
        prop_assert!(rebate(n, bps) <= fee(n, bps));
    }
}
