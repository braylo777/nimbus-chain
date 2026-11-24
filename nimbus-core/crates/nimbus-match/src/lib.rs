//! Deterministic price-time-priority matching engine with integer settlement.
//!
//! * Prices are integer ticks, quantities integer lots; notional = price × qty in checked u128, stored as u128.
//! * Every resting order locks exactly what it can owe: bids lock price × qty of quote, asks lock qty of base.
//! * Fills execute at the maker's price; a bid taker is refunded (limit − fill price) × qty of its lock.
//! * Self-trade prevention: a taker never fills against its own account's order — the resting order is cancelled.
//! * Markets share nothing, so a batch runs one market per core and the result is independent of thread count.
//! * Total deposits per asset are capped at u128::MAX, so no balance, lock or sum can overflow (a deposit that would
//!   exceed the cap is rejected); release builds also keep overflow checks on as a backstop.
//! * Fees (`Fees`, optional): each fill charges the taker ⌈n·t/10⁴⌉ and the maker ⌈n·m/10⁴⌉ quote units (n the fill's
//!   notional, t / m the taker / maker rates in basis points, at most 10 %), credited to a collector account: the
//!   buyer pays n + fee, the seller receives n − fee. A resting or incoming bid for r lots at price p locks
//!   L(p, r) = p·r + ⌈p·r·B/10⁴⌉ + r with B = max(t, m) (L = p·r without fees); a fill of q lots releases
//!   L(p, r) − L(p, r − q) ≥ fill price × q + fee, the excess returning to free balance. Fees move quote between
//!   accounts, so total supply is conserved exactly; with zero fees behaviour and state hashes are as before.
//! * Maker rebates (optional, on markets without a maker fee): the maker of each fill receives ⌊n·ρ/10⁴⌋ out of the
//!   taker's fee; ρ ≤ t keeps the collector's take ⌈n·t/10⁴⌉ − ⌊n·ρ/10⁴⌋ non-negative, so supply stays conserved.
#![forbid(unsafe_code)]

use nimbus_hash::{hash_tagged, merkle_root, Hash, Reader, Truncated, STATE};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, HashMap};

pub type Price = u64;
pub type Qty = u64;
pub type AccountId = u32;
pub type OrderId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Bid,
    Ask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tif {
    /// Rests on the book until filled or cancelled.
    Gtc,
    /// Matches what it can immediately; the remainder is released.
    Ioc,
    /// Fills its whole quantity immediately or is rejected (`Reject::NotFillable`) without touching state.
    Fok,
    /// Rests without taking: rejected (`Reject::WouldCross`) without touching state if it would match on arrival,
    /// so it can only ever be a maker.
    PostOnly,
}

impl Tif {
    /// Whether an unfilled remainder rests on the book.
    pub fn rests(self) -> bool {
        matches!(self, Tif::Gtc | Tif::PostOnly)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Deposit {
        acct: AccountId,
        base: u128,
        quote: u128,
    },
    Withdraw {
        acct: AccountId,
        base: u128,
        quote: u128,
    },
    Order {
        acct: AccountId,
        side: Side,
        price: Price,
        qty: Qty,
        tif: Tif,
    },
    Cancel {
        acct: AccountId,
        id: OrderId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reject {
    ZeroQtyOrPrice,
    InsufficientBalance,
    UnknownOrder,
    NotOwner,
    Overflow,
    /// A fill-or-kill order could not be filled in full at its limit (resting orders of the same account excluded).
    NotFillable,
    /// A post-only order's price reaches the best opposite price (including the account's own orders).
    WouldCross,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fill {
    pub maker: OrderId,
    pub taker_acct: AccountId,
    pub maker_acct: AccountId,
    pub price: Price,
    pub qty: Qty,
    /// Quote units charged to the taker and to the maker for this fill, and paid to the maker as a rebate.
    pub taker_fee: u128,
    pub maker_fee: u128,
    pub maker_rebate: u128,
}

/// Highest fee rate accepted, in basis points (10 %).
pub const MAX_FEE_BPS: u16 = 1_000;

/// A market's fee schedule: rates in basis points of each fill's notional, paid in quote to `collector`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fees {
    pub maker_bps: u16,
    pub taker_bps: u16,
    pub collector: AccountId,
    /// Paid to the maker of each fill, rounded down; at most `taker_bps`, and only with `maker_bps = 0`.
    pub maker_rebate_bps: u16,
}

impl Fees {
    pub fn is_zero(&self) -> bool {
        self.maker_bps == 0 && self.taker_bps == 0 && self.maker_rebate_bps == 0
    }
    /// Rates within bounds, and a rebate funded by the taker fee of the same fill.
    pub fn is_valid(&self) -> bool {
        self.maker_bps <= MAX_FEE_BPS
            && self.taker_bps <= MAX_FEE_BPS
            && self.maker_rebate_bps <= self.taker_bps
            && (self.maker_rebate_bps == 0 || self.maker_bps == 0)
    }
    fn max_bps(&self) -> u16 {
        self.maker_bps.max(self.taker_bps)
    }
}

/// ⌈n·bps/10⁴⌉, computed as ⌊n/10⁴⌋·bps + ⌈(n mod 10⁴)·bps/10⁴⌉ so that it cannot overflow for any n and
/// bps ≤ 10⁴ (it is at most n): a fee never fails in the middle of matching.
pub fn fee(n: u128, bps: u16) -> u128 {
    let b = bps as u128;
    (n / 10_000) * b + ((n % 10_000) * b).div_ceil(10_000)
}

/// ⌊n·bps/10⁴⌋, overflow-free like `fee`: rebates round down, so a maker never gains by splitting.
pub fn rebate(n: u128, bps: u16) -> u128 {
    let b = bps as u128;
    (n / 10_000) * b + ((n % 10_000) * b) / 10_000
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Placed {
        id: OrderId,
        fills: Vec<Fill>,
        resting: Qty,
        self_trade_cancels: u32,
    },
    Cancelled {
        id: OrderId,
        released: Qty,
    },
    Rejected(Reject),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub base_free: u128,
    pub base_locked: u128,
    pub quote_free: u128,
    pub quote_locked: u128,
}

const NIL: u32 = u32::MAX;

/// A resting order in the slab; each price level is an intrusive doubly-linked FIFO list (O(1) cancel).
#[derive(Clone, Copy, Debug)]
struct Node {
    id: OrderId,
    acct: AccountId,
    qty: Qty,
    prev: u32,
    next: u32,
}

#[derive(Clone, Copy, Debug)]
struct Level {
    head: u32,
    tail: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Market {
    bids: BTreeMap<Price, Level>, // best = highest key
    asks: BTreeMap<Price, Level>, // best = lowest key
    slab: Vec<Node>,
    free: Vec<u32>,
    index: FxHashMap<OrderId, (Side, Price, u32)>,
    /// SipHash with a per-process random key: account ids may be user-influenced, so collisions must not be
    /// engineerable. (The order index keeps FxHash: order ids are engine-assigned.)
    accounts: HashMap<AccountId, Balance>,
    next_id: OrderId,
    /// Total base / quote deposited and not withdrawn (derived: equals `totals()`; not part of the state hash).
    supply: (u128, u128),
    fees: Fees,
}

fn notional(p: Price, q: Qty) -> Result<u128, Reject> {
    (p as u128).checked_mul(q as u128).ok_or(Reject::Overflow)
}

impl Market {
    pub fn new() -> Self {
        Market {
            next_id: 1,
            ..Default::default()
        }
    }

    fn alloc(&mut self, n: Node) -> u32 {
        match self.free.pop() {
            Some(i) => {
                self.slab[i as usize] = n;
                i
            }
            None => {
                self.slab.push(n);
                (self.slab.len() - 1) as u32
            }
        }
    }

    fn push_back(
        &mut self,
        side: Side,
        price: Price,
        id: OrderId,
        acct: AccountId,
        qty: Qty,
    ) -> u32 {
        let tail = match side {
            Side::Bid => self.bids.get(&price),
            Side::Ask => self.asks.get(&price),
        }
        .map(|l| l.tail);
        let i = self.alloc(Node {
            id,
            acct,
            qty,
            prev: tail.unwrap_or(NIL),
            next: NIL,
        });
        match tail {
            Some(t) => {
                self.slab[t as usize].next = i;
                let book = match side {
                    Side::Bid => &mut self.bids,
                    Side::Ask => &mut self.asks,
                };
                book.get_mut(&price).expect("level").tail = i;
            }
            None => {
                let book = match side {
                    Side::Bid => &mut self.bids,
                    Side::Ask => &mut self.asks,
                };
                book.insert(price, Level { head: i, tail: i });
            }
        }
        i
    }

    /// Remove slot `i` from its level list (removing the level if it empties) and free the slot.
    fn unlink(&mut self, side: Side, price: Price, i: u32) {
        let Node { prev, next, .. } = self.slab[i as usize];
        if prev != NIL {
            self.slab[prev as usize].next = next;
        }
        if next != NIL {
            self.slab[next as usize].prev = prev;
        }
        let book = match side {
            Side::Bid => &mut self.bids,
            Side::Ask => &mut self.asks,
        };
        let lvl = book.get_mut(&price).expect("level");
        if lvl.head == i {
            lvl.head = next;
        }
        if lvl.tail == i {
            lvl.tail = prev;
        }
        if lvl.head == NIL {
            book.remove(&price);
        }
        self.free.push(i);
    }

    /// Set the fee schedule. Only while the book is empty: resting bids' locks depend on it.
    pub fn set_fees(&mut self, f: Fees) -> Result<(), Reject> {
        if !f.is_valid() || !self.index.is_empty() {
            return Err(Reject::Overflow);
        }
        self.fees = f;
        Ok(())
    }

    pub fn fees(&self) -> Fees {
        self.fees
    }

    /// Quote locked by a bid for `r` lots at price `p`: L(p, r) = p·r + ⌈p·r·B/10⁴⌉ + r (p·r without fees).
    pub fn bid_lock(&self, p: Price, r: Qty) -> Result<u128, Reject> {
        let n = notional(p, r)?;
        if self.fees.is_zero() || r == 0 {
            return Ok(n);
        }
        n.checked_add(fee(n, self.fees.max_bps()))
            .and_then(|x| x.checked_add(r as u128))
            .ok_or(Reject::Overflow)
    }

    /// Release the lock of `q` of the `r` lots a bid at `p` still has, pay `n + fee` out of it, return the rest.
    /// Infallible: L(p, r) was computed without overflow when the bid was admitted, and L is increasing in r.
    fn bid_pays(&self, p: Price, r: Qty, q: Qty, n: u128, fee: u128) -> (u128, u128) {
        let lock = |r| {
            self.bid_lock(p, r)
                .expect("bounded by the lock taken at admission")
        };
        let release = lock(r) - lock(r - q);
        let refund = release
            .checked_sub(n + fee)
            .expect("L(p, r) − L(p, r − q) covers the fill and its fee");
        (release, refund)
    }

    pub fn balance(&self, a: AccountId) -> Balance {
        self.accounts.get(&a).copied().unwrap_or_default()
    }
    pub fn best_bid(&self) -> Option<Price> {
        self.bids.keys().next_back().copied()
    }
    pub fn best_ask(&self) -> Option<Price> {
        self.asks.keys().next().copied()
    }
    /// The owner of resting order `id`, if it is resting.
    pub fn owner(&self, id: OrderId) -> Option<AccountId> {
        self.index
            .get(&id)
            .map(|&(_, _, i)| self.slab[i as usize].acct)
    }
    pub fn open_orders(&self) -> usize {
        self.index.len()
    }

    pub fn apply(&mut self, op: &Op) -> Outcome {
        match *op {
            Op::Deposit { acct, base, quote } => {
                // Capping total supply bounds every field and every sum below u128::MAX.
                let (Some(sb), Some(sq)) = (
                    self.supply.0.checked_add(base),
                    self.supply.1.checked_add(quote),
                ) else {
                    return Outcome::Rejected(Reject::Overflow);
                };
                self.supply = (sb, sq);
                let b = self.accounts.entry(acct).or_default();
                b.base_free += base;
                b.quote_free += quote;
                Outcome::Ok
            }
            Op::Withdraw { acct, base, quote } => {
                // Rejections must not touch state, so an unknown account is not created here.
                let Some(b) = self.accounts.get_mut(&acct) else {
                    return Outcome::Rejected(Reject::InsufficientBalance);
                };
                if b.base_free < base || b.quote_free < quote {
                    return Outcome::Rejected(Reject::InsufficientBalance);
                }
                b.base_free -= base;
                b.quote_free -= quote;
                self.supply.0 -= base;
                self.supply.1 -= quote;
                Outcome::Ok
            }
            Op::Order {
                acct,
                side,
                price,
                qty,
                tif,
            } => match self.order(acct, side, price, qty, tif) {
                Ok(o) => o,
                Err(r) => Outcome::Rejected(r),
            },
            Op::Cancel { acct, id } => match self.cancel(acct, id) {
                Ok(o) => o,
                Err(r) => Outcome::Rejected(r),
            },
        }
    }

    fn order(
        &mut self,
        acct: AccountId,
        side: Side,
        price: Price,
        qty: Qty,
        tif: Tif,
    ) -> Result<Outcome, Reject> {
        if qty == 0 || price == 0 {
            return Err(Reject::ZeroQtyOrPrice);
        }
        let crosses = |p: Price| match side {
            Side::Bid => p <= price,
            Side::Ask => p >= price,
        };
        match tif {
            Tif::PostOnly => {
                let best = match side {
                    Side::Bid => self.best_ask(),
                    Side::Ask => self.best_bid(),
                };
                if best.is_some_and(crosses) {
                    return Err(Reject::WouldCross);
                }
            }
            Tif::Fok => {
                // Matching skips (and cancels) the account's own resting orders, so they do not count as liquidity.
                if self.fillable(side, price, acct, qty) < qty {
                    return Err(Reject::NotFillable);
                }
            }
            Tif::Gtc | Tif::Ioc => {}
        }
        // Lock the worst case up front: all-or-nothing admission, so matching can never overdraw.
        let lock = match side {
            Side::Bid => self.bid_lock(price, qty)?,
            Side::Ask => qty as u128,
        };
        {
            let Some(b) = self.accounts.get_mut(&acct) else {
                return Err(Reject::InsufficientBalance);
            };
            let free = match side {
                Side::Bid => &mut b.quote_free,
                Side::Ask => &mut b.base_free,
            };
            if *free < lock {
                return Err(Reject::InsufficientBalance);
            }
            *free -= lock;
            match side {
                Side::Bid => b.quote_locked += lock,
                Side::Ask => b.base_locked += lock,
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut remaining = qty;
        let mut fills = Vec::new();
        let mut stp = 0u32;

        loop {
            if remaining == 0 {
                break;
            }
            let best = match side {
                Side::Bid => self.asks.keys().next().copied().filter(|&p| p <= price),
                Side::Ask => self
                    .bids
                    .keys()
                    .next_back()
                    .copied()
                    .filter(|&p| p >= price),
            };
            let Some(level_price) = best else { break };
            let maker_side = side.opposite();
            let slot = match maker_side {
                Side::Bid => self.bids[&level_price].head,
                Side::Ask => self.asks[&level_price].head,
            };
            let maker = self.slab[slot as usize];
            if maker.acct == acct {
                // Self-trade prevention: cancel the resting (older) order, release its lock, keep matching.
                self.unlink(maker_side, level_price, slot);
                self.index.remove(&maker.id);
                match side.opposite() {
                    Side::Bid => {
                        let n = self.bid_lock(level_price, maker.qty)?;
                        let mb = self.accounts.get_mut(&acct).expect("maker account");
                        mb.quote_locked -= n;
                        mb.quote_free += n;
                    }
                    Side::Ask => {
                        let mb = self.accounts.get_mut(&acct).expect("maker account");
                        mb.base_locked -= maker.qty as u128;
                        mb.base_free += maker.qty as u128;
                    }
                }
                stp += 1;
                continue;
            }
            let q = remaining.min(maker.qty);
            let n = notional(level_price, q)?;
            self.slab[slot as usize].qty -= q;
            if self.slab[slot as usize].qty == 0 {
                self.unlink(maker_side, level_price, slot);
                self.index.remove(&maker.id);
            }
            let (taker_fee, maker_fee) = (fee(n, self.fees.taker_bps), fee(n, self.fees.maker_bps));
            let maker_rebate = rebate(n, self.fees.maker_rebate_bps);
            // Settlement at the maker's price.
            match side {
                Side::Bid => {
                    // Price improvement and the unused fee reserve return to free balance.
                    let (release, refund) = self.bid_pays(price, remaining, q, n, taker_fee);
                    let t = self.accounts.get_mut(&acct).expect("taker");
                    t.quote_locked -= release;
                    t.quote_free += refund;
                    t.base_free += q as u128;
                    let m = self.accounts.get_mut(&maker.acct).expect("maker");
                    m.base_locked -= q as u128;
                    m.quote_free += n - maker_fee + maker_rebate;
                }
                Side::Ask => {
                    let t = self.accounts.get_mut(&acct).expect("taker");
                    t.base_locked -= q as u128;
                    t.quote_free += n - taker_fee;
                    let (release, refund) = self.bid_pays(level_price, maker.qty, q, n, maker_fee);
                    let m = self.accounts.get_mut(&maker.acct).expect("maker");
                    m.quote_locked -= release;
                    m.quote_free += refund + maker_rebate;
                    m.base_free += q as u128;
                }
            }
            // ρ ≤ t: ⌊n·ρ/10⁴⌋ ≤ ⌈n·t/10⁴⌉, so the collector's take is never negative.
            let take = taker_fee + maker_fee - maker_rebate;
            if take > 0 {
                self.accounts
                    .entry(self.fees.collector)
                    .or_default()
                    .quote_free += take;
            }
            remaining -= q;
            fills.push(Fill {
                maker: maker.id,
                taker_acct: acct,
                maker_acct: maker.acct,
                price: level_price,
                qty: q,
                taker_fee,
                maker_fee,
                maker_rebate,
            });
        }

        debug_assert!(tif != Tif::Fok || remaining == 0, "fill-or-kill pre-check");
        debug_assert!(
            tif != Tif::PostOnly || fills.is_empty(),
            "post-only pre-check"
        );
        let resting = if remaining > 0 && tif.rests() {
            let slot = self.push_back(side, price, id, acct, remaining);
            self.index.insert(id, (side, price, slot));
            remaining
        } else {
            if remaining > 0 {
                let rel = match side {
                    Side::Bid => self.bid_lock(price, remaining)?,
                    Side::Ask => remaining as u128,
                };
                let b = self.accounts.get_mut(&acct).expect("taker");
                match side {
                    Side::Bid => {
                        b.quote_locked -= rel;
                        b.quote_free += rel;
                    }
                    Side::Ask => {
                        b.base_locked -= rel;
                        b.base_free += rel;
                    }
                }
            }
            0
        };
        Ok(Outcome::Placed {
            id,
            fills,
            resting,
            self_trade_cancels: stp,
        })
    }

    /// Quantity resting at prices an order at `price` on `side` would take, excluding `acct`'s own orders; stops
    /// counting at `want`. Walks exactly the levels and orders matching would visit.
    fn fillable(&self, side: Side, price: Price, acct: AccountId, want: Qty) -> Qty {
        let levels: Box<dyn Iterator<Item = (&Price, &Level)>> = match side {
            Side::Bid => Box::new(self.asks.range(..=price)),
            Side::Ask => Box::new(self.bids.range(price..).rev()),
        };
        let mut got: Qty = 0;
        for (_, level) in levels {
            let mut i = level.head;
            while i != NIL {
                let n = &self.slab[i as usize];
                if n.acct != acct {
                    got = got.saturating_add(n.qty);
                    if got >= want {
                        return got;
                    }
                }
                i = n.next;
            }
        }
        got
    }

    fn cancel(&mut self, acct: AccountId, id: OrderId) -> Result<Outcome, Reject> {
        let &(side, price, slot) = self.index.get(&id).ok_or(Reject::UnknownOrder)?;
        let r = self.slab[slot as usize];
        if r.acct != acct {
            return Err(Reject::NotOwner);
        }
        self.unlink(side, price, slot);
        self.index.remove(&id);
        let n = match side {
            Side::Bid => self.bid_lock(price, r.qty)?,
            Side::Ask => 0,
        };
        let b = self.accounts.get_mut(&acct).expect("owner");
        match side {
            Side::Bid => {
                b.quote_locked -= n;
                b.quote_free += n;
            }
            Side::Ask => {
                b.base_locked -= r.qty as u128;
                b.base_free += r.qty as u128;
            }
        }
        Ok(Outcome::Cancelled {
            id,
            released: r.qty,
        })
    }

    fn level_orders(&self, l: &Level) -> Vec<Node> {
        let mut out = Vec::new();
        let mut i = l.head;
        while i != NIL {
            let n = self.slab[i as usize];
            out.push(n);
            i = n.next;
        }
        out
    }

    /// Deterministic commitment to balances and the full book (STATE domain, RFC 6962).
    pub fn state_hash(&self) -> Hash {
        let mut items: Vec<Vec<u8>> = Vec::with_capacity(self.accounts.len() + self.index.len());
        let mut accts: Vec<(&AccountId, &Balance)> = self.accounts.iter().collect();
        accts.sort_unstable_by_key(|(a, _)| **a);
        for (a, b) in accts {
            let mut v = vec![b'A'];
            v.extend_from_slice(&a.to_be_bytes());
            for x in [b.base_free, b.base_locked, b.quote_free, b.quote_locked] {
                v.extend_from_slice(&x.to_be_bytes());
            }
            items.push(v);
        }
        for (tag, book) in [(b'B', &self.bids), (b'S', &self.asks)] {
            for (p, level) in book {
                for r in self.level_orders(level) {
                    let mut v = vec![tag];
                    v.extend_from_slice(&p.to_be_bytes());
                    v.extend_from_slice(&r.id.to_be_bytes());
                    v.extend_from_slice(&r.acct.to_be_bytes());
                    v.extend_from_slice(&r.qty.to_be_bytes());
                    items.push(v);
                }
            }
        }
        if !self.fees.is_zero() {
            let f = self.fees;
            let mut v = vec![b'F'];
            v.extend_from_slice(&f.maker_bps.to_be_bytes());
            v.extend_from_slice(&f.taker_bps.to_be_bytes());
            v.extend_from_slice(&f.collector.to_be_bytes());
            if f.maker_rebate_bps > 0 {
                v.extend_from_slice(&f.maker_rebate_bps.to_be_bytes());
            }
            items.push(v);
        }
        merkle_root(STATE, &items)
    }

    /// Canonical encoding of the complete market state (snapshot, whitepaper Lemma 9″ domain 0x12): next order id ‖
    /// supply ‖ fees ‖ accounts (ascending id) ‖ bids ‖ asks, each side as its orders in ascending price, then time
    /// order within a price. Unlike `state_hash` it includes the next order id and the supply, so a decoded market
    /// behaves identically on every later operation.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.next_id.to_be_bytes());
        out.extend_from_slice(&self.supply.0.to_be_bytes());
        out.extend_from_slice(&self.supply.1.to_be_bytes());
        let f = self.fees;
        out.extend_from_slice(&f.maker_bps.to_be_bytes());
        out.extend_from_slice(&f.taker_bps.to_be_bytes());
        out.extend_from_slice(&f.collector.to_be_bytes());
        out.extend_from_slice(&f.maker_rebate_bps.to_be_bytes());
        let mut accts: Vec<(&AccountId, &Balance)> = self.accounts.iter().collect();
        accts.sort_unstable_by_key(|(a, _)| **a);
        out.extend_from_slice(&(accts.len() as u32).to_be_bytes());
        out.reserve(68 * accts.len());
        for (a, b) in accts {
            let mut rec = [0u8; 68];
            rec[..4].copy_from_slice(&a.to_be_bytes());
            for (k, x) in [b.base_free, b.base_locked, b.quote_free, b.quote_locked]
                .iter()
                .enumerate()
            {
                rec[4 + 16 * k..20 + 16 * k].copy_from_slice(&x.to_be_bytes());
            }
            out.extend_from_slice(&rec);
        }
        out.reserve(8 + 28 * self.index.len());
        for book in [&self.bids, &self.asks] {
            let count_at = out.len();
            out.extend_from_slice(&[0; 4]);
            let mut n = 0u32;
            for (p, l) in book {
                let mut i = l.head;
                while i != NIL {
                    let o = &self.slab[i as usize];
                    let mut rec = [0u8; 28];
                    rec[..8].copy_from_slice(&p.to_be_bytes());
                    rec[8..16].copy_from_slice(&o.id.to_be_bytes());
                    rec[16..20].copy_from_slice(&o.acct.to_be_bytes());
                    rec[20..].copy_from_slice(&o.qty.to_be_bytes());
                    out.extend_from_slice(&rec);
                    n += 1;
                    i = o.next;
                }
            }
            out[count_at..count_at + 4].copy_from_slice(&n.to_be_bytes());
        }
    }

    /// Inverse of `encode_into`. Refuses (without panicking) any input that is not the encoding of a consistent
    /// market: accounts not strictly ascending, an invalid fee schedule, a zero quantity, prices out of order, a
    /// duplicate or not-yet-issued order id, locks that differ from the book, a crossed book, supply ≠ totals.
    pub fn decode_from(r: &mut Reader) -> Result<Market, Truncated> {
        let bad = |ok: bool| if ok { Ok(()) } else { Err(Truncated) };
        let mut m = Market::new();
        m.next_id = r.u64()?;
        m.supply = (r.u128()?, r.u128()?);
        let f = Fees {
            maker_bps: r.u16()?,
            taker_bps: r.u16()?,
            collector: r.u32()?,
            maker_rebate_bps: r.u16()?,
        };
        bad(f.is_valid())?;
        m.fees = f;
        let n = r.count(4 + 64)?;
        let mut prev: Option<AccountId> = None;
        for _ in 0..n {
            let a = r.u32()?;
            bad(prev.is_none_or(|p| a > p))?;
            prev = Some(a);
            let b = Balance {
                base_free: r.u128()?,
                base_locked: r.u128()?,
                quote_free: r.u128()?,
                quote_locked: r.u128()?,
            };
            m.accounts.insert(a, b);
        }
        for side in [Side::Bid, Side::Ask] {
            let n = r.count(28)?;
            let mut last = 0;
            for _ in 0..n {
                let (p, id, acct, qty) = (r.u64()?, r.u64()?, r.u32()?, r.u64()?);
                bad(p >= last && p > 0 && qty > 0 && id < m.next_id && !m.index.contains_key(&id))?;
                bad(m.accounts.contains_key(&acct))?;
                last = p;
                let slot = m.push_back(side, p, id, acct, qty);
                m.index.insert(id, (side, p, slot));
            }
        }
        bad(m.check_invariants().is_ok())?;
        Ok(m)
    }

    /// Invariant check used by tests: locks equal book contents, no crossed book.
    pub fn check_invariants(&self) -> Result<(), String> {
        let mut quote_lock: BTreeMap<AccountId, u128> = BTreeMap::new();
        let mut base_lock: BTreeMap<AccountId, u128> = BTreeMap::new();
        for (p, level) in &self.bids {
            for r in self.level_orders(level) {
                *quote_lock.entry(r.acct).or_default() +=
                    self.bid_lock(*p, r.qty).map_err(|e| format!("{e:?}"))?;
            }
        }
        for level in self.asks.values() {
            for r in self.level_orders(level) {
                *base_lock.entry(r.acct).or_default() += r.qty as u128;
            }
        }
        for (a, b) in &self.accounts {
            if b.quote_locked != quote_lock.get(a).copied().unwrap_or(0) {
                return Err(format!("quote lock mismatch for {a}"));
            }
            if b.base_locked != base_lock.get(a).copied().unwrap_or(0) {
                return Err(format!("base lock mismatch for {a}"));
            }
        }
        if let (Some(b), Some(a)) = (self.best_bid(), self.best_ask()) {
            if b >= a {
                return Err(format!("crossed book {b} >= {a}"));
            }
        }
        let mut resting = 0usize;
        for l in self.bids.values().chain(self.asks.values()) {
            let os = self.level_orders(l);
            if os.is_empty() || os.iter().any(|r| r.qty == 0) {
                return Err("empty level or zero-qty order".into());
            }
            if self.slab[l.tail as usize].next != NIL {
                return Err("tail pointer broken".into());
            }
            resting += os.len();
        }
        if resting != self.index.len() {
            return Err(format!("index {} != resting {}", self.index.len(), resting));
        }
        if self.totals() != self.supply {
            return Err(format!(
                "totals {:?} != supply {:?}",
                self.totals(),
                self.supply
            ));
        }
        Ok(())
    }

    pub fn totals(&self) -> (u128, u128) {
        self.accounts.values().fold((0, 0), |(x, y), b| {
            (
                x + b.base_free + b.base_locked,
                y + b.quote_free + b.quote_locked,
            )
        })
    }
}

impl Op {
    /// The account the operation acts for.
    pub fn acct(&self) -> AccountId {
        match *self {
            Op::Deposit { acct, .. }
            | Op::Withdraw { acct, .. }
            | Op::Order { acct, .. }
            | Op::Cancel { acct, .. } => acct,
        }
    }
}

impl Side {
    pub fn opposite(self) -> Side {
        match self {
            Side::Bid => Side::Ask,
            Side::Ask => Side::Bid,
        }
    }
}

/// One applied operation: its outcome, the acting account's balance after it, and — aligned with the fills — each
/// maker's balance after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    pub outcome: Outcome,
    pub balance: Balance,
    pub makers: Vec<Balance>,
}

/// Many independent markets; a batch is split by market and executed in parallel.
pub struct Exchange {
    pub markets: Vec<Market>,
}

impl Exchange {
    pub fn new(n: usize) -> Self {
        Exchange {
            markets: (0..n).map(|_| Market::new()).collect(),
        }
    }
    /// Canonical encoding of every market (market count ‖ markets in index order).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.markets.len() as u32).to_be_bytes());
        // Markets encode independently on all cores; the concatenation is the canonical order.
        let parts: Vec<Vec<u8>> = self
            .markets
            .par_iter()
            .map(|m| {
                let mut v = Vec::new();
                m.encode_into(&mut v);
                v
            })
            .collect();
        out.reserve(parts.iter().map(Vec::len).sum());
        for v in parts {
            out.extend_from_slice(&v);
        }
    }
    /// Inverse of `encode_into` (each market validated as in `Market::decode_from`).
    pub fn decode_from(r: &mut Reader) -> Result<Exchange, Truncated> {
        let n = r.count(62)?;
        let markets = (0..n)
            .map(|_| Market::decode_from(r))
            .collect::<Result<_, _>>()?;
        Ok(Exchange { markets })
    }
    /// Set one fee schedule on every market (before any order rests).
    pub fn set_fees(&mut self, f: Fees) -> Result<(), Reject> {
        self.markets.iter_mut().try_for_each(|m| m.set_fees(f))
    }
    /// Apply `(market, op)` pairs. Order within each market is preserved; markets run concurrently.
    pub fn apply_batch(&mut self, batch: &[(usize, Op)]) -> Vec<Vec<Outcome>> {
        let mut per: Vec<Vec<&Op>> = vec![Vec::new(); self.markets.len()];
        for (m, op) in batch {
            per[*m].push(op);
        }
        self.markets
            .par_iter_mut()
            .zip(per.par_iter())
            .map(|(mkt, ops)| ops.iter().map(|op| mkt.apply(op)).collect())
            .collect()
    }
    /// `apply_batch`, also returning the acting account's balance in that market right after each op, and each filled
    /// maker's balance after it (for receipts that let takers and makers reconcile every trade exactly).
    pub fn apply_batch_detailed(&mut self, batch: &[(usize, Op)]) -> Vec<Vec<Applied>> {
        let mut per: Vec<Vec<&Op>> = vec![Vec::new(); self.markets.len()];
        for (m, op) in batch {
            per[*m].push(op);
        }
        self.markets
            .par_iter_mut()
            .zip(per.par_iter())
            .map(|(mkt, ops)| {
                ops.iter()
                    .map(|op| {
                        let outcome = mkt.apply(op);
                        let makers = match &outcome {
                            Outcome::Placed { fills, .. } => {
                                fills.iter().map(|f| mkt.balance(f.maker_acct)).collect()
                            }
                            _ => Vec::new(),
                        };
                        Applied {
                            balance: mkt.balance(op.acct()),
                            outcome,
                            makers,
                        }
                    })
                    .collect()
            })
            .collect()
    }
    pub fn state_hash(&self) -> Hash {
        let per: Vec<Hash> = self.markets.par_iter().map(|m| m.state_hash()).collect();
        let items: Vec<Vec<u8>> = per
            .iter()
            .enumerate()
            .map(|(i, h)| [(i as u64).to_be_bytes().as_slice(), h.as_slice()].concat())
            .collect();
        let _ = hash_tagged; // keep the domain API in scope for users of this crate
        merkle_root(STATE, &items)
    }
}
