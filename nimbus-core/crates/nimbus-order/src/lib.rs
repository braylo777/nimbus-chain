//! Signed client and bridge messages, the journal entry format, and engine-side admission.
//!
//! Messages (every signature follows `nimbus-sig`: ZIP-215 verification, checked keys):
//! * **Order** (domain 0x09, 140-byte wire): intent (43) ‖ public key (32) ‖ signature (64) ‖ version (1).
//! * **Account action** (domain 0x0F, 162-byte wire): cancel one's own resting order, or withdraw free balance.
//!   action (65) ‖ public key (32) ‖ signature (64) ‖ version (1). Shares the account's nonce sequence with orders.
//! * **Bridge operation** (domain 0x10): a deposit or an account registration, signed by at least `k` of the `m`
//!   bridge keys. op (113) ‖ count (1) ‖ count × (signer index 2 ‖ signature 64) ‖ version (1). Each carries a
//!   unique 32-byte reference and an expiry slot; it applies at most once, and only before its expiry.
//!
//! A journal **entry** is kind (1) ‖ message: 0 order, 1 action, 2 bridge, 3 tick (engine-internal: a slot whose only
//! effect was the expiry of resting orders).
//!
//! Admission of client messages requires: a registered key equal to the embedded one, a valid signature,
//! `expiry_slot ≥ current slot`, lifetime ≤ `max_life`, and `nonce == next_nonce(account)` — so every signed message
//! is accepted at most once, in order, before its deadline. Bridge operations additionally need a k-of-m quorum of
//! distinct bridge signers and respect per-slot deposit caps. Signature checks are stateless: `verify_entries` checks
//! a whole slot on all cores in batches, and `Admission::admit_verified` then admits in arrival order. A `Verified`
//! can only be made by verifying.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nimbus_hash::{hash_tagged, Hash, Reader, Truncated};
use nimbus_match::{AccountId, Op, OrderId, Price, Qty, Side, Tif};
use nimbus_sig::{CheckedKey, Item};
use rustc_hash::FxHashMap;
use std::collections::BTreeSet;

/// Domain tags (extending the whitepaper registry 0x00–0x08).
pub const ORDER_TAG: u8 = 0x09;
pub const ACTION_TAG: u8 = 0x0F;
pub const BRIDGE_TAG: u8 = 0x10;

pub const INTENT_LEN: usize = 43;
pub const WIRE_LEN: usize = INTENT_LEN + 32 + 64 + 1;
pub const WIRE_VERSION: u8 = 1;
pub const ACTION_LEN: usize = 65;
pub const ACTION_WIRE_LEN: usize = ACTION_LEN + 32 + 64 + 1;
pub const BRIDGE_LEN: usize = 113;
pub const MAX_BRIDGE_SIGNERS: usize = 16;
/// Longest entry (kind byte + a bridge operation with the maximum number of signatures).
pub const ENTRY_MAX: usize = 1 + BRIDGE_LEN + 1 + MAX_BRIDGE_SIGNERS * 66 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderError {
    Length,
    Version,
    Field(&'static str),
    UnknownAccount,
    KeyMismatch,
    BadSignature,
    /// A small-order, non-canonical or undecodable public key.
    WeakKey,
    Expired {
        expiry: u64,
        now: u64,
    },
    Nonce {
        expected: u64,
        got: u64,
    },
    LifetimeTooLong {
        expiry: u64,
        now: u64,
        max_life: u64,
    },
    /// No bridge keys are configured.
    NoBridge,
    /// Fewer distinct bridge signatures than the threshold.
    BridgeQuorum {
        have: usize,
        need: usize,
    },
    UnknownBridgeSigner(u16),
    DuplicateBridgeSigner(u16),
    /// This bridge reference was already applied.
    DuplicateReference,
    /// Deposits admitted to this market in this slot would exceed the per-slot cap.
    DepositCap,
    AlreadyRegistered,
    /// Ticks are engine-internal and never accepted from outside.
    Tick,
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes(b[i..i + 4].try_into().expect("4 bytes"))
}
fn u64_at(b: &[u8], i: usize) -> u64 {
    u64::from_be_bytes(b[i..i + 8].try_into().expect("8 bytes"))
}
fn u128_at(b: &[u8], i: usize) -> u128 {
    u128::from_be_bytes(b[i..i + 16].try_into().expect("16 bytes"))
}

// ---------------------------------------------------------------------------------------------------------------
// Orders (0x09)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intent {
    pub market: u32,
    pub acct: AccountId,
    pub side: Side,
    pub price: Price,
    pub qty: Qty,
    pub tif: Tif,
    pub nonce: u64,
    pub expiry_slot: u64,
}

impl Intent {
    pub fn encode(&self) -> [u8; INTENT_LEN] {
        let mut b = [0u8; INTENT_LEN];
        b[0..4].copy_from_slice(&self.market.to_be_bytes());
        b[4..8].copy_from_slice(&self.acct.to_be_bytes());
        b[8] = match self.side {
            Side::Bid => 0,
            Side::Ask => 1,
        };
        b[9..17].copy_from_slice(&self.price.to_be_bytes());
        b[17..25].copy_from_slice(&self.qty.to_be_bytes());
        b[25] = match self.tif {
            Tif::Gtc => 0,
            Tif::Ioc => 1,
            Tif::Fok => 2,
            Tif::PostOnly => 3,
        };
        b[26..34].copy_from_slice(&self.nonce.to_be_bytes());
        b[34..42].copy_from_slice(&self.expiry_slot.to_be_bytes());
        b[42] = 0; // reserved, must be zero
        b
    }

    pub fn decode(b: &[u8]) -> Result<Intent, OrderError> {
        if b.len() != INTENT_LEN {
            return Err(OrderError::Length);
        }
        let side = match b[8] {
            0 => Side::Bid,
            1 => Side::Ask,
            _ => return Err(OrderError::Field("side")),
        };
        let tif = match b[25] {
            0 => Tif::Gtc,
            1 => Tif::Ioc,
            2 => Tif::Fok,
            3 => Tif::PostOnly,
            _ => return Err(OrderError::Field("tif")),
        };
        if b[42] != 0 {
            return Err(OrderError::Field("reserved"));
        }
        let (price, qty) = (u64_at(b, 9), u64_at(b, 17));
        if price == 0 || qty == 0 {
            return Err(OrderError::Field("zero price or qty"));
        }
        Ok(Intent {
            market: u32_at(b, 0),
            acct: u32_at(b, 4),
            side,
            price,
            qty,
            tif,
            nonce: u64_at(b, 26),
            expiry_slot: u64_at(b, 34),
        })
    }

    /// The digest that is signed: H(0x09 ‖ intent).
    pub fn digest(&self) -> Hash {
        hash_tagged(ORDER_TAG, &[&self.encode()])
    }

    pub fn to_op(&self) -> Op {
        Op::Order {
            acct: self.acct,
            side: self.side,
            price: self.price,
            qty: self.qty,
            tif: self.tif,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedOrder {
    pub intent: Intent,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

impl SignedOrder {
    pub fn sign(intent: Intent, key: &SigningKey) -> SignedOrder {
        SignedOrder {
            intent,
            pubkey: key.verifying_key().to_bytes(),
            sig: key.sign(&intent.digest()).to_bytes(),
        }
    }

    pub fn to_bytes(&self) -> [u8; WIRE_LEN] {
        let mut b = [0u8; WIRE_LEN];
        b[..INTENT_LEN].copy_from_slice(&self.intent.encode());
        b[INTENT_LEN..INTENT_LEN + 32].copy_from_slice(&self.pubkey);
        b[INTENT_LEN + 32..INTENT_LEN + 96].copy_from_slice(&self.sig);
        b[WIRE_LEN - 1] = WIRE_VERSION;
        b
    }

    /// Parse untrusted bytes. Never panics; checks structure only.
    pub fn from_bytes(b: &[u8]) -> Result<SignedOrder, OrderError> {
        if b.len() != WIRE_LEN {
            return Err(OrderError::Length);
        }
        if b[WIRE_LEN - 1] != WIRE_VERSION {
            return Err(OrderError::Version);
        }
        Ok(SignedOrder {
            intent: Intent::decode(&b[..INTENT_LEN])?,
            pubkey: b[INTENT_LEN..INTENT_LEN + 32].try_into().expect("32 bytes"),
            sig: b[INTENT_LEN + 32..INTENT_LEN + 96]
                .try_into()
                .expect("64 bytes"),
        })
    }

    /// Signature check against the embedded key (no account binding).
    pub fn signature_valid(&self) -> bool {
        CheckedKey::new(self.pubkey)
            .is_some_and(|k| nimbus_sig::verify(&k, &self.intent.digest(), &self.sig))
    }

    /// Verify against the embedded key and wrap as `Verified`.
    pub fn verify(self) -> Result<Verified, OrderError> {
        let k = CheckedKey::new(self.pubkey).ok_or(OrderError::WeakKey)?;
        if nimbus_sig::verify(&k, &self.intent.digest(), &self.sig) {
            Ok(Verified(Entry::Order(self)))
        } else {
            Err(OrderError::BadSignature)
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Account actions (0x0F)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    /// Cancel one's own resting order.
    Cancel { order_id: OrderId },
    /// Move free balance out of the market (to the account's registered external address).
    Withdraw { base: u128, quote: u128 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Action {
    pub market: u32,
    pub acct: AccountId,
    pub nonce: u64,
    pub expiry_slot: u64,
    pub kind: ActionKind,
}

impl Action {
    /// kind (1) ‖ market (4) ‖ acct (4) ‖ nonce (8) ‖ expiry (8) ‖ order id (8) ‖ base (16) ‖ quote (16).
    pub fn encode(&self) -> [u8; ACTION_LEN] {
        let mut b = [0u8; ACTION_LEN];
        b[1..5].copy_from_slice(&self.market.to_be_bytes());
        b[5..9].copy_from_slice(&self.acct.to_be_bytes());
        b[9..17].copy_from_slice(&self.nonce.to_be_bytes());
        b[17..25].copy_from_slice(&self.expiry_slot.to_be_bytes());
        match self.kind {
            ActionKind::Cancel { order_id } => {
                b[0] = 0;
                b[25..33].copy_from_slice(&order_id.to_be_bytes());
            }
            ActionKind::Withdraw { base, quote } => {
                b[0] = 1;
                b[33..49].copy_from_slice(&base.to_be_bytes());
                b[49..65].copy_from_slice(&quote.to_be_bytes());
            }
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<Action, OrderError> {
        if b.len() != ACTION_LEN {
            return Err(OrderError::Length);
        }
        let (id, base, quote) = (u64_at(b, 25), u128_at(b, 33), u128_at(b, 49));
        let kind = match b[0] {
            0 if base == 0 && quote == 0 && id != 0 => ActionKind::Cancel { order_id: id },
            1 if id == 0 && (base > 0 || quote > 0) => ActionKind::Withdraw { base, quote },
            0 | 1 => return Err(OrderError::Field("action fields")),
            _ => return Err(OrderError::Field("action kind")),
        };
        Ok(Action {
            market: u32_at(b, 1),
            acct: u32_at(b, 5),
            nonce: u64_at(b, 9),
            expiry_slot: u64_at(b, 17),
            kind,
        })
    }

    /// The digest that is signed: H(0x0F ‖ action).
    pub fn digest(&self) -> Hash {
        hash_tagged(ACTION_TAG, &[&self.encode()])
    }

    pub fn to_op(&self) -> Op {
        match self.kind {
            ActionKind::Cancel { order_id } => Op::Cancel {
                acct: self.acct,
                id: order_id,
            },
            ActionKind::Withdraw { base, quote } => Op::Withdraw {
                acct: self.acct,
                base,
                quote,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAction {
    pub action: Action,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

impl SignedAction {
    pub fn sign(action: Action, key: &SigningKey) -> SignedAction {
        SignedAction {
            action,
            pubkey: key.verifying_key().to_bytes(),
            sig: key.sign(&action.digest()).to_bytes(),
        }
    }
    pub fn to_bytes(&self) -> [u8; ACTION_WIRE_LEN] {
        let mut b = [0u8; ACTION_WIRE_LEN];
        b[..ACTION_LEN].copy_from_slice(&self.action.encode());
        b[ACTION_LEN..ACTION_LEN + 32].copy_from_slice(&self.pubkey);
        b[ACTION_LEN + 32..ACTION_LEN + 96].copy_from_slice(&self.sig);
        b[ACTION_WIRE_LEN - 1] = WIRE_VERSION;
        b
    }
    pub fn from_bytes(b: &[u8]) -> Result<SignedAction, OrderError> {
        if b.len() != ACTION_WIRE_LEN {
            return Err(OrderError::Length);
        }
        if b[ACTION_WIRE_LEN - 1] != WIRE_VERSION {
            return Err(OrderError::Version);
        }
        Ok(SignedAction {
            action: Action::decode(&b[..ACTION_LEN])?,
            pubkey: b[ACTION_LEN..ACTION_LEN + 32].try_into().expect("32"),
            sig: b[ACTION_LEN + 32..ACTION_LEN + 96].try_into().expect("64"),
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Bridge operations (0x10)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeKind {
    Deposit {
        market: u32,
        acct: AccountId,
        base: u128,
        quote: u128,
    },
    Register {
        acct: AccountId,
        key: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeOp {
    /// Unique external reference (e.g. the deposit transaction id); each applies at most once.
    pub reference: [u8; 32],
    /// Last slot at which the operation may be admitted (after it, its reference can be forgotten).
    pub expiry_slot: u64,
    pub kind: BridgeKind,
}

impl BridgeOp {
    /// kind (1) ‖ reference (32) ‖ expiry (8) ‖ market (4) ‖ acct (4) ‖ base (16) ‖ quote (16) ‖ key (32).
    pub fn encode(&self) -> [u8; BRIDGE_LEN] {
        let mut b = [0u8; BRIDGE_LEN];
        b[1..33].copy_from_slice(&self.reference);
        b[33..41].copy_from_slice(&self.expiry_slot.to_be_bytes());
        match self.kind {
            BridgeKind::Deposit {
                market,
                acct,
                base,
                quote,
            } => {
                b[0] = 0;
                b[41..45].copy_from_slice(&market.to_be_bytes());
                b[45..49].copy_from_slice(&acct.to_be_bytes());
                b[49..65].copy_from_slice(&base.to_be_bytes());
                b[65..81].copy_from_slice(&quote.to_be_bytes());
            }
            BridgeKind::Register { acct, key } => {
                b[0] = 1;
                b[45..49].copy_from_slice(&acct.to_be_bytes());
                b[81..113].copy_from_slice(&key);
            }
        }
        b
    }

    pub fn decode(b: &[u8]) -> Result<BridgeOp, OrderError> {
        if b.len() != BRIDGE_LEN {
            return Err(OrderError::Length);
        }
        let (market, acct, base, quote) =
            (u32_at(b, 41), u32_at(b, 45), u128_at(b, 49), u128_at(b, 65));
        let key: [u8; 32] = b[81..113].try_into().expect("32");
        let kind = match b[0] {
            0 if key == [0; 32] && (base > 0 || quote > 0) => BridgeKind::Deposit {
                market,
                acct,
                base,
                quote,
            },
            1 if market == 0 && base == 0 && quote == 0 => BridgeKind::Register { acct, key },
            0 | 1 => return Err(OrderError::Field("bridge fields")),
            _ => return Err(OrderError::Field("bridge kind")),
        };
        Ok(BridgeOp {
            reference: b[1..33].try_into().expect("32"),
            expiry_slot: u64_at(b, 33),
            kind,
        })
    }

    /// The digest that is signed: H(0x10 ‖ op).
    pub fn digest(&self) -> Hash {
        hash_tagged(BRIDGE_TAG, &[&self.encode()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBridge {
    pub op: BridgeOp,
    /// (index into the configured bridge key set, signature)
    pub sigs: Vec<(u16, [u8; 64])>,
}

impl SignedBridge {
    /// Sign with the given (index, key) pairs of the bridge key set.
    pub fn sign(op: BridgeOp, signers: &[(u16, &SigningKey)]) -> SignedBridge {
        let d = op.digest();
        SignedBridge {
            op,
            sigs: signers
                .iter()
                .map(|(i, k)| (*i, k.sign(&d).to_bytes()))
                .collect(),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(BRIDGE_LEN + 2 + self.sigs.len() * 66);
        b.extend_from_slice(&self.op.encode());
        b.push(self.sigs.len() as u8);
        for (i, s) in &self.sigs {
            b.extend_from_slice(&i.to_be_bytes());
            b.extend_from_slice(s);
        }
        b.push(WIRE_VERSION);
        b
    }
    pub fn from_bytes(b: &[u8]) -> Result<SignedBridge, OrderError> {
        if b.len() < BRIDGE_LEN + 2 {
            return Err(OrderError::Length);
        }
        let n = b[BRIDGE_LEN] as usize;
        if n > MAX_BRIDGE_SIGNERS {
            return Err(OrderError::Field("too many bridge signatures"));
        }
        if b.len() != BRIDGE_LEN + 2 + n * 66 {
            return Err(OrderError::Length);
        }
        if b[b.len() - 1] != WIRE_VERSION {
            return Err(OrderError::Version);
        }
        let sigs = (0..n)
            .map(|k| {
                let o = BRIDGE_LEN + 1 + k * 66;
                (
                    u16::from_be_bytes([b[o], b[o + 1]]),
                    b[o + 2..o + 66].try_into().expect("64"),
                )
            })
            .collect();
        Ok(SignedBridge {
            op: BridgeOp::decode(&b[..BRIDGE_LEN])?,
            sigs,
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Entries

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Order(SignedOrder),
    Action(SignedAction),
    Bridge(SignedBridge),
    /// Engine-internal: the slot's only effect was expiring resting orders.
    Tick,
}

impl Entry {
    /// kind (1) ‖ message. At most `ENTRY_MAX` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + WIRE_LEN);
        match self {
            Entry::Order(o) => {
                v.push(0);
                v.extend_from_slice(&o.to_bytes());
            }
            Entry::Action(a) => {
                v.push(1);
                v.extend_from_slice(&a.to_bytes());
            }
            Entry::Bridge(b) => {
                v.push(2);
                v.extend_from_slice(&b.to_bytes());
            }
            Entry::Tick => v.push(3),
        }
        v
    }

    /// Parse untrusted bytes (exact length). Never panics.
    pub fn from_bytes(b: &[u8]) -> Result<Entry, OrderError> {
        let (&kind, body) = b.split_first().ok_or(OrderError::Length)?;
        match kind {
            0 => SignedOrder::from_bytes(body).map(Entry::Order),
            1 => SignedAction::from_bytes(body).map(Entry::Action),
            2 => SignedBridge::from_bytes(body).map(Entry::Bridge),
            3 if body.is_empty() => Ok(Entry::Tick),
            3 => Err(OrderError::Length),
            _ => Err(OrderError::Field("entry kind")),
        }
    }

    /// The signed digest (the subject of receipts). Ticks have none.
    pub fn digest(&self) -> Option<Hash> {
        match self {
            Entry::Order(o) => Some(o.intent.digest()),
            Entry::Action(a) => Some(a.action.digest()),
            Entry::Bridge(b) => Some(b.op.digest()),
            Entry::Tick => None,
        }
    }

    /// The account this entry concerns, and the market (if any).
    pub fn subject(&self) -> (Option<AccountId>, Option<u32>) {
        match self {
            Entry::Order(o) => (Some(o.intent.acct), Some(o.intent.market)),
            Entry::Action(a) => (Some(a.action.acct), Some(a.action.market)),
            Entry::Bridge(b) => match b.op.kind {
                BridgeKind::Deposit { market, acct, .. } => (Some(acct), Some(market)),
                BridgeKind::Register { acct, .. } => (Some(acct), None),
            },
            Entry::Tick => (None, None),
        }
    }
}

/// An entry whose signatures have passed the `nimbus-sig` rule. Only the verification functions construct it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified(Entry);

impl Verified {
    pub fn entry(&self) -> &Entry {
        &self.0
    }
    pub fn into_inner(self) -> Entry {
        self.0
    }
    /// An entry read back from this node's own journal, whose signatures were verified when it was admitted. Only
    /// for re-execution whose every result is compared with a signed checkpoint (a snapshot follower).
    pub fn trusted(e: Entry) -> Verified {
        Verified(e)
    }
    /// Ticks carry no signature; only the engine creates them.
    pub fn tick() -> Verified {
        Verified(Entry::Tick)
    }
}

/// Verify one entry's signature items singly (non-batch).
pub fn verify_entry(e: Entry, items: &[Item]) -> Result<Verified, OrderError> {
    if items.is_empty() {
        return Err(OrderError::Tick);
    }
    if items
        .iter()
        .all(|it| nimbus_sig::verify(&it.key, &it.msg, &it.sig))
    {
        Ok(Verified(e))
    } else {
        Err(OrderError::BadSignature)
    }
}

/// Verify many entries on all cores (batched, bisecting on failure). `items_for` supplies the signatures each entry
/// must carry (see `Admission::items_for`); an entry is valid when all of its items are.
pub fn verify_entries(
    entries: Vec<Entry>,
    items_for: impl Fn(&Entry) -> Result<Vec<Item>, OrderError> + Sync,
) -> Vec<Result<Verified, OrderError>> {
    verify_entries_with(entries, items_for, 16)
}

/// `verify_entries` with a chosen minimum batch per thread (1 = latency mode; see `nimbus_sig::verify_all_with`).
pub fn verify_entries_with(
    entries: Vec<Entry>,
    items_for: impl Fn(&Entry) -> Result<Vec<Item>, OrderError> + Sync,
    min_batch: usize,
) -> Vec<Result<Verified, OrderError>> {
    verify_entries_by(entries, items_for, |flat| {
        nimbus_sig::verify_all_with(flat, min_batch)
    })
}

/// `verify_entries_with` with the signature checker supplied (e.g. a `nimbus_sig::SpinPool`); `verify_all` must
/// return one result per item, equal to single verification.
pub fn verify_entries_by(
    entries: Vec<Entry>,
    items_for: impl Fn(&Entry) -> Result<Vec<Item>, OrderError> + Sync,
    verify_all: impl FnOnce(&[Item]) -> Vec<bool>,
) -> Vec<Result<Verified, OrderError>> {
    use rayon::prelude::*;
    let per: Vec<Result<Vec<Item>, OrderError>> = entries
        .par_iter()
        .with_min_len(64)
        .map(&items_for)
        .collect();
    let flat: Vec<Item> = per
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .flatten()
        .copied()
        .collect();
    let mut ok = verify_all(&flat).into_iter();
    entries
        .into_iter()
        .zip(per)
        .map(|(e, r)| {
            let items = r?;
            let all = items.iter().fold(true, |acc, _| {
                ok.next().expect("one result per item") && acc
            });
            if all {
                Ok(Verified(e))
            } else {
                Err(OrderError::BadSignature)
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Admission

/// What an admitted entry does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Apply `op` to `market`.
    Market {
        market: u32,
        op: Op,
    },
    /// A new account was registered (no market effect).
    Registered {
        acct: AccountId,
    },
    Tick,
}

/// Engine-side account registry, bridge quorum and caps, replay protection.
#[derive(Clone, Default)]
pub struct Admission {
    keys: FxHashMap<AccountId, CheckedKey>,
    next_nonce: FxHashMap<AccountId, u64>,
    max_life: Option<u64>,
    bridge: Vec<CheckedKey>,
    bridge_threshold: usize,
    references: FxHashMap<[u8; 32], u64>,
    reference_expiry: BTreeSet<(u64, [u8; 32])>,
    deposit_cap: Option<(u128, u128)>,
    cap_slot: u64,
    deposited: FxHashMap<u32, (u128, u128)>,
}

impl Admission {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `key` to `acct` (genesis / operator path). Weak or malformed keys are refused.
    pub fn register(&mut self, acct: AccountId, key: VerifyingKey) -> Result<(), OrderError> {
        self.register_bytes(acct, key.to_bytes())
    }

    pub fn register_bytes(&mut self, acct: AccountId, key: [u8; 32]) -> Result<(), OrderError> {
        let k = CheckedKey::new(key).ok_or(OrderError::WeakKey)?;
        self.keys.insert(acct, k);
        self.next_nonce.entry(acct).or_insert(0);
        Ok(())
    }

    /// The bridge key set and the number of distinct signatures a bridge operation needs.
    pub fn set_bridge(&mut self, keys: &[[u8; 32]], threshold: usize) -> Result<(), OrderError> {
        if keys.len() > MAX_BRIDGE_SIGNERS || threshold == 0 || threshold > keys.len() {
            return Err(OrderError::Field("bridge threshold"));
        }
        self.bridge = keys
            .iter()
            .map(|k| CheckedKey::new(*k).ok_or(OrderError::WeakKey))
            .collect::<Result<_, _>>()?;
        self.bridge_threshold = threshold;
        Ok(())
    }

    /// Cap on (base, quote) deposited per market per slot. Deposits beyond it are refused (the bridge retries later).
    pub fn set_deposit_cap(&mut self, base: u128, quote: u128) {
        self.deposit_cap = Some((base, quote));
    }

    /// Refuse messages whose expiry is more than `slots` beyond the admission slot.
    pub fn set_max_life(&mut self, slots: u64) {
        self.max_life = Some(slots);
    }

    /// Canonical encoding of the complete admission state (snapshot, domain 0x12): max life ‖ bridge keys and
    /// threshold ‖ deposit cap ‖ cap slot and per-market deposits ‖ account keys ‖ nonces ‖ live bridge references;
    /// every map in ascending key order.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let opt64 = |out: &mut Vec<u8>, x: Option<u64>| {
            out.push(x.is_some() as u8);
            out.extend_from_slice(&x.unwrap_or(0).to_be_bytes());
        };
        opt64(out, self.max_life);
        out.extend_from_slice(&(self.bridge_threshold as u32).to_be_bytes());
        out.extend_from_slice(&(self.bridge.len() as u32).to_be_bytes());
        for k in &self.bridge {
            out.extend_from_slice(k.as_bytes());
        }
        out.push(self.deposit_cap.is_some() as u8);
        let (cb, cq) = self.deposit_cap.unwrap_or((0, 0));
        out.extend_from_slice(&cb.to_be_bytes());
        out.extend_from_slice(&cq.to_be_bytes());
        out.extend_from_slice(&self.cap_slot.to_be_bytes());
        let mut dep: Vec<_> = self.deposited.iter().collect();
        dep.sort_unstable_by_key(|(m, _)| **m);
        out.extend_from_slice(&(dep.len() as u32).to_be_bytes());
        for (m, (b, q)) in dep {
            out.extend_from_slice(&m.to_be_bytes());
            out.extend_from_slice(&b.to_be_bytes());
            out.extend_from_slice(&q.to_be_bytes());
        }
        let mut keys: Vec<_> = self.keys.iter().collect();
        keys.sort_unstable_by_key(|(a, _)| **a);
        out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for (a, k) in keys {
            out.extend_from_slice(&a.to_be_bytes());
            out.extend_from_slice(k.as_bytes());
        }
        let mut nonces: Vec<_> = self.next_nonce.iter().collect();
        nonces.sort_unstable_by_key(|(a, _)| **a);
        out.extend_from_slice(&(nonces.len() as u32).to_be_bytes());
        for (a, n) in nonces {
            out.extend_from_slice(&a.to_be_bytes());
            out.extend_from_slice(&n.to_be_bytes());
        }
        let mut refs: Vec<_> = self.references.iter().collect();
        refs.sort_unstable();
        out.extend_from_slice(&(refs.len() as u32).to_be_bytes());
        for (r, exp) in refs {
            out.extend_from_slice(r);
            out.extend_from_slice(&exp.to_be_bytes());
        }
    }

    /// Inverse of `encode_into`; refuses weak keys, an invalid bridge quorum, maps not strictly ascending, and any
    /// truncated or over-long input.
    pub fn decode_from(r: &mut Reader) -> Result<Admission, Truncated> {
        let bad = |ok: bool| if ok { Ok(()) } else { Err(Truncated) };
        let key = |b: [u8; 32]| CheckedKey::new(b).ok_or(Truncated);
        let mut a = Admission::new();
        let opt64 = |r: &mut Reader| -> Result<Option<u64>, Truncated> {
            match (r.u8()?, r.u64()?) {
                (0, 0) => Ok(None),
                (1, x) => Ok(Some(x)),
                _ => Err(Truncated),
            }
        };
        a.max_life = opt64(r)?;
        a.bridge_threshold = r.u32()? as usize;
        let n = r.count(32)?;
        bad(n <= MAX_BRIDGE_SIGNERS)?;
        a.bridge = (0..n).map(|_| key(r.array()?)).collect::<Result<_, _>>()?;
        bad((n == 0 && a.bridge_threshold == 0) || (1..=n).contains(&a.bridge_threshold))?;
        a.deposit_cap = match (r.u8()?, r.u128()?, r.u128()?) {
            (0, 0, 0) => None,
            (1, b, q) => Some((b, q)),
            _ => return Err(Truncated),
        };
        a.cap_slot = r.u64()?;
        let mut last: Option<u32> = None;
        let mut ascending = |x: u32| {
            let ok = last.is_none_or(|l| x > l);
            last = Some(x);
            bad(ok)
        };
        for _ in 0..r.count(36)? {
            let m = r.u32()?;
            ascending(m)?;
            a.deposited.insert(m, (r.u128()?, r.u128()?));
        }
        last = None;
        for _ in 0..r.count(36)? {
            let acct = r.u32()?;
            let ok = last.is_none_or(|l| acct > l);
            last = Some(acct);
            bad(ok)?;
            a.keys.insert(acct, key(r.array()?)?);
        }
        last = None;
        for _ in 0..r.count(12)? {
            let acct = r.u32()?;
            let ok = last.is_none_or(|l| acct > l);
            last = Some(acct);
            bad(ok)?;
            a.next_nonce.insert(acct, r.u64()?);
        }
        let mut prev: Option<[u8; 32]> = None;
        for _ in 0..r.count(40)? {
            let reference: [u8; 32] = r.array()?;
            bad(prev.is_none_or(|p| reference > p))?;
            prev = Some(reference);
            let exp = r.u64()?;
            a.references.insert(reference, exp);
            a.reference_expiry.insert((exp, reference));
        }
        Ok(a)
    }

    pub fn key(&self, acct: AccountId) -> Option<&CheckedKey> {
        self.keys.get(&acct)
    }

    pub fn next_nonce(&self, acct: AccountId) -> u64 {
        self.next_nonce.get(&acct).copied().unwrap_or(0)
    }

    pub fn is_reference_used(&self, r: &[u8; 32]) -> bool {
        self.references.contains_key(r)
    }

    /// References still remembered (expired ones are forgotten).
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// The signatures an entry must carry: for client messages, one by the account's registered key (which must
    /// equal the embedded one) or, for a not-yet-registered account, the embedded key itself (it may be registered
    /// earlier in the same slot; admission decides); for bridge operations, a quorum of distinct bridge keys.
    pub fn items_for(&self, e: &Entry) -> Result<Vec<Item>, OrderError> {
        let (acct, embedded, msg, sig) = match e {
            Entry::Order(o) => (o.intent.acct, o.pubkey, o.intent.digest(), o.sig),
            Entry::Action(a) => (a.action.acct, a.pubkey, a.action.digest(), a.sig),
            Entry::Bridge(b) => return self.bridge_items(b),
            Entry::Tick => return Err(OrderError::Tick),
        };
        let key = match self.keys.get(&acct) {
            Some(k) if k.as_bytes() == &embedded => *k,
            Some(_) => return Err(OrderError::KeyMismatch),
            None => CheckedKey::new(embedded).ok_or(OrderError::WeakKey)?,
        };
        Ok(vec![Item { key, msg, sig }])
    }

    fn bridge_items(&self, b: &SignedBridge) -> Result<Vec<Item>, OrderError> {
        if self.bridge.is_empty() {
            return Err(OrderError::NoBridge);
        }
        if b.sigs.len() < self.bridge_threshold {
            return Err(OrderError::BridgeQuorum {
                have: b.sigs.len(),
                need: self.bridge_threshold,
            });
        }
        let d = b.op.digest();
        let mut seen = vec![false; self.bridge.len()];
        b.sigs
            .iter()
            .map(|(i, s)| {
                let key = *self
                    .bridge
                    .get(*i as usize)
                    .ok_or(OrderError::UnknownBridgeSigner(*i))?;
                if std::mem::replace(&mut seen[*i as usize], true) {
                    return Err(OrderError::DuplicateBridgeSigner(*i));
                }
                Ok(Item {
                    key,
                    msg: d,
                    sig: *s,
                })
            })
            .collect()
    }

    /// Admit a single signed order at `now_slot` (verifies the signature). On failure nothing changes.
    pub fn admit(&mut self, o: &SignedOrder, now_slot: u64) -> Result<Op, OrderError> {
        let i = &o.intent;
        let expected = self.check_client(i.acct, &o.pubkey, i.nonce, i.expiry_slot, now_slot)?;
        if !nimbus_sig::verify(&self.keys[&i.acct], &i.digest(), &o.sig) {
            return Err(OrderError::BadSignature);
        }
        self.next_nonce.insert(i.acct, expected + 1);
        Ok(i.to_op())
    }

    /// Admit a verified entry. Same rules as `admit`, plus bridge quorum, expiry, references, caps, registrations.
    pub fn admit_verified(&mut self, v: &Verified, now_slot: u64) -> Result<Effect, OrderError> {
        self.forget_expired(now_slot);
        match &v.0 {
            Entry::Order(o) => {
                let i = &o.intent;
                let expected =
                    self.check_client(i.acct, &o.pubkey, i.nonce, i.expiry_slot, now_slot)?;
                self.next_nonce.insert(i.acct, expected + 1);
                Ok(Effect::Market {
                    market: i.market,
                    op: i.to_op(),
                })
            }
            Entry::Action(a) => {
                let x = &a.action;
                let expected =
                    self.check_client(x.acct, &a.pubkey, x.nonce, x.expiry_slot, now_slot)?;
                self.next_nonce.insert(x.acct, expected + 1);
                Ok(Effect::Market {
                    market: x.market,
                    op: x.to_op(),
                })
            }
            Entry::Bridge(b) => {
                self.check_bridge(&b.op, now_slot)?;
                let effect = match b.op.kind {
                    BridgeKind::Deposit {
                        market,
                        acct,
                        base,
                        quote,
                    } => {
                        if let Some((cb, cq)) = self.deposit_cap {
                            if self.cap_slot != now_slot {
                                self.cap_slot = now_slot;
                                self.deposited.clear();
                            }
                            let used = self.deposited.entry(market).or_default();
                            let (nb, nq) =
                                (used.0.saturating_add(base), used.1.saturating_add(quote));
                            if nb > cb || nq > cq {
                                return Err(OrderError::DepositCap);
                            }
                            *used = (nb, nq);
                        }
                        Effect::Market {
                            market,
                            op: Op::Deposit { acct, base, quote },
                        }
                    }
                    BridgeKind::Register { acct, key } => {
                        if self.keys.contains_key(&acct) {
                            return Err(OrderError::AlreadyRegistered);
                        }
                        self.register_bytes(acct, key)?;
                        Effect::Registered { acct }
                    }
                };
                self.references.insert(b.op.reference, b.op.expiry_slot);
                self.reference_expiry
                    .insert((b.op.expiry_slot, b.op.reference));
                Ok(effect)
            }
            Entry::Tick => Ok(Effect::Tick),
        }
    }

    /// Forget references of operations that can no longer be admitted (their expiry has passed).
    fn forget_expired(&mut self, now_slot: u64) {
        while let Some(&(exp, r)) = self.reference_expiry.first() {
            if exp >= now_slot {
                break;
            }
            self.reference_expiry.pop_first();
            self.references.remove(&r);
        }
    }

    fn check_bridge(&self, op: &BridgeOp, now_slot: u64) -> Result<(), OrderError> {
        if op.expiry_slot < now_slot {
            return Err(OrderError::Expired {
                expiry: op.expiry_slot,
                now: now_slot,
            });
        }
        if let Some(max_life) = self.max_life {
            if op.expiry_slot - now_slot > max_life {
                return Err(OrderError::LifetimeTooLong {
                    expiry: op.expiry_slot,
                    now: now_slot,
                    max_life,
                });
            }
        }
        // A reference is unique within its operation's validity window. Decide on the stored expiry rather than on
        // whether pruning has run yet, so the read-only screen and admission always agree.
        if self
            .references
            .get(&op.reference)
            .is_some_and(|&exp| exp >= now_slot)
        {
            return Err(OrderError::DuplicateReference);
        }
        Ok(())
    }

    /// Read-only screen for a parallel pre-pass: everything admission checks except signatures, with the nonce test
    /// relaxed to "not already used" and unknown accounts let through (they may be registered earlier in the same
    /// slot). Bridge operations that are expired or whose reference is used are refused.
    pub fn precheck(&self, e: &Entry, now_slot: u64) -> Result<(), OrderError> {
        let (acct, pk, nonce, expiry) = match e {
            Entry::Order(o) => (
                o.intent.acct,
                o.pubkey,
                o.intent.nonce,
                o.intent.expiry_slot,
            ),
            Entry::Action(a) => (
                a.action.acct,
                a.pubkey,
                a.action.nonce,
                a.action.expiry_slot,
            ),
            Entry::Bridge(b) => return self.check_bridge(&b.op, now_slot),
            Entry::Tick => return Err(OrderError::Tick),
        };
        match self.check_client(acct, &pk, nonce, expiry, now_slot) {
            Err(OrderError::Nonce { expected, got }) if got > expected => Ok(()),
            Err(OrderError::UnknownAccount) => Ok(()),
            r => r.map(|_| ()),
        }
    }

    /// Key, expiry, lifetime and nonce rules for client messages; returns the expected nonce.
    fn check_client(
        &self,
        acct: AccountId,
        pubkey: &[u8; 32],
        nonce: u64,
        expiry: u64,
        now_slot: u64,
    ) -> Result<u64, OrderError> {
        let key = self.keys.get(&acct).ok_or(OrderError::UnknownAccount)?;
        if key.as_bytes() != pubkey {
            return Err(OrderError::KeyMismatch);
        }
        if expiry < now_slot {
            return Err(OrderError::Expired {
                expiry,
                now: now_slot,
            });
        }
        if let Some(max_life) = self.max_life {
            if expiry - now_slot > max_life {
                return Err(OrderError::LifetimeTooLong {
                    expiry,
                    now: now_slot,
                    max_life,
                });
            }
        }
        let expected = self.next_nonce(acct);
        if nonce != expected {
            return Err(OrderError::Nonce {
                expected,
                got: nonce,
            });
        }
        Ok(expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn key(seed: u64) -> SigningKey {
        SigningKey::generate(&mut StdRng::seed_from_u64(seed))
    }
    fn intent(nonce: u64) -> Intent {
        Intent {
            market: 3,
            acct: 7,
            side: Side::Bid,
            price: 100,
            qty: 5,
            tif: Tif::Gtc,
            nonce,
            expiry_slot: 1_000,
        }
    }
    fn cancel(nonce: u64, id: u64) -> Action {
        Action {
            market: 3,
            acct: 7,
            nonce,
            expiry_slot: 1_000,
            kind: ActionKind::Cancel { order_id: id },
        }
    }
    fn admission(k: &SigningKey) -> Admission {
        let mut a = Admission::new();
        a.register(7, k.verifying_key()).unwrap();
        a
    }
    /// Bridge keys 20, 21, 22 with a 2-of-3 quorum.
    fn bridge_keys() -> Vec<SigningKey> {
        (20..23).map(key).collect()
    }
    fn with_bridge(mut a: Admission) -> Admission {
        let ks: Vec<[u8; 32]> = bridge_keys()
            .iter()
            .map(|k| k.verifying_key().to_bytes())
            .collect();
        a.set_bridge(&ks, 2).unwrap();
        a
    }
    fn signed(op: BridgeOp, idx: &[u16]) -> SignedBridge {
        let ks = bridge_keys();
        let signers: Vec<(u16, &SigningKey)> = idx.iter().map(|&i| (i, &ks[i as usize])).collect();
        SignedBridge::sign(op, &signers)
    }
    fn deposit(r: u8, quote: u128, expiry: u64) -> BridgeOp {
        BridgeOp {
            reference: [r; 32],
            expiry_slot: expiry,
            kind: BridgeKind::Deposit {
                market: 2,
                acct: 40,
                base: 0,
                quote,
            },
        }
    }
    fn verify1(a: &Admission, e: Entry) -> Result<Verified, OrderError> {
        verify_entries(vec![e], |e| a.items_for(e)).pop().unwrap()
    }

    #[test]
    fn roundtrip_and_admission() {
        let k = key(1);
        let mut a = admission(&k);
        let o = SignedOrder::sign(intent(0), &k);
        let back = SignedOrder::from_bytes(&o.to_bytes()).unwrap();
        assert_eq!(back, o);
        assert!(a.admit(&back, 10).is_ok());
        assert_eq!(
            a.admit(&back, 10),
            Err(OrderError::Nonce {
                expected: 1,
                got: 0
            }),
            "replay must fail"
        );
        assert!(a.admit(&SignedOrder::sign(intent(1), &k), 10).is_ok());
    }

    #[test]
    fn every_time_in_force_roundtrips_and_other_codes_are_refused() {
        for tif in [Tif::Gtc, Tif::Ioc, Tif::Fok, Tif::PostOnly] {
            let i = Intent { tif, ..intent(0) };
            assert_eq!(Intent::decode(&i.encode()).unwrap(), i);
        }
        let mut b = intent(0).encode();
        for code in 4..=255u8 {
            b[25] = code;
            assert_eq!(Intent::decode(&b), Err(OrderError::Field("tif")));
        }
    }

    #[test]
    fn expiry_wrong_key_and_foreign_account_rejected() {
        let (k, evil) = (key(1), key(2));
        let mut a = admission(&k);
        assert!(matches!(
            a.admit(&SignedOrder::sign(intent(0), &k), 1_001),
            Err(OrderError::Expired { .. })
        ));
        assert_eq!(
            a.admit(&SignedOrder::sign(intent(0), &evil), 10),
            Err(OrderError::KeyMismatch)
        );
        let mut forged = SignedOrder::sign(intent(0), &evil);
        forged.pubkey = k.verifying_key().to_bytes();
        assert_eq!(a.admit(&forged, 10), Err(OrderError::BadSignature));
        let other = Intent {
            acct: 8,
            ..intent(0)
        };
        assert_eq!(
            a.admit(&SignedOrder::sign(other, &k), 10),
            Err(OrderError::UnknownAccount)
        );
        assert_eq!(
            a.next_nonce(7),
            0,
            "failed admissions must not consume the nonce"
        );
    }

    #[test]
    fn engine_enforces_max_lifetime() {
        let k = key(1);
        let mut a = admission(&k);
        a.set_max_life(100);
        let long = Intent {
            expiry_slot: 500,
            ..intent(0)
        };
        assert!(matches!(
            a.admit(&SignedOrder::sign(long, &k), 10),
            Err(OrderError::LifetimeTooLong { .. })
        ));
        let ok = Intent {
            expiry_slot: 110,
            ..intent(0)
        };
        assert!(a.admit(&SignedOrder::sign(ok, &k), 10).is_ok());
    }

    #[test]
    fn signatures_do_not_cross_domains() {
        // The same bytes signed under another tag (a header 0x02, an order 0x09 vs an action 0x0F) must not verify.
        let k = key(3);
        let i = intent(0);
        let o = SignedOrder {
            intent: i,
            pubkey: k.verifying_key().to_bytes(),
            sig: k.sign(&hash_tagged(0x02, &[&i.encode()])).to_bytes(),
        };
        assert!(!o.signature_valid());
        let act = cancel(0, 5);
        let wrong = SignedAction {
            action: act,
            pubkey: k.verifying_key().to_bytes(),
            sig: k.sign(&hash_tagged(ORDER_TAG, &[&act.encode()])).to_bytes(),
        };
        let a = admission(&k);
        assert_eq!(
            verify1(&a, Entry::Action(wrong)),
            Err(OrderError::BadSignature)
        );
    }

    /// v0.4 regression: under the identity key, R = identity and s = 0 satisfy non-strict verification for every
    /// message. Such keys are refused wherever keys enter, and the signature never verifies.
    #[test]
    fn weak_keys_are_refused_and_keyless_signatures_rejected() {
        let mut id = [0u8; 32];
        id[0] = 1;
        let weak = VerifyingKey::from_bytes(&id).unwrap();
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let forged = SignedOrder {
            intent: Intent {
                acct: 9,
                qty: 1_000_000,
                ..intent(0)
            },
            pubkey: id,
            sig,
        };
        assert!(weak
            .verify(&forged.intent.digest(), &Signature::from_bytes(&sig))
            .is_ok());
        assert!(!forged.signature_valid());
        assert_eq!(forged.clone().verify(), Err(OrderError::WeakKey));
        let mut a = Admission::new();
        assert_eq!(a.register(9, weak), Err(OrderError::WeakKey));
        assert_eq!(a.set_bridge(&[id], 1), Err(OrderError::WeakKey));
        assert_eq!(a.admit(&forged, 1), Err(OrderError::UnknownAccount));
        assert_eq!(
            a.items_for(&Entry::Order(forged)).unwrap_err(),
            OrderError::WeakKey
        );
    }

    #[test]
    fn actions_share_the_nonce_sequence_and_map_to_engine_ops() {
        let k = key(4);
        let mut a = admission(&k);
        let entries = vec![
            Entry::Order(SignedOrder::sign(intent(0), &k)),
            Entry::Action(SignedAction::sign(cancel(1, 1), &k)),
            Entry::Action(SignedAction::sign(
                Action {
                    kind: ActionKind::Withdraw { base: 0, quote: 5 },
                    ..cancel(2, 0)
                },
                &k,
            )),
            Entry::Action(SignedAction::sign(cancel(2, 9), &k)), // nonce 2 already used by the withdrawal
        ];
        let v = verify_entries(entries, |e| a.items_for(e));
        let effects: Vec<_> = v
            .iter()
            .map(|r| a.admit_verified(r.as_ref().unwrap(), 10))
            .collect();
        assert!(matches!(
            effects[0],
            Ok(Effect::Market {
                market: 3,
                op: Op::Order { .. }
            })
        ));
        assert_eq!(
            effects[1],
            Ok(Effect::Market {
                market: 3,
                op: Op::Cancel { acct: 7, id: 1 }
            })
        );
        assert_eq!(
            effects[2],
            Ok(Effect::Market {
                market: 3,
                op: Op::Withdraw {
                    acct: 7,
                    base: 0,
                    quote: 5
                }
            })
        );
        assert_eq!(
            effects[3],
            Err(OrderError::Nonce {
                expected: 3,
                got: 2
            })
        );
        let mut b = cancel(0, 1).encode();
        b[40] = 1;
        assert!(Action::decode(&b).is_err());
        let w = Action {
            kind: ActionKind::Withdraw { base: 0, quote: 0 },
            ..cancel(0, 0)
        };
        assert!(Action::decode(&w.encode()).is_err());
    }

    #[test]
    fn bridge_needs_a_quorum_of_distinct_bridge_keys() {
        let a = with_bridge(Admission::new());
        let op = deposit(1, 1_000, 50);
        assert!(verify1(&a, Entry::Bridge(signed(op, &[0, 2]))).is_ok());
        assert!(verify1(&a, Entry::Bridge(signed(op, &[2, 1, 0]))).is_ok());
        assert_eq!(
            verify1(&a, Entry::Bridge(signed(op, &[1]))),
            Err(OrderError::BridgeQuorum { have: 1, need: 2 })
        );
        assert_eq!(
            verify1(&a, Entry::Bridge(signed(op, &[1, 1]))),
            Err(OrderError::DuplicateBridgeSigner(1))
        );
        let mut unknown = signed(op, &[0, 1]);
        unknown.sigs[1].0 = 7;
        assert_eq!(
            verify1(&a, Entry::Bridge(unknown)),
            Err(OrderError::UnknownBridgeSigner(7))
        );
        // One compromised bridge key alone cannot mint: a second "signature" from a non-bridge key fails.
        let rogue = key(99);
        let mut one_real = signed(op, &[0, 1]);
        one_real.sigs[1].1 = rogue.sign(&op.digest()).to_bytes();
        assert_eq!(
            verify1(&a, Entry::Bridge(one_real)),
            Err(OrderError::BadSignature)
        );
        let bad_threshold =
            Admission::new().set_bridge(&[bridge_keys()[0].verifying_key().to_bytes()], 2);
        assert!(bad_threshold.is_err());
    }

    #[test]
    fn bridge_registers_accounts_and_deposits_apply_once() {
        let user = key(11);
        let mut a = with_bridge(Admission::new());
        let reg = signed(
            BridgeOp {
                reference: [1; 32],
                expiry_slot: 50,
                kind: BridgeKind::Register {
                    acct: 40,
                    key: user.verifying_key().to_bytes(),
                },
            },
            &[0, 1],
        );
        let order = SignedOrder::sign(
            Intent {
                acct: 40,
                ..intent(0)
            },
            &user,
        );
        let entries = vec![
            Entry::Bridge(reg),
            Entry::Order(order),
            Entry::Bridge(signed(deposit(2, 1_000, 50), &[1, 2])),
            Entry::Bridge(signed(deposit(2, 1_000, 50), &[0, 2])),
        ];
        let v = verify_entries(entries, |e| a.items_for(e));
        let effects: Vec<_> = v
            .iter()
            .map(|r| a.admit_verified(r.as_ref().unwrap(), 10))
            .collect();
        assert_eq!(effects[0], Ok(Effect::Registered { acct: 40 }));
        assert!(matches!(effects[1], Ok(Effect::Market { market: 3, .. })));
        assert!(matches!(
            effects[2],
            Ok(Effect::Market {
                market: 2,
                op: Op::Deposit { .. }
            })
        ));
        assert_eq!(
            effects[3],
            Err(OrderError::DuplicateReference),
            "same reference, other signers"
        );
        assert_eq!(
            a.precheck(&Entry::Bridge(signed(deposit(2, 1_000, 50), &[0, 1])), 10),
            Err(OrderError::DuplicateReference)
        );
        let again = signed(
            BridgeOp {
                reference: [4; 32],
                expiry_slot: 50,
                kind: BridgeKind::Register {
                    acct: 40,
                    key: key(12).verifying_key().to_bytes(),
                },
            },
            &[0, 1],
        );
        let v = verify1(&a, Entry::Bridge(again)).unwrap();
        assert_eq!(a.admit_verified(&v, 10), Err(OrderError::AlreadyRegistered));
        assert!(!a.is_reference_used(&[4; 32]));
        let mut id = [0u8; 32];
        id[0] = 1;
        let weak = signed(
            BridgeOp {
                reference: [5; 32],
                expiry_slot: 50,
                kind: BridgeKind::Register { acct: 41, key: id },
            },
            &[0, 1],
        );
        let v = verify1(&a, Entry::Bridge(weak)).unwrap();
        assert_eq!(a.admit_verified(&v, 10), Err(OrderError::WeakKey));
        assert!(!a.is_reference_used(&[5; 32]));
    }

    #[test]
    fn deposit_caps_are_per_market_per_slot() {
        let mut a = with_bridge(Admission::new());
        a.set_deposit_cap(0, 1_500);
        let mut admit = |r: u8, q: u128, slot: u64| {
            let v = verify1(&a, Entry::Bridge(signed(deposit(r, q, 100), &[0, 1]))).unwrap();
            a.admit_verified(&v, slot)
        };
        assert!(admit(1, 1_000, 10).is_ok());
        assert_eq!(
            admit(2, 600, 10),
            Err(OrderError::DepositCap),
            "1,600 > 1,500 in one slot"
        );
        assert!(admit(3, 500, 10).is_ok(), "exactly at the cap");
        assert!(
            admit(2, 600, 11).is_ok(),
            "the cap resets each slot; a refused reference can be retried"
        );
    }

    /// A snapshot taken mid-slot (cap partly used, references live, nonces advanced) restores an admission that
    /// decides every later entry identically, and re-encodes to the same bytes.
    #[test]
    fn a_restored_admission_decides_identically() {
        let enc = |a: &Admission| {
            let mut v = Vec::new();
            a.encode_into(&mut v);
            v
        };
        let dec = |b: &[u8]| {
            let mut r = nimbus_hash::Reader::new(b);
            let a = Admission::decode_from(&mut r).unwrap();
            r.end().unwrap();
            a
        };
        let k = key(1);
        let mut a = with_bridge(admission(&k));
        a.set_deposit_cap(0, 1_500);
        a.set_max_life(2_000);
        let bridge = |a: &mut Admission, r: u8, q: u128, slot: u64| {
            let v = verify1(a, Entry::Bridge(signed(deposit(r, q, 100), &[0, 1]))).unwrap();
            a.admit_verified(&v, slot)
        };
        assert!(bridge(&mut a, 1, 1_000, 10).is_ok());
        assert!(a.admit(&SignedOrder::sign(intent(0), &k), 10).is_ok());
        let snap = enc(&a);
        let mut b = dec(&snap);
        assert_eq!(enc(&b), snap);
        for x in [&mut a, &mut b] {
            assert_eq!(bridge(x, 2, 600, 10), Err(OrderError::DepositCap));
            assert_eq!(
                bridge(x, 1, 10, 11).unwrap_err(),
                OrderError::DuplicateReference
            );
            assert!(bridge(x, 3, 500, 10).is_ok());
            assert!(
                x.admit(&SignedOrder::sign(intent(0), &k), 10).is_err(),
                "replayed nonce"
            );
            assert!(x.admit(&SignedOrder::sign(intent(1), &k), 10).is_ok());
        }
        assert_eq!(enc(&a), enc(&b));
        // Damage: every single-byte truncation is refused.
        for n in 0..snap.len() {
            let mut r = nimbus_hash::Reader::new(&snap[..n]);
            assert!(Admission::decode_from(&mut r)
                .and_then(|_| r.end())
                .is_err());
        }
    }

    #[test]
    fn expired_bridge_ops_are_refused_and_their_references_forgotten() {
        let mut a = with_bridge(Admission::new());
        a.set_max_life(100);
        let v = verify1(&a, Entry::Bridge(signed(deposit(1, 10, 20), &[0, 1]))).unwrap();
        assert!(a.admit_verified(&v, 10).is_ok());
        assert_eq!(a.reference_count(), 1);
        assert_eq!(
            a.admit_verified(&v, 15),
            Err(OrderError::DuplicateReference)
        );
        // After its expiry, replaying it fails on expiry, and the reference is no longer stored.
        assert!(matches!(
            a.admit_verified(&v, 21),
            Err(OrderError::Expired { .. })
        ));
        assert_eq!(a.reference_count(), 0);
        // Screen and admission agree on an expired reference whether or not it has been pruned yet (v0.6 fix).
        let mut b = with_bridge(Admission::new());
        let v = verify1(&b, Entry::Bridge(signed(deposit(3, 10, 20), &[0, 1]))).unwrap();
        b.admit_verified(&v, 10).unwrap();
        let reuse = Entry::Bridge(signed(deposit(3, 10, 40), &[0, 1]));
        assert_eq!(
            b.precheck(&reuse, 21),
            Ok(()),
            "not yet pruned, but its window has passed"
        );
        let v = verify1(&b, reuse).unwrap();
        assert!(b.admit_verified(&v, 21).is_ok());
        let long = verify1(&a, Entry::Bridge(signed(deposit(9, 10, 500), &[0, 1]))).unwrap();
        assert!(matches!(
            a.admit_verified(&long, 21),
            Err(OrderError::LifetimeTooLong { .. })
        ));
    }

    #[test]
    fn batch_verification_equals_single_verification_and_admission() {
        let k = key(6);
        let mut a = admission(&k);
        let mut b = admission(&k);
        let mut orders: Vec<SignedOrder> =
            (0..300).map(|n| SignedOrder::sign(intent(n), &k)).collect();
        orders[5].sig[3] ^= 1;
        orders.swap(10, 11);
        orders[20].intent.expiry_slot = 1;
        let seq: Vec<bool> = orders.iter().map(|o| a.admit(o, 10).is_ok()).collect();
        let v = verify_entries(orders.into_iter().map(Entry::Order).collect(), |e| {
            b.items_for(e)
        });
        let par: Vec<bool> = v
            .iter()
            .map(|r| r.as_ref().is_ok_and(|v| b.admit_verified(v, 10).is_ok()))
            .collect();
        assert_eq!(seq, par);
        assert_eq!(a.next_nonce(7), b.next_nonce(7));
    }

    #[test]
    fn entries_roundtrip() {
        let k = key(8);
        for e in [
            Entry::Order(SignedOrder::sign(intent(0), &k)),
            Entry::Action(SignedAction::sign(cancel(0, 4), &k)),
            Entry::Bridge(signed(deposit(7, 3, 9), &[0, 1, 2])),
            Entry::Tick,
        ] {
            let b = e.to_bytes();
            assert!(b.len() <= ENTRY_MAX);
            assert_eq!(Entry::from_bytes(&b).unwrap(), e);
            let mut longer = b.clone();
            longer.push(0);
            assert!(
                Entry::from_bytes(&longer).is_err(),
                "trailing bytes are refused"
            );
        }
    }

    proptest! {
        #[test]
        fn parsers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..1300)) {
            let _ = SignedOrder::from_bytes(&bytes);
            let _ = Intent::decode(&bytes);
            let _ = Entry::from_bytes(&bytes);
            let _ = SignedAction::from_bytes(&bytes);
            let _ = SignedBridge::from_bytes(&bytes);
        }

        /// Flipping any bit of any signed entry (order, action, 2-of-3 bridge op) never yields an admitted entry.
        #[test]
        fn any_single_bit_flip_is_rejected(kind in 0u8..3, byte in 0usize..1000, bit in 0u8..8) {
            let k = key(4);
            let mut a = with_bridge(admission(&k));
            let e = match kind {
                0 => Entry::Order(SignedOrder::sign(intent(0), &k)),
                1 => Entry::Action(SignedAction::sign(cancel(0, 9), &k)),
                _ => Entry::Bridge(signed(deposit(9, 5, 50), &[0, 2])),
            };
            let mut w = e.to_bytes();
            let byte = 1 + byte % (w.len() - 2); // skip the kind byte and the version byte
            w[byte] ^= 1 << bit;
            let admitted = Entry::from_bytes(&w).map(|e| {
                let v = verify_entries(vec![e], |e| a.items_for(e));
                v.into_iter().next().unwrap().map(|v| a.admit_verified(&v, 10))
            });
            prop_assert!(!matches!(admitted, Ok(Ok(Ok(_)))), "tampered entry admitted (kind {kind}, byte {byte}, bit {bit})");
        }
    }
}
