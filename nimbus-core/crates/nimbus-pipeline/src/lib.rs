//! Slot pipeline: the admission → journal → matching → receipts path of a single-operator DEX engine, in process.
//! There is no networking and no consensus here. Journal replication is: `attach_replicas` adds replicas behind the
//! `Replica` trait (any transport), and a slot is acknowledged only once `need` of them hold it durably. Blocking
//! replication waits for the acknowledgements inside the slot's commit; windowed replication
//! (`attach_replicas_windowed`, then `submit_slot` / `drain`) keeps committing later slots and releases each slot's
//! results, in slot order, once `need` replicas hold its journal prefix.
//!
//! Entries are orders, account actions (cancel, withdraw), bridge operations (deposit, register) and engine ticks.
//! Per slot:
//! 1. expire — resting orders whose signed `expiry_slot` has passed are cancelled, in (expiry, market, id) order,
//!    each with a receipt;
//! 2. verify (all cores) — parse, read-only admission screen, ZIP-215 batch verification with bisection;
//! 3. admit (arrival order) — keys, expiry, lifetime, strict nonces, bridge quorum, references, deposit caps,
//!    registrations;
//! 4. journal ∥ match — one write + one fsync for the slot (group commit), shipped to the replicas in parallel with
//!    the fsync, runs concurrently with matching (markets in parallel) and receipt building; nothing leaves the
//!    pipeline until the local fsync, `need` replica acknowledgements and matching are all done;
//! 5. checkpoint — operator-signed (0x0C) over slot, journal (length, head), receipts root (0x0D/0x0E) and count.
//!
//! A slot whose only effect is expiries is journaled as a tick, so replay visits exactly the slots live processing
//! changed. Ed25519 signing is deterministic, so every checkpoint is a pure function of genesis, the journal and the
//! operator key: recovery replays the journal, re-derives every checkpoint and requires byte equality with each stored
//! or externally supplied one.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nimbus_hash::{hash_tagged, leaf_hash, verify_audit_path, Hash, MerkleTree, Reader, Tree};
use nimbus_journal::{Anchor, Journal, JournalError, Record};
use nimbus_match::{AccountId, Balance, Exchange, Fees, Fill, Op, OrderId, Outcome, Reject};
use nimbus_order::{
    verify_entries_by, verify_entries_with, Admission, Effect, Entry, OrderError, Verified,
};
use nimbus_sig::{CheckedKey, SpinPool};
use rayon::prelude::*;
use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

pub const CHECKPOINT_TAG: u8 = 0x0C;
pub const RECEIPTS: Tree = Tree {
    leaf: 0x0D,
    node: 0x0E,
};
pub const CHECKPOINT_BODY: usize = 8 + 8 + 48 + 48 + 8;
pub const CHECKPOINT_LEN: usize = CHECKPOINT_BODY + 64;
/// Domain of a replay-state snapshot's integrity digest (whitepaper Lemma 9″): H(0x12 ‖ body).
pub const SNAPSHOT_TAG: u8 = 0x12;
pub const SNAPSHOT_VERSION: u8 = 1;

// ---------------------------------------------------------------------------------------------------------------
// Receipts

/// What caused a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A journaled entry: its sequence number and the digest its signer signed.
    Entry { seq: u64, digest: Hash },
    /// The engine expired a resting order (no signed input).
    Expiry { order_id: OrderId },
    /// A resting order was filled by the taker entry `taker_seq`: the maker's own receipt.
    Fill {
        taker_seq: u64,
        maker_order: OrderId,
    },
}

/// What the engine did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Executed {
        id: OrderId,
        /// Total quantity filled, and Σ price × qty over the fills (exact; average price = notional / filled).
        filled: u64,
        notional: u128,
        /// Σ taker fees over the fills, in quote: the account paid notional + fees (bid) or received notional − fees
        /// (ask).
        fees: u128,
        resting: u64,
        self_trade_cancels: u32,
        fills: Vec<Fill>,
    },
    Cancelled {
        id: OrderId,
        released: u64,
    },
    Deposited {
        base: u128,
        quote: u128,
    },
    Withdrawn {
        base: u128,
        quote: u128,
    },
    Registered,
    Rejected(Reject),
    /// The maker side of one fill: this account's resting order `order_id` traded `qty` at `price`, paying `fee` and
    /// receiving `rebate`.
    MakerFill {
        order_id: OrderId,
        price: u64,
        qty: u64,
        fee: u128,
        rebate: u128,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub slot: u64,
    pub source: Source,
    pub acct: AccountId,
    pub market: Option<u32>,
    pub status: Status,
    /// The account's balance in `market` right after this change (none for registrations): an agent reconciles
    /// every trade against it exactly.
    pub balance: Option<Balance>,
}

fn reject_code(r: &Reject) -> u8 {
    match r {
        Reject::ZeroQtyOrPrice => 0,
        Reject::InsufficientBalance => 1,
        Reject::UnknownOrder => 2,
        Reject::NotOwner => 3,
        Reject::Overflow => 4,
        Reject::NotFillable => 5,
        Reject::WouldCross => 6,
    }
}

impl Receipt {
    /// Canonical encoding (the Merkle leaf). Fixed layout, big-endian integers.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(128);
        v.extend_from_slice(&self.slot.to_be_bytes());
        match self.source {
            Source::Entry { seq, digest } => {
                v.push(0);
                v.extend_from_slice(&seq.to_be_bytes());
                v.extend_from_slice(&digest);
            }
            Source::Expiry { order_id } => {
                v.push(1);
                v.extend_from_slice(&order_id.to_be_bytes());
            }
            Source::Fill {
                taker_seq,
                maker_order,
            } => {
                v.push(2);
                v.extend_from_slice(&taker_seq.to_be_bytes());
                v.extend_from_slice(&maker_order.to_be_bytes());
            }
        }
        v.extend_from_slice(&self.acct.to_be_bytes());
        match self.market {
            Some(m) => {
                v.push(1);
                v.extend_from_slice(&m.to_be_bytes());
            }
            None => v.push(0),
        }
        match &self.status {
            Status::Executed {
                id,
                filled,
                notional,
                fees,
                resting,
                self_trade_cancels,
                fills,
            } => {
                v.push(0);
                v.extend_from_slice(&id.to_be_bytes());
                v.extend_from_slice(&filled.to_be_bytes());
                v.extend_from_slice(&notional.to_be_bytes());
                v.extend_from_slice(&fees.to_be_bytes());
                v.extend_from_slice(&resting.to_be_bytes());
                v.extend_from_slice(&self_trade_cancels.to_be_bytes());
                v.extend_from_slice(&(fills.len() as u32).to_be_bytes());
                for f in fills {
                    v.extend_from_slice(&f.maker.to_be_bytes());
                    v.extend_from_slice(&f.maker_acct.to_be_bytes());
                    v.extend_from_slice(&f.price.to_be_bytes());
                    v.extend_from_slice(&f.qty.to_be_bytes());
                    v.extend_from_slice(&f.taker_fee.to_be_bytes());
                    v.extend_from_slice(&f.maker_fee.to_be_bytes());
                    v.extend_from_slice(&f.maker_rebate.to_be_bytes());
                }
            }
            Status::Cancelled { id, released } => {
                v.push(1);
                v.extend_from_slice(&id.to_be_bytes());
                v.extend_from_slice(&released.to_be_bytes());
            }
            Status::Deposited { base, quote } => {
                v.push(2);
                v.extend_from_slice(&base.to_be_bytes());
                v.extend_from_slice(&quote.to_be_bytes());
            }
            Status::Withdrawn { base, quote } => {
                v.push(3);
                v.extend_from_slice(&base.to_be_bytes());
                v.extend_from_slice(&quote.to_be_bytes());
            }
            Status::Registered => v.push(4),
            Status::Rejected(r) => {
                v.push(5);
                v.push(reject_code(r));
            }
            Status::MakerFill {
                order_id,
                price,
                qty,
                fee,
                rebate,
            } => {
                v.push(6);
                v.extend_from_slice(&order_id.to_be_bytes());
                v.extend_from_slice(&price.to_be_bytes());
                v.extend_from_slice(&qty.to_be_bytes());
                v.extend_from_slice(&fee.to_be_bytes());
                v.extend_from_slice(&rebate.to_be_bytes());
            }
        }
        match &self.balance {
            Some(b) => {
                v.push(1);
                for x in [b.base_free, b.base_locked, b.quote_free, b.quote_locked] {
                    v.extend_from_slice(&x.to_be_bytes());
                }
            }
            None => v.push(0),
        }
        v
    }

    pub fn leaf(&self) -> Hash {
        leaf_hash(RECEIPTS, &self.encode())
    }

    /// Average execution price as an exact fraction (notional, filled), if anything filled.
    pub fn average_price(&self) -> Option<(u128, u64)> {
        match &self.status {
            Status::Executed {
                filled, notional, ..
            } if *filled > 0 => Some((*notional, *filled)),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Checkpoints and proofs

/// Operator-signed statement: after `slot`, the journal was `journal` and the slot's receipts had this root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub slot: u64,
    pub journal: Anchor,
    pub receipts_root: Hash,
    pub receipts: u64,
    pub sig: [u8; 64],
}

impl Checkpoint {
    fn body(&self) -> [u8; CHECKPOINT_BODY] {
        let mut b = [0u8; CHECKPOINT_BODY];
        b[0..8].copy_from_slice(&self.slot.to_be_bytes());
        b[8..16].copy_from_slice(&self.journal.len.to_be_bytes());
        b[16..64].copy_from_slice(&self.journal.head);
        b[64..112].copy_from_slice(&self.receipts_root);
        b[112..120].copy_from_slice(&self.receipts.to_be_bytes());
        b
    }
    pub fn digest(&self) -> Hash {
        hash_tagged(CHECKPOINT_TAG, &[&self.body()])
    }
    fn signed(mut self, key: &SigningKey) -> Checkpoint {
        self.sig = key.sign(&self.digest()).to_bytes();
        self
    }
    pub fn to_bytes(&self) -> [u8; CHECKPOINT_LEN] {
        let mut b = [0u8; CHECKPOINT_LEN];
        b[..CHECKPOINT_BODY].copy_from_slice(&self.body());
        b[CHECKPOINT_BODY..].copy_from_slice(&self.sig);
        b
    }
    /// An unsigned checkpoint from its 120-byte body.
    pub fn from_body(b: &[u8; CHECKPOINT_BODY]) -> Checkpoint {
        let mut full = [0u8; CHECKPOINT_LEN];
        full[..CHECKPOINT_BODY].copy_from_slice(b);
        Checkpoint::from_bytes(&full).expect("fixed length")
    }
    /// Parse untrusted bytes (structure only; call `verify`).
    pub fn from_bytes(b: &[u8]) -> Option<Checkpoint> {
        if b.len() != CHECKPOINT_LEN {
            return None;
        }
        let u64_at = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().expect("8"));
        Some(Checkpoint {
            slot: u64_at(0),
            journal: Anchor {
                len: u64_at(8),
                head: b[16..64].try_into().expect("48"),
            },
            receipts_root: b[64..112].try_into().expect("48"),
            receipts: u64_at(112),
            sig: b[CHECKPOINT_BODY..].try_into().expect("64"),
        })
    }
    pub fn verify(&self, operator: &VerifyingKey) -> bool {
        CheckedKey::new(operator.to_bytes())
            .is_some_and(|k| nimbus_sig::verify(&k, &self.digest(), &self.sig))
    }
}

/// Everything an agent needs to check one receipt offline: the receipt, its position and audit path in the slot's
/// receipt tree, and the operator-signed checkpoint that commits to the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptProof {
    pub receipt: Receipt,
    pub index: u64,
    pub path: Vec<Hash>,
    pub checkpoint: Checkpoint,
}

impl ReceiptProof {
    pub fn verify(&self, operator: &VerifyingKey) -> bool {
        self.checkpoint.verify(operator)
            && self.receipt.slot == self.checkpoint.slot
            && verify_audit_path(
                RECEIPTS,
                &self.receipt.leaf(),
                self.index,
                self.checkpoint.receipts,
                &self.path,
                &self.checkpoint.receipts_root,
            )
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Pipeline

#[derive(Clone, Debug)]
pub struct Config {
    pub markets: u32,
    /// Longest lifetime (slots) the engine admits for client messages, independent of any signer's policy.
    pub max_life: u64,
    /// fsync the journal once per slot. `false` is for benchmarks only: acknowledgements are then not crash-safe.
    pub fsync: bool,
    /// Minimum signature batch per core: 16 for throughput (large slots), 1 for latency (sub-millisecond slots;
    /// see the paper's §6.6 engine model). Results are identical either way.
    pub min_batch: usize,
}

/// State at slot 0. Later accounts and funds arrive as bridge operations in the journal.
#[derive(Clone, Debug, Default)]
pub struct Genesis {
    pub accounts: Vec<(AccountId, VerifyingKey)>,
    /// (market, account, base, quote)
    pub deposits: Vec<(u32, AccountId, u128, u128)>,
    /// The bridge key set (empty disables bridge operations) and how many distinct keys must sign each operation.
    pub bridge: Vec<VerifyingKey>,
    pub bridge_threshold: usize,
    /// Per-market, per-slot cap on (base, quote) deposited through the bridge.
    pub deposit_cap: Option<(u128, u128)>,
    /// Fee schedule applied to every market (zero: no fees).
    pub fees: Fees,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Entry(OrderError),
    UnknownMarket(u32),
}

#[derive(Debug)]
pub enum PipelineError {
    Io(std::io::Error),
    Journal(JournalError),
    Genesis(String),
    SlotNotIncreasing {
        slot: u64,
        last: u64,
    },
    /// A supplied checkpoint does not carry a valid operator signature.
    CheckpointInvalid,
    /// The journal is shorter than a signed checkpoint says it was.
    Truncated {
        have: u64,
        need: u64,
        slot: u64,
    },
    /// Replay does not reproduce a signed checkpoint (different journal, genesis or engine behaviour).
    Diverged {
        slot: u64,
    },
    /// A snapshot is damaged, has the wrong digest or version, or does not fit the configuration.
    Snapshot(String),
    /// A journaled entry no longer passes admission on replay.
    ReplayRejected {
        seq: u64,
        reason: String,
    },
    /// `attach_replicas`: a replica is not at the engine's journal anchor, or `need` exceeds the replicas given.
    ReplicaSetup {
        index: usize,
    },
    /// `process_slot(s)` with windowed replication attached, or `submit_*` / `drain` without it.
    WrongMode,
    /// Fewer than `need` replicas acknowledged the slot. The pipeline is poisoned (nothing was acknowledged).
    Replication {
        acks: usize,
        need: usize,
    },
    /// A journal write failed after matching had run; in-memory state is ahead of the durable journal. Restart
    /// (recovery replays the journal).
    Poisoned,
}

impl From<std::io::Error> for PipelineError {
    fn from(e: std::io::Error) -> Self {
        PipelineError::Io(e)
    }
}
impl From<JournalError> for PipelineError {
    fn from(e: JournalError) -> Self {
        PipelineError::Journal(e)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    pub expire: Duration,
    pub verify: Duration,
    pub admit: Duration,
    /// Wall time of the concurrent journal ∥ (match + receipts) stage.
    pub commit: Duration,
    /// Inside `commit`: journal write + fsync ∥ replication, and matching + receipt building (they overlap).
    pub journal: Duration,
    pub matching: Duration,
    pub checkpoint: Duration,
    /// Encoding a periodic snapshot (sealing and writing run on the writer's thread).
    pub snapshot: Duration,
}

impl Timings {
    pub fn add(&mut self, o: &Timings) {
        self.expire += o.expire;
        self.verify += o.verify;
        self.admit += o.admit;
        self.commit += o.commit;
        self.journal += o.journal;
        self.matching += o.matching;
        self.checkpoint += o.checkpoint;
        self.snapshot += o.snapshot;
    }
    pub fn total(&self) -> Duration {
        self.expire + self.verify + self.admit + self.commit + self.checkpoint + self.snapshot
    }
}

pub struct SlotResult {
    pub slot: u64,
    /// One entry per submission, in input order: the receipt index, or why it was refused (refused submissions
    /// consume no nonce or reference and are not journaled).
    pub decisions: Vec<Result<usize, Refusal>>,
    /// Expiry receipts first, then one per admitted entry in journal order.
    pub receipts: Vec<Receipt>,
    pub tree: MerkleTree,
    /// `None` when the slot changed nothing.
    pub checkpoint: Option<Checkpoint>,
    pub expired: u32,
    pub timings: Timings,
}

impl SlotResult {
    pub fn proof(&self, receipt: usize) -> Option<ReceiptProof> {
        Some(ReceiptProof {
            receipt: self.receipts.get(receipt)?.clone(),
            index: receipt as u64,
            path: self.tree.path(receipt),
            checkpoint: self.checkpoint?,
        })
    }
}

#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub records: u64,
    pub slots: u64,
    pub journal_truncated_bytes: u64,
    /// Stored checkpoints that matched replay byte for byte.
    pub checkpoints_matched: u64,
    /// Replayed slots with no valid stored checkpoint (derived afresh and written back).
    pub checkpoints_rederived: u64,
    /// Stored entries that were torn or failed signature verification (discarded, never trusted).
    pub checkpoints_discarded: u64,
    pub external_matched: bool,
    /// The slot of the snapshot recovery resumed from (`None`: replayed from genesis).
    pub resumed_from: Option<u64>,
}

type Expiries = BTreeMap<(u64, u32, OrderId), AccountId>;

/// A copy of the engine journal on another disk or machine. `replicate` must make the records durable before it
/// returns the replica's anchor; the engine counts an acknowledgement only if that anchor equals its own.
pub trait Replica: Send {
    fn anchor(&self) -> Anchor;
    fn replicate(&mut self, from: &Anchor, bytes: &[u8]) -> Result<Anchor, String>;
    /// Windowed mode calls this with the instant the engine shipped the batch. A transport that keeps several
    /// batches in flight uses it so that time already spent queued behind earlier batches counts towards the
    /// transfer; the default ignores it.
    fn replicate_shipped(
        &mut self,
        from: &Anchor,
        bytes: &[u8],
        _shipped: Instant,
    ) -> Result<Anchor, String> {
        self.replicate(from, bytes)
    }
}

/// A replica reached through a transport that keeps several batches in flight: a sending half and an
/// acknowledgement half, driven from two threads (windowed mode). Acknowledgements must come back in shipping order.
pub trait ReplicaStream: Send {
    fn anchor(&self) -> Anchor;
    fn split(self: Box<Self>) -> (Box<dyn StreamSend>, Box<dyn StreamAcks>);
}

pub trait StreamSend: Send {
    /// Ship records continuing `from` that must leave the replica at `to`; return once handed to the transport.
    fn send(
        &mut self,
        from: &Anchor,
        to: &Anchor,
        bytes: &[u8],
        shipped: Instant,
    ) -> Result<(), String>;
}

pub trait StreamAcks: Send {
    /// The replica's anchor after the oldest unacknowledged batch (blocks until it arrives).
    fn next_ack(&mut self) -> Result<Anchor, String>;
}

/// Any `Replica` is a stream whose sending half applies each batch and queues the result for the other half.
struct Local(Box<dyn Replica>);
struct LocalSend(Box<dyn Replica>, mpsc::Sender<Result<Anchor, String>>);
struct LocalAcks(mpsc::Receiver<Result<Anchor, String>>);
impl ReplicaStream for Local {
    fn anchor(&self) -> Anchor {
        self.0.anchor()
    }
    fn split(self: Box<Self>) -> (Box<dyn StreamSend>, Box<dyn StreamAcks>) {
        let (tx, rx) = mpsc::channel();
        (Box::new(LocalSend(self.0, tx)), Box::new(LocalAcks(rx)))
    }
}
impl StreamSend for LocalSend {
    fn send(
        &mut self,
        from: &Anchor,
        _to: &Anchor,
        bytes: &[u8],
        shipped: Instant,
    ) -> Result<(), String> {
        self.1
            .send(self.0.replicate_shipped(from, bytes, shipped))
            .map_err(|_| "acknowledgement half gone".to_string())
    }
}
impl StreamAcks for LocalAcks {
    fn next_ack(&mut self) -> Result<Anchor, String> {
        self.0.recv().map_err(|_| "sending half gone".to_string())?
    }
}

/// Windowed-replication limits.
#[derive(Clone, Copy, Debug)]
pub struct WindowConfig {
    /// Committed slots allowed to wait for their replication quorum before `submit_*` blocks.
    pub depth: usize,
    /// A replica whose oldest unacknowledged batch is older than this is dropped.
    pub ack_timeout: Duration,
    /// A replica with this many unacknowledged batches is dropped instead of queueing more. A replica the quorum
    /// depends on can have `depth + 1` batches legitimately in flight, so choose at least `depth + 2`.
    pub max_inflight: usize,
    /// Wait for acknowledgements by spinning instead of sleeping (latency mode on a reserved core).
    pub spin: bool,
}

impl WindowConfig {
    pub fn new(depth: usize) -> WindowConfig {
        WindowConfig {
            depth,
            ack_timeout: Duration::from_secs(1),
            max_inflight: 1024,
            spin: false,
        }
    }
}

/// A replica driven, together with every other replica, by one polling I/O thread: `queue` and `poll` never block,
/// so no thread sleeps or is woken on the replication path (`attach_polled_windowed`).
pub trait ReplicaPoll: Send {
    fn anchor(&self) -> Anchor;
    /// Queue a shipment of records continuing `from` that must leave the replica at `to`. Must not block.
    fn queue(&mut self, from: &Anchor, to: &Anchor, bytes: &[u8]) -> Result<(), String>;
    /// Make progress without blocking (send queued bytes, read acknowledgements); append the replica's anchor after
    /// every batch acknowledged since the last call, in shipping order.
    fn poll(&mut self, acks: &mut Vec<Anchor>) -> Result<(), String>;
}

/// A local journal is a replica (tests, a second disk, or the far end of a transport).
impl Replica for Journal {
    fn anchor(&self) -> Anchor {
        Journal::anchor(self)
    }
    fn replicate(&mut self, from: &Anchor, bytes: &[u8]) -> Result<Anchor, String> {
        Journal::replicate(self, from, bytes).map_err(|e| format!("{e:?}"))
    }
}

struct Replicas {
    set: Vec<Box<dyn Replica>>,
    /// A replica that failed or diverged once is not used again (it must be re-attached after catching up).
    live: Vec<bool>,
    need: usize,
    window: Option<Window>,
}

type Shipment = (Anchor, Anchor, Arc<Vec<u8>>, Instant);

/// Windowed replication. Each replica applies shipped batches in order on its own thread; the engine records the
/// anchor it expects back for every batch in flight and counts a replica's durable prefix only when the replica
/// returns exactly that anchor.
struct Window {
    ship: Vec<Option<mpsc::Sender<Shipment>>>,
    /// Per replica: the anchor expected back for each batch in flight, and when it was shipped.
    inflight: Vec<VecDeque<(Anchor, Instant)>>,
    cfg: WindowConfig,
    /// Journal length each replica has acknowledged with the expected anchor.
    acked: Vec<u64>,
    acks: mpsc::Receiver<(usize, Result<Anchor, String>)>,
    /// Committed slots whose results are not yet released.
    pending: VecDeque<SlotResult>,
    need: usize,
}

impl Window {
    fn absorb(&mut self, i: usize, res: Result<Anchor, String>) {
        if self.ship[i].is_none() {
            return;
        }
        match (res, self.inflight[i].pop_front()) {
            (Ok(a), Some((e, _))) if a == e => self.acked[i] = a.len,
            _ => self.drop_replica(i),
        }
    }
    fn drop_replica(&mut self, i: usize) {
        self.ship[i] = None;
        self.inflight[i].clear();
    }
    fn ship(&mut self, from: Anchor, expect: Anchor, bytes: &[u8]) {
        // Count only batches still unacknowledged: absorb acknowledgements that have already arrived.
        while let Ok((i, res)) = self.acks.try_recv() {
            self.absorb(i, res);
        }
        let bytes = Arc::new(bytes.to_vec());
        let now = Instant::now();
        for i in 0..self.ship.len() {
            if self.inflight[i].len() >= self.cfg.max_inflight {
                self.drop_replica(i);
                continue;
            }
            let sent = self.ship[i]
                .as_ref()
                .is_some_and(|tx| tx.send((from, expect, bytes.clone(), now)).is_ok());
            if sent {
                self.inflight[i].push_back((expect, now));
            } else {
                self.drop_replica(i);
            }
        }
    }
    /// Drop replicas whose oldest batch has waited longer than the timeout; return the time until the next deadline.
    fn expire(&mut self) -> Duration {
        let mut next = self.cfg.ack_timeout;
        for i in 0..self.ship.len() {
            if let Some(&(_, t)) = self.inflight[i].front() {
                match self.cfg.ack_timeout.checked_sub(t.elapsed()) {
                    Some(left) => next = next.min(left),
                    None => self.drop_replica(i),
                }
            }
        }
        next.max(Duration::from_micros(50))
    }
    /// Replicas holding a journal of at least `len` records.
    fn holding(&self, len: u64) -> usize {
        self.acked.iter().filter(|&&l| l >= len).count()
    }
}

pub struct Pipeline {
    cfg: Config,
    /// Latency mode on dedicated cores: verification by spinning workers (`use_spin_pool`).
    pool: Option<Arc<SpinPool>>,
    replicas: Replicas,
    operator: SigningKey,
    admission: Admission,
    exchange: Exchange,
    journal: Journal,
    ckpt_path: PathBuf,
    ckpt_file: File,
    expiries: Expiries,
    last_slot: Option<u64>,
    latest: Option<Checkpoint>,
    poisoned: bool,
    dir: PathBuf,
    /// Snapshot every this many slots (0: never); written in the background.
    snapshot_every: u64,
    last_snapshot: u64,
    writer: Option<SnapshotWriter>,
}

fn genesis_state(cfg: &Config, g: &Genesis) -> Result<(Admission, Exchange), PipelineError> {
    let mut adm = Admission::new();
    adm.set_max_life(cfg.max_life);
    for (a, k) in &g.accounts {
        adm.register(*a, *k)
            .map_err(|e| PipelineError::Genesis(format!("account {a}: {e:?}")))?;
    }
    if !g.bridge.is_empty() {
        let keys: Vec<[u8; 32]> = g.bridge.iter().map(|k| k.to_bytes()).collect();
        adm.set_bridge(&keys, g.bridge_threshold)
            .map_err(|e| PipelineError::Genesis(format!("bridge keys: {e:?}")))?;
    }
    if let Some((b, q)) = g.deposit_cap {
        adm.set_deposit_cap(b, q);
    }
    let mut ex = Exchange::new(cfg.markets as usize);
    ex.set_fees(g.fees)
        .map_err(|_| PipelineError::Genesis("fee rate above MAX_FEE_BPS".into()))?;
    for &(m, a, base, quote) in &g.deposits {
        let mkt = ex
            .markets
            .get_mut(m as usize)
            .ok_or_else(|| PipelineError::Genesis(format!("deposit to unknown market {m}")))?;
        if mkt.apply(&Op::Deposit {
            acct: a,
            base,
            quote,
        }) != Outcome::Ok
        {
            return Err(PipelineError::Genesis(format!("deposit overflow {a}")));
        }
    }
    Ok((adm, ex))
}

/// Cancel resting orders whose expiry is before `slot`, in (expiry, market, id) order; one receipt per order that
/// was still resting.
fn expire(exchange: &mut Exchange, expiries: &mut Expiries, slot: u64) -> Vec<Receipt> {
    let mut out = Vec::new();
    while let Some((&(exp, m, id), &acct)) = expiries.first_key_value() {
        if exp >= slot {
            break;
        }
        expiries.pop_first();
        // Already filled or cancelled orders answer UnknownOrder; they get no receipt.
        let mkt = &mut exchange.markets[m as usize];
        if let Outcome::Cancelled { id, released } = mkt.apply(&Op::Cancel { acct, id }) {
            out.push(Receipt {
                slot,
                source: Source::Expiry { order_id: id },
                acct,
                market: Some(m),
                status: Status::Cancelled { id, released },
                balance: Some(mkt.balance(acct)),
            });
        }
    }
    out
}

/// Match admitted entries (markets in parallel) and append receipts to `out`: one per signed entry, followed — for
/// an order that traded — by one per fill for the maker. Returns, per admitted entry, the index of its own receipt.
fn execute(
    exchange: &mut Exchange,
    expiries: &mut Expiries,
    slot: u64,
    admitted: &[(Entry, Effect)],
    first_seq: u64,
    out: &mut Vec<Receipt>,
) -> Vec<usize> {
    let batch: Vec<(usize, Op)> = admitted
        .iter()
        .filter_map(|(_, eff)| match eff {
            Effect::Market { market, op } => Some((*market as usize, op.clone())),
            _ => None,
        })
        .collect();
    let per_market = exchange.apply_batch_detailed(&batch);
    let mut cursor = vec![0usize; per_market.len()];
    let mut own = Vec::with_capacity(admitted.len());
    for (k, (entry, eff)) in admitted.iter().enumerate() {
        let (acct, market) = entry.subject();
        let seq = first_seq + k as u64;
        let mut balance = None;
        let mut makers = Vec::new();
        let status = match eff {
            Effect::Registered { .. } => Status::Registered,
            Effect::Tick => {
                own.push(usize::MAX);
                continue;
            }
            Effect::Market { market: m, op } => {
                let m = *m as usize;
                let applied = &per_market[m][cursor[m]];
                cursor[m] += 1;
                balance = Some(applied.balance);
                match (op, &applied.outcome) {
                    (_, Outcome::Rejected(r)) => Status::Rejected(r.clone()),
                    (
                        _,
                        Outcome::Placed {
                            id,
                            fills,
                            resting,
                            self_trade_cancels,
                        },
                    ) => {
                        if let Entry::Order(o) = entry {
                            if *resting > 0 && o.intent.tif.rests() {
                                expiries.insert(
                                    (o.intent.expiry_slot, o.intent.market, *id),
                                    o.intent.acct,
                                );
                            }
                        }
                        makers = fills
                            .iter()
                            .zip(&applied.makers)
                            .map(|(f, b)| Receipt {
                                slot,
                                source: Source::Fill {
                                    taker_seq: seq,
                                    maker_order: f.maker,
                                },
                                acct: f.maker_acct,
                                market: Some(m as u32),
                                status: Status::MakerFill {
                                    order_id: f.maker,
                                    price: f.price,
                                    qty: f.qty,
                                    fee: f.maker_fee,
                                    rebate: f.maker_rebate,
                                },
                                balance: Some(*b),
                            })
                            .collect();
                        Status::Executed {
                            id: *id,
                            filled: fills.iter().map(|f| f.qty).sum(),
                            notional: fills.iter().map(|f| f.price as u128 * f.qty as u128).sum(),
                            fees: fills.iter().map(|f| f.taker_fee).sum(),
                            resting: *resting,
                            self_trade_cancels: *self_trade_cancels,
                            fills: fills.clone(),
                        }
                    }
                    (_, Outcome::Cancelled { id, released }) => Status::Cancelled {
                        id: *id,
                        released: *released,
                    },
                    (Op::Deposit { base, quote, .. }, Outcome::Ok) => Status::Deposited {
                        base: *base,
                        quote: *quote,
                    },
                    (Op::Withdraw { base, quote, .. }, Outcome::Ok) => Status::Withdrawn {
                        base: *base,
                        quote: *quote,
                    },
                    (op, other) => unreachable!("{op:?} produced {other:?}"),
                }
            }
        };
        own.push(out.len());
        out.push(Receipt {
            slot,
            source: Source::Entry {
                seq,
                digest: entry.digest().expect("signed entry"),
            },
            acct: acct.expect("signed entries name an account"),
            market,
            status,
            balance,
        });
        out.extend(makers);
    }
    own
}

fn receipts_tree(receipts: &[Receipt]) -> MerkleTree {
    let leaves = receipts
        .par_iter()
        .with_min_len(64)
        .map(|r| r.leaf())
        .collect();
    MerkleTree::from_leaf_hashes(RECEIPTS, leaves)
}

fn market_of(e: &Entry) -> Option<u32> {
    e.subject().1
}

/// Step 2's output: per-submission decisions (Ok = passed the screen) and the verification results of the passed
/// entries, in order.
struct Screened {
    decisions: Vec<Result<usize, Refusal>>,
    verified: Vec<Result<Verified, OrderError>>,
    took: Duration,
}

/// Step 2: parse and screen (read-only), then verify every signature in batches on all cores.
fn screen<S: AsRef<[u8]> + Sync>(
    adm: &Admission,
    cfg: &Config,
    pool: Option<&SpinPool>,
    slot: u64,
    submissions: &[S],
) -> Screened {
    let t0 = Instant::now();
    let markets = cfg.markets;
    let screened: Vec<Result<Entry, Refusal>> = submissions
        .par_iter()
        .with_min_len(64)
        .map(|b| {
            let e = Entry::from_bytes(b.as_ref()).map_err(Refusal::Entry)?;
            if let Some(m) = market_of(&e).filter(|&m| m >= markets) {
                return Err(Refusal::UnknownMarket(m));
            }
            adm.precheck(&e, slot).map_err(Refusal::Entry)?;
            Ok(e)
        })
        .collect();
    let mut passed = Vec::with_capacity(screened.len());
    let decisions = screened
        .into_iter()
        .map(|s| {
            s.map(|e| {
                passed.push(e);
                usize::MAX
            })
        })
        .collect();
    let verified = verify_entries_by(
        passed,
        |e| adm.items_for(e),
        |flat| match pool {
            Some(p) => p.verify_all(flat),
            None => nimbus_sig::verify_all_with(flat, cfg.min_batch),
        },
    );
    Screened {
        decisions,
        verified,
        took: t0.elapsed(),
    }
}

/// Replace `dir/name` with `bytes` atomically and durably: temporary file, fsync, rename, fsync of the directory. A
/// crash leaves the old or the new file, never a mixture.
pub fn durable_write(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, dir.join(name))?;
    File::open(dir)?.sync_all()
}

/// Writes snapshots on a background thread, so the caller only pays for encoding. At most one snapshot waits while
/// another is written; `submit` blocks only if the disk cannot keep up with that (backpressure, never unbounded
/// memory, never a skipped snapshot). Dropping the writer waits for the queued writes.
pub struct SnapshotWriter {
    tx: Option<mpsc::SyncSender<Vec<u8>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    error: Arc<std::sync::Mutex<Option<String>>>,
}

impl SnapshotWriter {
    pub fn new(dir: &Path, name: &str) -> SnapshotWriter {
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(1);
        let error = Arc::new(std::sync::Mutex::new(None));
        let (dir, name, err) = (dir.to_path_buf(), name.to_string(), error.clone());
        let thread = std::thread::spawn(move || {
            for body in rx {
                if let Err(e) = durable_write(&dir, &name, &seal(body)) {
                    *err.lock().expect("writer error lock") = Some(e.to_string());
                }
            }
        });
        SnapshotWriter {
            tx: Some(tx),
            thread: Some(thread),
            error,
        }
    }

    /// Queue a snapshot body for sealing (H(0x12 ‖ body)) and writing, both on the writer's thread; returns the error
    /// of an earlier write, if one failed.
    pub fn submit(&self, body: Vec<u8>) -> Result<(), String> {
        if let Some(e) = self.error.lock().expect("writer error lock").take() {
            return Err(e);
        }
        self.tx
            .as_ref()
            .expect("writer open")
            .send(body)
            .map_err(|_| "snapshot writer stopped".to_string())
    }

    /// Wait until every queued snapshot is durable.
    pub fn finish(mut self) -> Result<(), String> {
        self.stop();
        match self.error.lock().expect("writer error lock").take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn stop(&mut self) {
        drop(self.tx.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for SnapshotWriter {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Entry `i` of a checkpoint file (fixed-size entries).
fn checkpoint_at(f: &mut File, i: u64) -> std::io::Result<[u8; CHECKPOINT_LEN]> {
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(i * CHECKPOINT_LEN as u64))?;
    let mut b = [0u8; CHECKPOINT_LEN];
    f.read_exact(&mut b)?;
    Ok(b)
}

/// Index of the first of the `n` entries with slot > `s` (entries are appended in slot order): binary search.
fn first_checkpoint_after(f: &mut File, n: u64, s: u64) -> std::io::Result<u64> {
    let (mut lo, mut hi) = (0, n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if u64::from_be_bytes(checkpoint_at(f, mid)?[..8].try_into().expect("8")) <= s {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Produces an engine's snapshots off its critical path: it reads the engine's journal read-only, re-executes it
/// with `Replayer` (Proposition Z), and writes `snapshot.bin` into the engine's directory, from which
/// `Pipeline::open` resumes. A slot is applied only once the engine's checkpoint for it is in `checkpoints.bin` —
/// written after the slot's journal fsync — and the follower's re-derived checkpoint must equal it. Run it in its
/// own thread or process alongside the engine; restart it with the engine.
pub struct SnapshotFollower {
    dir: PathBuf,
    replay: Replayer,
    bytes: u64,
    /// Byte offset in `checkpoints.bin` up to which entries were read; read but not yet applied ones wait in
    /// `pending`.
    ckpt_offset: Option<u64>,
    pending: BTreeMap<u64, Checkpoint>,
    latest: Option<Checkpoint>,
}

impl SnapshotFollower {
    /// Start at the engine directory's snapshot if it is valid, otherwise at genesis.
    pub fn new(
        dir: &Path,
        cfg: Config,
        genesis: &Genesis,
    ) -> Result<SnapshotFollower, PipelineError> {
        let resumed = std::fs::read(dir.join("snapshot.bin"))
            .ok()
            .and_then(|b| Replayer::restore(cfg.clone(), &b).ok());
        let (mut replay, bytes, latest) = match resumed {
            Some((r, bytes, window)) => (r, bytes, window.last().copied()),
            None => (Replayer::new(cfg, genesis)?, 0, None),
        };
        // The engine verified every entry before journaling it, and each slot re-derived here must equal the engine's
        // checkpoint: re-verification would only double the signature work on the engine's host.
        replay.trust_own_journal();
        Ok(SnapshotFollower {
            dir: dir.to_path_buf(),
            replay,
            bytes,
            ckpt_offset: None,
            pending: BTreeMap::new(),
            latest,
        })
    }

    /// The last slot applied.
    pub fn last_slot(&self) -> Option<u64> {
        self.replay.last_slot()
    }

    /// Apply every slot the engine has made durable since the last call; returns the number of slots applied.
    pub fn catch_up(&mut self) -> Result<u64, PipelineError> {
        // The engine's checkpoints written since the last call (complete entries only); on the first call, from
        // the first entry after the follower's slot (binary search), so each entry is read once.
        if let Ok(mut f) = File::open(self.dir.join("checkpoints.bin")) {
            use std::io::Seek;
            let n = f.metadata()?.len() / CHECKPOINT_LEN as u64;
            let from = match self.ckpt_offset {
                Some(o) => o,
                None => {
                    first_checkpoint_after(&mut f, n, self.replay.last_slot().unwrap_or(0))?
                        * CHECKPOINT_LEN as u64
                }
            };
            f.seek(std::io::SeekFrom::Start(from))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            let whole = buf.len() / CHECKPOINT_LEN * CHECKPOINT_LEN;
            for c in buf[..whole].as_chunks::<CHECKPOINT_LEN>().0 {
                let c = Checkpoint::from_bytes(c).expect("fixed length");
                self.pending.insert(c.slot, c);
            }
            self.ckpt_offset = Some(from + whole as u64);
        }
        let rec = match Journal::read_from(
            &self.dir.join("journal.bin"),
            &self.replay.anchor(),
            self.bytes,
            self.replay.last_slot().unwrap_or(0),
        ) {
            Ok(r) => r,
            Err(JournalError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let base = self.replay.anchor().len;
        let (mut i, mut applied) = (0usize, 0u64);
        while i < rec.records.len() {
            let slot = rec.records[i].slot;
            let end = i + rec.records[i..]
                .iter()
                .take_while(|r| r.slot == slot)
                .count();
            let after = Anchor {
                len: base + end as u64,
                head: rec.chain[end - 1],
            };
            // Not yet durable (or not complete) in the engine: stop here and retry later.
            let Some(engine) = self
                .pending
                .get(&slot)
                .filter(|c| c.journal == after)
                .copied()
            else {
                break;
            };
            let ck = self.replay.apply_slot(&rec.records[i..end], after)?;
            if !ck.same_body(&engine) {
                return Err(PipelineError::Diverged { slot });
            }
            self.pending = self.pending.split_off(&(slot + 1));
            self.bytes = rec.offsets[end - 1];
            self.latest = Some(ck);
            applied += 1;
            i = end;
        }
        Ok(applied)
    }

    /// Write the follower's state as the engine's `snapshot.bin` (atomically and durably).
    pub fn snapshot(&self) -> Result<(), PipelineError> {
        let window: Vec<Checkpoint> = self.latest.into_iter().collect();
        durable_write(
            &self.dir,
            "snapshot.bin",
            &self.replay.snapshot(self.bytes, &window),
        )?;
        Ok(())
    }
}

/// Replay state decoded from a snapshot.
struct Restored {
    admission: Admission,
    exchange: Exchange,
    expiries: Expiries,
    last_slot: Option<u64>,
    anchor: Anchor,
    journal_bytes: u64,
    window: Vec<Checkpoint>,
}

type ExpiryEntry = ((u64, u32, OrderId), AccountId);

/// The expiry entries whose order is still resting, in key order. The index is cleaned lazily — `expire` skips
/// filled or cancelled orders, and order ids are never reused — so the others change no later outcome. One random
/// lookup per entry, spread over all cores.
fn live_expiries(exchange: &Exchange, expiries: &Expiries) -> Vec<ExpiryEntry> {
    let all: Vec<ExpiryEntry> = expiries.iter().map(|(k, a)| (*k, *a)).collect();
    all.into_par_iter()
        .filter(|((_, m, id), acct)| exchange.markets[*m as usize].owner(*id) == Some(*acct))
        .collect()
}

/// Append H(0x12 ‖ body) to a snapshot body.
pub fn seal(mut body: Vec<u8>) -> Vec<u8> {
    let d = hash_tagged(SNAPSHOT_TAG, &[&body]);
    body.extend_from_slice(&d);
    body
}

/// Snapshot body: version ‖ last slot? ‖ journal length ‖ journal head ‖ journal bytes ‖ admission ‖ exchange ‖
/// expiries ‖ window (count ‖ 120-byte checkpoint bodies).
fn encode_body(
    admission: &Admission,
    exchange: &Exchange,
    live: &[ExpiryEntry],
    last_slot: Option<u64>,
    anchor: Anchor,
    journal_bytes: u64,
    window: &[Checkpoint],
) -> Vec<u8> {
    let mut b = vec![SNAPSHOT_VERSION, last_slot.is_some() as u8];
    b.extend_from_slice(&last_slot.unwrap_or(0).to_be_bytes());
    b.extend_from_slice(&anchor.len.to_be_bytes());
    b.extend_from_slice(&anchor.head);
    b.extend_from_slice(&journal_bytes.to_be_bytes());
    admission.encode_into(&mut b);
    exchange.encode_into(&mut b);
    b.extend_from_slice(&(live.len() as u32).to_be_bytes());
    b.reserve(24 * live.len() + 4 + CHECKPOINT_BODY * window.len());
    for ((slot, market, id), acct) in live {
        b.extend_from_slice(&slot.to_be_bytes());
        b.extend_from_slice(&market.to_be_bytes());
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&acct.to_be_bytes());
    }
    b.extend_from_slice(&(window.len() as u32).to_be_bytes());
    for c in window {
        b.extend_from_slice(&c.body());
    }
    b
}

/// Inverse of `encode_state`: checks the seal, the version, canonical and consistent state (see the decoders) and
/// that the market count fits `cfg`.
fn decode_state(cfg: &Config, bytes: &[u8]) -> Result<Restored, PipelineError> {
    let bad = |why: &str| PipelineError::Snapshot(why.into());
    if bytes.len() < 48 {
        return Err(bad("short"));
    }
    let (body, d) = bytes.split_at(bytes.len() - 48);
    if hash_tagged(SNAPSHOT_TAG, &[body]).as_slice() != d {
        return Err(bad("digest"));
    }
    let t = |_| bad("layout");
    let mut r = Reader::new(body);
    if r.u8().map_err(t)? != SNAPSHOT_VERSION {
        return Err(bad("version"));
    }
    let last_slot = match (r.u8().map_err(t)?, r.u64().map_err(t)?) {
        (0, 0) => None,
        (1, s) => Some(s),
        _ => return Err(bad("layout")),
    };
    let len = r.u64().map_err(t)?;
    let head = r.array().map_err(t)?;
    let journal_bytes = r.u64().map_err(t)?;
    let admission = Admission::decode_from(&mut r).map_err(t)?;
    let exchange = Exchange::decode_from(&mut r).map_err(t)?;
    if exchange.markets.len() != cfg.markets as usize {
        return Err(bad("market count differs from the configuration"));
    }
    let mut expiries = BTreeMap::new();
    for _ in 0..r.count(24).map_err(t)? {
        let k = (
            r.u64().map_err(t)?,
            r.u32().map_err(t)?,
            r.u64().map_err(t)?,
        );
        if expiries.last_key_value().is_some_and(|(l, _)| *l >= k) {
            return Err(bad("expiries not ascending"));
        }
        let acct = r.u32().map_err(t)?;
        // Canonical: every entry names a resting order of that account.
        if exchange
            .markets
            .get(k.1 as usize)
            .and_then(|m| m.owner(k.2))
            != Some(acct)
        {
            return Err(bad("expiry of an order that is not resting"));
        }
        expiries.insert(k, acct);
    }
    let mut window: Vec<Checkpoint> = Vec::new();
    for _ in 0..r.count(CHECKPOINT_BODY).map_err(t)? {
        let c = Checkpoint::from_body(&r.array().map_err(t)?);
        if window.last().is_some_and(|l| l.slot >= c.slot) || last_slot.is_none_or(|s| c.slot > s) {
            return Err(bad("window"));
        }
        window.push(c);
    }
    r.end().map_err(t)?;
    Ok(Restored {
        admission,
        exchange,
        expiries,
        last_slot,
        anchor: Anchor { len, head },
        journal_bytes,
        window,
    })
}

/// Deterministic re-execution of journal records, one slot at a time, without the operator's key: the state machine
/// recovery replays (Proposition Z), for a certifier that re-derives checkpoints from a replicated journal and
/// co-signs only those it reproduces. A checkpoint it returns has a zero signature; compare bodies (`same_body`).
pub struct Replayer {
    cfg: Config,
    admission: Admission,
    exchange: Exchange,
    expiries: Expiries,
    len: u64,
    head: Hash,
    last_slot: Option<u64>,
    /// Re-verify signatures (default); off only for a node replaying its own journal against its signed checkpoints.
    verify: bool,
}

impl Replayer {
    pub fn new(cfg: Config, genesis: &Genesis) -> Result<Replayer, PipelineError> {
        let (admission, exchange) = genesis_state(&cfg, genesis)?;
        Ok(Replayer {
            cfg,
            admission,
            exchange,
            expiries: BTreeMap::new(),
            len: 0,
            head: nimbus_journal::genesis_chain(),
            last_slot: None,
            verify: true,
        })
    }

    /// The journal anchor after the records applied so far.
    pub fn anchor(&self) -> Anchor {
        Anchor {
            len: self.len,
            head: self.head,
        }
    }

    /// The last slot applied, if any.
    pub fn last_slot(&self) -> Option<u64> {
        self.last_slot
    }

    /// Skip signature re-verification: for a node re-executing its own journal (whose entries were verified at
    /// admission) and comparing every derived checkpoint with its own signed one. Never for a replicated journal.
    pub fn trust_own_journal(&mut self) {
        self.verify = false;
    }

    /// Snapshot of the complete replay state after `len()` records (journal head and byte length included), with a
    /// window of derived checkpoints to carry along (`encode_state`).
    pub fn snapshot(&self, journal_bytes: u64, window: &[Checkpoint]) -> Vec<u8> {
        seal(self.snapshot_body(journal_bytes, window))
    }

    /// `snapshot` without the seal (for `SnapshotWriter::submit`, which seals on its own thread).
    pub fn snapshot_body(&self, journal_bytes: u64, window: &[Checkpoint]) -> Vec<u8> {
        encode_body(
            &self.admission,
            &self.exchange,
            &live_expiries(&self.exchange, &self.expiries),
            self.last_slot,
            self.anchor(),
            journal_bytes,
            window,
        )
    }

    /// Inverse of `snapshot` (`decode_state`); returns the replayer, the journal byte length it was taken at, and
    /// the window.
    pub fn restore(
        cfg: Config,
        bytes: &[u8],
    ) -> Result<(Replayer, u64, Vec<Checkpoint>), PipelineError> {
        let r = decode_state(&cfg, bytes)?;
        Ok((
            Replayer {
                cfg,
                admission: r.admission,
                exchange: r.exchange,
                expiries: r.expiries,
                len: r.anchor.len,
                head: r.anchor.head,
                last_slot: r.last_slot,
                verify: true,
            },
            r.journal_bytes,
            r.window,
        ))
    }

    /// Records applied so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn exchange(&self) -> &Exchange {
        &self.exchange
    }

    /// Apply one slot: `records` are consecutive from sequence `len()`, all for one slot later than the last, and the
    /// journal ends at `after` once they are appended. Returns that slot's checkpoint (zero signature).
    pub fn apply_slot(
        &mut self,
        records: &[Record],
        after: Anchor,
    ) -> Result<Checkpoint, PipelineError> {
        let rejected = |seq, reason: &str| PipelineError::ReplayRejected {
            seq,
            reason: reason.into(),
        };
        let first = records.first().ok_or(rejected(self.len, "empty slot"))?;
        let slot = first.slot;
        if self.last_slot.is_some_and(|l| slot <= l) {
            return Err(rejected(first.seq, "slot not after the previous one"));
        }
        for (k, r) in records.iter().enumerate() {
            if r.slot != slot || r.seq != self.len + k as u64 {
                return Err(rejected(r.seq, "records do not form one consecutive slot"));
            }
        }
        if after.len != self.len + records.len() as u64 {
            return Err(rejected(self.len, "anchor length"));
        }
        let signed: Vec<Entry> = records
            .iter()
            .filter(|r| r.entry != Entry::Tick)
            .map(|r| r.entry.clone())
            .collect();
        let adm = &self.admission;
        let mut verified = if self.verify {
            verify_entries_with(signed, |e| adm.items_for(e), 16)
        } else {
            signed
                .into_iter()
                .map(|e| Ok(Verified::trusted(e)))
                .collect()
        }
        .into_iter();
        let mut receipts = expire(&mut self.exchange, &mut self.expiries, slot);
        let mut admitted = Vec::with_capacity(records.len());
        for r in records {
            let v = if r.entry == Entry::Tick {
                Ok(Verified::tick())
            } else {
                verified.next().expect("one result per signed entry")
            };
            if market_of(&r.entry).is_some_and(|m| m >= self.cfg.markets) {
                return Err(rejected(r.seq, "market"));
            }
            let v = v.map_err(|e| PipelineError::ReplayRejected {
                seq: r.seq,
                reason: format!("{e:?}"),
            })?;
            let eff = self.admission.admit_verified(&v, slot).map_err(|e| {
                PipelineError::ReplayRejected {
                    seq: r.seq,
                    reason: format!("{e:?}"),
                }
            })?;
            admitted.push((r.entry.clone(), eff));
        }
        execute(
            &mut self.exchange,
            &mut self.expiries,
            slot,
            &admitted,
            self.len,
            &mut receipts,
        );
        let tree = receipts_tree(&receipts);
        self.len += records.len() as u64;
        self.head = after.head;
        self.last_slot = Some(slot);
        Ok(Checkpoint {
            slot,
            journal: after,
            receipts_root: tree.root(),
            receipts: receipts.len() as u64,
            sig: [0; 64],
        })
    }
}

impl Checkpoint {
    /// Equal slot, journal anchor, receipts root and count (signatures ignored): the statement both sides make.
    pub fn same_body(&self, other: &Checkpoint) -> bool {
        self.digest() == other.digest()
    }
}

impl Pipeline {
    /// Open (or create) the pipeline in `dir`: replay the journal from genesis, re-derive every checkpoint and
    /// require equality with each stored one and with `external` (a checkpoint obtained from outside this machine —
    /// an agent's receipt or a published copy — which is what detects records cut from the journal's end).
    pub fn open(
        dir: &Path,
        cfg: Config,
        genesis: &Genesis,
        operator: SigningKey,
        external: Option<&Checkpoint>,
    ) -> Result<(Pipeline, RecoveryReport), PipelineError> {
        std::fs::create_dir_all(dir)?;
        let pk = operator.verifying_key();
        if let Some(x) = external {
            if !x.verify(&pk) {
                return Err(PipelineError::CheckpointInvalid);
            }
        }
        let mut report = RecoveryReport::default();

        // Stored checkpoints are a cache of derived data: torn or unsigned entries are re-derived, not trusted.
        let ckpt_path = dir.join("checkpoints.bin");
        let jpath = dir.join("journal.bin");
        let snapshot = std::fs::read(dir.join("snapshot.bin"))
            .ok()
            .and_then(|b| decode_state(&cfg, &b).ok())
            .filter(|r| r.last_slot.is_some());
        // Resume from this engine's own snapshot if it fits the journal and every signed checkpoint. Only the
        // checkpoints after it are read (entries are fixed-size and in slot order: binary search), so recovery reads
        // O(state + suffix + log history) bytes.
        let mut stored: BTreeMap<u64, Checkpoint> = BTreeMap::new();
        let resume = match snapshot {
            Some(r) => Self::try_resume(
                &ckpt_path,
                &jpath,
                &pk,
                r,
                external,
                &mut stored,
                &mut report,
            )?,
            None => None,
        };
        let (journal, rec, restored, kept_bytes) = match resume {
            Some((r, j, rec, kept_bytes)) => (j, rec, Some(r), Some(kept_bytes)),
            None => {
                stored.clear();
                report.checkpoints_discarded = 0;
                if let Ok(mut f) = File::open(&ckpt_path) {
                    let mut buf = Vec::new();
                    f.read_to_end(&mut buf)?;
                    if buf.len() % CHECKPOINT_LEN != 0 {
                        report.checkpoints_discarded += 1;
                    }
                    for c in buf.as_chunks::<CHECKPOINT_LEN>().0 {
                        match Checkpoint::from_bytes(c).filter(|c| c.verify(&pk)) {
                            Some(c) => {
                                stored.insert(c.slot, c);
                            }
                            None => report.checkpoints_discarded += 1,
                        }
                    }
                }
                // The longest signed anchor must be a prefix of the journal (records cut from the end are caught).
                let longest = stored
                    .values()
                    .chain(external)
                    .max_by_key(|c| c.journal.len)
                    .copied();
                let opened = match &longest {
                    Some(c) => Journal::open_anchored(&jpath, usize::MAX, &c.journal),
                    None => Journal::open(&jpath, usize::MAX),
                };
                let (j, rec) = Self::opened(opened, longest)?;
                (j, rec, None, None)
            }
        };
        report.records = rec.records.len() as u64;
        report.journal_truncated_bytes = rec.truncated_bytes;
        let base = restored.as_ref().map_or(0, |r| r.anchor.len);
        let s0 = restored.as_ref().and_then(|r| r.last_slot);
        report.resumed_from = s0;
        if external.is_some_and(|x| s0.is_some_and(|s0| x.slot <= s0)) {
            report.external_matched = true;
        }
        let (admission, exchange, expiries, latest) = match restored {
            Some(r) => (
                r.admission,
                r.exchange,
                r.expiries,
                r.window.last().map(|c| c.signed(&operator)),
            ),
            None => {
                let (a, e) = genesis_state(&cfg, genesis)?;
                (a, e, BTreeMap::new(), None)
            }
        };
        let ckpt_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ckpt_path)?;
        let mut p = Pipeline {
            cfg,
            pool: None,
            replicas: Replicas {
                set: Vec::new(),
                live: Vec::new(),
                need: 0,
                window: None,
            },
            operator,
            admission,
            exchange,
            journal,
            ckpt_path,
            ckpt_file,
            expiries,
            last_slot: s0,
            latest,
            poisoned: false,
            dir: dir.to_path_buf(),
            snapshot_every: 0,
            last_snapshot: s0.unwrap_or(0),
            writer: None,
        };
        p.replay_from(&rec, base, &mut stored, external, &mut report, kept_bytes)?;
        Ok((p, report))
    }

    /// The resume attempt of `open`: the stored checkpoints after the snapshot (into `stored`), an external checkpoint
    /// at or before it found among the stored ones, the journal opened at the snapshot's anchor and every longer
    /// signed anchor on its suffix. `None`: fall back to replay from genesis. On success also returns the byte
    /// length of the checkpoint file's prefix up to the snapshot (kept as is).
    #[allow(clippy::type_complexity)]
    fn try_resume(
        ckpt_path: &Path,
        jpath: &Path,
        pk: &VerifyingKey,
        r: Restored,
        external: Option<&Checkpoint>,
        stored: &mut BTreeMap<u64, Checkpoint>,
        report: &mut RecoveryReport,
    ) -> Result<Option<(Restored, Journal, nimbus_journal::Recovery, u64)>, PipelineError> {
        let s0 = r.last_slot.expect("filtered");
        let (mut f, n, torn) = match File::open(ckpt_path) {
            Ok(f) => {
                let len = f.metadata()?.len();
                (
                    Some(f),
                    len / CHECKPOINT_LEN as u64,
                    len % CHECKPOINT_LEN as u64 != 0,
                )
            }
            Err(_) => (None, 0, false),
        };
        let mut at = |i: u64| -> std::io::Result<[u8; CHECKPOINT_LEN]> {
            checkpoint_at(f.as_mut().expect("entries exist only with a file"), i)
        };
        let idx = match File::open(ckpt_path) {
            Ok(mut g) => first_checkpoint_after(&mut g, n, s0)?,
            Err(_) => 0,
        };
        if let Some(x) = external.filter(|x| x.slot <= s0) {
            let j = match (File::open(ckpt_path), x.slot) {
                (Ok(mut g), s) if s > 0 => first_checkpoint_after(&mut g, n, s - 1)?,
                _ => 0,
            };
            if j >= n || at(j)? != x.to_bytes() {
                return Ok(None);
            }
        }
        if torn {
            report.checkpoints_discarded += 1;
        }
        for i in idx..n {
            match Checkpoint::from_bytes(&at(i)?).filter(|c| c.verify(pk) && c.slot > s0) {
                Some(c) => {
                    stored.insert(c.slot, c);
                }
                None => report.checkpoints_discarded += 1,
            }
        }
        let (j, rec) = match Journal::open_from(jpath, usize::MAX, &r.anchor, r.journal_bytes, s0) {
            Ok(x) => x,
            Err(_) => return Ok(None),
        };
        // Signed anchors beyond the snapshot must lie on the journal's suffix.
        let longest = stored
            .values()
            .chain(external)
            .max_by_key(|c| c.journal.len)
            .copied();
        if let Some(c) = longest.filter(|c| c.journal.len > r.anchor.len) {
            let k = (c.journal.len - r.anchor.len) as usize;
            if k > rec.records.len() || rec.chain[k - 1] != c.journal.head {
                return Ok(None);
            }
        }
        Ok(Some((r, j, rec, idx * CHECKPOINT_LEN as u64)))
    }

    /// Map journal-open errors onto recovery errors.
    fn opened(
        opened: Result<(Journal, nimbus_journal::Recovery), JournalError>,
        longest: Option<Checkpoint>,
    ) -> Result<(Journal, nimbus_journal::Recovery), PipelineError> {
        let slot = longest.map(|c| c.slot).unwrap_or(0);
        match opened {
            Err(JournalError::BehindAnchor { have, anchored }) => Err(PipelineError::Truncated {
                have,
                need: anchored,
                slot,
            }),
            Err(JournalError::AnchorMismatch { .. }) => Err(PipelineError::Diverged { slot }),
            Err(e) => Err(e.into()),
            Ok(x) => Ok(x),
        }
    }

    /// Re-execute the journal records `rec` (which start at sequence `base`), re-derive and sign each slot's
    /// checkpoint, and require equality with every stored checkpoint after the resume point and with `external`.
    fn replay_from(
        &mut self,
        rec: &nimbus_journal::Recovery,
        base: u64,
        stored: &mut BTreeMap<u64, Checkpoint>,
        external: Option<&Checkpoint>,
        report: &mut RecoveryReport,
        kept_bytes: Option<u64>,
    ) -> Result<(), PipelineError> {
        let p = self;
        // Verify every journaled signature up front (batched, all cores). Registrations only add accounts, so keys
        // resolved against genesis are the keys admission will require.
        let mut verified: Vec<Option<Result<Verified, OrderError>>> = {
            let adm = &p.admission;
            let signed: Vec<Entry> = rec
                .records
                .iter()
                .filter(|r| r.entry != Entry::Tick)
                .map(|r| r.entry.clone())
                .collect();
            let mut v = verify_entries_with(signed, |e| adm.items_for(e), 16).into_iter();
            rec.records
                .iter()
                .map(|r| {
                    Some(if r.entry == Entry::Tick {
                        Ok(Verified::tick())
                    } else {
                        v.next().expect("one result per signed entry")
                    })
                })
                .collect()
        };

        let mut derived: Vec<Checkpoint> = Vec::new();
        let mut i = 0usize;
        while i < rec.records.len() {
            let slot = rec.records[i].slot;
            let end = i + rec.records[i..]
                .iter()
                .take_while(|r| r.slot == slot)
                .count();
            let mut receipts = expire(&mut p.exchange, &mut p.expiries, slot);
            let mut admitted = Vec::with_capacity(end - i);
            for (r, v) in rec.records[i..end].iter().zip(&mut verified[i..end]) {
                let v = v.take().expect("each verified once");
                admitted.push((r.entry.clone(), p.readmit(r, v)?));
            }
            execute(
                &mut p.exchange,
                &mut p.expiries,
                slot,
                &admitted,
                base + i as u64,
                &mut receipts,
            );
            let tree = receipts_tree(&receipts);
            let ck = Checkpoint {
                slot,
                journal: Anchor {
                    len: base + end as u64,
                    head: rec.chain[end - 1],
                },
                receipts_root: tree.root(),
                receipts: receipts.len() as u64,
                sig: [0; 64],
            }
            .signed(&p.operator);
            if let Some(s) = stored.remove(&slot) {
                if s != ck {
                    return Err(PipelineError::Diverged { slot });
                }
                report.checkpoints_matched += 1;
            } else {
                report.checkpoints_rederived += 1;
            }
            if let Some(x) = external {
                if x.slot == slot {
                    if *x != ck {
                        return Err(PipelineError::Diverged { slot });
                    }
                    report.external_matched = true;
                }
            }
            derived.push(ck);
            p.last_slot = Some(slot);
            p.latest = Some(ck);
            report.slots += 1;
            i = end;
        }
        // A signed checkpoint for a slot the journal does not contain is a divergence too.
        if let Some((&slot, _)) = stored.iter().next() {
            return Err(PipelineError::Diverged { slot });
        }
        if let Some(x) = external {
            if !report.external_matched {
                return Err(PipelineError::Diverged { slot: x.slot });
            }
        }
        if report.checkpoints_rederived + report.checkpoints_discarded > 0 {
            match kept_bytes {
                None => p.rewrite_checkpoints(&derived)?,
                Some(keep) => p.rewrite_checkpoints_after(keep, &derived)?,
            }
        }
        Ok(())
    }

    fn readmit(
        &mut self,
        r: &Record,
        v: Result<Verified, OrderError>,
    ) -> Result<Effect, PipelineError> {
        let rejected = |reason: String| PipelineError::ReplayRejected { seq: r.seq, reason };
        if market_of(&r.entry).is_some_and(|m| m >= self.cfg.markets) {
            return Err(rejected("market".into()));
        }
        let v = v.map_err(|e| rejected(format!("{e:?}")))?;
        self.admission
            .admit_verified(&v, r.slot)
            .map_err(|e| rejected(format!("{e:?}")))
    }

    fn rewrite_checkpoints(&mut self, all: &[Checkpoint]) -> Result<(), PipelineError> {
        let tmp = self.ckpt_path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            let mut buf = Vec::with_capacity(all.len() * CHECKPOINT_LEN);
            all.iter()
                .for_each(|c| buf.extend_from_slice(&c.to_bytes()));
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.ckpt_path)?;
        self.ckpt_file = OpenOptions::new().append(true).open(&self.ckpt_path)?;
        Ok(())
    }

    /// Snapshot the engine state every `k` slots (0 disables): encoded on the engine thread at the end of a slot,
    /// written durably in the background (`SnapshotWriter`). Recovery then re-executes only the journal after the
    /// newest snapshot.
    pub fn set_snapshot_every(&mut self, k: u64) {
        self.snapshot_every = k;
    }

    /// Write a snapshot now and wait until it is durable (queued background snapshots are written first).
    pub fn snapshot_now(&mut self) -> Result<(), PipelineError> {
        self.flush_snapshots()?;
        let body = self.snapshot_body()?;
        durable_write(&self.dir, "snapshot.bin", &seal(body))?;
        Ok(())
    }

    /// Wait until every queued background snapshot is durable.
    pub fn flush_snapshots(&mut self) -> Result<(), PipelineError> {
        match self.writer.take() {
            Some(w) => w.finish().map_err(PipelineError::Snapshot),
            None => Ok(()),
        }
    }

    fn snapshot_body(&mut self) -> Result<Vec<u8>, PipelineError> {
        let bytes = self.journal.byte_len()?;
        // Keep only expiry entries of resting orders, in the engine too: the index then holds the resting orders plus
        // those placed since the last snapshot (bulk rebuild from sorted entries).
        let live = live_expiries(&self.exchange, &self.expiries);
        self.expiries = live.iter().copied().collect();
        let window: Vec<Checkpoint> = self.latest.into_iter().collect();
        Ok(encode_body(
            &self.admission,
            &self.exchange,
            &live,
            self.last_slot,
            self.journal.anchor(),
            bytes,
            &window,
        ))
    }

    /// Keep the first `keep` bytes of the checkpoint file (the entries up to the snapshot) and write `tail` after
    /// them. The file is a cache: a crash here leaves entries that the next recovery re-derives.
    fn rewrite_checkpoints_after(
        &mut self,
        keep: u64,
        tail: &[Checkpoint],
    ) -> Result<(), PipelineError> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.ckpt_path)?;
        f.set_len(keep)?;
        let mut buf = Vec::with_capacity(tail.len() * CHECKPOINT_LEN);
        tail.iter()
            .for_each(|c| buf.extend_from_slice(&c.to_bytes()));
        use std::io::Seek;
        f.seek(std::io::SeekFrom::End(0))?;
        f.write_all(&buf)?;
        f.sync_all()?;
        self.ckpt_file = OpenOptions::new().append(true).open(&self.ckpt_path)?;
        Ok(())
    }

    pub fn operator_key(&self) -> VerifyingKey {
        self.operator.verifying_key()
    }
    pub fn latest_checkpoint(&self) -> Option<Checkpoint> {
        self.latest
    }
    pub fn journal_anchor(&self) -> Anchor {
        self.journal.anchor()
    }
    pub fn journal_durable_len(&self) -> u64 {
        self.journal.durable_len()
    }
    pub fn exchange(&self) -> &Exchange {
        &self.exchange
    }
    pub fn admission(&self) -> &Admission {
        &self.admission
    }
    pub fn next_nonce(&self, acct: AccountId) -> u64 {
        self.admission.next_nonce(acct)
    }

    /// Run one slot. `slot` must increase strictly between calls. On return the admitted entries are durable (when
    /// `fsync` is on), executed, and covered by a signed checkpoint; acknowledge them with `SlotResult::proof`.
    pub fn process_slot<S: AsRef<[u8]> + Sync>(
        &mut self,
        slot: u64,
        submissions: &[S],
    ) -> Result<SlotResult, PipelineError> {
        if self.replicas.window.is_some() {
            return Err(PipelineError::WrongMode);
        }
        self.check_slot(slot)?;
        let screened = screen(
            &self.admission,
            &self.cfg,
            self.pool.as_deref(),
            slot,
            submissions,
        );
        self.commit(slot, screened)
    }

    /// Run consecutive slots with verification of slot s+1 overlapping the admission, journal, matching and
    /// checkpoint of slot s. Slot s+1 is screened against a snapshot of admission taken before slot s: keys never
    /// change once registered and nonces and references only advance, so the stale screen refuses a subset of what
    /// the current one would, and admission — always current — decides. Results equal `process_slot` one by one.
    pub fn process_slots<S: AsRef<[u8]> + Sync>(
        &mut self,
        slots: &[(u64, &[S])],
    ) -> Result<Vec<SlotResult>, PipelineError> {
        if self.replicas.window.is_some() {
            return Err(PipelineError::WrongMode);
        }
        self.run_slots(slots)
    }

    fn run_slots<S: AsRef<[u8]> + Sync>(
        &mut self,
        slots: &[(u64, &[S])],
    ) -> Result<Vec<SlotResult>, PipelineError> {
        let mut last = self.last_slot;
        for &(slot, _) in slots {
            if let Some(l) = last {
                if slot <= l {
                    return Err(PipelineError::SlotNotIncreasing { slot, last: l });
                }
            }
            last = Some(slot);
        }
        let mut out = Vec::with_capacity(slots.len());
        let Some(&(first, subs)) = slots.first() else {
            return Ok(out);
        };
        self.check_slot(first)?;
        let pool = self.pool.clone();
        let mut pending = screen(&self.admission, &self.cfg, pool.as_deref(), first, subs);
        for i in 0..slots.len() {
            let slot = slots[i].0;
            let next = slots
                .get(i + 1)
                .map(|&(s, subs)| (s, subs, self.admission.clone()));
            let cfg = self.cfg.clone();
            let (res, screened_next) = rayon::join(
                || self.commit(slot, pending),
                || next.map(|(s, subs, snap)| screen(&snap, &cfg, pool.as_deref(), s, subs)),
            );
            out.push(res?);
            match screened_next {
                Some(sn) => pending = sn,
                None => break,
            }
        }
        Ok(out)
    }

    /// Replicate every later slot to `set` and acknowledge a slot only when `need` replicas hold it durably (the local
    /// journal is always required as well). Each replica must be at the engine's current journal anchor.
    pub fn attach_replicas(
        &mut self,
        set: Vec<Box<dyn Replica>>,
        need: usize,
    ) -> Result<(), PipelineError> {
        if need > set.len() {
            return Err(PipelineError::ReplicaSetup { index: set.len() });
        }
        let at = self.journal.anchor();
        if let Some(index) = set.iter().position(|r| r.anchor() != at) {
            return Err(PipelineError::ReplicaSetup { index });
        }
        self.replicas = Replicas {
            live: vec![true; set.len()],
            set,
            need,
            window: None,
        };
        Ok(())
    }

    /// Windowed replication: each replica applies shipped slots on its own thread, the engine keeps committing, and
    /// `submit_slot` / `submit_slots` / `drain` release each slot's results, in slot order, once `need` replicas hold
    /// its journal prefix. At most `depth` committed slots wait for acknowledgements; beyond that `submit_*` blocks.
    /// `process_slot(s)` is refused in this mode because it would release unreplicated results.
    pub fn attach_replicas_windowed(
        &mut self,
        set: Vec<Box<dyn Replica>>,
        need: usize,
        depth: usize,
    ) -> Result<(), PipelineError> {
        let streams = set
            .into_iter()
            .map(|r| Box::new(Local(r)) as Box<dyn ReplicaStream>)
            .collect();
        self.attach_streams_windowed(streams, need, WindowConfig::new(depth))
    }

    /// Windowed replication over streaming transports (several batches in flight per replica), with a timeout and
    /// an in-flight cap per replica (`WindowConfig`).
    pub fn attach_streams_windowed(
        &mut self,
        set: Vec<Box<dyn ReplicaStream>>,
        need: usize,
        cfg: WindowConfig,
    ) -> Result<(), PipelineError> {
        if need > set.len() {
            return Err(PipelineError::ReplicaSetup { index: set.len() });
        }
        let at = self.journal.anchor();
        if let Some(index) = set.iter().position(|r| r.anchor() != at) {
            return Err(PipelineError::ReplicaSetup { index });
        }
        let (ack_tx, acks) = mpsc::channel();
        let n = set.len();
        let mut ship = Vec::with_capacity(n);
        for (i, r) in set.into_iter().enumerate() {
            let (mut out, mut back) = r.split();
            let (tx, rx) = mpsc::channel::<Shipment>();
            std::thread::spawn(move || {
                for (from, to, bytes, shipped) in rx {
                    if out.send(&from, &to, &bytes, shipped).is_err() {
                        break;
                    }
                }
            });
            let ack = ack_tx.clone();
            std::thread::spawn(move || loop {
                let a = back.next_ack();
                let failed = a.is_err();
                if ack.send((i, a)).is_err() || failed {
                    break;
                }
            });
            ship.push(Some(tx));
        }
        self.replicas = Replicas {
            set: Vec::new(),
            live: Vec::new(),
            need: 0,
            window: Some(Window {
                ship,
                inflight: vec![VecDeque::new(); n],
                cfg: WindowConfig {
                    depth: cfg.depth.max(1),
                    max_inflight: cfg.max_inflight.max(1),
                    ..cfg
                },
                acked: vec![at.len; n],
                acks,
                pending: VecDeque::new(),
                need,
            }),
        };
        Ok(())
    }

    /// Windowed replication with one spinning I/O thread for all replicas (`ReplicaPoll`), instead of a sending and
    /// an acknowledging thread per replica that sleep between messages. The thread owns a core while replicas are
    /// attached.
    pub fn attach_polled_windowed(
        &mut self,
        set: Vec<Box<dyn ReplicaPoll>>,
        need: usize,
        cfg: WindowConfig,
    ) -> Result<(), PipelineError> {
        if need > set.len() {
            return Err(PipelineError::ReplicaSetup { index: set.len() });
        }
        let at = self.journal.anchor();
        if let Some(index) = set.iter().position(|r| r.anchor() != at) {
            return Err(PipelineError::ReplicaSetup { index });
        }
        let (ack_tx, acks) = mpsc::channel();
        let n = set.len();
        let (mut ship, mut rxs) = (Vec::with_capacity(n), Vec::with_capacity(n));
        for _ in 0..n {
            let (tx, rx) = mpsc::channel::<Shipment>();
            ship.push(Some(tx));
            rxs.push(Some(rx));
        }
        let mut set: Vec<Option<Box<dyn ReplicaPoll>>> = set.into_iter().map(Some).collect();
        std::thread::spawn(move || {
            let mut got = Vec::new();
            loop {
                let mut live = 0;
                for i in 0..n {
                    let (Some(r), Some(rx)) = (set[i].as_mut(), rxs[i].as_ref()) else {
                        continue;
                    };
                    live += 1;
                    let mut res = Ok(());
                    loop {
                        match rx.try_recv() {
                            Ok((from, to, bytes, _)) => {
                                res = r.queue(&from, &to, &bytes);
                                if res.is_err() {
                                    break;
                                }
                            }
                            Err(mpsc::TryRecvError::Empty) => break,
                            // The engine dropped this replica (or itself): close the connection.
                            Err(mpsc::TryRecvError::Disconnected) => {
                                res = Err("detached".to_string());
                                break;
                            }
                        }
                    }
                    if res.is_ok() {
                        got.clear();
                        res = r.poll(&mut got);
                        for a in got.drain(..) {
                            if ack_tx.send((i, Ok(a))).is_err() {
                                return;
                            }
                        }
                    }
                    if let Err(e) = res {
                        let _ = ack_tx.send((i, Err(e)));
                        set[i] = None;
                        rxs[i] = None;
                    }
                }
                if live == 0 {
                    return;
                }
                std::hint::spin_loop();
            }
        });
        self.replicas = Replicas {
            set: Vec::new(),
            live: Vec::new(),
            need: 0,
            window: Some(Window {
                ship,
                inflight: vec![VecDeque::new(); n],
                cfg: WindowConfig {
                    depth: cfg.depth.max(1),
                    max_inflight: cfg.max_inflight.max(1),
                    ..cfg
                },
                acked: vec![at.len; n],
                acks,
                pending: VecDeque::new(),
                need,
            }),
        };
        Ok(())
    }

    /// Windowed mode: commit one slot and return every earlier slot whose replication quorum is now complete.
    pub fn submit_slot<S: AsRef<[u8]> + Sync>(
        &mut self,
        slot: u64,
        submissions: &[S],
    ) -> Result<Vec<SlotResult>, PipelineError> {
        self.windowed()?;
        self.check_slot(slot)?;
        let screened = screen(
            &self.admission,
            &self.cfg,
            self.pool.as_deref(),
            slot,
            submissions,
        );
        let r = self.commit(slot, screened)?;
        self.queue(vec![r])
    }

    /// Windowed mode with cross-slot pipelining (`process_slots` semantics).
    pub fn submit_slots<S: AsRef<[u8]> + Sync>(
        &mut self,
        slots: &[(u64, &[S])],
    ) -> Result<Vec<SlotResult>, PipelineError> {
        self.windowed()?;
        let rs = self.run_slots(slots)?;
        self.queue(rs)
    }

    /// Windowed mode: wait until every committed slot is released.
    pub fn drain(&mut self) -> Result<Vec<SlotResult>, PipelineError> {
        self.windowed()?;
        if self.poisoned {
            return Err(PipelineError::Poisoned);
        }
        self.release(true)
    }

    /// Committed slots still waiting for replica acknowledgements (windowed mode).
    pub fn unreleased(&self) -> usize {
        self.replicas.window.as_ref().map_or(0, |w| w.pending.len())
    }

    fn windowed(&self) -> Result<(), PipelineError> {
        if self.replicas.window.is_none() {
            return Err(PipelineError::WrongMode);
        }
        Ok(())
    }

    fn queue(&mut self, rs: Vec<SlotResult>) -> Result<Vec<SlotResult>, PipelineError> {
        let w = self.replicas.window.as_mut().expect("windowed");
        w.pending.extend(rs);
        self.release(false)
    }

    /// Release pending slots in order while their quorum is complete; wait for acknowledgements while more than
    /// `depth` slots are pending (or any, if `all`). A slot that can no longer reach its quorum poisons the pipeline.
    fn release(&mut self, all: bool) -> Result<Vec<SlotResult>, PipelineError> {
        let w = self.replicas.window.as_mut().expect("windowed");
        let mut out = Vec::new();
        loop {
            while let Ok((i, res)) = w.acks.try_recv() {
                w.absorb(i, res);
            }
            // Timeouts apply even when other replicas already meet the quorum.
            w.expire();
            while let Some(len) = w
                .pending
                .front()
                .map(|r| r.checkpoint.map_or(0, |c| c.journal.len))
            {
                if w.holding(len) < w.need {
                    break;
                }
                out.extend(w.pending.pop_front());
            }
            let waiting = if all {
                !w.pending.is_empty()
            } else {
                w.pending.len() > w.cfg.depth
            };
            if !waiting {
                return Ok(out);
            }
            let len = w
                .pending
                .front()
                .map_or(0, |r| r.checkpoint.map_or(0, |c| c.journal.len));
            let reachable = (0..w.ship.len())
                .filter(|&i| w.acked[i] >= len || w.ship[i].is_some())
                .count();
            if reachable < w.need {
                if !out.is_empty() {
                    return Ok(out);
                }
                self.poisoned = true;
                return Err(PipelineError::Replication {
                    acks: w.holding(len),
                    need: w.need,
                });
            }
            let wait = w.expire();
            let next = if w.cfg.spin {
                let until = Instant::now() + wait;
                loop {
                    match w.acks.try_recv() {
                        Err(mpsc::TryRecvError::Empty) if Instant::now() < until => {
                            std::hint::spin_loop()
                        }
                        Err(mpsc::TryRecvError::Empty) => {
                            break Err(mpsc::RecvTimeoutError::Timeout)
                        }
                        Err(mpsc::TryRecvError::Disconnected) => {
                            break Err(mpsc::RecvTimeoutError::Disconnected)
                        }
                        Ok(x) => break Ok(x),
                    }
                }
            } else {
                w.acks.recv_timeout(wait)
            };
            match next {
                Ok((i, res)) => w.absorb(i, res),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.poisoned = true;
                    return Err(PipelineError::Replication {
                        acks: w.holding(len),
                        need: w.need,
                    });
                }
            }
        }
    }

    /// Verify signatures on `workers` spinning threads plus the calling thread instead of the rayon pool: no thread
    /// wake-up per slot, for sub-millisecond slots on cores reserved for verification. `0` returns to rayon.
    /// Results are identical either way.
    pub fn use_spin_pool(&mut self, workers: usize) {
        self.pool = (workers > 0).then(|| Arc::new(SpinPool::new(workers)));
    }

    /// Replicas still in use.
    pub fn live_replicas(&self) -> usize {
        match &self.replicas.window {
            Some(w) => w.ship.iter().filter(|t| t.is_some()).count(),
            None => self.replicas.live.iter().filter(|l| **l).count(),
        }
    }

    fn check_slot(&self, slot: u64) -> Result<(), PipelineError> {
        if self.poisoned {
            return Err(PipelineError::Poisoned);
        }
        if let Some(last) = self.last_slot {
            if slot <= last {
                return Err(PipelineError::SlotNotIncreasing { slot, last });
            }
        }
        Ok(())
    }

    /// Steps 1 and 3–5: expire, admit in arrival order, journal ∥ match, checkpoint.
    fn commit(&mut self, slot: u64, screened: Screened) -> Result<SlotResult, PipelineError> {
        if self.poisoned {
            return Err(PipelineError::Poisoned);
        }
        let mut t = Timings {
            verify: screened.took,
            ..Timings::default()
        };
        let t0 = Instant::now();
        let mut receipts = expire(&mut self.exchange, &mut self.expiries, slot);
        let expired = receipts.len() as u32;
        t.expire = t0.elapsed();

        // Admit in arrival order. Decisions hold the admitted index until receipts are built.
        let t0 = Instant::now();
        let mut decisions = screened.decisions;
        let mut verified = screened.verified.into_iter();
        let mut admitted: Vec<(Entry, Effect)> = Vec::new();
        for d in decisions.iter_mut().filter(|d| d.is_ok()) {
            *d = match verified.next().expect("one per screened entry") {
                Ok(v) => match self.admission.admit_verified(&v, slot) {
                    Ok(eff) => {
                        admitted.push((v.into_inner(), eff));
                        Ok(admitted.len() - 1)
                    }
                    Err(e) => Err(Refusal::Entry(e)),
                },
                Err(e) => Err(Refusal::Entry(e)),
            };
        }
        t.admit = t0.elapsed();
        self.last_slot = Some(slot);
        if admitted.is_empty() && expired == 0 {
            return Ok(SlotResult {
                slot,
                decisions,
                receipts,
                tree: MerkleTree::from_leaf_hashes(RECEIPTS, Vec::new()),
                checkpoint: None,
                expired,
                timings: t,
            });
        }
        let tick = [(Entry::Tick, Effect::Tick)];
        let to_journal: &[(Entry, Effect)] = if admitted.is_empty() {
            &tick
        } else {
            &admitted
        };

        // Journal (one write, one fsync) concurrently with matching and receipts.
        let t0 = Instant::now();
        let first_seq = self.journal.len();
        let fsync = self.cfg.fsync;
        let (journal, exchange, expiries, replicas) = (
            &mut self.journal,
            &mut self.exchange,
            &mut self.expiries,
            &mut self.replicas,
        );
        let ((jres, t_journal), (tree, own, t_match)) = rayon::join(
            || {
                let t0 = Instant::now();
                let refs: Vec<&Entry> = to_journal.iter().map(|(e, _)| e).collect();
                let from = journal.anchor();
                let r = journal.append_batch(slot, &refs).and_then(|_| {
                    let expect = journal.anchor();
                    if let Some(w) = replicas.window.as_mut() {
                        // Windowed: ship now, before the local fsync; acknowledgements are collected at release.
                        w.ship(from, expect, journal.last_write());
                    }
                    let shipped = if replicas.set.is_empty() {
                        Vec::new()
                    } else {
                        journal.last_write().to_vec()
                    };
                    let (local, acks) = rayon::join(
                        || if fsync { journal.sync() } else { Ok(()) },
                        || {
                            replicas
                                .set
                                .par_iter_mut()
                                .zip(replicas.live.par_iter_mut())
                                .filter(|(_, live)| **live)
                                .map(|(r, live)| match r.replicate(&from, &shipped) {
                                    Ok(a) if a == expect => 1,
                                    _ => {
                                        *live = false;
                                        0
                                    }
                                })
                                .sum::<usize>()
                        },
                    );
                    local.map(|_| acks)
                });
                (r, t0.elapsed())
            },
            || {
                let t0 = Instant::now();
                let own = execute(
                    exchange,
                    expiries,
                    slot,
                    to_journal,
                    first_seq,
                    &mut receipts,
                );
                (receipts_tree(&receipts), own, t0.elapsed())
            },
        );
        (t.journal, t.matching) = (t_journal, t_match);
        match jres {
            // Matching already ran: memory is ahead of the durable journal. Nothing was acknowledged; stop here.
            Err(e) => {
                self.poisoned = true;
                return Err(e.into());
            }
            Ok(acks) if acks < self.replicas.need => {
                self.poisoned = true;
                return Err(PipelineError::Replication {
                    acks,
                    need: self.replicas.need,
                });
            }
            Ok(_) => {}
        }
        for k in decisions.iter_mut().flatten() {
            *k = own[*k];
        }
        t.commit = t0.elapsed();

        // Signed checkpoint. Not fsynced: it is re-derived bit-identically from the journal on recovery.
        let t0 = Instant::now();
        let ck = Checkpoint {
            slot,
            journal: self.journal.anchor(),
            receipts_root: tree.root(),
            receipts: receipts.len() as u64,
            sig: [0; 64],
        }
        .signed(&self.operator);
        self.ckpt_file.write_all(&ck.to_bytes())?;
        self.latest = Some(ck);
        t.checkpoint = t0.elapsed();
        if self.snapshot_every > 0 && slot >= self.last_snapshot + self.snapshot_every {
            let t0 = Instant::now();
            let bytes = self.snapshot_body()?;
            t.snapshot = t0.elapsed();
            self.writer
                .get_or_insert_with(|| SnapshotWriter::new(&self.dir, "snapshot.bin"))
                .submit(bytes)
                .map_err(PipelineError::Snapshot)?;
            self.last_snapshot = slot;
        }

        Ok(SlotResult {
            slot,
            decisions,
            receipts,
            tree,
            checkpoint: Some(ck),
            expired,
            timings: t,
        })
    }
}
