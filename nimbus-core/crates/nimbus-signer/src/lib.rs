//! Key-isolating signer.
//!
//! The agent process never sees the private key. It sends an order *request*; the signer fills in the account and
//! the next nonce itself, applies the risk policy and the rate limit on its own clock, and only then signs.
//!
//! Reference price and current slot come only from the feed: quorum-signed attestations (`nimbus-feed`) are pushed
//! to the signer on a separate feed channel, verified, and cached per market. Agent requests carry no price data
//! at all, so an agent cannot pick a convenient attestation; the signer always uses the newest one it holds and
//! refuses to sign when that is older than the feed's freshness window (fail closed). Accepted observations are
//! persisted before they are used, so slot monotonicity survives restarts.
//!
//! Agents can also have the signer sign a **cancel** of one of their orders. Cancels only reduce risk, so they are
//! signed even while the feed is stale; their expiry is the newest feed slot plus the policy's maximum lifetime, which
//! covers every order this signer ever signed. There is no withdrawal request: an agent can never move funds out.
//!
//! A compromised agent can therefore not sign for another account, reuse or skip nonces, move the price band,
//! stretch order lifetimes, exceed its rate limit, or withdraw.
#![forbid(unsafe_code)]

use ed25519_dalek::SigningKey;
use nimbus_feed::{Attestation, FeedError, FeedSet, FeedTracker, Observation};
use nimbus_match::{AccountId, Side, Tif};
use nimbus_order::{Action, ActionKind, Entry, Intent, SignedAction, SignedOrder};
use nimbus_sdk::{RateLimiter, RiskPolicy, RiskReject};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub market: u32,
    /// "bid" | "ask"
    pub side: String,
    pub price: u64,
    pub qty: u64,
    /// "gtc" | "ioc"
    pub tif: String,
    pub expiry_slot: u64,
}

/// `{"cancel": {"market": 1, "order_id": 42}}`
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    pub market: u32,
    pub order_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelEnvelope {
    cancel: CancelRequest,
}

/// Parse one agent line: a cancel envelope or an order request (anything else is refused).
pub fn parse_request(line: &str) -> Result<Request, String> {
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("bad request: {e}"))?;
    if v.get("cancel").is_some() {
        serde_json::from_value::<CancelEnvelope>(v)
            .map(|e| Request::Cancel(e.cancel))
            .map_err(|e| format!("bad request: {e}"))
    } else {
        serde_json::from_value::<SignRequest>(v)
            .map(Request::Order)
            .map_err(|e| format!("bad request: {e}"))
    }
}

#[derive(Clone, Debug)]
pub enum Request {
    Order(SignRequest),
    Cancel(CancelRequest),
}

/// A signed journal entry (`nimbus_order::Entry` bytes, hex) ready to submit to the engine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SignResponse {
    Ok { entry_hex: String, nonce: u64 },
    Err { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FeedResponse {
    Ok { market: u32, slot: u64, price: u64 },
    Err { reason: String },
}

/// On-disk form of the latest accepted observation per market.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationRecord {
    pub market: u32,
    pub price: u64,
    pub slot: u64,
    pub time_ms: u64,
}

impl From<Observation> for ObservationRecord {
    fn from(o: Observation) -> Self {
        ObservationRecord {
            market: o.market,
            price: o.price,
            slot: o.slot,
            time_ms: o.time_ms,
        }
    }
}
impl From<ObservationRecord> for Observation {
    fn from(o: ObservationRecord) -> Self {
        Observation {
            market: o.market,
            price: o.price,
            slot: o.slot,
            time_ms: o.time_ms,
        }
    }
}

/// Load persisted feed state; a missing file is an empty state, an unreadable one is an error (fail closed).
pub fn load_state(path: &Path) -> std::io::Result<FeedTracker> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let recs: Vec<ObservationRecord> =
                serde_json::from_str(&text).map_err(std::io::Error::other)?;
            Ok(FeedTracker::restore(
                recs.into_iter().map(Observation::from),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FeedTracker::default()),
        Err(e) => Err(e),
    }
}

/// Atomically replace the state file: write a 0600 temp file, fsync, rename, fsync the directory.
pub fn save_state(path: &Path, tracker: &FeedTracker) -> std::io::Result<()> {
    use std::io::Write;
    let recs: Vec<ObservationRecord> = tracker.all().map(|o| (*o).into()).collect();
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(
            serde_json::to_string(&recs)
                .map_err(std::io::Error::other)?
                .as_bytes(),
        )?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

pub struct SignerCore {
    key: SigningKey,
    acct: AccountId,
    policy: RiskPolicy,
    rate: RateLimiter,
    cancel_rate: RateLimiter,
    next_nonce: u64,
    feed: FeedSet,
    tracker: FeedTracker,
    state: Option<PathBuf>,
}

impl SignerCore {
    pub fn new(
        key: SigningKey,
        acct: AccountId,
        policy: RiskPolicy,
        feed: FeedSet,
        start_nonce: u64,
        now_ms: u64,
    ) -> Self {
        let rate = RateLimiter::new(policy.max_orders_per_sec, now_ms);
        let cancel_rate = RateLimiter::new(policy.max_orders_per_sec, now_ms);
        SignerCore {
            key,
            acct,
            policy,
            rate,
            cancel_rate,
            next_nonce: start_nonce,
            feed,
            tracker: FeedTracker::default(),
            state: None,
        }
    }

    /// Start from restored feed state (`load_state`) and persist every accepted observation to `path` before it
    /// can be used.
    pub fn with_state(mut self, tracker: FeedTracker, path: PathBuf) -> Self {
        self.tracker = tracker;
        self.state = Some(path);
        self
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Feed channel: verify an attestation (quorum, freshness, no slot regression, no same-slot conflict), persist,
    /// then make it the market's reference.
    pub fn ingest(&mut self, bytes: &[u8], now_ms: u64) -> FeedResponse {
        let att = match Attestation::from_bytes(bytes) {
            Ok(a) => a,
            Err(e) => return feed_err(&format!("malformed attestation: {e:?}")),
        };
        let mut next = self.tracker.clone();
        let obs = match next.accept(&self.feed, &att, att.obs.market, now_ms) {
            Ok(o) => o,
            Err(e) => return feed_err(&describe_feed(&e)),
        };
        if next.latest(obs.market) != self.tracker.latest(obs.market) {
            if let Some(p) = &self.state {
                if let Err(e) = save_state(p, &next) {
                    return feed_err(&format!("state not persisted: {e}"));
                }
            }
            self.tracker = next;
        }
        FeedResponse::Ok {
            market: obs.market,
            slot: obs.slot,
            price: obs.price,
        }
    }

    pub fn sign(&mut self, r: &SignRequest, now_ms: u64) -> SignResponse {
        let side = match r.side.as_str() {
            "bid" => Side::Bid,
            "ask" => Side::Ask,
            _ => return err("side must be bid|ask"),
        };
        let tif = match r.tif.as_str() {
            "gtc" => Tif::Gtc,
            "ioc" => Tif::Ioc,
            "fok" => Tif::Fok,
            "post_only" => Tif::PostOnly,
            _ => return err("tif must be gtc|ioc|fok|post_only"),
        };
        if r.price == 0 || r.qty == 0 {
            return err("zero price or qty");
        }
        let Some(obs) = self.tracker.latest(r.market) else {
            return err("no feed price for this market");
        };
        let age = now_ms.saturating_sub(obs.time_ms);
        if age > self.feed.max_age_ms {
            return err(&format!(
                "feed stale: newest price is {age} ms old (max {} ms)",
                self.feed.max_age_ms
            ));
        }
        let intent = Intent {
            market: r.market,
            acct: self.acct,
            side,
            price: r.price,
            qty: r.qty,
            tif,
            nonce: self.next_nonce,
            expiry_slot: r.expiry_slot,
        };
        if let Err(e) = self.policy.check(&intent, obs.price, obs.slot) {
            return err(&describe(&e));
        }
        if !self.rate.try_take(now_ms) {
            return err("rate limit");
        }
        let o = SignedOrder::sign(intent, &self.key);
        self.next_nonce += 1;
        SignResponse::Ok {
            entry_hex: hex::encode(Entry::Order(o).to_bytes()),
            nonce: intent.nonce,
        }
    }

    /// Sign a cancel of one of this account's orders. Allowed while the feed is stale (it only reduces risk); it
    /// needs one feed observation for the market to know the slot. Has its own rate bucket, so an order flood
    /// cannot lock the agent out of cancelling.
    pub fn cancel(&mut self, r: &CancelRequest, now_ms: u64) -> SignResponse {
        if !self.policy.markets.contains(&r.market) {
            return err(&format!("market {} not allowed", r.market));
        }
        if r.order_id == 0 {
            return err("order_id must be non-zero");
        }
        let Some(obs) = self.tracker.latest(r.market) else {
            return err("no feed slot known for this market");
        };
        if !self.cancel_rate.try_take(now_ms) {
            return err("rate limit");
        }
        let action = Action {
            market: r.market,
            acct: self.acct,
            nonce: self.next_nonce,
            expiry_slot: obs.slot + self.policy.max_expiry_slots,
            kind: ActionKind::Cancel {
                order_id: r.order_id,
            },
        };
        let a = SignedAction::sign(action, &self.key);
        self.next_nonce += 1;
        SignResponse::Ok {
            entry_hex: hex::encode(Entry::Action(a).to_bytes()),
            nonce: action.nonce,
        }
    }

    pub fn handle(&mut self, r: &Request, now_ms: u64) -> SignResponse {
        match r {
            Request::Order(o) => self.sign(o, now_ms),
            Request::Cancel(c) => self.cancel(c, now_ms),
        }
    }
}

fn err(s: &str) -> SignResponse {
    SignResponse::Err {
        reason: s.to_string(),
    }
}

fn feed_err(s: &str) -> FeedResponse {
    FeedResponse::Err {
        reason: s.to_string(),
    }
}

fn describe_feed(e: &FeedError) -> String {
    match e {
        FeedError::Stale { age_ms, max_ms } => format!("stale: {age_ms} ms old (max {max_ms})"),
        FeedError::SlotRegressed { slot, last } => {
            format!("slot {slot} is older than accepted slot {last}")
        }
        FeedError::Conflict { slot } => format!("conflicting observation for slot {slot}"),
        e => format!("{e:?}"),
    }
}

fn describe(e: &RiskReject) -> String {
    match e {
        RiskReject::Market(m) => format!("market {m} not allowed"),
        RiskReject::Qty { qty, max } => format!("qty {qty} > max {max}"),
        RiskReject::Notional { notional, max } => format!("notional {notional} > max {max}"),
        RiskReject::PriceBand {
            price,
            reference,
            band_bps,
        } => format!("price {price} outside {band_bps} bps of {reference}"),
        RiskReject::Expiry {
            expiry,
            now,
            max_life,
        } => format!("expiry {expiry} invalid at slot {now} (max life {max_life})"),
        RiskReject::Rate => "rate limit".into(),
        RiskReject::NoReference => "no reference price".into(),
    }
}

/// Clients: one JSON line per request (agents) or one hex attestation per line (feed relays) over Unix sockets.
#[cfg(unix)]
pub mod client {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    pub struct SignerClient {
        w: UnixStream,
        r: BufReader<UnixStream>,
    }

    impl SignerClient {
        pub fn connect(path: &std::path::Path) -> std::io::Result<Self> {
            let s = UnixStream::connect(path)?;
            Ok(SignerClient {
                r: BufReader::new(s.try_clone()?),
                w: s,
            })
        }
        fn roundtrip(&mut self, mut line: String) -> std::io::Result<String> {
            line.push('\n');
            self.w.write_all(line.as_bytes())?;
            let mut resp = String::new();
            self.r.read_line(&mut resp)?;
            Ok(resp)
        }
        pub fn sign(&mut self, req: &SignRequest) -> std::io::Result<SignResponse> {
            let line = serde_json::to_string(req).map_err(std::io::Error::other)?;
            serde_json::from_str(&self.roundtrip(line)?).map_err(std::io::Error::other)
        }
        pub fn cancel(&mut self, market: u32, order_id: u64) -> std::io::Result<SignResponse> {
            let line =
                serde_json::json!({"cancel": {"market": market, "order_id": order_id}}).to_string();
            serde_json::from_str(&self.roundtrip(line)?).map_err(std::io::Error::other)
        }
        /// Push an attestation on the feed socket.
        pub fn push(&mut self, attestation: &[u8]) -> std::io::Result<FeedResponse> {
            serde_json::from_str(&self.roundtrip(hex::encode(attestation))?)
                .map_err(std::io::Error::other)
        }
    }
}
