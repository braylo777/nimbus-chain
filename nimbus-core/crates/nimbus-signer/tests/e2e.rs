//! End-to-end: feed relay → signer (feed socket); agent request → signer (agent socket) → engine admission → matching.
use ed25519_dalek::{SigningKey, VerifyingKey};
use nimbus_feed::{Attestation, Observation};
use nimbus_match::{Market, Op, Outcome};
use nimbus_order::{verify_entries, Admission, Effect, Entry, SignedOrder};
use nimbus_sdk::RiskPolicy;
use nimbus_signer::{client::SignerClient, FeedResponse, SignRequest, SignResponse};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_nimbus-signer");

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nimbus-signer-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn feed_keys() -> Vec<SigningKey> {
    (0..5u8)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect()
}

/// A fresh attestation from 3 of the 5 feed keys.
fn att_at(market: u32, price: u64, slot: u64, time_ms: u64) -> Vec<u8> {
    let o = Observation {
        market,
        price,
        slot,
        time_ms,
    };
    Attestation::sign(o, &feed_keys(), &[0, 2, 4]).to_bytes()
}
fn att(market: u32, price: u64, slot: u64) -> Vec<u8> {
    att_at(market, price, slot, now_ms())
}

fn policy(rate: u32) -> RiskPolicy {
    RiskPolicy {
        markets: vec![1],
        max_qty: 50,
        max_notional: 100_000,
        price_band_bps: 300,
        max_orders_per_sec: rate,
        max_expiry_slots: 50,
    }
}

fn write_configs(dir: &Path, rate: u32, max_age_ms: u64) -> (PathBuf, PathBuf) {
    let pol = dir.join("policy.json");
    std::fs::write(&pol, serde_json::to_string(&policy(rate)).unwrap()).unwrap();
    let feed = dir.join("feed.json");
    let keys: Vec<String> = feed_keys()
        .iter()
        .map(|k| hex::encode(k.verifying_key().to_bytes()))
        .collect();
    std::fs::write(
        &feed,
        serde_json::json!({"keys": keys, "threshold": 3, "max_age_ms": max_age_ms, "max_skew_ms": 200})
            .to_string(),
    )
    .unwrap();
    (pol, feed)
}

struct Signer {
    child: Child,
    agents: PathBuf,
    feed: PathBuf,
    pk: VerifyingKey,
}

impl Drop for Signer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Signer {
    fn client(&self) -> SignerClient {
        SignerClient::connect(&self.agents).unwrap()
    }
    fn push(&self, a: &[u8]) -> FeedResponse {
        SignerClient::connect(&self.feed).unwrap().push(a).unwrap()
    }
}

fn start_with(dir: &Path, rate: u32, max_age_ms: u64) -> Signer {
    let key = dir.join("agent.key");
    if !key.exists() {
        Command::new(BIN)
            .args(["--gen-key", key.to_str().unwrap()])
            .output()
            .unwrap();
    }
    let sk: [u8; 32] = hex::decode(std::fs::read_to_string(&key).unwrap().trim())
        .unwrap()
        .try_into()
        .unwrap();
    let (pol, feed) = write_configs(dir, rate, max_age_ms);
    let (agents, feed_sock) = (dir.join("agent.sock"), dir.join("feed.sock"));
    let _ = std::fs::remove_file(&agents);
    let _ = std::fs::remove_file(&feed_sock);
    let child = Command::new(BIN)
        .args([
            "--key",
            key.to_str().unwrap(),
            "--acct",
            "7",
            "--policy",
            pol.to_str().unwrap(),
            "--feed",
            feed.to_str().unwrap(),
            "--socket",
            agents.to_str().unwrap(),
            "--feed-socket",
            feed_sock.to_str().unwrap(),
            "--state",
            dir.join("feed-state.json").to_str().unwrap(),
        ])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t = Instant::now();
    while !(agents.exists() && feed_sock.exists()) && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    Signer {
        child,
        agents,
        feed: feed_sock,
        pk: SigningKey::from_bytes(&sk).verifying_key(),
    }
}

fn start(dir: &Path, rate: u32) -> Signer {
    start_with(dir, rate, 2_000)
}

fn order_of(entry_hex: &str) -> SignedOrder {
    match Entry::from_bytes(&hex::decode(entry_hex).unwrap()).unwrap() {
        Entry::Order(o) => o,
        e => panic!("expected an order, got {e:?}"),
    }
}

fn ok(r: &FeedResponse) -> bool {
    matches!(r, FeedResponse::Ok { .. })
}

fn request(market: u32, price: u64, qty: u64, expiry: u64) -> SignRequest {
    SignRequest {
        market,
        side: "bid".into(),
        price,
        qty,
        tif: "gtc".into(),
        expiry_slot: expiry,
    }
}

/// One in three requests violates the policy in some way. The feed puts market 1 at 1000, slot 5.
fn req(i: u64) -> SignRequest {
    let (market, price, qty, expiry) = match i % 6 {
        0 => (2, 1000, 10, 20), // forbidden market (and no feed for it)
        1 => (1, 1000, 80, 20), // qty > 50
        2 => (1, 1040, 10, 20), // outside 300 bps of 1000
        _ => (1, 990 + i % 20, 1 + i % 40, 10 + i % 30),
    };
    SignRequest {
        market,
        side: if i.is_multiple_of(2) {
            "bid".into()
        } else {
            "ask".into()
        },
        price,
        qty,
        tif: if i.is_multiple_of(5) {
            "ioc".into()
        } else {
            "gtc".into()
        },
        expiry_slot: expiry,
    }
}

#[test]
fn agent_signer_engine_end_to_end() {
    let dir = tmpdir("e2e");
    let s = start(&dir, 1_000_000);
    assert!(ok(&s.push(&att(1, 1000, 5))));
    let mut c = s.client();
    let p = policy(1_000_000);
    let mut adm = Admission::new();
    adm.register(7, s.pk).unwrap();
    adm.set_max_life(p.max_expiry_slots);
    let mut mkt = Market::new();
    mkt.apply(&Op::Deposit {
        acct: 7,
        base: 1_000_000,
        quote: 1_000_000_000,
    });
    let (mut signed, mut refused, mut placed) = (0u64, 0u64, 0u64);
    let mut orders = Vec::new();
    for i in 0..2000u64 {
        match c.sign(&req(i)).unwrap() {
            SignResponse::Ok { entry_hex, nonce } => {
                let o = order_of(&entry_hex);
                assert!(o.signature_valid());
                assert_eq!(o.intent.nonce, nonce);
                assert_eq!(o.intent.nonce, signed, "nonces must be contiguous from 0");
                assert_eq!(o.intent.acct, 7, "signer must bind the account");
                assert!(
                    p.check(&o.intent, 1000, 5).is_ok(),
                    "signed an out-of-policy order: {:?}",
                    o.intent
                );
                let op = adm
                    .admit(&o, 5)
                    .expect("engine must admit every signed order");
                if let Outcome::Placed { .. } = mkt.apply(&op) {
                    placed += 1;
                }
                orders.push(o);
                signed += 1;
            }
            SignResponse::Err { .. } => refused += 1,
        }
    }
    assert_eq!(refused, (0..2000u64).filter(|i| i % 6 < 3).count() as u64);
    assert_eq!(signed + refused, 2000);
    for o in &orders {
        assert!(adm.admit(o, 5).is_err(), "replay admitted");
    }
    mkt.check_invariants().unwrap();
    println!("signed {signed}, refused {refused}, placed {placed}; all {signed} replays rejected");
}

#[test]
fn signer_uses_only_the_newest_feed_price() {
    let dir = tmpdir("feed");
    let s = start(&dir, 1000);
    let mut c = s.client();
    let refused = |r: SignResponse| matches!(r, SignResponse::Err { .. });
    // No feed yet: nothing is signed.
    assert!(refused(c.sign(&request(1, 1000, 5, 30)).unwrap()));
    // The feed says the market is at 1100: a bid at 1000 is outside the 300 bps band, whatever the agent believes.
    assert!(ok(&s.push(&att(1, 1100, 10))));
    assert!(refused(c.sign(&request(1, 1000, 5, 30)).unwrap()));
    assert!(ok(&s.push(&att(1, 1000, 11))));
    assert!(matches!(
        c.sign(&request(1, 1000, 5, 30)).unwrap(),
        SignResponse::Ok { .. }
    ));
    // Nothing the feed socket refuses changes the reference: stale, forged, below-quorum, older-slot and
    // same-slot-different-price attestations.
    let stale = att_at(1, 1100, 12, now_ms() - 10_000);
    let rogue: Vec<SigningKey> = (0..5u8)
        .map(|i| SigningKey::from_bytes(&[i + 100; 32]))
        .collect();
    let obs = Observation {
        market: 1,
        price: 1100,
        slot: 12,
        time_ms: now_ms(),
    };
    for bad in [
        stale,
        Attestation::sign(obs, &rogue, &[0, 1, 2]).to_bytes(),
        Attestation::sign(obs, &feed_keys(), &[0, 1]).to_bytes(),
        att(1, 1100, 9),
        att(1, 1100, 11),
        b"not an attestation".to_vec(),
    ] {
        assert!(!ok(&s.push(&bad)), "feed accepted a bad attestation");
    }
    assert!(matches!(
        c.sign(&request(1, 1000, 5, 30)).unwrap(),
        SignResponse::Ok { .. }
    ));
    // Lifetime is measured from the feed's slot: expiry 70 at slot 11 exceeds max_expiry_slots = 50.
    assert!(refused(c.sign(&request(1, 1000, 5, 70)).unwrap()));
}

#[test]
fn agent_supplied_price_data_is_refused() {
    let dir = tmpdir("agentprice");
    let s = start(&dir, 1000);
    assert!(ok(&s.push(&att(1, 1000, 5))));
    let mut st = UnixStream::connect(&s.agents).unwrap();
    let mut r = BufReader::new(st.try_clone().unwrap());
    // v0.3 clients attached an attestation; v0.4 refuses any extra field rather than silently ignoring it.
    let line = format!(
        "{{\"market\":1,\"side\":\"bid\",\"price\":1000,\"qty\":1,\"tif\":\"gtc\",\"expiry_slot\":9,\"attestation_hex\":\"{}\"}}\n",
        hex::encode(att(1, 1000, 6))
    );
    st.write_all(line.as_bytes()).unwrap();
    let mut resp = String::new();
    r.read_line(&mut resp).unwrap();
    assert!(resp.contains("unknown field"), "got {resp}");
}

#[test]
fn signing_stops_when_the_feed_goes_stale() {
    let dir = tmpdir("stale");
    let s = start_with(&dir, 1000, 300);
    let mut c = s.client();
    assert!(ok(&s.push(&att(1, 1000, 5))));
    assert!(matches!(
        c.sign(&request(1, 1000, 5, 30)).unwrap(),
        SignResponse::Ok { .. }
    ));
    std::thread::sleep(Duration::from_millis(450));
    match c.sign(&request(1, 1000, 5, 30)).unwrap() {
        SignResponse::Err { reason } => assert!(reason.contains("stale"), "{reason}"),
        r => panic!("signed on a stale feed: {r:?}"),
    }
    assert!(ok(&s.push(&att(1, 1000, 6))));
    assert!(matches!(
        c.sign(&request(1, 1000, 5, 30)).unwrap(),
        SignResponse::Ok { .. }
    ));
}

#[test]
fn feed_state_survives_restart() {
    let dir = tmpdir("restart");
    let s = start(&dir, 1000);
    let first = att(1, 1000, 20);
    assert!(ok(&s.push(&first)));
    drop(s);
    let s = start(&dir, 1000);
    // A fresh-looking attestation for an older slot is refused after the restart (v0.3 accepted it once).
    match s.push(&att(1, 950, 15)) {
        FeedResponse::Err { reason } => assert!(reason.contains("older"), "{reason}"),
        r => panic!("older slot accepted after restart: {r:?}"),
    }
    assert!(!ok(&s.push(&att(1, 950, 20))), "same slot, different price");
    assert!(ok(&s.push(&first)), "identical re-push is harmless");
    assert!(
        !ok(&s.push(&att(1, 1000, 20))),
        "same slot, new timestamp: a different observation"
    );
    assert!(ok(&s.push(&att(1, 1001, 21))));
    let mode = std::fs::metadata(dir.join("feed-state.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "state file must be private");
    // A corrupted state file stops the signer from starting (fail closed).
    drop(s);
    std::fs::write(dir.join("feed-state.json"), "{garbage").unwrap();
    let (pol, feed) = write_configs(&dir, 10, 2_000);
    let out = Command::new(BIN)
        .args([
            "--key",
            dir.join("agent.key").to_str().unwrap(),
            "--acct",
            "7",
            "--policy",
            pol.to_str().unwrap(),
            "--feed",
            feed.to_str().unwrap(),
            "--socket",
            dir.join("a2").to_str().unwrap(),
            "--feed-socket",
            dir.join("f2").to_str().unwrap(),
            "--state",
            dir.join("feed-state.json").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("state file"));
}

#[test]
fn rate_limit_is_enforced_by_the_signer() {
    let dir = tmpdir("rate");
    let s = start(&dir, 20);
    assert!(ok(&s.push(&att(1, 1000, 5))));
    let mut c = s.client();
    let ok = (0..100u64)
        .filter(|i| {
            matches!(
                c.sign(&request(1, 1000, 1 + i % 3, 20)).unwrap(),
                SignResponse::Ok { .. }
            )
        })
        .count();
    assert!(
        (20..=22).contains(&ok),
        "burst of 100 requests should yield ~20 signatures, got {ok}"
    );
}

#[test]
fn loose_key_permissions_and_weak_feed_keys_are_refused() {
    let dir = tmpdir("perm");
    let key = dir.join("k");
    Command::new(BIN)
        .args(["--gen-key", key.to_str().unwrap()])
        .output()
        .unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (pol, feed) = write_configs(&dir, 10, 2_000);
    let run = |key: &Path, feed: &Path| {
        Command::new(BIN)
            .args([
                "--key",
                key.to_str().unwrap(),
                "--acct",
                "1",
                "--policy",
                pol.to_str().unwrap(),
                "--feed",
                feed.to_str().unwrap(),
                "--socket",
                dir.join("s").to_str().unwrap(),
                "--feed-socket",
                dir.join("f").to_str().unwrap(),
                "--state",
                dir.join("st").to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let out = run(&key, &feed);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("chmod 600"));
    // A small-order feed key would let anyone forge that operator's signature.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut id = [0u8; 32];
    id[0] = 1;
    let mut keys: Vec<String> = feed_keys()
        .iter()
        .map(|k| hex::encode(k.verifying_key().to_bytes()))
        .collect();
    keys[2] = hex::encode(id);
    let weak = dir.join("weak-feed.json");
    std::fs::write(
        &weak,
        serde_json::json!({"keys": keys, "threshold": 3, "max_age_ms": 2000, "max_skew_ms": 200})
            .to_string(),
    )
    .unwrap();
    let out = run(&key, &weak);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("WeakKey"));
}

#[test]
fn malformed_input_gets_errors_not_crashes() {
    let dir = tmpdir("bad");
    let s = start(&dir, 1000);
    assert!(ok(&s.push(&att(1, 1000, 5))));
    let mut st = UnixStream::connect(&s.agents).unwrap();
    let mut r = BufReader::new(st.try_clone().unwrap());
    let junk = [
        "{}",
        "not json",
        "{\"market\":1}",
        "{\"market\":1,\"side\":\"sell\",\"price\":1,\"qty\":1,\"tif\":\"gtc\",\"expiry_slot\":9}",
        "{\"market\":1,\"side\":\"bid\",\"price\":0,\"qty\":1,\"tif\":\"gtc\",\"expiry_slot\":9}",
    ];
    for j in junk {
        st.write_all(format!("{j}\n").as_bytes()).unwrap();
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert!(
            line.contains("\"err\""),
            "expected error for {j:?}, got {line}"
        );
    }
    let mut f = UnixStream::connect(&s.feed).unwrap();
    let mut fr = BufReader::new(f.try_clone().unwrap());
    for j in ["zz", "", "00", &"ab".repeat(3000)] {
        f.write_all(format!("{j}\n").as_bytes()).unwrap();
        let mut line = String::new();
        fr.read_line(&mut line).unwrap();
        assert!(line.contains("\"err\""), "feed accepted {j:?}: {line}");
    }
    let mut c = s.client();
    assert!(
        matches!(c.sign(&req(3)).unwrap(), SignResponse::Ok { .. }),
        "signer still serves after bad input"
    );
}

#[test]
fn idle_clients_do_not_block_and_oversized_lines_are_refused() {
    let dir = tmpdir("dos");
    let s = start(&dir, 1000);
    let _idle_agent = UnixStream::connect(&s.agents).unwrap(); // connects and never sends
    let _idle_feed = UnixStream::connect(&s.feed).unwrap();
    let t = Instant::now();
    assert!(ok(&s.push(&att(1, 1000, 5))));
    let mut c = s.client();
    assert!(matches!(c.sign(&req(3)).unwrap(), SignResponse::Ok { .. }));
    assert!(
        t.elapsed() < Duration::from_secs(2),
        "idle client blocked the signer"
    );
    for (sock, size) in [(&s.agents, 10_000), (&s.feed, 40_000)] {
        let mut st = UnixStream::connect(sock).unwrap();
        let mut r = BufReader::new(st.try_clone().unwrap());
        let _ = st.write_all(&vec![b'a'; size]); // the signer may close mid-write
        st.write_all(b"\n").ok();
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert!(line.contains("too long"), "got {line}");
    }
    assert!(
        matches!(c.sign(&req(4)).unwrap(), SignResponse::Ok { .. }),
        "signer still serves"
    );
}

#[test]
fn agents_can_cancel_their_orders_even_on_a_stale_feed_but_never_withdraw() {
    let dir = tmpdir("cancel");
    let s = start_with(&dir, 1000, 300);
    assert!(ok(&s.push(&att(1, 1000, 5))));
    let mut c = s.client();
    let mut adm = Admission::new();
    adm.register(7, s.pk).unwrap();
    adm.set_max_life(50);
    let mut mkt = Market::new();
    mkt.apply(&Op::Deposit {
        acct: 7,
        base: 0,
        quote: 1_000_000,
    });
    // Place a resting bid through the signer and the engine.
    let SignResponse::Ok { entry_hex, .. } = c.sign(&request(1, 1000, 5, 30)).unwrap() else {
        panic!()
    };
    let op = adm.admit(&order_of(&entry_hex), 5).unwrap();
    let Outcome::Placed { id, resting: 5, .. } = mkt.apply(&op) else {
        panic!()
    };
    assert_eq!(mkt.balance(7).quote_locked, 5_000);
    // The feed goes stale: new orders are refused, but a cancel is still signed.
    std::thread::sleep(Duration::from_millis(450));
    assert!(matches!(
        c.sign(&request(1, 1000, 5, 30)).unwrap(),
        SignResponse::Err { .. }
    ));
    let SignResponse::Ok { entry_hex, nonce } = c.cancel(1, id).unwrap() else {
        panic!("cancel refused")
    };
    assert_eq!(nonce, 1, "cancels share the order nonce sequence");
    let e = Entry::from_bytes(&hex::decode(entry_hex).unwrap()).unwrap();
    let Entry::Action(a) = &e else { panic!() };
    assert_eq!(
        a.action.expiry_slot,
        5 + 50,
        "expiry = newest feed slot + max lifetime"
    );
    let v = verify_entries(vec![e], |e| adm.items_for(e))
        .pop()
        .unwrap()
        .unwrap();
    let Effect::Market { op, .. } = adm.admit_verified(&v, 6).unwrap() else {
        panic!()
    };
    assert_eq!(mkt.apply(&op), Outcome::Cancelled { id, released: 5 });
    assert_eq!(mkt.balance(7).quote_locked, 0);
    // Other markets, zero ids, and anything that is not an order or a cancel are refused.
    assert!(matches!(c.cancel(2, id).unwrap(), SignResponse::Err { .. }));
    assert!(matches!(c.cancel(1, 0).unwrap(), SignResponse::Err { .. }));
    let mut st = UnixStream::connect(&s.agents).unwrap();
    let mut r = BufReader::new(st.try_clone().unwrap());
    for line in [
        "{\"withdraw\":{\"market\":1,\"base\":0,\"quote\":100}}",
        "{\"cancel\":{\"market\":1,\"order_id\":3,\"expiry_slot\":999}}",
        "{\"cancel\":{\"market\":1,\"order_id\":3},\"extra\":1}",
    ] {
        st.write_all(format!("{line}\n").as_bytes()).unwrap();
        let mut resp = String::new();
        r.read_line(&mut resp).unwrap();
        assert!(resp.contains("\"err\""), "{line} → {resp}");
    }
}
