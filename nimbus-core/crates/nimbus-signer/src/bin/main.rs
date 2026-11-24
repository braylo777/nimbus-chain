//! nimbus-signer --key KEYFILE --acct N --policy POLICY.json --feed FEED.json --socket PATH --feed-socket PATH
//!               --state STATE.json [--start-nonce N]
//! nimbus-signer --gen-key KEYFILE
//!
//! Two Unix sockets (mode 0600), one thread per connection, bounded lines:
//! * `--socket`: agents send one JSON order or cancel request per line (≤ 4 KiB) and get a signed entry or a refusal;
//! * `--feed-socket`: the feed relay sends one hex attestation per line (≤ 16 KiB).
//!
//! Refuses key files readable by group/others. FEED.json:
//! `{"keys": [hex, ...], "threshold": k, "max_age_ms": 2000, "max_skew_ms": 200}`
use ed25519_dalek::{SigningKey, VerifyingKey};
use nimbus_feed::FeedSet;
use nimbus_sdk::RiskPolicy;
use nimbus_signer::{load_state, parse_request, FeedResponse, SignResponse, SignerCore};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_REQUEST: u64 = 4096;
const MAX_ATTESTATION: u64 = 16 * 1024;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn die(msg: &str) -> ! {
    eprintln!("nimbus-signer: {msg}");
    std::process::exit(2)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

#[derive(serde::Deserialize)]
struct FeedConfig {
    keys: Vec<String>,
    threshold: usize,
    max_age_ms: u64,
    max_skew_ms: u64,
}

fn load_feed(path: &str) -> FeedSet {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("feed: {e}")));
    let cfg: FeedConfig =
        serde_json::from_str(&text).unwrap_or_else(|e| die(&format!("feed: {e}")));
    let keys: Vec<VerifyingKey> = cfg
        .keys
        .iter()
        .map(|h| {
            let b: [u8; 32] = hex::decode(h)
                .ok()
                .and_then(|v| v.try_into().ok())
                .unwrap_or_else(|| die("feed key must be 32 hex bytes"));
            VerifyingKey::from_bytes(&b).unwrap_or_else(|_| die("invalid feed key"))
        })
        .collect();
    let n = keys.len();
    let set = FeedSet::new(keys, cfg.threshold, cfg.max_age_ms, cfg.max_skew_ms)
        .unwrap_or_else(|e| die(&format!("feed config rejected: {e:?}")));
    if cfg.threshold * 2 <= n {
        eprintln!("nimbus-signer: warning: feed threshold is not a majority of feed keys");
    }
    set
}

fn listen(path: &str) -> UnixListener {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| die(&e.to_string()));
    l
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(path) = arg(&args, "--gen-key") {
        let k = SigningKey::generate(&mut rand::rngs::OsRng);
        std::fs::write(&path, hex::encode(k.to_bytes())).unwrap_or_else(|e| die(&e.to_string()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| die(&e.to_string()));
        println!("{}", hex::encode(k.verifying_key().to_bytes()));
        return;
    }
    let key_path = arg(&args, "--key").unwrap_or_else(|| die("--key required"));
    let meta = std::fs::metadata(&key_path).unwrap_or_else(|e| die(&format!("key file: {e}")));
    if meta.permissions().mode() & 0o077 != 0 {
        die("key file must not be accessible by group/others (chmod 600)");
    }
    let raw = std::fs::read_to_string(&key_path).unwrap_or_else(|e| die(&e.to_string()));
    let bytes: [u8; 32] = hex::decode(raw.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(|| die("key must be 32 hex bytes"));
    let acct: u32 = arg(&args, "--acct")
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| die("--acct N required"));
    let policy_path = arg(&args, "--policy").unwrap_or_else(|| die("--policy required"));
    let policy: RiskPolicy = serde_json::from_str(
        &std::fs::read_to_string(policy_path).unwrap_or_else(|e| die(&e.to_string())),
    )
    .unwrap_or_else(|e| die(&format!("policy: {e}")));
    let feed = load_feed(&arg(&args, "--feed").unwrap_or_else(|| die("--feed required")));
    let start: u64 = arg(&args, "--start-nonce")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let state = PathBuf::from(arg(&args, "--state").unwrap_or_else(|| die("--state required")));
    let tracker =
        load_state(&state).unwrap_or_else(|e| die(&format!("state file {}: {e}", state.display())));
    let sock = arg(&args, "--socket").unwrap_or_else(|| die("--socket required"));
    let feed_sock = arg(&args, "--feed-socket").unwrap_or_else(|| die("--feed-socket required"));
    let agents = listen(&sock);
    let relays = listen(&feed_sock);
    let core = SignerCore::new(
        SigningKey::from_bytes(&bytes),
        acct,
        policy,
        feed,
        start,
        now_ms(),
    )
    .with_state(tracker, state);
    eprintln!(
        "nimbus-signer: account {acct}, key {}…, agents on {sock}, feed on {feed_sock}",
        &hex::encode(core.public_key())[..16]
    );
    // One thread per connection so an idle or slow client cannot block others; the core sits behind a mutex, so
    // nonce assignment, feed tracking and rate limiting stay strictly serialised.
    let core = Arc::new(Mutex::new(core));
    {
        let core = Arc::clone(&core);
        std::thread::spawn(move || {
            for conn in relays.incoming() {
                let Ok(stream) = conn else { continue };
                let core = Arc::clone(&core);
                std::thread::spawn(move || serve(stream, MAX_ATTESTATION, |l| feed_line(&core, l)));
            }
        });
    }
    for conn in agents.incoming() {
        let Ok(stream) = conn else { continue };
        let core = Arc::clone(&core);
        std::thread::spawn(move || serve(stream, MAX_REQUEST, |l| sign_line(&core, l)));
    }
}

fn sign_line(core: &Mutex<SignerCore>, line: &str) -> String {
    let resp = match parse_request(line) {
        Ok(req) => match core.lock() {
            Ok(mut c) => c.handle(&req, now_ms()),
            Err(_) => SignResponse::Err {
                reason: "signer unavailable".into(),
            },
        },
        Err(reason) => SignResponse::Err { reason },
    };
    serde_json::to_string(&resp).unwrap_or_else(|_| "{\"err\":{\"reason\":\"encode\"}}".into())
}

fn feed_line(core: &Mutex<SignerCore>, line: &str) -> String {
    let resp = match hex::decode(line) {
        Ok(bytes) => match core.lock() {
            Ok(mut c) => c.ingest(&bytes, now_ms()),
            Err(_) => FeedResponse::Err {
                reason: "signer unavailable".into(),
            },
        },
        Err(_) => FeedResponse::Err {
            reason: "attestation must be hex".into(),
        },
    };
    serde_json::to_string(&resp).unwrap_or_else(|_| "{\"err\":{\"reason\":\"encode\"}}".into())
}

fn serve(stream: UnixStream, max_line: u64, handle: impl Fn(&str) -> String) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(300)));
    let Ok(mut w) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        // Bounded read: a client cannot exhaust memory with an endless line.
        match (&mut reader).take(max_line).read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if !line.ends_with('\n') {
            let _ = w.write_all(b"{\"err\":{\"reason\":\"request too long\"}}\n");
            return;
        }
        let mut out = handle(line.trim_end());
        out.push('\n');
        if w.write_all(out.as_bytes()).is_err() {
            return;
        }
    }
}
