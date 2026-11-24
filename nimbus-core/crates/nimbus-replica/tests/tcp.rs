//! Replication over loopback TCP: byte-identical replicas with failover, and every forged, altered or silent peer
//! dropped without releasing unreplicated results — each with sleeping per-replica threads and with the polled,
//! spinning I/O path (`attach_polled_windowed`, `serve_one_spinning`).
use ed25519_dalek::SigningKey;
use nimbus_journal::Journal;
use nimbus_match::{Side, Tif};
use nimbus_order::*;
use nimbus_pipeline::*;
use nimbus_replica::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const ACCOUNTS: u32 = 16;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nimbus-tcp-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn key(a: u32) -> SigningKey {
    let mut s = [3u8; 32];
    s[..4].copy_from_slice(&a.to_be_bytes());
    SigningKey::from_bytes(&s)
}
fn operator() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}
fn genesis() -> Genesis {
    Genesis {
        accounts: (0..ACCOUNTS).map(|a| (a, key(a).verifying_key())).collect(),
        deposits: (0..ACCOUNTS).map(|a| (0, a, 1 << 30, 1 << 40)).collect(),
        ..Genesis::default()
    }
}
fn cfg() -> Config {
    Config {
        markets: 1,
        max_life: 1_000,
        fsync: true,
        min_batch: 16,
    }
}
fn traffic(slots: u64, per: u32) -> Vec<Vec<Vec<u8>>> {
    let mut nonce = vec![0u64; ACCOUNTS as usize];
    (1..=slots)
        .map(|slot| {
            (0..per)
                .map(|i| {
                    let a = ((slot as u32) * per + i) % ACCOUNTS;
                    nonce[a as usize] += 1;
                    Entry::Order(SignedOrder::sign(
                        Intent {
                            market: 0,
                            acct: a,
                            side: if i % 2 == 0 { Side::Bid } else { Side::Ask },
                            price: 1_000 + (i as u64 % 3),
                            qty: 1 + (i as u64 % 4),
                            tif: Tif::Gtc,
                            nonce: nonce[a as usize] - 1,
                            expiry_slot: slot + 200,
                        },
                        &key(a),
                    ))
                    .to_bytes()
                })
                .collect()
        })
        .collect()
}
fn replica_key(id: u16) -> SigningKey {
    SigningKey::from_bytes(&[50 + id as u8; 32])
}
/// Server side of link `id` accepting shipments from `accepts`.
fn server_auth(id: u16, accepts: &SigningKey) -> Auth {
    Auth::Signatures {
        mine: replica_key(id),
        theirs: accepts.verifying_key(),
    }
}
/// Engine side of link `id`.
fn engine_auth(id: u16) -> Auth {
    Auth::Signatures {
        mine: operator(),
        theirs: replica_key(id).verifying_key(),
    }
}
/// The server and how its one connection ended.
type Served = JoinHandle<(ReplicaServer, Result<(), String>)>;
/// A replica server on a fresh loopback port, journal at `d/journal.bin`; returns once its one connection ends.
fn spawn_m(polled: bool, d: &Path, id: u16, auth: Auth) -> (String, Served) {
    let j = Journal::open(&d.join("journal.bin"), usize::MAX).unwrap().0;
    let mut s = ReplicaServer::new(j, auth, id).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    (
        addr,
        std::thread::spawn(move || {
            let r = if polled {
                s.serve_one_spinning(&l)
            } else {
                s.serve_one(&l)
            };
            (s, r)
        }),
    )
}
/// Attach replicas at `links` with per-replica threads, or polled by one spinning thread (engine waits spinning).
fn attach(
    e: &mut Pipeline,
    polled: bool,
    links: Vec<(&str, Auth, u16)>,
    need: usize,
    w: WindowConfig,
) -> Result<(), PipelineError> {
    if polled {
        let set = links
            .into_iter()
            .map(|(a, auth, id)| {
                Box::new(
                    TcpReplica::connect(a, auth, id)
                        .unwrap()
                        .into_poll()
                        .unwrap(),
                ) as Box<dyn ReplicaPoll>
            })
            .collect();
        e.attach_polled_windowed(set, need, WindowConfig { spin: true, ..w })
    } else {
        let set = links
            .into_iter()
            .map(|(a, auth, id)| {
                Box::new(TcpReplica::connect(a, auth, id).unwrap()) as Box<dyn ReplicaStream>
            })
            .collect();
        e.attach_streams_windowed(set, need, w)
    }
}
fn window(timeout_ms: u64, max_inflight: usize) -> WindowConfig {
    WindowConfig {
        depth: 8,
        ack_timeout: Duration::from_millis(timeout_ms),
        max_inflight,
        spin: false,
    }
}

#[test]
fn tcp_replicas_hold_the_engine_journal_and_take_over() {
    for mac in [false, true] {
        for polled in [false, true] {
            hold_and_take_over(mac, polled);
        }
    }
}

fn hold_and_take_over(mac: bool, polled: bool) {
    let (de, d0, d1, dp) = (dir("e"), dir("r0"), dir("r1"), dir("plain"));
    let secret = |id: u16| Auth::Mac([40 + id as u8; 32]);
    let sa = |id: u16| {
        if mac {
            secret(id)
        } else {
            server_auth(id, &operator())
        }
    };
    let ea = |id: u16| if mac { secret(id) } else { engine_auth(id) };
    let (a0, h0) = spawn_m(polled, &d0, 0, sa(0));
    let (a1, h1) = spawn_m(polled, &d1, 1, sa(1));
    let (mut e, _) = Pipeline::open(&de, cfg(), &genesis(), operator(), None).unwrap();
    let (mut plain, _) = Pipeline::open(&dp, cfg(), &genesis(), operator(), None).unwrap();
    attach(
        &mut e,
        polled,
        vec![(a0.as_str(), ea(0), 0), (a1.as_str(), ea(1), 1)],
        2,
        window(5_000, 1024),
    )
    .unwrap();
    let t = traffic(30, 16);
    let mut got = Vec::new();
    for (i, subs) in t.iter().enumerate() {
        got.extend(e.submit_slot(i as u64 + 1, subs).unwrap());
    }
    got.extend(e.drain().unwrap());
    assert_eq!(got.len(), 30);
    for (i, r) in got.iter().enumerate() {
        let w = plain.process_slot(i as u64 + 1, &t[i]).unwrap();
        assert_eq!(r.slot, i as u64 + 1);
        assert_eq!(r.checkpoint, w.checkpoint);
    }
    let last = e.latest_checkpoint().unwrap();
    drop(e);
    for h in [h0, h1] {
        let (s, r) = h.join().unwrap();
        r.unwrap();
        drop(s);
    }
    let engine_journal = std::fs::read(de.join("journal.bin")).unwrap();
    for d in [&d0, &d1] {
        assert_eq!(
            std::fs::read(d.join("journal.bin")).unwrap(),
            engine_journal,
            "byte-identical replica"
        );
        let (q, _) = Pipeline::open(d, cfg(), &genesis(), operator(), Some(&last)).unwrap();
        assert_eq!(q.latest_checkpoint(), Some(last), "failover");
    }
    for d in [&de, &d0, &d1, &dp] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn a_shipment_not_signed_by_the_operator_is_refused() {
    for polled in [false, true] {
        a_shipment_not_signed_by_the_operator_is_refused_in(polled);
    }
}

fn a_shipment_not_signed_by_the_operator_is_refused_in(polled: bool) {
    let (de, d0, d1) = (dir("e2"), dir("g"), dir("b"));
    let (a0, h0) = spawn_m(polled, &d0, 0, server_auth(0, &operator()));
    // This replica only accepts shipments from a different operator.
    let (a1, h1) = spawn_m(
        polled,
        &d1,
        1,
        server_auth(1, &SigningKey::from_bytes(&[77; 32])),
    );
    let (mut e, _) = Pipeline::open(&de, cfg(), &genesis(), operator(), None).unwrap();
    attach(
        &mut e,
        polled,
        vec![
            (a0.as_str(), engine_auth(0), 0),
            (a1.as_str(), engine_auth(1), 1),
        ],
        1,
        window(5_000, 1024),
    )
    .unwrap();
    let mut n = 0;
    for (i, subs) in traffic(10, 8).iter().enumerate() {
        n += e.submit_slot(i as u64 + 1, subs).unwrap().len();
    }
    n += e.drain().unwrap().len();
    assert_eq!(n, 10);
    assert_eq!(e.live_replicas(), 1);
    drop(e);
    let (s, r) = h1.join().unwrap();
    assert!(r.unwrap_err().contains("not authenticated by the operator"));
    assert_eq!(s.anchor().len, 0, "the refusing replica stored nothing");
    h0.join().unwrap().1.unwrap();
    // A hello under the wrong replica key is refused at connect.
    let (a2, _h2) = spawn_m(polled, &dir("c"), 2, server_auth(2, &operator()));
    assert!(TcpReplica::connect(
        &a2,
        Auth::Signatures {
            mine: operator(),
            theirs: replica_key(3).verifying_key()
        },
        2
    )
    .is_err());
    for d in [&de, &d0, &d1] {
        let _ = std::fs::remove_dir_all(d);
    }
}

/// Forwards bytes both ways and flips one bit at `flip` bytes into the replica→engine direction.
fn proxy(upstream: String, flip: usize) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (client, _) = l.accept().unwrap();
        let server = TcpStream::connect(upstream).unwrap();
        let (mut c2, mut s2) = (client.try_clone().unwrap(), server.try_clone().unwrap());
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut c2, &mut s2);
        });
        let (mut s, mut c) = (server, client);
        let mut seen = 0usize;
        let mut buf = [0u8; 4096];
        loop {
            let n = match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if (seen..seen + n).contains(&flip) {
                buf[flip - seen] ^= 0x10;
            }
            seen += n;
            if c.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });
    addr
}

#[test]
fn an_altered_acknowledgement_drops_the_replica() {
    for polled in [false, true] {
        an_altered_acknowledgement_drops_the_replica_in(polled);
    }
}

fn an_altered_acknowledgement_drops_the_replica_in(polled: bool) {
    for need in [1usize, 2] {
        let (de, d0, d1) = (dir("e3"), dir("p0"), dir("p1"));
        let (a0, _h0) = spawn_m(polled, &d0, 0, server_auth(0, &operator()));
        let (a1, _h1) = spawn_m(polled, &d1, 1, server_auth(1, &operator()));
        // Hello is 121 bytes; byte 121 + 70 lies inside the first acknowledgement's `to` anchor.
        let via = proxy(a1, 121 + 70);
        let (mut e, _) = Pipeline::open(&de, cfg(), &genesis(), operator(), None).unwrap();
        attach(
            &mut e,
            polled,
            vec![
                (a0.as_str(), engine_auth(0), 0),
                (via.as_str(), engine_auth(1), 1),
            ],
            need,
            window(5_000, 1024),
        )
        .unwrap();
        let mut released = 0;
        let mut err = None;
        for (i, subs) in traffic(10, 8).iter().enumerate() {
            match e.submit_slot(i as u64 + 1, subs) {
                Ok(rs) => released += rs.len(),
                Err(x) => {
                    err = Some(x);
                    break;
                }
            }
        }
        if need == 1 {
            released += e.drain().unwrap().len();
            assert_eq!(released, 10);
            // The altered acknowledgement may arrive after the quorum of one was met: wait for it to be processed.
            let t0 = Instant::now();
            while e.live_replicas() > 1 && t0.elapsed() < Duration::from_secs(2) {
                std::thread::sleep(Duration::from_millis(5));
                assert!(e.drain().unwrap().is_empty());
            }
            assert_eq!(e.live_replicas(), 1);
        } else {
            let err = err.or_else(|| e.drain().err());
            assert!(
                matches!(err, Some(PipelineError::Replication { .. })),
                "{err:?}"
            );
            assert_eq!(released, 0, "nothing released on a forged acknowledgement");
        }
        for d in [&de, &d0, &d1] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// Sends a valid hello, then reads and discards forever.
fn silent(id: u16) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let genesis_anchor = nimbus_journal::Anchor {
            len: 0,
            head: nimbus_journal::genesis_chain(),
        };
        s.write_all(&hello_frame(
            &server_auth(id, &operator()),
            id,
            &genesis_anchor,
        ))
        .unwrap();
        let _ = std::io::copy(&mut s, &mut std::io::sink());
    });
    addr
}

#[test]
fn a_silent_replica_is_dropped_by_timeout_or_in_flight_cap() {
    for polled in [false, true] {
        a_silent_replica_is_dropped_by_timeout_or_in_flight_cap_in(polled);
    }
}

fn a_silent_replica_is_dropped_by_timeout_or_in_flight_cap_in(polled: bool) {
    for (need, timeout_ms, cap) in [(1usize, 100u64, 1024usize), (2, 100, 1024), (1, 60_000, 10)] {
        let (de, d0) = (dir("e4"), dir("s0"));
        let (a0, _h0) = spawn_m(polled, &d0, 0, server_auth(0, &operator()));
        let quiet = silent(1);
        let (mut e, _) = Pipeline::open(&de, cfg(), &genesis(), operator(), None).unwrap();
        attach(
            &mut e,
            polled,
            vec![
                (a0.as_str(), engine_auth(0), 0),
                (quiet.as_str(), engine_auth(1), 1),
            ],
            need,
            window(timeout_ms, cap),
        )
        .unwrap();
        let t0 = Instant::now();
        let mut released = 0;
        let mut err = None;
        for (i, subs) in traffic(20, 4).iter().enumerate() {
            match e.submit_slot(i as u64 + 1, subs) {
                Ok(rs) => released += rs.len(),
                Err(x) => {
                    err = Some(x);
                    break;
                }
            }
        }
        if need == 1 {
            released += e.drain().unwrap().len();
            assert_eq!(
                released, 20,
                "a quorum of one never waits for the silent replica"
            );
            if cap > 20 {
                // The timeout is enforced at the engine's next release.
                std::thread::sleep(Duration::from_millis(timeout_ms + 50));
                assert!(e.drain().unwrap().is_empty());
            }
            assert_eq!(
                e.live_replicas(),
                1,
                "silent replica dropped (need {need}, cap {cap})"
            );
        } else {
            let err = err.or_else(|| e.drain().err());
            assert!(
                matches!(err, Some(PipelineError::Replication { .. })),
                "{err:?}"
            );
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "fails by timeout instead of hanging"
            );
            assert_eq!(released, 0);
        }
        for d in [&de, &d0] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

#[test]
fn a_link_secret_mismatch_is_refused() {
    let polled = false;
    let d = dir("mac");
    let (a, h) = spawn_m(polled, &d, 0, Auth::Mac([1; 32]));
    assert!(
        TcpReplica::connect(&a, Auth::Mac([2; 32]), 0).is_err(),
        "hello under another secret"
    );
    drop(h);
    let (a, h) = spawn_m(polled, &d, 0, Auth::Mac([1; 32]));
    // Right secret, wrong link id: every tag binds the replica index.
    assert!(TcpReplica::connect(&a, Auth::Mac([1; 32]), 1).is_err());
    drop(h);
    let _ = std::fs::remove_dir_all(&d);
}

/// Replays a genuine hello, then acknowledges every shipment with exactly the anchors it names — stores nothing and
/// tags the acknowledgements with a key it does not hold.
fn liar(id: u16) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let g = nimbus_journal::Anchor {
            len: 0,
            head: nimbus_journal::genesis_chain(),
        };
        s.write_all(&hello_frame(&server_auth(id, &operator()), id, &g))
            .unwrap();
        let forger = server_auth(99, &operator());
        loop {
            let mut head = [0u8; 1 + 56 + 56 + 64 + 4];
            if s.read_exact(&mut head).is_err() {
                return;
            }
            let n = u32::from_be_bytes(head[177..181].try_into().unwrap()) as usize;
            let mut body = vec![0u8; n];
            if s.read_exact(&mut body).is_err() {
                return;
            }
            let anchor = |b: &[u8]| nimbus_journal::Anchor {
                len: u64::from_be_bytes(b[..8].try_into().unwrap()),
                head: b[8..56].try_into().unwrap(),
            };
            let (from, to) = (anchor(&head[1..57]), anchor(&head[57..113]));
            // An acknowledgement frame with a tag from the wrong key: reuse hello_frame's tagging on a forged digest.
            let forged = hello_frame(&forger, id, &to);
            let mut f = vec![3u8];
            f.extend_from_slice(&head[1..57]);
            f.extend_from_slice(&head[57..113]);
            f.extend_from_slice(&forged[57..121]);
            let _ = (from, to);
            if s.write_all(&f).is_err() {
                return;
            }
        }
    });
    addr
}

#[test]
fn a_forged_acknowledgement_is_not_counted() {
    for polled in [false, true] {
        a_forged_acknowledgement_is_not_counted_in(polled);
    }
}

fn a_forged_acknowledgement_is_not_counted_in(polled: bool) {
    let (de, d0) = (dir("e5"), dir("l0"));
    let (a0, _h0) = spawn_m(polled, &d0, 0, server_auth(0, &operator()));
    let fake = liar(1);
    let (mut e, _) = Pipeline::open(&de, cfg(), &genesis(), operator(), None).unwrap();
    attach(
        &mut e,
        polled,
        vec![
            (a0.as_str(), engine_auth(0), 0),
            (fake.as_str(), engine_auth(1), 1),
        ],
        2,
        window(5_000, 1024),
    )
    .unwrap();
    let mut released = 0;
    let mut err = None;
    for (i, subs) in traffic(10, 8).iter().enumerate() {
        match e.submit_slot(i as u64 + 1, subs) {
            Ok(rs) => released += rs.len(),
            Err(x) => {
                err = Some(x);
                break;
            }
        }
    }
    let err = err.or_else(|| e.drain().err());
    assert_eq!(
        released, 0,
        "a replica that stores nothing must not complete a quorum"
    );
    assert!(
        matches!(err, Some(PipelineError::Replication { .. })),
        "{err:?}"
    );
    for d in [&de, &d0] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn a_refusing_replica_fails_the_quorum_promptly() {
    for polled in [false, true] {
        let (de, d0, d1) = (dir("e6"), dir("q0"), dir("q1"));
        let (a0, _h0) = spawn_m(polled, &d0, 0, server_auth(0, &operator()));
        let (a1, _h1) = spawn_m(
            polled,
            &d1,
            1,
            server_auth(1, &SigningKey::from_bytes(&[77; 32])),
        );
        let (mut e, _) = Pipeline::open(&de, cfg(), &genesis(), operator(), None).unwrap();
        attach(
            &mut e,
            polled,
            vec![
                (a0.as_str(), engine_auth(0), 0),
                (a1.as_str(), engine_auth(1), 1),
            ],
            2,
            window(30_000, 1024),
        )
        .unwrap();
        let t0 = Instant::now();
        let first = e.submit_slot(1, &traffic(1, 8)[0]);
        let err = first.err().or_else(|| e.drain().err());
        assert!(
            matches!(err, Some(PipelineError::Replication { .. })),
            "{err:?}"
        );
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the refusal is reported, not discovered by the 30 s timeout (polled: {polled})"
        );
        for d in [&de, &d0, &d1] {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}
