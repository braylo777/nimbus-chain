//! Authenticated TCP transport for engine journal replication.
//!
//! A `ReplicaServer` owns a replica's journal and serves one engine connection at a time. Every message is
//! authenticated over a domain-0x11 digest (`nimbus_journal::replication_digest`) — the replica's hello (its current
//! anchor) and each acknowledgement by the replica, each shipment by the operator — either with Ed25519 signatures
//! (`Auth::Signatures`: transferable evidence; four signature operations per batch per hop) or with HMAC-SHA384
//! under a secret shared by the two ends of the link (`Auth::Mac`: microseconds; evidence of operator misbehaviour
//! then comes from certified checkpoints, not from the link). The replica applies a shipment only if it is
//! authenticated, continues the replica's journal and ends exactly at the authenticated anchor; the engine counts an
//! acknowledgement only if it is authenticated and continues the previous one. A network attacker can delay or drop
//! messages (the engine's timeout then drops the replica) but cannot make a replica store, or the engine believe it
//! stores, anything the operator did not ship.
//!
//! Frames (big-endian): anchor = len (8) ‖ head (48); tag = signature (64) or HMAC (48) ‖ 16 zero bytes.
//!   hello  0x01 ‖ anchor ‖ tag                          role 2, from = to = anchor
//!   ship   0x02 ‖ from ‖ to ‖ tag ‖ n (4) ‖ n bytes      role 0
//!   ack    0x03 ‖ from ‖ to ‖ tag                       role 1
//!   error  0x04 ‖ n (2) ‖ n bytes of UTF-8, then the sender closes
//! `TcpReplica` implements `nimbus_pipeline::ReplicaStream`: its sending and acknowledgement halves run on separate
//! threads, so any number of batches can be in flight. For latency, `TcpReplica::into_poll` gives a non-blocking
//! `TcpPoll` (`nimbus_pipeline::ReplicaPoll`) that one spinning engine thread drives for all replicas, and
//! `ReplicaServer::serve_spinning` serves without ever blocking in the kernel: no thread on the replication path
//! sleeps or has to be woken.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nimbus_hash::Hash;
use nimbus_journal::{replication_digest, Anchor, Journal, ROLE_ACK, ROLE_HELLO, ROLE_SHIP};
use nimbus_pipeline::{ReplicaPoll, ReplicaStream, StreamAcks, StreamSend};
use nimbus_sig::CheckedKey;
use sha2::{Digest, Sha384};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Instant;

const T_HELLO: u8 = 1;
const T_SHIP: u8 = 2;
const T_ACK: u8 = 3;
const T_ERR: u8 = 4;
const ACK_LEN: usize = 1 + 56 + 56 + 64;
/// Largest shipment accepted (bytes of journal records).
pub const MAX_SHIPMENT: usize = 64 << 20;

/// HMAC-SHA384 (RFC 2104) of a replication digest.
fn hmac(key: &[u8; 32], digest: &Hash) -> [u8; 48] {
    let mut k = [0u8; 128];
    k[..32].copy_from_slice(key);
    let pad = |b: u8| k.map(|x| x ^ b);
    let inner = Sha384::new()
        .chain_update(pad(0x36))
        .chain_update(digest)
        .finalize();
    Sha384::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

/// How one end of a link authenticates what it sends and checks what it receives.
// One value per link, built once: the size difference between the variants does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum Auth {
    /// Sign with `mine`; accept only messages signed by `theirs` (engine: operator key / replica key; replica: the
    /// reverse).
    Signatures {
        mine: SigningKey,
        theirs: VerifyingKey,
    },
    /// HMAC-SHA384 under a 256-bit secret shared by both ends of this link.
    Mac([u8; 32]),
}

impl Auth {
    fn tag(&self, d: &Hash) -> [u8; 64] {
        match self {
            Auth::Signatures { mine, .. } => mine.sign(d).to_bytes(),
            Auth::Mac(k) => {
                let mut t = [0u8; 64];
                t[..48].copy_from_slice(&hmac(k, d));
                t
            }
        }
    }
    fn check(&self, d: &Hash, t: &[u8; 64]) -> bool {
        match self {
            Auth::Signatures { theirs, .. } => {
                CheckedKey::new(theirs.to_bytes()).is_some_and(|k| nimbus_sig::verify(&k, d, t))
            }
            // Constant-time comparison of the whole field.
            Auth::Mac(_) => {
                self.tag(d)
                    .iter()
                    .zip(t)
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
            }
        }
    }
    fn validate(&self) -> Result<(), String> {
        match self {
            Auth::Signatures { theirs, .. } => CheckedKey::new(theirs.to_bytes())
                .map(|_| ())
                .ok_or_else(|| "weak or invalid key".to_string()),
            Auth::Mac(_) => Ok(()),
        }
    }
}

fn put_anchor(out: &mut Vec<u8>, a: &Anchor) {
    out.extend_from_slice(&a.len.to_be_bytes());
    out.extend_from_slice(&a.head);
}

fn read_exact<R: Read>(r: &mut R, n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).map_err(|e| format!("read: {e}"))?;
    Ok(b)
}

fn read_anchor<R: Read>(r: &mut R) -> Result<Anchor, String> {
    let b = read_exact(r, 56)?;
    Ok(Anchor {
        len: u64::from_be_bytes(b[..8].try_into().expect("8")),
        head: b[8..].try_into().expect("48"),
    })
}

fn read_tag<R: Read>(r: &mut R) -> Result<[u8; 64], String> {
    Ok(read_exact(r, 64)?.try_into().expect("64"))
}

fn read_error<R: Read>(r: &mut R) -> String {
    let n = read_exact(r, 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
        .unwrap_or(0);
    read_exact(r, n)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

fn ship_frame(auth: &Auth, id: u16, from: &Anchor, to: &Anchor, bytes: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(1 + 112 + 64 + 4 + bytes.len());
    f.push(T_SHIP);
    put_anchor(&mut f, from);
    put_anchor(&mut f, to);
    f.extend_from_slice(&auth.tag(&replication_digest(ROLE_SHIP, id, from, to)));
    f.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    f.extend_from_slice(bytes);
    f
}

/// Check an acknowledgement (frame without its type byte) and advance `at`.
fn accept_ack(auth: &Auth, id: u16, at: &mut Anchor, body: &[u8]) -> Result<Anchor, String> {
    let mut r = body;
    let from = read_anchor(&mut r)?;
    let to = read_anchor(&mut r)?;
    let tag = read_tag(&mut r)?;
    if !auth.check(&replication_digest(ROLE_ACK, id, &from, &to), &tag) {
        return Err("acknowledgement not authenticated by the replica".into());
    }
    if from != *at {
        return Err("acknowledgement does not continue the previous one".into());
    }
    *at = to;
    Ok(to)
}

/// A non-blocking socket that spins instead of sleeping when no data is ready.
struct Spin(TcpStream);
impl Read for Spin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.0.read(buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::hint::spin_loop(),
                r => return r,
            }
        }
    }
}
impl Write for Spin {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            match self.0.write(buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::hint::spin_loop(),
                r => return r,
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// A hello frame: replica `id` states that its journal is at `anchor`.
pub fn hello_frame(auth: &Auth, id: u16, anchor: &Anchor) -> Vec<u8> {
    let mut f = vec![T_HELLO];
    put_anchor(&mut f, anchor);
    f.extend_from_slice(&auth.tag(&replication_digest(ROLE_HELLO, id, anchor, anchor)));
    f
}

/// Replica side: a journal and the link's authentication (`mine` = the replica's key, `theirs` = the operator's).
pub struct ReplicaServer {
    journal: Journal,
    auth: Auth,
    id: u16,
}

impl ReplicaServer {
    pub fn new(journal: Journal, auth: Auth, id: u16) -> Result<Self, String> {
        auth.validate()?;
        Ok(ReplicaServer { journal, auth, id })
    }

    pub fn anchor(&self) -> Anchor {
        self.journal.anchor()
    }

    pub fn into_journal(self) -> Journal {
        self.journal
    }

    /// Accept one connection and serve it until the engine disconnects (`Ok`) or a message is refused (`Err`, after
    /// sending an error frame).
    pub fn serve_one(&mut self, listener: &TcpListener) -> Result<(), String> {
        let (stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        self.serve(stream)
    }

    pub fn serve(&mut self, stream: TcpStream) -> Result<(), String> {
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let r = stream.try_clone().map_err(|e| e.to_string())?;
        self.serve_with(r, stream)
    }

    /// `serve_one` without ever blocking in the kernel: the thread spins on a non-blocking socket (latency mode on a
    /// reserved core).
    pub fn serve_one_spinning(&mut self, listener: &TcpListener) -> Result<(), String> {
        let (stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        stream.set_nonblocking(true).map_err(|e| e.to_string())?;
        let r = Spin(stream.try_clone().map_err(|e| e.to_string())?);
        self.serve_with(r, Spin(stream))
    }

    fn serve_with<R: Read, W: Write>(&mut self, r: R, w: W) -> Result<(), String> {
        let mut r = BufReader::new(r);
        let mut w = BufWriter::new(w);
        let res = self.run(&mut r, &mut w);
        if let Err(msg) = &res {
            let m = &msg.as_bytes()[..msg.len().min(1000)];
            let mut f = vec![T_ERR];
            f.extend_from_slice(&(m.len() as u16).to_be_bytes());
            f.extend_from_slice(m);
            let _ = w.write_all(&f).and_then(|_| w.flush());
        }
        res
    }

    fn run<R: Read, W: Write>(&mut self, r: &mut R, w: &mut W) -> Result<(), String> {
        let io = |e: std::io::Error| format!("write: {e}");
        w.write_all(&hello_frame(&self.auth, self.id, &self.journal.anchor()))
            .and_then(|_| w.flush())
            .map_err(io)?;
        loop {
            let mut t = [0u8; 1];
            match r.read(&mut t) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(format!("read: {e}")),
            }
            if t[0] != T_SHIP {
                return Err(format!("unexpected frame type {}", t[0]));
            }
            let from = read_anchor(r)?;
            let to = read_anchor(r)?;
            let tag = read_tag(r)?;
            let n = u32::from_be_bytes(read_exact(r, 4)?.try_into().expect("4")) as usize;
            if n > MAX_SHIPMENT {
                return Err(format!("shipment of {n} bytes exceeds the limit"));
            }
            let bytes = read_exact(r, n)?;
            if !self
                .auth
                .check(&replication_digest(ROLE_SHIP, self.id, &from, &to), &tag)
            {
                return Err("shipment not authenticated by the operator".into());
            }
            let got = self
                .journal
                .replicate_to(&from, &to, &bytes)
                .map_err(|e| format!("refused: {e:?}"))?;
            let mut f = vec![T_ACK];
            put_anchor(&mut f, &from);
            put_anchor(&mut f, &got);
            f.extend_from_slice(
                &self
                    .auth
                    .tag(&replication_digest(ROLE_ACK, self.id, &from, &got)),
            );
            w.write_all(&f).and_then(|_| w.flush()).map_err(io)?;
        }
    }
}

/// Engine side of one replica connection.
pub struct TcpReplica {
    stream: TcpStream,
    id: u16,
    auth: Auth,
    anchor: Anchor,
}

impl TcpReplica {
    /// Connect and read the replica's authenticated hello. `auth`: `mine` = the operator's key, `theirs` = the
    /// replica's.
    pub fn connect<A: ToSocketAddrs>(addr: A, auth: Auth, id: u16) -> Result<TcpReplica, String> {
        auth.validate()?;
        let stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let mut r = &stream;
        let mut t = [0u8; 1];
        r.read_exact(&mut t).map_err(|e| format!("read: {e}"))?;
        if t[0] != T_HELLO {
            return Err(format!("expected hello, got frame type {}", t[0]));
        }
        let anchor = read_anchor(&mut r)?;
        let tag = read_tag(&mut r)?;
        if !auth.check(&replication_digest(ROLE_HELLO, id, &anchor, &anchor), &tag) {
            return Err("hello not authenticated by the replica".into());
        }
        Ok(TcpReplica {
            stream,
            id,
            auth,
            anchor,
        })
    }
}

struct TcpSend {
    w: BufWriter<TcpStream>,
    id: u16,
    auth: Auth,
}

struct TcpAcks {
    r: BufReader<TcpStream>,
    id: u16,
    auth: Auth,
    /// Where the next acknowledgement must continue from.
    at: Anchor,
}

impl ReplicaStream for TcpReplica {
    fn anchor(&self) -> Anchor {
        self.anchor
    }
    fn split(self: Box<Self>) -> (Box<dyn StreamSend>, Box<dyn StreamAcks>) {
        let reader = self.stream.try_clone().expect("clone TCP stream");
        (
            Box::new(TcpSend {
                w: BufWriter::new(self.stream),
                id: self.id,
                auth: self.auth.clone(),
            }),
            Box::new(TcpAcks {
                r: BufReader::new(reader),
                id: self.id,
                auth: self.auth,
                at: self.anchor,
            }),
        )
    }
}

/// Closing the sending half ends the connection: the replica sees end-of-stream, finishes and closes, which in
/// turn ends the acknowledgement half.
impl Drop for TcpSend {
    fn drop(&mut self) {
        let _ = self.w.flush();
        let _ = self.w.get_ref().shutdown(std::net::Shutdown::Write);
    }
}

impl StreamSend for TcpSend {
    fn send(
        &mut self,
        from: &Anchor,
        to: &Anchor,
        bytes: &[u8],
        _shipped: Instant,
    ) -> Result<(), String> {
        let f = ship_frame(&self.auth, self.id, from, to, bytes);
        self.w
            .write_all(&f)
            .and_then(|_| self.w.flush())
            .map_err(|e| format!("write: {e}"))
    }
}

impl StreamAcks for TcpAcks {
    fn next_ack(&mut self) -> Result<Anchor, String> {
        let mut t = [0u8; 1];
        self.r
            .read_exact(&mut t)
            .map_err(|e| format!("read: {e}"))?;
        match t[0] {
            T_ACK => {
                let body = read_exact(&mut self.r, ACK_LEN - 1)?;
                accept_ack(&self.auth, self.id, &mut self.at, &body)
            }
            T_ERR => Err(format!("replica refused: {}", read_error(&mut self.r))),
            other => Err(format!("unexpected frame type {other}")),
        }
    }
}

/// Engine side of one replica connection, non-blocking, for `Pipeline::attach_polled_windowed`.
pub struct TcpPoll {
    stream: TcpStream,
    id: u16,
    auth: Auth,
    anchor: Anchor,
    /// Where the next acknowledgement must continue from.
    at: Anchor,
    out: Vec<u8>,
    sent: usize,
    inbuf: Vec<u8>,
}

impl TcpReplica {
    pub fn into_poll(self) -> Result<TcpPoll, String> {
        self.stream
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        Ok(TcpPoll {
            stream: self.stream,
            id: self.id,
            auth: self.auth,
            anchor: self.anchor,
            at: self.anchor,
            out: Vec::new(),
            sent: 0,
            inbuf: Vec::new(),
        })
    }
}

impl ReplicaPoll for TcpPoll {
    fn anchor(&self) -> Anchor {
        self.anchor
    }

    fn queue(&mut self, from: &Anchor, to: &Anchor, bytes: &[u8]) -> Result<(), String> {
        self.out
            .extend_from_slice(&ship_frame(&self.auth, self.id, from, to, bytes));
        Ok(())
    }

    fn poll(&mut self, acks: &mut Vec<Anchor>) -> Result<(), String> {
        while self.sent < self.out.len() {
            match self.stream.write(&self.out[self.sent..]) {
                Ok(0) => return Err("connection closed".into()),
                Ok(n) => self.sent += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("write: {e}")),
            }
        }
        if self.sent == self.out.len() {
            self.out.clear();
            self.sent = 0;
        }
        let mut closed = false;
        let mut buf = [0u8; 16384];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => self.inbuf.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("read: {e}")),
            }
        }
        let mut used = 0;
        while used < self.inbuf.len() {
            let rest = &self.inbuf[used..];
            match rest[0] {
                T_ACK if rest.len() >= ACK_LEN => {
                    acks.push(accept_ack(
                        &self.auth,
                        self.id,
                        &mut self.at,
                        &rest[1..ACK_LEN],
                    )?);
                    used += ACK_LEN;
                }
                T_ACK => break,
                T_ERR => {
                    let mut r = &rest[1..];
                    if rest.len() < 3
                        || rest.len() < 3 + u16::from_be_bytes([rest[1], rest[2]]) as usize
                    {
                        break;
                    }
                    return Err(format!("replica refused: {}", read_error(&mut r)));
                }
                other => return Err(format!("unexpected frame type {other}")),
            }
        }
        self.inbuf.drain(..used);
        if closed {
            return Err("replica closed the connection".into());
        }
        Ok(())
    }
}

/// Closing ends the connection after sending what is queued (the replica then finishes and closes).
impl Drop for TcpPoll {
    fn drop(&mut self) {
        let _ = self.stream.set_nonblocking(false);
        let _ = self.stream.write_all(&self.out[self.sent..]);
        let _ = self.stream.shutdown(std::net::Shutdown::Write);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2 structure checked against an independent HMAC: key "Jefe" (padded to 32 bytes here, so
    /// compare with a direct construction instead of the RFC vector) — and the tag depends on every input bit.
    #[test]
    fn hmac_matches_the_rfc2104_construction_and_binds_its_input() {
        let key = [7u8; 32];
        let d = [9u8; 48];
        let mut k = [0u8; 128];
        k[..32].copy_from_slice(&key);
        let ipad: Vec<u8> = k.iter().map(|x| x ^ 0x36).chain(d).collect();
        let inner = Sha384::digest(&ipad);
        let opad: Vec<u8> = k.iter().map(|x| x ^ 0x5c).chain(inner).collect();
        assert_eq!(hmac(&key, &d).as_slice(), Sha384::digest(&opad).as_slice());
        for bit in 0..384 {
            let mut e = d;
            e[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(hmac(&key, &e), hmac(&key, &d));
        }
        let a = Auth::Mac(key);
        let t = a.tag(&d);
        assert!(a.check(&d, &t));
        assert!(!Auth::Mac([8; 32]).check(&d, &t));
        let mut bad = t;
        bad[63] ^= 1;
        assert!(!a.check(&d, &bad), "the zero padding is checked too");
    }
}
