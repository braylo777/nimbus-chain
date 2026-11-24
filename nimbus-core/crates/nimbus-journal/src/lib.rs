//! Write-ahead journal of admitted entries (orders, account actions, bridge operations, ticks).
//!
//! Record (variable length): len (2) ‖ seq (8) ‖ slot (8) ‖ entry (len bytes) ‖ chain hash (48), where
//! chain_i = H(0x0B ‖ chain_{i−1} ‖ len ‖ seq ‖ slot ‖ entry) and chain_{−1} = H(0x0B ‖ "genesis"). An order record is
//! 207 bytes. `open` verifies the whole chain: a partially written tail (crash mid-write: shorter than one maximal
//! record) is truncated away; any modified, reordered or removed record is reported as `Tampered` or `Corrupt` with
//! its position. A length field corrupted within the last maximal record's span can look like a torn tail; published
//! anchors catch that case (the journal is then shorter than anchored).
//!
//! Group commit: `append_batch` writes a whole slot with one `write` and `sync` makes it durable with one fsync;
//! `durable_len` is the watermark below which records survive a crash — acknowledge nothing above it.
//! Anchors: a chain alone cannot reveal that whole records were cut from its *end*. `open_anchored` takes a
//! previously published `(len, head)` and fails unless the journal still contains that exact prefix.
#![forbid(unsafe_code)]

use nimbus_hash::{hash_tagged, Hash};
use nimbus_order::{Entry, ENTRY_MAX, WIRE_LEN};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const JOURNAL_TAG: u8 = 0x0B;
/// Replication protocol statements (signed): role ‖ replica ‖ from (len ‖ head) ‖ to (len ‖ head).
pub const REPLICATION_TAG: u8 = 0x11;
/// The engine ships records taking a replica from `from` to `to` (signed by the operator).
pub const ROLE_SHIP: u8 = 0;
/// A replica holds records up to `to`, having continued from `from` (signed by the replica).
pub const ROLE_ACK: u8 = 1;
/// A replica's journal is at `to` (= `from`) when a connection opens (signed by the replica).
pub const ROLE_HELLO: u8 = 2;
pub const REPLICATION_BODY: usize = 1 + 2 + 2 * (8 + 48);
/// len (2) ‖ seq (8) ‖ slot (8)
pub const HEADER_LEN: usize = 18;
/// Bytes a record takes for an entry of `entry_len` bytes.
pub const fn record_len(entry_len: usize) -> usize {
    HEADER_LEN + entry_len + 48
}
pub const ORDER_RECORD_LEN: usize = record_len(1 + WIRE_LEN);
pub const MAX_RECORD_LEN: usize = record_len(ENTRY_MAX);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub slot: u64,
    pub entry: Entry,
}

#[derive(Debug)]
pub enum JournalError {
    Io(std::io::Error),
    Tampered {
        seq: u64,
    },
    Sequence {
        expected: u64,
        got: u64,
    },
    Corrupt {
        seq: u64,
    },
    /// Records carry non-decreasing slots.
    SlotOrder {
        seq: u64,
    },
    /// The journal is shorter than a published anchor: records were removed from its end.
    BehindAnchor {
        have: u64,
        anchored: u64,
    },
    /// The journal's prefix of the anchored length does not hash to the anchored head.
    AnchorMismatch {
        len: u64,
    },
    /// Replication: the shipped records do not end at the anchor the engine signed.
    EndMismatch,
    /// Replication: the shipped records do not continue this replica's journal.
    NotContiguous {
        have: u64,
        from: u64,
    },
}

/// A published commitment to a journal prefix: its length and the chain hash after its last record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub len: u64,
    pub head: Hash,
}

impl From<std::io::Error> for JournalError {
    fn from(e: std::io::Error) -> Self {
        JournalError::Io(e)
    }
}

pub fn replication_body(
    role: u8,
    replica: u16,
    from: &Anchor,
    to: &Anchor,
) -> [u8; REPLICATION_BODY] {
    let mut b = [0u8; REPLICATION_BODY];
    b[0] = role;
    b[1..3].copy_from_slice(&replica.to_be_bytes());
    b[3..11].copy_from_slice(&from.len.to_be_bytes());
    b[11..59].copy_from_slice(&from.head);
    b[59..67].copy_from_slice(&to.len.to_be_bytes());
    b[67..115].copy_from_slice(&to.head);
    b
}

/// What the parties of the replication protocol sign (domain 0x11).
pub fn replication_digest(role: u8, replica: u16, from: &Anchor, to: &Anchor) -> Hash {
    hash_tagged(
        REPLICATION_TAG,
        &[&replication_body(role, replica, from, to)],
    )
}

pub fn genesis_chain() -> Hash {
    hash_tagged(JOURNAL_TAG, &[b"genesis"])
}

fn payload(seq: u64, slot: u64, e: &Entry, out: &mut Vec<u8>) {
    let b = e.to_bytes();
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&slot.to_be_bytes());
    out.extend_from_slice(&b);
}

fn chain_next(prev: &Hash, p: &[u8]) -> Hash {
    hash_tagged(JOURNAL_TAG, &[prev, p])
}

/// Parse and verify the record at the start of `b` as record `seq`, continuing chain `head` after slot `last_slot`.
/// `Ok(None)`: `b` holds only part of a record.
fn parse_record(
    b: &[u8],
    head: &Hash,
    seq: u64,
    last_slot: u64,
) -> Result<Option<(usize, Record, Hash)>, JournalError> {
    if b.len() < 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([b[0], b[1]]) as usize;
    if len == 0 || len > ENTRY_MAX {
        return Err(JournalError::Corrupt { seq });
    }
    let total = record_len(len);
    if b.len() < total {
        return Ok(None);
    }
    let (p, h) = b[..total].split_at(HEADER_LEN + len);
    let next = chain_next(head, p);
    if next.as_slice() != h {
        return Err(JournalError::Tampered { seq });
    }
    let got = u64::from_be_bytes(p[2..10].try_into().expect("8"));
    if got != seq {
        return Err(JournalError::Sequence { expected: seq, got });
    }
    let entry = Entry::from_bytes(&p[HEADER_LEN..]).map_err(|_| JournalError::Corrupt { seq })?;
    let slot = u64::from_be_bytes(p[10..18].try_into().expect("8"));
    if slot < last_slot {
        return Err(JournalError::SlotOrder { seq });
    }
    Ok(Some((total, Record { seq, slot, entry }, next)))
}

/// Verify the stored link just before byte `bytes` against `anchor` and parse the complete records after it.
/// Returns the records (suffix only; absolute offsets), the byte offset after the last complete record, and the
/// last record's slot.
fn scan_from(
    file: &mut File,
    anchor: &Anchor,
    bytes: u64,
    last_slot: u64,
) -> Result<(Recovery, u64, u64), JournalError> {
    let size = file.metadata()?.len();
    let behind = JournalError::BehindAnchor {
        have: 0,
        anchored: anchor.len,
    };
    if size < bytes || (anchor.len == 0) != (bytes == 0) {
        return Err(behind);
    }
    if anchor.len == 0 {
        if anchor.head != genesis_chain() {
            return Err(JournalError::AnchorMismatch { len: 0 });
        }
    } else {
        let mut link = [0u8; 48];
        if bytes < 48 {
            return Err(behind);
        }
        file.seek(SeekFrom::Start(bytes - 48))?;
        file.read_exact(&mut link)?;
        if link != anchor.head {
            return Err(JournalError::AnchorMismatch { len: anchor.len });
        }
    }
    file.seek(SeekFrom::Start(bytes))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let (mut head, mut last_slot) = (anchor.head, last_slot);
    let (mut records, mut chain, mut offsets) = (Vec::new(), Vec::new(), Vec::new());
    let (mut off, mut truncated) = (0usize, 0u64);
    while off < buf.len() {
        let i = anchor.len + records.len() as u64;
        let rest = buf.len() - off;
        match parse_record(&buf[off..], &head, i, last_slot)? {
            Some((total, rec, next)) => {
                last_slot = rec.slot;
                records.push(rec);
                head = next;
                chain.push(head);
                off += total;
                offsets.push(bytes + off as u64);
            }
            None if rest < MAX_RECORD_LEN => {
                truncated = rest as u64;
                break;
            }
            None => return Err(JournalError::Corrupt { seq: i }),
        }
    }
    Ok((
        Recovery {
            records,
            truncated_bytes: truncated,
            head,
            chain,
            offsets,
        },
        bytes + off as u64,
        last_slot,
    ))
}

pub struct Journal {
    file: File,
    /// Bytes written by the last `append_batch` (what a primary ships to its replicas).
    last_write: Vec<u8>,
    head: Hash,
    next_seq: u64,
    last_slot: u64,
    durable: u64,
    unsynced: usize,
    sync_every: usize,
}

/// What `open` found on disk.
#[derive(Debug)]
pub struct Recovery {
    pub records: Vec<Record>,
    /// Bytes of an incomplete trailing record that were discarded (crash mid-write).
    pub truncated_bytes: u64,
    pub head: Hash,
    /// `chain[i]` is the chain hash after record i (for checking checkpoints taken at any length).
    pub chain: Vec<Hash>,
    /// `offsets[i]` is the byte offset just past record i.
    pub offsets: Vec<u64>,
}

impl Journal {
    /// Open (or create) a journal, verify the full chain, and truncate an incomplete tail.
    pub fn open(path: &Path, sync_every: usize) -> Result<(Journal, Recovery), JournalError> {
        Self::open_inner(path, sync_every, None)
    }

    /// `open`, and additionally require the exact prefix committed to by `anchor`.
    pub fn open_anchored(
        path: &Path,
        sync_every: usize,
        anchor: &Anchor,
    ) -> Result<(Journal, Recovery), JournalError> {
        Self::open_inner(path, sync_every, Some(anchor))
    }

    /// Resume at a trusted position: `anchor` (length, head) of this file, `bytes` its byte length there and
    /// `last_slot` the slot of record `anchor.len − 1` — all from a snapshot this node wrote. The prefix is not re-read:
    /// only the stored chain value just before `bytes` is compared with the anchor's head (a replaced or cut file is
    /// refused), then the suffix is verified and returned as in `open` (`records`, `chain` and `offsets` hold the
    /// suffix only; `offsets` are absolute). Cost O(suffix).
    pub fn open_from(
        path: &Path,
        sync_every: usize,
        anchor: &Anchor,
        bytes: u64,
        last_slot: u64,
    ) -> Result<(Journal, Recovery), JournalError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let (rec, end, last) = scan_from(&mut file, anchor, bytes, last_slot)?;
        if rec.truncated_bytes > 0 {
            file.set_len(end)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        let n = anchor.len + rec.records.len() as u64;
        let j = Journal {
            file,
            last_write: Vec::new(),
            head: rec.head,
            next_seq: n,
            last_slot: last,
            durable: n,
            unsynced: 0,
            sync_every: sync_every.max(1),
        };
        Ok((j, rec))
    }

    /// Read-only `open_from` for a journal another process is appending to (a snapshot follower): returns the
    /// complete records after the anchor and ignores — never truncates — a partial record at the end.
    pub fn read_from(
        path: &Path,
        anchor: &Anchor,
        bytes: u64,
        last_slot: u64,
    ) -> Result<Recovery, JournalError> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        Ok(scan_from(&mut file, anchor, bytes, last_slot)?.0)
    }

    fn open_inner(
        path: &Path,
        sync_every: usize,
        anchor: Option<&Anchor>,
    ) -> Result<(Journal, Recovery), JournalError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let mut head = genesis_chain();
        let mut records = Vec::new();
        let mut chain = Vec::new();
        let mut offsets = Vec::new();
        let mut last_slot = 0u64;
        let mut off = 0usize;
        let mut truncated = 0u64;
        while off < buf.len() {
            let i = records.len() as u64;
            let rest = buf.len() - off;
            // A crash leaves at most one partial record, written front to back.
            match parse_record(&buf[off..], &head, i, last_slot)? {
                Some((total, rec, next)) => {
                    last_slot = rec.slot;
                    records.push(rec);
                    head = next;
                    chain.push(head);
                    off += total;
                    offsets.push(off as u64);
                }
                None if rest < MAX_RECORD_LEN => {
                    truncated = rest as u64;
                    break;
                }
                None => return Err(JournalError::Corrupt { seq: i }),
            }
        }
        let full = records.len();
        if let Some(a) = anchor {
            if a.len > full as u64 {
                return Err(JournalError::BehindAnchor {
                    have: full as u64,
                    anchored: a.len,
                });
            }
            let at = if a.len == 0 {
                genesis_chain()
            } else {
                chain[a.len as usize - 1]
            };
            if at != a.head {
                return Err(JournalError::AnchorMismatch { len: a.len });
            }
        }
        if truncated > 0 {
            file.set_len(off as u64)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        let j = Journal {
            file,
            last_write: Vec::new(),
            head,
            next_seq: full as u64,
            last_slot,
            durable: full as u64,
            unsynced: 0,
            sync_every: sync_every.max(1),
        };
        Ok((
            j,
            Recovery {
                records,
                truncated_bytes: truncated,
                head,
                chain,
                offsets,
            },
        ))
    }

    /// Append an admitted entry. Durable once `sync` has run (automatically every `sync_every` appends).
    pub fn append(&mut self, slot: u64, entry: &Entry) -> Result<u64, JournalError> {
        let seq = self.next_seq;
        self.append_batch(slot, &[entry])?;
        if self.unsynced >= self.sync_every {
            self.sync()?;
        }
        Ok(seq)
    }

    /// Append a slot's records with a single `write` (no fsync; call `sync` once for the whole group). Returns the
    /// sequence range written. If the write fails nothing is recorded as appended (the tail is cut back on the next
    /// `open`).
    pub fn append_batch(
        &mut self,
        slot: u64,
        entries: &[&Entry],
    ) -> Result<std::ops::Range<u64>, JournalError> {
        if slot < self.last_slot {
            return Err(JournalError::SlotOrder { seq: self.next_seq });
        }
        let start = self.next_seq;
        let mut buf = Vec::with_capacity(entries.len() * ORDER_RECORD_LEN);
        let mut head = self.head;
        for (k, e) in entries.iter().enumerate() {
            let at = buf.len();
            payload(start + k as u64, slot, e, &mut buf);
            head = chain_next(&head, &buf[at..]);
            buf.extend_from_slice(&head);
        }
        self.file.write_all(&buf)?;
        self.last_write = buf;
        self.head = head;
        self.last_slot = slot;
        self.next_seq += entries.len() as u64;
        self.unsynced += entries.len();
        Ok(start..self.next_seq)
    }

    /// The bytes the last `append_batch` wrote: records continuing the anchor taken before it. A replica applies them
    /// with `replicate`.
    pub fn last_write(&self) -> &[u8] {
        &self.last_write
    }

    /// Replica side: verify `bytes` as complete records continuing `from` (which must be this journal's anchor),
    /// write them with one `write`, make them durable with one fsync, and return the new anchor. Nothing is written
    /// unless every record verifies, so a replica holds a byte-identical prefix of the primary's journal and can be
    /// opened as a primary after failover.
    pub fn replicate(&mut self, from: &Anchor, bytes: &[u8]) -> Result<Anchor, JournalError> {
        self.replicate_inner(from, None, bytes).map(|(a, _)| a)
    }

    /// `replicate`, also returning the records it made durable (for a replica that re-executes them).
    pub fn replicate_records(
        &mut self,
        from: &Anchor,
        bytes: &[u8],
    ) -> Result<(Anchor, Vec<Record>), JournalError> {
        self.replicate_inner(from, None, bytes)
    }

    /// `replicate`, and write nothing unless the records end exactly at `to` (the anchor the engine signed).
    pub fn replicate_to(
        &mut self,
        from: &Anchor,
        to: &Anchor,
        bytes: &[u8],
    ) -> Result<Anchor, JournalError> {
        self.replicate_inner(from, Some(to), bytes).map(|(a, _)| a)
    }

    fn replicate_inner(
        &mut self,
        from: &Anchor,
        to: Option<&Anchor>,
        bytes: &[u8],
    ) -> Result<(Anchor, Vec<Record>), JournalError> {
        let mine = self.anchor();
        if *from != mine {
            return Err(JournalError::NotContiguous {
                have: mine.len,
                from: from.len,
            });
        }
        let (mut head, mut seq, mut last_slot, mut off) =
            (self.head, self.next_seq, self.last_slot, 0);
        let mut records = Vec::new();
        while off < bytes.len() {
            let (total, rec, next) = parse_record(&bytes[off..], &head, seq, last_slot)?
                .ok_or(JournalError::Corrupt { seq })?;
            (head, seq, last_slot) = (next, seq + 1, rec.slot);
            records.push(rec);
            off += total;
        }
        if to.is_some_and(|t| t.len != seq || t.head != head) {
            return Err(JournalError::EndMismatch);
        }
        let at = self.file.stream_position()?;
        if let Err(e) = self
            .file
            .write_all(bytes)
            .and_then(|_| self.file.sync_data())
        {
            // Leave the file as it was so that the replica stays a clean prefix.
            let _ = self.file.set_len(at);
            let _ = self.file.seek(SeekFrom::Start(at));
            return Err(e.into());
        }
        self.head = head;
        self.last_slot = last_slot;
        self.next_seq = seq;
        self.durable = seq;
        self.unsynced = 0;
        Ok((self.anchor(), records))
    }

    /// Make every appended record durable (one fsync).
    pub fn sync(&mut self) -> Result<(), JournalError> {
        self.file.sync_data()?;
        self.unsynced = 0;
        self.durable = self.next_seq;
        Ok(())
    }

    /// Records `0..durable_len()` are on stable storage; only these may be acknowledged.
    pub fn durable_len(&self) -> u64 {
        self.durable
    }

    /// Anchor for the current state (publish it after `sync`).
    pub fn anchor(&self) -> Anchor {
        Anchor {
            len: self.next_seq,
            head: self.head,
        }
    }

    /// Chain head: commits to every record so far (publish it to detect divergent histories).
    pub fn head(&self) -> Hash {
        self.head
    }
    /// Byte length of the journal file up to the last record written.
    pub fn byte_len(&mut self) -> Result<u64, JournalError> {
        Ok(self.file.stream_position()?)
    }

    pub fn len(&self) -> u64 {
        self.next_seq
    }
    pub fn is_empty(&self) -> bool {
        self.next_seq == 0
    }
}
