//! Bridge-side settlement.
//!
//! Funds leave the engine's world only here. The bridge pays a withdrawal, or refunds a deposit the engine rejected,
//! only against a `ReceiptProof` — the receipt, its Merkle path, and the operator-signed checkpoint that commits to it
//! — and each receipt settles at most once, across restarts: the receipt's leaf digest is appended to a settled-set
//! file and fsynced before the instruction is released. A refund also needs the bridge's own signed operation, whose
//! digest must be the one the receipt names, because a receipt of a rejected deposit carries no amounts.
//!
//! The bridge also remembers the checkpoint it accepted for each slot (a second file, fsynced like the first). A proof
//! under a different operator-signed checkpoint for the same slot is refused as `Equivocation`: two signed
//! checkpoints for one slot are proof that the operator misbehaved, and must never both pay.
//!
//! The operator key alone cannot stop a fabricated checkpoint for a slot the bridge has not yet seen. A bridge opened
//! with `open_certified` therefore also requires a `Certificate`: co-signatures of at least `quorum` validators on
//! the same checkpoint digest (domain 0x0C), where 3·quorum > 2n. A validator co-signs only the checkpoint it
//! re-derived by replaying the replicated journal, and at most one per slot, so with f < n/3 faulty validators a
//! fabricated checkpoint cannot be certified, and two certified checkpoints for one slot identify ≥ 2·quorum − n > f
//! validators that signed both.
#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nimbus_hash::Hash;
use nimbus_match::AccountId;
use nimbus_order::{BridgeKind, BridgeOp};
use nimbus_pipeline::{Checkpoint, ReceiptProof, Source, Status};
use nimbus_sig::{CheckedKey, Item};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// What the bridge must do on the external chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// Pay a completed withdrawal to the account's registered external address.
    Pay {
        acct: AccountId,
        market: u32,
        base: u128,
        quote: u128,
    },
    /// Return a deposit the engine rejected (e.g. at the supply cap).
    Refund {
        acct: AccountId,
        market: u32,
        base: u128,
        quote: u128,
        reference: [u8; 32],
    },
}

#[derive(Debug)]
pub enum SettleError {
    Io(std::io::Error),
    /// The checkpoint signature or the Merkle path does not verify under the operator key.
    BadProof,
    /// This receipt was already settled.
    AlreadySettled,
    /// The receipt is not a completed withdrawal (for `pay`) or a rejected deposit (for `refund`).
    NotSettleable,
    /// The supplied bridge operation is not the one the receipt names.
    OperationMismatch,
    /// The operator signed a different checkpoint for this slot earlier: keep both as evidence; settle nothing.
    Equivocation {
        slot: u64,
    },
    /// This bridge requires validator-certified checkpoints and the certificate is missing or invalid.
    Uncertified(CertError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertError {
    Missing,
    /// Fewer distinct valid signers than the quorum.
    Quorum {
        have: usize,
        need: usize,
    },
    UnknownValidator,
    DuplicateSigner,
    Signature,
    /// The validator set itself is unusable: a weak key, or a quorum with 3·quorum ≤ 2n or above n.
    BadSet,
}

/// Validators whose co-signatures certify engine checkpoints.
#[derive(Clone, Debug)]
pub struct Validators {
    keys: Vec<CheckedKey>,
    quorum: usize,
}

/// Co-signatures on a checkpoint's digest: (validator index, signature).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub sigs: Vec<(u16, [u8; 64])>,
}

impl Certificate {
    /// What each validator does after re-deriving `ck` from the replicated journal.
    pub fn sign(ck: &Checkpoint, signers: &[(u16, &SigningKey)]) -> Certificate {
        let d = ck.digest();
        Certificate {
            sigs: signers
                .iter()
                .map(|(i, k)| (*i, k.sign(&d).to_bytes()))
                .collect(),
        }
    }
}

impl Validators {
    /// `quorum` must satisfy 2n < 3·quorum ≤ 3n: any two quorums then share more than n/3 validators.
    pub fn new(keys: &[VerifyingKey], quorum: usize) -> Result<Validators, CertError> {
        let n = keys.len();
        if n == 0 || 3 * quorum <= 2 * n || quorum > n || n > u16::MAX as usize + 1 {
            return Err(CertError::BadSet);
        }
        let keys = keys
            .iter()
            .map(|k| CheckedKey::new(k.to_bytes()).ok_or(CertError::BadSet))
            .collect::<Result<_, _>>()?;
        Ok(Validators { keys, quorum })
    }

    pub fn quorum(&self) -> usize {
        self.quorum
    }

    /// Accept iff at least `quorum` distinct validators signed this checkpoint's digest (one ZIP-215 batch).
    pub fn verify(&self, ck: &Checkpoint, cert: &Certificate) -> Result<(), CertError> {
        if cert.sigs.len() < self.quorum {
            return Err(CertError::Quorum {
                have: cert.sigs.len(),
                need: self.quorum,
            });
        }
        let msg = ck.digest();
        let mut seen = vec![false; self.keys.len()];
        let mut items = Vec::with_capacity(cert.sigs.len());
        for (i, sig) in &cert.sigs {
            let i = *i as usize;
            let key = *self.keys.get(i).ok_or(CertError::UnknownValidator)?;
            if std::mem::replace(&mut seen[i], true) {
                return Err(CertError::DuplicateSigner);
            }
            items.push(Item {
                key,
                msg,
                sig: *sig,
            });
        }
        if nimbus_sig::verify_batch(&items) {
            Ok(())
        } else {
            Err(CertError::Signature)
        }
    }
}

impl From<std::io::Error> for SettleError {
    fn from(e: std::io::Error) -> Self {
        SettleError::Io(e)
    }
}

pub struct Settlement {
    operator: VerifyingKey,
    validators: Option<Validators>,
    settled: HashSet<Hash>,
    log: File,
    checkpoints: HashMap<u64, Hash>,
    cklog: File,
}

/// Read a file of fixed-size records, cutting away a torn trailing record.
fn load(path: &Path, rec: usize) -> Result<(File, Vec<u8>), SettleError> {
    let mut f = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let whole = buf.len() / rec * rec;
    if whole != buf.len() {
        f.set_len(whole as u64)?;
        f.sync_all()?;
        buf.truncate(whole);
    }
    Ok((f, buf))
}

impl Settlement {
    /// Open (or create) the settled-set file. A torn trailing entry (crash mid-append) is ignored and cut away.
    /// The checkpoint record lives next to it with extension `.checkpoints`.
    pub fn open(path: &Path, operator: VerifyingKey) -> Result<Settlement, SettleError> {
        Self::open_inner(path, operator, None)
    }

    /// `open`, and additionally require every checkpoint to be certified by `validators` (`pay_certified`,
    /// `refund_certified`); `pay` and `refund` then refuse.
    pub fn open_certified(
        path: &Path,
        operator: VerifyingKey,
        validators: Validators,
    ) -> Result<Settlement, SettleError> {
        Self::open_inner(path, operator, Some(validators))
    }

    fn open_inner(
        path: &Path,
        operator: VerifyingKey,
        validators: Option<Validators>,
    ) -> Result<Settlement, SettleError> {
        let (log, buf) = load(path, 48)?;
        let settled = buf
            .chunks_exact(48)
            .map(|c| c.try_into().expect("48"))
            .collect();
        let (cklog, buf) = load(&path.with_extension("checkpoints"), 56)?;
        let checkpoints = buf
            .chunks_exact(56)
            .map(|c| {
                (
                    u64::from_be_bytes(c[..8].try_into().expect("8")),
                    c[8..].try_into().expect("48"),
                )
            })
            .collect();
        Ok(Settlement {
            operator,
            validators,
            settled,
            log,
            checkpoints,
            cklog,
        })
    }

    pub fn settled_count(&self) -> usize {
        self.settled.len()
    }

    fn check(&self, p: &ReceiptProof, cert: Option<&Certificate>) -> Result<Hash, SettleError> {
        if !p.verify(&self.operator) {
            return Err(SettleError::BadProof);
        }
        if let Some(v) = &self.validators {
            let cert = cert.ok_or(SettleError::Uncertified(CertError::Missing))?;
            v.verify(&p.checkpoint, cert)
                .map_err(SettleError::Uncertified)?;
        }
        let ck = p.checkpoint.digest();
        if self
            .checkpoints
            .get(&p.checkpoint.slot)
            .is_some_and(|seen| *seen != ck)
        {
            return Err(SettleError::Equivocation {
                slot: p.checkpoint.slot,
            });
        }
        let leaf = p.receipt.leaf();
        if self.settled.contains(&leaf) {
            return Err(SettleError::AlreadySettled);
        }
        Ok(leaf)
    }

    fn record(&mut self, p: &ReceiptProof, leaf: Hash) -> Result<(), SettleError> {
        let slot = p.checkpoint.slot;
        if !self.checkpoints.contains_key(&slot) {
            let mut rec = slot.to_be_bytes().to_vec();
            rec.extend_from_slice(&p.checkpoint.digest());
            self.cklog.write_all(&rec)?;
            self.cklog.sync_data()?;
            self.checkpoints.insert(slot, p.checkpoint.digest());
        }
        self.log.write_all(&leaf)?;
        self.log.sync_data()?;
        self.settled.insert(leaf);
        Ok(())
    }

    /// Pay a withdrawal the engine completed.
    pub fn pay(&mut self, p: &ReceiptProof) -> Result<Instruction, SettleError> {
        self.pay_inner(p, None)
    }

    /// `pay` under a validator certificate of the proof's checkpoint.
    pub fn pay_certified(
        &mut self,
        p: &ReceiptProof,
        cert: &Certificate,
    ) -> Result<Instruction, SettleError> {
        self.pay_inner(p, Some(cert))
    }

    /// `refund` under a validator certificate of the proof's checkpoint.
    pub fn refund_certified(
        &mut self,
        p: &ReceiptProof,
        op: &BridgeOp,
        cert: &Certificate,
    ) -> Result<Instruction, SettleError> {
        self.refund_inner(p, op, Some(cert))
    }

    fn pay_inner(
        &mut self,
        p: &ReceiptProof,
        cert: Option<&Certificate>,
    ) -> Result<Instruction, SettleError> {
        let leaf = self.check(p, cert)?;
        let (Status::Withdrawn { base, quote }, Some(market), Source::Entry { .. }) =
            (&p.receipt.status, p.receipt.market, p.receipt.source)
        else {
            return Err(SettleError::NotSettleable);
        };
        let ins = Instruction::Pay {
            acct: p.receipt.acct,
            market,
            base: *base,
            quote: *quote,
        };
        self.record(p, leaf)?;
        Ok(ins)
    }

    /// Refund a deposit the engine rejected; `op` is the bridge's own operation that the receipt names.
    pub fn refund(&mut self, p: &ReceiptProof, op: &BridgeOp) -> Result<Instruction, SettleError> {
        self.refund_inner(p, op, None)
    }

    fn refund_inner(
        &mut self,
        p: &ReceiptProof,
        op: &BridgeOp,
        cert: Option<&Certificate>,
    ) -> Result<Instruction, SettleError> {
        let leaf = self.check(p, cert)?;
        let (Status::Rejected(_), Source::Entry { digest, .. }) =
            (&p.receipt.status, p.receipt.source)
        else {
            return Err(SettleError::NotSettleable);
        };
        if op.digest() != digest {
            return Err(SettleError::OperationMismatch);
        }
        let BridgeKind::Deposit {
            market,
            acct,
            base,
            quote,
        } = op.kind
        else {
            return Err(SettleError::NotSettleable);
        };
        let ins = Instruction::Refund {
            acct,
            market,
            base,
            quote,
            reference: op.reference,
        };
        self.record(p, leaf)?;
        Ok(ins)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Certifier

#[derive(Debug)]
pub enum CertifyError {
    Io(std::io::Error),
    /// The checkpoint is not signed by the operator.
    NotOperatorSigned,
    /// This certifier has not yet replicated and re-executed that slot.
    NotYetReplicated {
        slot: u64,
    },
    /// The operator's checkpoint differs from the one this certifier re-derived: evidence; nothing is signed.
    Mismatch {
        slot: u64,
    },
    /// This certifier already signed a different checkpoint for the slot (cannot happen for an honest operator).
    AlreadySignedOther {
        slot: u64,
    },
    /// The slot is older than the retention window: its body and signing record were pruned, and nothing below the
    /// (durable, never decreasing) floor is ever signed again.
    Pruned {
        slot: u64,
        floor: u64,
    },
}

impl From<std::io::Error> for CertifyError {
    fn from(e: std::io::Error) -> Self {
        CertifyError::Io(e)
    }
}

/// A validator's checkpoint certifier. It is a journal replica (`Replica`): it makes every shipped batch durable,
/// re-executes it with `Replayer`, and keeps the checkpoint body it derives for each slot. `certify` co-signs an
/// operator-signed checkpoint only if it equals that body, and at most one checkpoint per slot — recorded durably
/// (slot ‖ digest, fsynced) before the signature is released, so the rule holds across restarts. These are exactly
/// the honest-validator assumptions of the bridge's certificate rule (`Validators`).
/// A shipment must hold whole slots; the engine ships one slot's journal write per batch.
///
/// Memory is bounded by a retention window of `retain` slots (`open_retaining`): bodies and signing records of slots
/// below `floor = newest − retain + 1` are dropped and such slots are refused (`Pruned`). The floor is written
/// durably before a signing record leaves the disk and never decreases, also if the journal is replaced by a
/// shorter one, so "at most one checkpoint per slot" holds for every slot, pruned or not.
pub struct Certifier {
    journal: nimbus_journal::Journal,
    replay: nimbus_pipeline::Replayer,
    derived: std::collections::BTreeMap<u64, Checkpoint>,
    key: SigningKey,
    index: u16,
    operator: VerifyingKey,
    signed: std::collections::BTreeMap<u64, Hash>,
    signed_log: File,
    /// Signing records currently in `signed.bin` (retained or not yet compacted away).
    on_disk: usize,
    dir: std::path::PathBuf,
    retain: u64,
    floor: u64,
    /// Write a snapshot every this many slots (0: never).
    snapshot_every: u64,
    last_snapshot: u64,
    resumed_from: Option<u64>,
    writer: Option<SnapshotWriter>,
}

use nimbus_pipeline::{durable_write, seal, SnapshotWriter};

/// Compact `signed.bin` once it holds this many more records than twice the retained ones.
const COMPACT_SLACK: usize = 64;

impl Certifier {
    /// Open (or create) the certifier in `dir`: replay its journal from genesis (re-deriving every checkpoint body)
    /// and load the slots it has signed.
    pub fn open(
        dir: &Path,
        cfg: nimbus_pipeline::Config,
        genesis: &nimbus_pipeline::Genesis,
        operator: VerifyingKey,
        key: SigningKey,
        index: u16,
    ) -> Result<Certifier, String> {
        Certifier::open_retaining(dir, cfg, genesis, operator, key, index, u64::MAX)
    }

    /// `open` with a retention window of `retain ≥ 1` slots (see the type's documentation).
    pub fn open_retaining(
        dir: &Path,
        cfg: nimbus_pipeline::Config,
        genesis: &nimbus_pipeline::Genesis,
        operator: VerifyingKey,
        key: SigningKey,
        index: u16,
        retain: u64,
    ) -> Result<Certifier, String> {
        if retain == 0 {
            return Err("retain must be at least one slot".into());
        }
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let stored_floor = match std::fs::read(dir.join("floor.bin")) {
            Ok(b) => u64::from_be_bytes(b.try_into().map_err(|_| "floor.bin: not 8 bytes")?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.to_string()),
        };
        let path = dir.join("journal.bin");
        // Resume from this certifier's own snapshot when it matches the journal; otherwise replay from genesis.
        let resumed = std::fs::read(dir.join("snapshot.bin"))
            .ok()
            .and_then(|b| nimbus_pipeline::Replayer::restore(cfg.clone(), &b).ok())
            .and_then(|(replay, bytes, window)| {
                let (journal, rec) = nimbus_journal::Journal::open_from(
                    &path,
                    usize::MAX,
                    &replay.anchor(),
                    bytes,
                    replay.last_slot().unwrap_or(0),
                )
                .ok()?;
                Some((journal, rec, replay, window))
            });
        let resumed_from = resumed.as_ref().and_then(|r| r.2.last_slot());
        let (journal, rec, mut replay, window) = match resumed {
            Some(r) => r,
            None => {
                let (journal, rec) = nimbus_journal::Journal::open(&path, usize::MAX)
                    .map_err(|e| format!("{e:?}"))?;
                let replay =
                    nimbus_pipeline::Replayer::new(cfg, genesis).map_err(|e| format!("{e:?}"))?;
                (journal, rec, replay, Vec::new())
            }
        };
        let base = replay.anchor().len;
        let mut derived: std::collections::BTreeMap<u64, Checkpoint> =
            window.into_iter().map(|c| (c.slot, c)).collect();
        let mut i = 0;
        while i < rec.records.len() {
            let slot = rec.records[i].slot;
            let end = i + rec.records[i..]
                .iter()
                .take_while(|r| r.slot == slot)
                .count();
            let after = nimbus_journal::Anchor {
                len: base + end as u64,
                head: rec.chain[end - 1],
            };
            let ck = replay
                .apply_slot(&rec.records[i..end], after)
                .map_err(|e| format!("{e:?}"))?;
            derived.insert(slot, ck);
            if derived.len() as u64 > retain {
                derived.pop_first();
            }
            i = end;
        }
        let (signed_log, buf) = load(&dir.join("signed.bin"), 56).map_err(|e| format!("{e:?}"))?;
        let signed = buf
            .chunks_exact(56)
            .map(|c| {
                (
                    u64::from_be_bytes(c[..8].try_into().expect("8")),
                    c[8..].try_into().expect("48"),
                )
            })
            .collect();
        let mut c = Certifier {
            journal,
            replay,
            derived,
            key,
            index,
            operator,
            signed,
            signed_log,
            on_disk: buf.len() / 56,
            dir: dir.to_path_buf(),
            retain,
            floor: stored_floor,
            snapshot_every: 0,
            last_snapshot: resumed_from.unwrap_or(0),
            resumed_from,
            writer: None,
        };
        c.prune().map_err(|e| e.to_string())?;
        Ok(c)
    }

    /// Write a snapshot of the replay state every `k` slots (0 disables). A restart then re-executes only the
    /// journal written after the newest snapshot (`Journal::open_from`).
    pub fn set_snapshot_every(&mut self, k: u64) {
        self.snapshot_every = k;
    }

    /// The slot of the snapshot this certifier resumed from at open (`None`: replayed from genesis).
    pub fn resumed_from(&self) -> Option<u64> {
        self.resumed_from
    }

    /// Write the replay state and the retained checkpoint bodies to `snapshot.bin` now and wait until it is durable
    /// (write, fsync, rename, fsync of the directory: a crash leaves the old or the new snapshot, never a mixture).
    pub fn snapshot_now(&mut self) -> std::io::Result<()> {
        if let Some(w) = self.writer.take() {
            w.finish().map_err(std::io::Error::other)?;
        }
        let body = self.snapshot_body()?;
        durable_write(&self.dir, "snapshot.bin", &seal(body))?;
        self.last_snapshot = self.replay.last_slot().unwrap_or(0);
        Ok(())
    }

    fn snapshot_body(&mut self) -> std::io::Result<Vec<u8>> {
        let bytes = self
            .journal
            .byte_len()
            .map_err(|e| std::io::Error::other(format!("{e:?}")))?;
        let window: Vec<Checkpoint> = self.derived.values().copied().collect();
        Ok(self.replay.snapshot_body(bytes, &window))
    }

    /// The lowest slot this certifier will still certify.
    pub fn floor(&self) -> u64 {
        self.floor
    }

    /// Slots whose derived body is held in memory (at most `retain`).
    pub fn retained(&self) -> usize {
        self.derived.len()
    }

    /// Raise the floor to `newest − retain + 1` (never lower it), drop what lies below, and compact `signed.bin`
    /// when it has grown well past the retained records. The new floor is made durable before any record is removed
    /// from disk.
    fn prune(&mut self) -> std::io::Result<()> {
        if let Some(&newest) = self.derived.keys().next_back() {
            self.floor = self.floor.max((newest + 1).saturating_sub(self.retain));
        }
        // Amortised O(1) per slot: each body and record is popped once.
        while self
            .derived
            .first_key_value()
            .is_some_and(|(&k, _)| k < self.floor)
        {
            self.derived.pop_first();
        }
        while self
            .signed
            .first_key_value()
            .is_some_and(|(&k, _)| k < self.floor)
        {
            self.signed.pop_first();
        }
        if self.on_disk > 2 * self.signed.len() + COMPACT_SLACK {
            let durable = |name: &str, bytes: &[u8]| durable_write(&self.dir, name, bytes);
            durable("floor.bin", &self.floor.to_be_bytes())?;
            let mut buf = Vec::with_capacity(self.signed.len() * 56);
            for (slot, d) in &self.signed {
                buf.extend_from_slice(&slot.to_be_bytes());
                buf.extend_from_slice(d);
            }
            durable("signed.bin", &buf)?;
            self.signed_log = std::fs::OpenOptions::new()
                .append(true)
                .open(self.dir.join("signed.bin"))?;
            self.on_disk = self.signed.len();
        }
        Ok(())
    }

    pub fn index(&self) -> u16 {
        self.index
    }

    /// The checkpoint body this certifier derived for `slot` (zero signature), if replicated.
    pub fn derived(&self, slot: u64) -> Option<Checkpoint> {
        self.derived.get(&slot).copied()
    }

    /// Co-sign `ck` if the operator signed it and it equals this certifier's own re-derivation of that slot.
    pub fn certify(&mut self, ck: &Checkpoint) -> Result<(u16, [u8; 64]), CertifyError> {
        if !ck.verify(&self.operator) {
            return Err(CertifyError::NotOperatorSigned);
        }
        if ck.slot < self.floor {
            return Err(CertifyError::Pruned {
                slot: ck.slot,
                floor: self.floor,
            });
        }
        let mine = self
            .derived
            .get(&ck.slot)
            .ok_or(CertifyError::NotYetReplicated { slot: ck.slot })?;
        if !mine.same_body(ck) {
            return Err(CertifyError::Mismatch { slot: ck.slot });
        }
        let d = ck.digest();
        match self.signed.get(&ck.slot) {
            Some(prev) if *prev != d => {
                return Err(CertifyError::AlreadySignedOther { slot: ck.slot })
            }
            Some(_) => {}
            None => {
                let mut rec = ck.slot.to_be_bytes().to_vec();
                rec.extend_from_slice(&d);
                self.signed_log.write_all(&rec)?;
                self.signed_log.sync_data()?;
                self.signed.insert(ck.slot, d);
                self.on_disk += 1;
            }
        }
        Ok((self.index, self.key.sign(&d).to_bytes()))
    }

    fn apply(
        &mut self,
        from: &nimbus_journal::Anchor,
        bytes: &[u8],
    ) -> Result<nimbus_journal::Anchor, String> {
        // The engine ships each slot's journal write as one batch; anything else is refused before it is written.
        // Record header: len (2) ‖ seq (8) ‖ slot (8); a record is 18 + len + 48 bytes (journal format).
        let mut slots = std::collections::BTreeSet::new();
        let mut off = 0;
        while off + 18 <= bytes.len() {
            let len = u16::from_be_bytes([bytes[off], bytes[off + 1]]) as usize;
            slots.insert(u64::from_be_bytes(
                bytes[off + 10..off + 18].try_into().expect("8"),
            ));
            off += 18 + len + 48;
        }
        let first = match (slots.len(), slots.first()) {
            (1, Some(&s)) => s,
            _ => return Err("a shipment must hold exactly one slot".into()),
        };
        let (after, records) = self
            .journal
            .replicate_records(from, bytes)
            .map_err(|e| format!("{e:?}"))?;
        let ck = self
            .replay
            .apply_slot(&records, after)
            .map_err(|e| format!("{e:?}"))?;
        self.derived.insert(first, ck);
        self.prune().map_err(|e| e.to_string())?;
        if self.snapshot_every > 0 && first >= self.last_snapshot + self.snapshot_every {
            // Encoded here; written durably in the background (the acknowledgement does not wait for the disk).
            let bytes = self.snapshot_body().map_err(|e| e.to_string())?;
            self.writer
                .get_or_insert_with(|| SnapshotWriter::new(&self.dir, "snapshot.bin"))
                .submit(bytes)?;
            self.last_snapshot = first;
        }
        Ok(after)
    }
}

/// A certifier shared between the engine (which ships it the journal as a `Replica`) and whoever asks it to certify.
#[derive(Clone)]
pub struct SharedCertifier(pub std::sync::Arc<std::sync::Mutex<Certifier>>);

impl SharedCertifier {
    pub fn new(c: Certifier) -> SharedCertifier {
        SharedCertifier(std::sync::Arc::new(std::sync::Mutex::new(c)))
    }
    pub fn certify(&self, ck: &Checkpoint) -> Result<(u16, [u8; 64]), CertifyError> {
        self.0.lock().expect("certifier lock").certify(ck)
    }
}

impl nimbus_pipeline::Replica for SharedCertifier {
    fn anchor(&self) -> nimbus_journal::Anchor {
        self.0.lock().expect("certifier lock").journal.anchor()
    }
    fn replicate(
        &mut self,
        from: &nimbus_journal::Anchor,
        bytes: &[u8],
    ) -> Result<nimbus_journal::Anchor, String> {
        self.0.lock().expect("certifier lock").apply(from, bytes)
    }
}

/// Collect co-signatures from certifiers until `quorum` have signed; refusals are returned alongside.
pub fn certify_with(
    certifiers: &[SharedCertifier],
    ck: &Checkpoint,
    quorum: usize,
) -> (Option<Certificate>, Vec<CertifyError>) {
    let mut sigs = Vec::new();
    let mut refusals = Vec::new();
    for c in certifiers {
        if sigs.len() == quorum {
            break;
        }
        match c.certify(ck) {
            Ok(s) => sigs.push(s),
            Err(e) => refusals.push(e),
        }
    }
    (
        (sigs.len() == quorum).then_some(Certificate { sigs }),
        refusals,
    )
}
