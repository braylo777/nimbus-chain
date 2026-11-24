//! Settlement against real pipeline receipts: pay once, refund once, survive restarts, refuse forgeries.
use ed25519_dalek::SigningKey;
use nimbus_bridge::*;
use nimbus_order::*;
use nimbus_pipeline::*;

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nimbus-bridge-{tag}-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn withdrawals_pay_once_rejected_deposits_refund_once() {
    let d = dir("settle");
    let user = SigningKey::from_bytes(&[1; 32]);
    let bridge: Vec<SigningKey> = (10..13u8)
        .map(|b| SigningKey::from_bytes(&[b; 32]))
        .collect();
    let operator = SigningKey::from_bytes(&[9; 32]);
    let g = Genesis {
        accounts: vec![(7, user.verifying_key())],
        deposits: vec![(0, 7, 1_000, 50_000)],
        bridge: bridge.iter().map(|k| k.verifying_key()).collect(),
        bridge_threshold: 2,
        deposit_cap: None,
        fees: Default::default(),
    };
    let cfg = Config {
        markets: 2,
        max_life: 100,
        fsync: true,
        min_batch: 16,
    };
    let (mut p, _) = Pipeline::open(&d.join("engine"), cfg, &g, operator.clone(), None).unwrap();
    let withdraw = Entry::Action(SignedAction::sign(
        Action {
            market: 0,
            acct: 7,
            nonce: 0,
            expiry_slot: 50,
            kind: ActionKind::Withdraw {
                base: 0,
                quote: 20_000,
            },
        },
        &user,
    ));
    // A deposit the engine must reject: it would push total quote supply past u128::MAX.
    let huge = BridgeOp {
        reference: [5; 32],
        expiry_slot: 50,
        kind: BridgeKind::Deposit {
            market: 0,
            acct: 7,
            base: 0,
            quote: u128::MAX,
        },
    };
    let dep = Entry::Bridge(SignedBridge::sign(
        huge,
        &[(0, &bridge[0]), (1, &bridge[1])],
    ));
    let r = p
        .process_slot(1, &[withdraw.to_bytes(), dep.to_bytes()])
        .unwrap();
    let wd = r.proof(r.decisions[0].clone().unwrap()).unwrap();
    let rj = r.proof(r.decisions[1].clone().unwrap()).unwrap();
    assert!(matches!(rj.receipt.status, Status::Rejected(_)));

    let log = d.join("settled.bin");
    let mut s = Settlement::open(&log, operator.verifying_key()).unwrap();
    assert_eq!(
        s.pay(&wd).unwrap(),
        Instruction::Pay {
            acct: 7,
            market: 0,
            base: 0,
            quote: 20_000
        }
    );
    assert!(matches!(s.pay(&wd), Err(SettleError::AlreadySettled)));
    // A withdrawal receipt is not a refund, a rejected deposit is not a payout, and the operation must match.
    assert!(matches!(s.pay(&rj), Err(SettleError::NotSettleable)));
    let other = BridgeOp {
        reference: [6; 32],
        ..huge
    };
    assert!(matches!(
        s.refund(&rj, &other),
        Err(SettleError::OperationMismatch)
    ));
    assert_eq!(
        s.refund(&rj, &huge).unwrap(),
        Instruction::Refund {
            acct: 7,
            market: 0,
            base: 0,
            quote: u128::MAX,
            reference: [5; 32]
        }
    );
    // Restart: nothing settles twice; a torn trailing write is cut away.
    drop(s);
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut f, &[0xAB; 20]).unwrap();
    let mut s = Settlement::open(&log, operator.verifying_key()).unwrap();
    assert_eq!(s.settled_count(), 2);
    assert!(matches!(s.pay(&wd), Err(SettleError::AlreadySettled)));
    assert!(matches!(
        s.refund(&rj, &huge),
        Err(SettleError::AlreadySettled)
    ));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn forged_or_foreign_receipts_are_refused() {
    let d = dir("forge");
    let user = SigningKey::from_bytes(&[1; 32]);
    let operator = SigningKey::from_bytes(&[9; 32]);
    let g = Genesis {
        accounts: vec![(7, user.verifying_key())],
        deposits: vec![(0, 7, 1_000, 50_000)],
        bridge: Vec::new(),
        bridge_threshold: 0,
        deposit_cap: None,
        fees: Default::default(),
    };
    let cfg = Config {
        markets: 1,
        max_life: 100,
        fsync: true,
        min_batch: 16,
    };
    let (mut p, _) = Pipeline::open(&d.join("engine"), cfg, &g, operator.clone(), None).unwrap();
    let w = Entry::Action(SignedAction::sign(
        Action {
            market: 0,
            acct: 7,
            nonce: 0,
            expiry_slot: 50,
            kind: ActionKind::Withdraw {
                base: 0,
                quote: 1_000,
            },
        },
        &user,
    ));
    let r = p.process_slot(1, &[w.to_bytes()]).unwrap();
    let good = r.proof(0).unwrap();
    let mut s = Settlement::open(&d.join("settled.bin"), operator.verifying_key()).unwrap();
    let mut inflated = good.clone();
    inflated.receipt.status = Status::Withdrawn {
        base: 0,
        quote: 1_000_000,
    };
    assert!(
        matches!(s.pay(&inflated), Err(SettleError::BadProof)),
        "amount changed after signing"
    );
    let mut redirected = good.clone();
    redirected.receipt.acct = 8;
    assert!(
        matches!(s.pay(&redirected), Err(SettleError::BadProof)),
        "payee changed"
    );
    let mut foreign = Settlement::open(
        &d.join("other.bin"),
        SigningKey::from_bytes(&[3; 32]).verifying_key(),
    )
    .unwrap();
    assert!(
        matches!(foreign.pay(&good), Err(SettleError::BadProof)),
        "checkpoint from another operator"
    );
    assert!(s.pay(&good).is_ok());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_second_signed_checkpoint_for_a_slot_is_refused_as_equivocation() {
    use ed25519_dalek::Signer;
    let d = dir("equiv");
    let user = SigningKey::from_bytes(&[1; 32]);
    let operator = SigningKey::from_bytes(&[9; 32]);
    let g = Genesis {
        accounts: vec![(7, user.verifying_key())],
        deposits: vec![(0, 7, 1_000, 50_000)],
        bridge: Vec::new(),
        bridge_threshold: 0,
        deposit_cap: None,
        fees: Default::default(),
    };
    let cfg = Config {
        markets: 1,
        max_life: 100,
        fsync: true,
        min_batch: 16,
    };
    let (mut p, _) = Pipeline::open(&d.join("engine"), cfg, &g, operator.clone(), None).unwrap();
    let w = Entry::Action(SignedAction::sign(
        Action {
            market: 0,
            acct: 7,
            nonce: 0,
            expiry_slot: 50,
            kind: ActionKind::Withdraw {
                base: 0,
                quote: 1_000,
            },
        },
        &user,
    ));
    let r = p.process_slot(1, &[w.to_bytes()]).unwrap();
    let real = r.proof(0).unwrap();
    let mut s = Settlement::open(&d.join("settled.bin"), operator.verifying_key()).unwrap();
    s.pay(&real).unwrap();
    // A malicious operator fabricates a one-receipt tree for the same slot and signs a second checkpoint for it.
    let mut fake = real.clone();
    fake.receipt.status = Status::Withdrawn {
        base: 0,
        quote: 40_000,
    };
    fake.index = 0;
    fake.path.clear();
    fake.checkpoint.receipts = 1;
    fake.checkpoint.receipts_root = fake.receipt.leaf();
    fake.checkpoint.sig = operator.sign(&fake.checkpoint.digest()).to_bytes();
    assert!(
        fake.verify(&operator.verifying_key()),
        "the fabricated proof is validly signed"
    );
    assert!(matches!(
        s.pay(&fake),
        Err(SettleError::Equivocation { slot: 1 })
    ));
    drop(s);
    let mut s = Settlement::open(&d.join("settled.bin"), operator.verifying_key()).unwrap();
    assert!(
        matches!(s.pay(&fake), Err(SettleError::Equivocation { slot: 1 })),
        "remembered across restarts"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn certified_bridge_needs_a_validator_quorum_on_the_checkpoint() {
    use ed25519_dalek::Signer;
    let d = dir("cert");
    let user = SigningKey::from_bytes(&[1; 32]);
    let operator = SigningKey::from_bytes(&[9; 32]);
    let vals: Vec<SigningKey> = (40..47u8)
        .map(|b| SigningKey::from_bytes(&[b; 32]))
        .collect(); // n = 7, quorum 5 (3·5 > 2·7)
    let vpk: Vec<_> = vals.iter().map(|k| k.verifying_key()).collect();
    assert!(
        Validators::new(&vpk, 4).is_err(),
        "3·4 ≤ 14: two quorums could share no honest validator"
    );
    assert!(Validators::new(&vpk, 8).is_err());
    let g = Genesis {
        accounts: vec![(7, user.verifying_key())],
        deposits: vec![(0, 7, 1_000, 50_000)],
        bridge: Vec::new(),
        bridge_threshold: 0,
        deposit_cap: None,
        fees: Default::default(),
    };
    let cfg = Config {
        markets: 1,
        max_life: 100,
        fsync: true,
        min_batch: 16,
    };
    let (mut p, _) = Pipeline::open(&d.join("engine"), cfg, &g, operator.clone(), None).unwrap();
    let w = |nonce, quote| {
        Entry::Action(SignedAction::sign(
            Action {
                market: 0,
                acct: 7,
                nonce,
                expiry_slot: 50,
                kind: ActionKind::Withdraw { base: 0, quote },
            },
            &user,
        ))
        .to_bytes()
    };
    let r1 = p.process_slot(1, &[w(0, 1_000)]).unwrap();
    let r2 = p.process_slot(2, &[w(1, 2_000)]).unwrap();
    let (a, b) = (r1.proof(0).unwrap(), r2.proof(0).unwrap());
    let signers = |ids: &[u16]| -> Vec<(u16, &SigningKey)> {
        ids.iter().map(|&i| (i, &vals[i as usize])).collect()
    };
    let cert_a = Certificate::sign(&a.checkpoint, &signers(&[0, 1, 2, 3, 4]));
    let mut s = Settlement::open_certified(
        &d.join("settled.bin"),
        operator.verifying_key(),
        Validators::new(&vpk, 5).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        s.pay(&a),
        Err(SettleError::Uncertified(CertError::Missing))
    ));
    let short = Certificate::sign(&a.checkpoint, &signers(&[0, 1, 2, 3]));
    assert!(matches!(
        s.pay_certified(&a, &short),
        Err(SettleError::Uncertified(CertError::Quorum {
            have: 4,
            need: 5
        }))
    ));
    let mut dup = short.clone();
    dup.sigs.push(dup.sigs[0]);
    assert!(matches!(
        s.pay_certified(&a, &dup),
        Err(SettleError::Uncertified(CertError::DuplicateSigner))
    ));
    let mut unknown = short.clone();
    unknown.sigs.push((7, [0; 64]));
    assert!(matches!(
        s.pay_certified(&a, &unknown),
        Err(SettleError::Uncertified(CertError::UnknownValidator))
    ));
    // A certificate for slot 1 does not certify slot 2.
    assert!(matches!(
        s.pay_certified(&b, &cert_a),
        Err(SettleError::Uncertified(CertError::Signature))
    ));
    assert!(s.pay_certified(&a, &cert_a).is_ok());

    // The operator fabricates a checkpoint for slot 3, which the bridge has never seen. Its own signature verifies;
    // only the two faulty validators (5, 6) co-sign it, which is below the quorum.
    let mut fake = b.clone();
    fake.receipt.slot = 3;
    fake.receipt.status = Status::Withdrawn {
        base: 0,
        quote: 40_000,
    };
    fake.index = 0;
    fake.path.clear();
    fake.checkpoint.slot = 3;
    fake.checkpoint.receipts = 1;
    fake.checkpoint.receipts_root = fake.receipt.leaf();
    fake.checkpoint.sig = operator.sign(&fake.checkpoint.digest()).to_bytes();
    assert!(fake.verify(&operator.verifying_key()));
    let mut plain = Settlement::open(&d.join("plain.bin"), operator.verifying_key()).unwrap();
    assert!(
        plain.pay(&fake).is_ok(),
        "without certification (v0.7, finding B6) the fabricated checkpoint pays"
    );
    let faulty = Certificate::sign(&fake.checkpoint, &signers(&[5, 6]));
    assert!(matches!(
        s.pay_certified(&fake, &faulty),
        Err(SettleError::Uncertified(CertError::Quorum { .. }))
    ));
    // Padding the faulty signatures with honest signatures of a different checkpoint fails the batch.
    let mut padded = faulty.clone();
    padded
        .sigs
        .extend(Certificate::sign(&b.checkpoint, &signers(&[0, 1, 2])).sigs);
    assert!(matches!(
        s.pay_certified(&fake, &padded),
        Err(SettleError::Uncertified(CertError::Signature))
    ));
    let cert_b = Certificate::sign(&b.checkpoint, &signers(&[2, 3, 4, 5, 6]));
    assert!(s.pay_certified(&b, &cert_b).is_ok());
    assert_eq!(s.settled_count(), 2);
    let _ = std::fs::remove_dir_all(&d);
}
