//! Finality proofs across validator-set and batch sizes: every index verifies with exactly the quorum, one signer
//! fewer is refused, and the wire codec round-trips.
use ed25519_dalek::SigningKey;
use nimbus_lightclient::*;

fn run(n: usize, batch: usize) {
    let keys: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[(i as u8).wrapping_add(40); 32]))
        .collect();
    let vs =
        ValidatorSet::new(&keys.iter().map(|k| k.verifying_key()).collect::<Vec<_>>()).unwrap();
    let q = vs.quorum();
    assert!(5 * q >= 4 * n && 5 * (q - 1) < 4 * n, "q = ceil(0.8 n)");
    let ops: Vec<Vec<u8>> = (0..batch).map(|i| format!("op-{i}").into_bytes()).collect();
    let signers: Vec<usize> = (n - q..n).collect();
    for idx in 0..batch {
        let p = testkit::build(&ops, idx, idx as u64 + 1, &keys, &signers);
        let b = p.encode();
        assert_eq!(verify_bytes(&vs, &b).unwrap().height, idx as u64 + 1);
        assert_eq!(FinalityProof::decode(&b).unwrap().encode(), b);
    }
    let short = testkit::build(&ops, 0, 1, &keys, &signers[1..]);
    assert_eq!(
        vs.verify(&short).err(),
        Some(Error::Quorum {
            have: q - 1,
            need: q
        })
    );
}

macro_rules! cases {
    ($($name:ident: $n:expr, $b:expr;)*) => {$(
        #[test]
        fn $name() { run($n, $b); }
    )*};
}

cases! {
    n1_batch1: 1, 1;
    n4_batch1: 4, 1;
    n4_batch7: 4, 7;
    n5_batch16: 5, 16;
    n7_batch3: 7, 3;
    n10_batch33: 10, 33;
    n21_batch9: 21, 9;
    n31_batch2: 31, 2;
    n64_batch5: 64, 5;
}

#[test]
fn a_proof_for_another_validator_set_is_refused() {
    let a: Vec<SigningKey> = (0..5)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect();
    let b: Vec<SigningKey> = (0..5)
        .map(|i| SigningKey::from_bytes(&[i + 100; 32]))
        .collect();
    let vb = ValidatorSet::new(&b.iter().map(|k| k.verifying_key()).collect::<Vec<_>>()).unwrap();
    let p = testkit::build(&[b"x".to_vec(), b"y".to_vec()], 1, 3, &a, &[0, 1, 2, 3]);
    assert_eq!(vb.verify(&p).err(), Some(Error::Signature));
}

#[test]
fn verify_bytes_reports_encoding_errors() {
    let a: Vec<SigningKey> = (0..4)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect();
    let vs = ValidatorSet::new(&a.iter().map(|k| k.verifying_key()).collect::<Vec<_>>()).unwrap();
    assert_eq!(verify_bytes(&vs, &[]).err(), Some(Error::Encoding));
    assert_eq!(verify_bytes(&vs, &[0xff; 300]).err(), Some(Error::Encoding));
}
