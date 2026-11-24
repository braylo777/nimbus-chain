//! Light-client verification of untrusted proof bytes: decoding never panics, decode ∘ encode is the identity,
//! and no proof derived from a valid one by the fuzzer's edits verifies unless its verified content is unchanged.
#![no_main]
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use nimbus_lightclient::{testkit, verify_bytes, FinalityProof, ValidatorSet};
use rand::{rngs::StdRng, SeedableRng};
use std::sync::OnceLock;

struct Fixture {
    set: ValidatorSet,
    valid: Vec<u8>,
    proof: FinalityProof,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(3);
        let keys: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut rng)).collect();
        let set =
            ValidatorSet::new(&keys.iter().map(|k| k.verifying_key()).collect::<Vec<_>>()).unwrap();
        let ops: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 40]).collect();
        let proof = testkit::build(&ops, 2, 9, &keys, &[0, 1, 2, 3]);
        Fixture {
            set,
            valid: proof.encode(),
            proof,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    // 1. Raw bytes.
    if let Ok(p) = FinalityProof::decode(data) {
        assert_eq!(p.encode(), data);
        let _ = f.set.verify(&p);
    }
    // 2. Edits of a valid proof.
    let mut b = f.valid.clone();
    for c in data.chunks_exact(3) {
        let i = u16::from_le_bytes([c[0], c[1]]) as usize % b.len();
        b[i] ^= c[2];
    }
    if let Ok(h) = verify_bytes(&f.set, &b) {
        let p = FinalityProof::decode(&b).unwrap();
        assert_eq!(p.op, f.proof.op, "a different operation was proven");
        assert_eq!(p.header, f.proof.header);
        assert_eq!(h.height, 9);
    }
});
