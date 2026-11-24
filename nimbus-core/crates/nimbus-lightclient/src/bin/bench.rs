//! Proof size and verification time for n = 21 / 64 / 100 validators.
use ed25519_dalek::SigningKey;
use nimbus_lightclient::{testkit::build, ValidatorSet};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::time::Instant;

fn main() {
    let mut rng = StdRng::seed_from_u64(3);
    let ops: Vec<Vec<u8>> = (0..1366)
        .map(|_| {
            let mut v = vec![0u8; 96];
            rng.fill(&mut v[..]);
            v
        })
        .collect();
    for n in [21usize, 64, 100] {
        let keys: Vec<SigningKey> = (0..n).map(|_| SigningKey::generate(&mut rng)).collect();
        let vs = ValidatorSet::new(&keys.iter().map(|k| k.verifying_key()).collect::<Vec<_>>())
            .expect("valid keys");
        let q = vs.quorum();
        let p = build(&ops, 777, 1, &keys, &(0..q).collect::<Vec<_>>());
        let bytes = p.op.len() + 16 + p.path.len() * 48 + p.header.len() + p.cert.sigs.len() * 66;
        let reps = 2000;
        let mut ts: Vec<f64> = (0..reps)
            .map(|_| {
                let t = Instant::now();
                vs.verify(&p).unwrap();
                t.elapsed().as_secs_f64() * 1e6
            })
            .collect();
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("n = {n:3} (q = {q:2}): proof {bytes} B, verify p50 {:.0} us, p99 {:.0} us (one core, ZIP-215 batch)", ts[reps / 2], ts[reps * 99 / 100]);
    }
}
