//! The single Ed25519 rule: every small-order and non-canonical key is refused, and batched verification (rayon or
//! spin pool, any batch size) finds exactly the invalid signatures for each adversarial pattern.
use ed25519_dalek::{Signer, SigningKey};
use nimbus_sig::*;

fn hex32(s: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, c) in b.iter_mut().enumerate() {
        *c = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    b
}

macro_rules! weak_key {
    ($($name:ident: $hex:expr, $why:expr;)*) => {$(
        #[test]
        fn $name() {
            let k = hex32($hex);
            assert!(CheckedKey::new(k).is_none());
            assert_eq!(key_problem(&k), Some($why));
        }
    )*};
}

// The eight small-order points of edwards25519 (canonical encodings) and non-canonical / invalid encodings.
weak_key! {
    order_1_identity: "0100000000000000000000000000000000000000000000000000000000000000", "small-order (weak) key";
    order_2: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "small-order (weak) key";
    order_4_a: "0000000000000000000000000000000000000000000000000000000000000000", "small-order (weak) key";
    order_4_b: "0000000000000000000000000000000000000000000000000000000000000080", "small-order (weak) key";
    order_8_a: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "small-order (weak) key";
    order_8_b: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "small-order (weak) key";
    order_8_c: "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "small-order (weak) key";
    order_8_d: "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "small-order (weak) key";
    non_canonical_y_equals_p: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "non-canonical encoding";
    non_canonical_identity_plus_p: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "non-canonical encoding";
}

#[test]
fn not_a_curve_point() {
    // y = 2 has no x on the curve.
    let k = hex32("0200000000000000000000000000000000000000000000000000000000000000");
    assert!(CheckedKey::new(k).is_none());
    assert_eq!(key_problem(&k), Some("not a curve point"));
}

#[test]
fn ordinary_keys_pass() {
    for i in 1..=20u8 {
        let k = SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes();
        assert_eq!(key_problem(&k), None);
        assert_eq!(CheckedKey::new(k).unwrap().as_bytes(), &k);
    }
}

fn items(n: usize, bad: impl Fn(usize) -> bool) -> Vec<Item> {
    (0..n)
        .map(|i| {
            let sk = SigningKey::from_bytes(&[(i % 7) as u8 + 1; 32]);
            let mut msg = [0u8; 48];
            msg[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut sig = sk.sign(&msg).to_bytes();
            if bad(i) {
                sig[(i * 13) % 32] ^= 1 << (i % 8);
            }
            Item {
                key: CheckedKey::new(sk.verifying_key().to_bytes()).unwrap(),
                msg,
                sig,
            }
        })
        .collect()
}

fn check(n: usize, bad: impl Fn(usize) -> bool + Copy) {
    let it = items(n, bad);
    let expect: Vec<bool> = (0..n).map(|i| !bad(i)).collect();
    for (i, x) in it.iter().enumerate() {
        assert_eq!(verify(&x.key, &x.msg, &x.sig), expect[i], "single {i}");
    }
    assert_eq!(verify_all(&it), expect, "verify_all");
    for mb in [1, 4, 64] {
        assert_eq!(verify_all_with(&it, mb), expect, "min_batch {mb}");
    }
    assert_eq!(verify_batch(&it), expect.iter().all(|x| *x));
}

macro_rules! patterns {
    ($($name:ident: $n:expr, $bad:expr;)*) => {$(
        #[test]
        fn $name() { check($n, $bad); }
    )*};
}

patterns! {
    all_valid_1: 1, |_| false;
    all_valid_100: 100, |_| false;
    all_invalid_33: 33, |_| true;
    first_bad: 50, |i| i == 0;
    last_bad: 50, |i| i == 49;
    middle_bad: 51, |i| i == 25;
    alternating: 40, |i| i % 2 == 1;
    every_seventeenth: 200, |i| i % 17 == 3;
    dense_block: 64, |i| (20..30).contains(&i);
}

#[test]
fn empty_input() {
    assert!(verify_all(&[]).is_empty());
    assert!(verify_batch(&[]));
}

#[test]
fn spin_pool_equals_single_verification() {
    let pool = SpinPool::new(2);
    for (n, every) in [(1usize, 2usize), (16, 3), (100, 7), (257, 11)] {
        let it = items(n, |i| i % every == 1);
        let expect: Vec<bool> = (0..n).map(|i| i % every != 1).collect();
        assert_eq!(pool.verify_all(&it), expect, "n {n}");
    }
}

#[test]
fn a_signature_under_another_message_fails() {
    let mut it = items(3, |_| false);
    it[1].msg[47] ^= 1;
    assert_eq!(verify_all(&it), vec![true, false, true]);
}
