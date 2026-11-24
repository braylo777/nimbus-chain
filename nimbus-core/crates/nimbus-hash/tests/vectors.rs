//! Table-driven Merkle checks per tree size: the reference, streaming, parallel and indexed-tree roots agree, every
//! audit path verifies at its own index only, and the three domains never collide.
use nimbus_hash::*;

fn items(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| {
            let mut v = (i as u64).to_be_bytes().to_vec();
            v.extend_from_slice(&[(i % 251) as u8; 23]);
            v
        })
        .collect()
}

fn check_size(n: usize) {
    for t in [BATCH, HISTORY, STATE] {
        let it = items(n);
        let reference = merkle_root(t, &it);
        assert_eq!(par_merkle_root(t, &it), reference, "parallel n={n}");
        let mut f = Frontier::new(t);
        for x in &it {
            f.push(x);
        }
        assert_eq!(f.root(), reference, "streaming n={n}");
        assert_eq!(f.len(), n as u64);
        if n > 0 {
            let fold = (n as u64).count_ones() as u64 - 1; // the final fold of the frontier
            assert_eq!(f.hashes() + fold, 2 * n as u64 - 1, "2m - 1 hashes, n={n}");
        }
        let tree = MerkleTree::from_items(t, &it);
        assert_eq!(tree.root(), reference, "indexed tree n={n}");
        assert_eq!(tree.len(), n);
        let leaves: Vec<Hash> = it.iter().map(|x| leaf_hash(t, x)).collect();
        for i in 0..n {
            let p = audit_path(t, &leaves, i);
            assert_eq!(tree.path(i), p, "tree path = reference path, n={n} i={i}");
            assert!(verify_audit_path(
                t, &leaves[i], i as u64, n as u64, &p, &reference
            ));
            if n > 1 {
                let j = (i + 1) % n;
                assert!(
                    leaves[i] == leaves[j]
                        || !verify_audit_path(t, &leaves[i], j as u64, n as u64, &p, &reference),
                    "path for {i} must not verify at {j}, n={n}"
                );
            }
            assert!(!verify_audit_path(
                t, &leaves[i], n as u64, n as u64, &p, &reference
            ));
        }
    }
}

macro_rules! sizes {
    ($($name:ident: $n:expr,)*) => {$(
        #[test]
        fn $name() { check_size($n); }
    )*};
}

sizes! {
    size_0: 0, size_1: 1, size_2: 2, size_3: 3, size_4: 4, size_5: 5, size_6: 6, size_7: 7, size_8: 8,
    size_9: 9, size_15: 15, size_16: 16, size_17: 17, size_31: 31, size_33: 33, size_63: 63, size_64: 64,
    size_65: 65, size_100: 100, size_127: 127, size_129: 129, size_255: 255, size_257: 257, size_1023: 1023,
    size_1025: 1025, size_2049: 2049,
}

#[test]
fn domains_separate_identical_inputs() {
    let x = b"same bytes";
    let l = [
        leaf_hash(BATCH, x),
        leaf_hash(HISTORY, x),
        leaf_hash(STATE, x),
    ];
    assert!(l[0] != l[1] && l[1] != l[2] && l[0] != l[2]);
    let (a, b) = ([1u8; 48], [2u8; 48]);
    let n = [
        node_hash(BATCH, &a, &b),
        node_hash(HISTORY, &a, &b),
        node_hash(STATE, &a, &b),
    ];
    assert!(n[0] != n[1] && n[1] != n[2] && n[0] != n[2]);
}

#[test]
fn leaf_and_node_tags_differ_so_a_node_is_never_a_leaf() {
    let (a, b) = ([3u8; 48], [4u8; 48]);
    let mut cat = a.to_vec();
    cat.extend_from_slice(&b);
    assert_ne!(node_hash(BATCH, &a, &b), leaf_hash(BATCH, &cat));
}

#[test]
fn empty_roots_are_domain_tagged() {
    assert_eq!(empty_root(BATCH), hash_tagged(domain::BATCH_NODE, &[]));
    assert_ne!(empty_root(BATCH), empty_root(STATE));
    assert_eq!(merkle_root::<&[u8]>(BATCH, &[]), empty_root(BATCH));
}

#[test]
fn single_leaf_root_is_the_leaf_hash() {
    assert_eq!(merkle_root(HISTORY, &[b"x"]), leaf_hash(HISTORY, b"x"));
}

#[test]
fn order_matters() {
    assert_ne!(
        merkle_root(BATCH, &[b"a", b"b"]),
        merkle_root(BATCH, &[b"b", b"a"])
    );
}

#[test]
fn hash_tagged_is_concatenation_insensitive_to_part_boundaries() {
    assert_eq!(
        hash_tagged(9, &[b"ab", b"cd"]),
        hash_tagged(9, &[b"a", b"bcd"])
    );
    assert_ne!(hash_tagged(9, &[b"abcd"]), hash_tagged(10, &[b"abcd"]));
}

#[test]
fn reader_reads_big_endian_and_reports_truncation() {
    let mut b = vec![7u8];
    b.extend_from_slice(&0x0102u16.to_be_bytes());
    b.extend_from_slice(&0x03040506u32.to_be_bytes());
    b.extend_from_slice(&42u64.to_be_bytes());
    b.extend_from_slice(&(1u128 << 100).to_be_bytes());
    let mut r = Reader::new(&b);
    assert_eq!(r.u8().unwrap(), 7);
    assert_eq!(r.u16().unwrap(), 0x0102);
    assert_eq!(r.u32().unwrap(), 0x03040506);
    assert_eq!(r.u64().unwrap(), 42);
    assert_eq!(r.u128().unwrap(), 1 << 100);
    assert_eq!(r.remaining(), 0);
    assert!(r.end().is_ok());
    assert!(r.u8().is_err());
    let mut r = Reader::new(&b[..3]);
    assert!(r.u32().is_err());
}

#[test]
fn reader_array_take_and_trailing_bytes() {
    let b = [1u8, 2, 3, 4, 5];
    let mut r = Reader::new(&b);
    assert_eq!(r.array::<2>().unwrap(), [1, 2]);
    assert_eq!(r.take(2).unwrap(), &[3, 4]);
    assert!(r.end().is_err(), "one byte left");
    assert!(r.take(2).is_err());
}

#[test]
fn reader_count_bounds_allocation_by_remaining_bytes() {
    let mut b = 1_000_000u32.to_be_bytes().to_vec();
    b.extend_from_slice(&[0u8; 10]);
    let mut r = Reader::new(&b);
    assert!(
        r.count(8).is_err(),
        "a count larger than the input allows is refused"
    );
    let mut b = 2u32.to_be_bytes().to_vec();
    b.extend_from_slice(&[0u8; 16]);
    let mut r = Reader::new(&b);
    assert_eq!(r.count(8).unwrap(), 2);
}
