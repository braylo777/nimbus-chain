//! Market snapshots: encode → decode reproduces a market that behaves identically on every later operation, the
//! encoding is canonical (a decodable input re-encodes to itself), and the decoder refuses damaged input without
//! panicking.
use nimbus_hash::Reader;
use nimbus_match::*;
use proptest::prelude::*;

fn ops() -> impl Strategy<Value = Op> {
    prop_oneof![
        1 => (0u32..5, 0u128..80, 0u128..4000).prop_map(|(a, b, q)| Op::Deposit { acct: a, base: b, quote: q }),
        1 => (0u32..5, 0u128..30, 0u128..600).prop_map(|(a, b, q)| Op::Withdraw { acct: a, base: b, quote: q }),
        8 => (0u32..5, any::<bool>(), 1u64..20, 1u64..14, 0u8..4).prop_map(|(a, bid, p, q, t)| Op::Order {
            acct: a, side: if bid { Side::Bid } else { Side::Ask }, price: p, qty: q,
            tif: [Tif::Gtc, Tif::Ioc, Tif::Fok, Tif::PostOnly][t as usize] }),
        2 => (0u32..5, 0u64..60).prop_map(|(a, id)| Op::Cancel { acct: a, id }),
    ]
}

fn market(fees: u8) -> Market {
    let mut m = Market::new();
    let f = match fees {
        0 => Fees::default(),
        1 => Fees {
            maker_bps: 10,
            taker_bps: 25,
            collector: 9,
            maker_rebate_bps: 0,
        },
        _ => Fees {
            maker_bps: 0,
            taker_bps: 25,
            collector: 3,
            maker_rebate_bps: 10,
        },
    };
    m.set_fees(f).unwrap();
    m
}

fn encode(m: &Market) -> Vec<u8> {
    let mut v = Vec::new();
    m.encode_into(&mut v);
    v
}

fn decode(b: &[u8]) -> Option<Market> {
    let mut r = Reader::new(b);
    let m = Market::decode_from(&mut r).ok()?;
    r.end().ok()?;
    Some(m)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(1000), .. ProptestConfig::default() })]

    /// Snapshot after any prefix, restore, run the rest on both: identical outcomes, state hashes and encodings.
    #[test]
    fn a_restored_market_behaves_identically(ops in prop::collection::vec(ops(), 1..300), cut in 0usize..300, fees in 0u8..3) {
        let cut = cut % ops.len();
        let mut a = market(fees);
        for op in &ops[..cut] {
            a.apply(op);
        }
        let bytes = encode(&a);
        let mut b = decode(&bytes).expect("a market's own encoding decodes");
        prop_assert_eq!(encode(&b), bytes);
        prop_assert_eq!(a.state_hash(), b.state_hash());
        for (k, op) in ops[cut..].iter().enumerate() {
            prop_assert_eq!(a.apply(op), b.apply(op), "op {} after the snapshot", k);
        }
        prop_assert_eq!(encode(&a), encode(&b));
    }

    /// Damaged snapshots: a flipped bit, a cut, or appended bytes either fail to decode or decode to a market whose
    /// encoding is exactly the input (never a panic, never two encodings of one market).
    #[test]
    fn damaged_snapshots_are_refused_or_canonical(ops in prop::collection::vec(ops(), 1..120), byte in any::<usize>(), bit in 0u8..8, cut in any::<usize>()) {
        let mut a = market(1);
        for op in &ops {
            a.apply(op);
        }
        let bytes = encode(&a);
        let mut flipped = bytes.clone();
        let i = byte % flipped.len();
        flipped[i] ^= 1 << bit;
        for input in [flipped, bytes[..cut % bytes.len()].to_vec(), [bytes.clone(), vec![0]].concat()] {
            if let Some(m) = decode(&input) {
                prop_assert_eq!(encode(&m), input);
                prop_assert!(m.check_invariants().is_ok());
            }
        }
    }
}
