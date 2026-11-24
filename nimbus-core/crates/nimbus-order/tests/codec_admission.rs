//! Wire codecs (orders 0x09, actions 0x0F, bridge operations 0x10, entries) and client admission rules, one rule per
//! test.
use ed25519_dalek::SigningKey;
use nimbus_match::{Side, Tif};
use nimbus_order::*;

fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i; 32])
}
fn intent(side: Side, tif: Tif) -> Intent {
    Intent {
        market: 3,
        acct: 7,
        side,
        price: 1_234,
        qty: 56,
        tif,
        nonce: 0,
        expiry_slot: 100,
    }
}

macro_rules! intent_roundtrip {
    ($($name:ident: $side:expr, $tif:expr;)*) => {$(
        #[test]
        fn $name() {
            let i = intent($side, $tif);
            assert_eq!(Intent::decode(&i.encode()).unwrap(), i);
            let o = SignedOrder::sign(i, &key(1));
            let b = o.to_bytes();
            assert_eq!(SignedOrder::from_bytes(&b).unwrap(), o);
            assert!(o.signature_valid());
            let e = Entry::Order(o);
            assert_eq!(Entry::from_bytes(&e.to_bytes()).unwrap(), e);
        }
    )*};
}

intent_roundtrip! {
    bid_gtc: Side::Bid, Tif::Gtc; bid_ioc: Side::Bid, Tif::Ioc; bid_fok: Side::Bid, Tif::Fok;
    bid_post_only: Side::Bid, Tif::PostOnly; ask_gtc: Side::Ask, Tif::Gtc; ask_ioc: Side::Ask, Tif::Ioc;
    ask_fok: Side::Ask, Tif::Fok; ask_post_only: Side::Ask, Tif::PostOnly;
}

macro_rules! intent_field_rejected {
    ($($name:ident: $at:expr, $val:expr, $why:expr;)*) => {$(
        #[test]
        fn $name() {
            let mut b = intent(Side::Bid, Tif::Gtc).encode();
            b[$at] = $val;
            assert_eq!(Intent::decode(&b).err(), Some(OrderError::Field($why)));
        }
    )*};
}

intent_field_rejected! {
    side_byte_2_rejected: 8, 2, "side";
    side_byte_ff_rejected: 8, 0xff, "side";
    tif_byte_4_rejected: 25, 4, "tif";
    tif_byte_ff_rejected: 25, 0xff, "tif";
    reserved_byte_rejected: 42, 1, "reserved";
}

#[test]
fn zero_price_or_qty_rejected_on_the_wire() {
    let mut i = intent(Side::Bid, Tif::Gtc);
    i.price = 0;
    assert_eq!(
        Intent::decode(&i.encode()).err(),
        Some(OrderError::Field("zero price or qty"))
    );
    let mut i = intent(Side::Bid, Tif::Gtc);
    i.qty = 0;
    assert!(Intent::decode(&i.encode()).is_err());
}

#[test]
fn every_wrong_length_is_refused() {
    let o = SignedOrder::sign(intent(Side::Ask, Tif::Gtc), &key(1)).to_bytes();
    for n in 0..WIRE_LEN {
        assert_eq!(
            SignedOrder::from_bytes(&o[..n]).err(),
            Some(OrderError::Length)
        );
    }
    let mut longer = o.to_vec();
    longer.push(0);
    assert_eq!(
        SignedOrder::from_bytes(&longer).err(),
        Some(OrderError::Length)
    );
}

#[test]
fn unknown_wire_version_is_refused() {
    let mut o = SignedOrder::sign(intent(Side::Ask, Tif::Gtc), &key(1)).to_bytes();
    o[WIRE_LEN - 1] = 2;
    assert_eq!(SignedOrder::from_bytes(&o).err(), Some(OrderError::Version));
}

#[test]
fn a_flipped_signature_bit_fails_verification() {
    let mut o = SignedOrder::sign(intent(Side::Ask, Tif::Gtc), &key(1));
    o.sig[5] ^= 1;
    assert!(!o.signature_valid());
    assert_eq!(o.verify().err(), Some(OrderError::BadSignature));
}

#[test]
fn a_changed_field_invalidates_the_signature() {
    let mut o = SignedOrder::sign(intent(Side::Ask, Tif::Gtc), &key(1));
    o.intent.price += 1;
    assert!(!o.signature_valid());
}

#[test]
fn action_cancel_roundtrip() {
    let a = Action {
        market: 1,
        acct: 2,
        nonce: 3,
        expiry_slot: 4,
        kind: ActionKind::Cancel { order_id: 99 },
    };
    assert_eq!(Action::decode(&a.encode()).unwrap(), a);
    let s = SignedAction::sign(a, &key(2));
    assert_eq!(SignedAction::from_bytes(&s.to_bytes()).unwrap(), s);
}

#[test]
fn action_withdraw_roundtrip() {
    let a = Action {
        market: 1,
        acct: 2,
        nonce: 3,
        expiry_slot: 4,
        kind: ActionKind::Withdraw {
            base: 1 << 100,
            quote: 5,
        },
    };
    assert_eq!(Action::decode(&a.encode()).unwrap(), a);
    let e = Entry::Action(SignedAction::sign(a, &key(2)));
    assert_eq!(Entry::from_bytes(&e.to_bytes()).unwrap(), e);
}

#[test]
fn action_unknown_kind_is_refused() {
    let mut b = Action {
        market: 1,
        acct: 2,
        nonce: 3,
        expiry_slot: 4,
        kind: ActionKind::Cancel { order_id: 1 },
    }
    .encode();
    b[0] = 9;
    assert!(Action::decode(&b).is_err());
    assert_eq!(Action::decode(&b[..10]).err(), Some(OrderError::Length));
}

#[test]
fn bridge_deposit_and_register_roundtrip() {
    for kind in [
        BridgeKind::Deposit {
            market: 1,
            acct: 2,
            base: 3,
            quote: 4,
        },
        BridgeKind::Register {
            acct: 5,
            key: key(5).verifying_key().to_bytes(),
        },
    ] {
        let op = BridgeOp {
            reference: [7; 32],
            expiry_slot: 50,
            kind,
        };
        assert_eq!(BridgeOp::decode(&op.encode()).unwrap(), op);
        let s = SignedBridge::sign(op, &[(0, &key(30)), (1, &key(31))]);
        let e = Entry::Bridge(s);
        assert_eq!(Entry::from_bytes(&e.to_bytes()).unwrap(), e);
    }
}

#[test]
fn bridge_wrong_length_is_refused() {
    assert_eq!(
        BridgeOp::decode(&[0u8; BRIDGE_LEN - 1]).err(),
        Some(OrderError::Length)
    );
}

#[test]
fn entry_kind_byte_rules() {
    assert_eq!(Entry::from_bytes(&[3]).unwrap(), Entry::Tick);
    assert_eq!(Entry::from_bytes(&[3, 0]).err(), Some(OrderError::Length));
    assert_eq!(
        Entry::from_bytes(&[4]).err(),
        Some(OrderError::Field("entry kind"))
    );
    assert_eq!(Entry::from_bytes(&[]).err(), Some(OrderError::Length));
    assert_eq!(Entry::Tick.digest(), None);
}

#[test]
fn order_and_action_digests_are_domain_separated() {
    let o = intent(Side::Bid, Tif::Gtc);
    let a = Action {
        market: 3,
        acct: 7,
        nonce: 0,
        expiry_slot: 100,
        kind: ActionKind::Cancel { order_id: 1 },
    };
    assert_ne!(o.digest(), a.digest());
    let mut so = SignedOrder::sign(o, &key(1));
    // An action signature pasted onto an order does not verify (different domain tag and body).
    so.sig = SignedAction::sign(a, &key(1)).sig;
    assert!(!so.signature_valid());
}

fn admission() -> Admission {
    let mut a = Admission::new();
    a.register(7, key(1).verifying_key()).unwrap();
    a
}

#[test]
fn admission_unknown_account() {
    let mut a = Admission::new();
    let o = SignedOrder::sign(intent(Side::Bid, Tif::Gtc), &key(1));
    assert_eq!(a.admit(&o, 0).err(), Some(OrderError::UnknownAccount));
}

#[test]
fn admission_key_mismatch() {
    let mut a = admission();
    let o = SignedOrder::sign(intent(Side::Bid, Tif::Gtc), &key(2));
    assert_eq!(a.admit(&o, 0).err(), Some(OrderError::KeyMismatch));
}

#[test]
fn admission_nonce_must_be_exact_and_advances() {
    let mut a = admission();
    let mut i = intent(Side::Bid, Tif::Gtc);
    i.nonce = 1;
    assert_eq!(
        a.admit(&SignedOrder::sign(i, &key(1)), 0).err(),
        Some(OrderError::Nonce {
            expected: 0,
            got: 1
        })
    );
    i.nonce = 0;
    assert!(a.admit(&SignedOrder::sign(i, &key(1)), 0).is_ok());
    assert_eq!(a.next_nonce(7), 1);
    assert_eq!(
        a.admit(&SignedOrder::sign(i, &key(1)), 0).err(),
        Some(OrderError::Nonce {
            expected: 1,
            got: 0
        }),
        "replay refused"
    );
}

#[test]
fn admission_expired() {
    let mut a = admission();
    let o = SignedOrder::sign(intent(Side::Bid, Tif::Gtc), &key(1));
    assert_eq!(
        a.admit(&o, 101).err(),
        Some(OrderError::Expired {
            expiry: 100,
            now: 101
        })
    );
    assert!(
        a.admit(&o, 100).is_ok(),
        "expiry slot itself is still valid"
    );
}

#[test]
fn admission_lifetime_cap() {
    let mut a = admission();
    a.set_max_life(10);
    let o = SignedOrder::sign(intent(Side::Bid, Tif::Gtc), &key(1));
    assert_eq!(
        a.admit(&o, 0).err(),
        Some(OrderError::LifetimeTooLong {
            expiry: 100,
            now: 0,
            max_life: 10
        })
    );
    assert!(a.admit(&o, 90).is_ok());
}

#[test]
fn admission_bad_signature_consumes_no_nonce() {
    let mut a = admission();
    let mut o = SignedOrder::sign(intent(Side::Bid, Tif::Gtc), &key(1));
    o.sig[0] ^= 1;
    assert_eq!(a.admit(&o, 0).err(), Some(OrderError::BadSignature));
    assert_eq!(a.next_nonce(7), 0);
}

#[test]
fn weak_keys_cannot_register() {
    let mut a = Admission::new();
    let mut id = [0u8; 32];
    id[0] = 1; // the identity point: small order
    assert_eq!(a.register_bytes(1, id).err(), Some(OrderError::WeakKey));
    assert_eq!(
        a.register_bytes(1, [0xff; 32]).err(),
        Some(OrderError::WeakKey)
    );
    assert!(a.key(1).is_none());
}

#[test]
fn precheck_tolerates_future_nonces_but_not_past_ones() {
    let mut a = admission();
    let mut i = intent(Side::Bid, Tif::Gtc);
    i.nonce = 5;
    assert!(a
        .precheck(&Entry::Order(SignedOrder::sign(i, &key(1))), 0)
        .is_ok());
    i.nonce = 0;
    a.admit(&SignedOrder::sign(i, &key(1)), 0).unwrap();
    assert!(a
        .precheck(&Entry::Order(SignedOrder::sign(i, &key(1))), 0)
        .is_err());
    assert_eq!(a.precheck(&Entry::Tick, 0).err(), Some(OrderError::Tick));
}

#[test]
fn admission_state_encoding_roundtrips() {
    let mut a = admission();
    a.set_max_life(1_000);
    a.set_deposit_cap(5, 6);
    a.admit(&SignedOrder::sign(intent(Side::Bid, Tif::Gtc), &key(1)), 0)
        .unwrap();
    let mut b = Vec::new();
    a.encode_into(&mut b);
    let back = Admission::decode_from(&mut nimbus_hash::Reader::new(&b)).unwrap();
    let mut c = Vec::new();
    back.encode_into(&mut c);
    assert_eq!(b, c);
    assert_eq!(back.next_nonce(7), 1);
}
