//! Nimbus Chain light-client verifier compiled to WebAssembly with a plain C ABI (no JS bindings generator, no npm).
//!
//! Host protocol (see `demo/site/verifier.js`):
//! 1. `buf = alloc(n)`, copy bytes into linear memory at `buf`;
//! 2. `set_validators(buf, 32·n)` with the n validator public keys → n, or a negative error code;
//! 3. `verify(buf, len)` with an encoded `FinalityProof` → the proven height (≥ 0), or a negative error code;
//! 4. `dealloc(buf, n)`.
//!
//! The host supplies randomness for batch verification through the import `env.random_fill(ptr, len)`
//! (`crypto.getRandomValues` in a browser or Node).
use nimbus_lightclient::{verify_bytes, Error, ValidatorSet};
use std::cell::RefCell;

thread_local! {
    static SET: RefCell<Option<ValidatorSet>> = const { RefCell::new(None) };
}

/// Error codes returned to the host (negative).
pub fn code(e: &Error) -> i64 {
    match e {
        Error::Encoding => -1,
        Error::HeaderLength => -2,
        Error::HeaderDomain => -3,
        Error::Inclusion => -4,
        Error::UnknownValidator => -5,
        Error::DuplicateSigner => -6,
        Error::Quorum { .. } => -7,
        Error::Signature => -8,
        Error::WeakKey => -9,
    }
}
/// No validator set loaded.
pub const NO_SET: i64 = -10;
/// Validator bytes are not a multiple of 32 or empty.
pub const BAD_SET_LEN: i64 = -11;

/// Safe core of `set_validators`.
pub fn load_validators(bytes: &[u8]) -> i64 {
    if bytes.is_empty() || !bytes.len().is_multiple_of(32) {
        return BAD_SET_LEN;
    }
    let keys: Result<Vec<_>, _> = bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(ed25519_dalek::VerifyingKey::from_bytes)
        .collect();
    let Ok(keys) = keys else {
        return code(&Error::WeakKey);
    };
    match ValidatorSet::new(&keys) {
        Ok(s) => {
            let n = s.keys.len() as i64;
            SET.with(|c| *c.borrow_mut() = Some(s));
            n
        }
        Err(e) => code(&e),
    }
}

/// Safe core of `verify`.
pub fn verify_proof(bytes: &[u8]) -> i64 {
    SET.with(|c| match c.borrow().as_ref() {
        None => NO_SET,
        Some(s) => match verify_bytes(s, bytes) {
            Ok(h) => h.height as i64,
            Err(e) => code(&e),
        },
    })
}

// ---- C ABI (the only unsafe code: turning host pointers into slices) ----

/// Allocate `len` bytes for the host to write into.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Free a buffer from `alloc`.
///
/// # Safety
/// `ptr` and `len` must come from one `alloc(len)` call, freed once.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
}

/// # Safety
/// `ptr..ptr+len` must be initialised memory from `alloc`.
#[no_mangle]
pub unsafe extern "C" fn set_validators(ptr: *const u8, len: usize) -> i64 {
    load_validators(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// # Safety
/// `ptr..ptr+len` must be initialised memory from `alloc`.
#[no_mangle]
pub unsafe extern "C" fn verify(ptr: *const u8, len: usize) -> i64 {
    verify_proof(unsafe { std::slice::from_raw_parts(ptr, len) })
}

#[cfg(target_arch = "wasm32")]
mod rng {
    #[link(wasm_import_module = "env")]
    extern "C" {
        fn random_fill(ptr: *mut u8, len: usize);
    }
    fn host_random(buf: &mut [u8]) -> Result<(), getrandom::Error> {
        // SAFETY: the host writes exactly `len` bytes into our buffer.
        unsafe { random_fill(buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }
    getrandom::register_custom_getrandom!(host_random);
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimbus_lightclient::testkit;

    #[test]
    fn verifies_and_refuses_through_the_safe_core() {
        let keys: Vec<_> = (0..4u8)
            .map(|i| ed25519_dalek::SigningKey::from_bytes(&[i + 1; 32]))
            .collect();
        let mut set = Vec::new();
        for k in &keys {
            set.extend_from_slice(&k.verifying_key().to_bytes());
        }
        assert_eq!(verify_proof(&[]), NO_SET);
        assert_eq!(load_validators(&set[..31]), BAD_SET_LEN);
        assert_eq!(load_validators(&set), 4);
        let ops = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let p = testkit::build(&ops, 1, 77, &keys, &[0, 1, 2, 3]).encode();
        assert_eq!(verify_proof(&p), 77);
        let mut bad = p.clone();
        bad[5] ^= 1;
        assert!(verify_proof(&bad) < 0);
        assert_eq!(verify_proof(&p[..10]), -1);
    }
}
