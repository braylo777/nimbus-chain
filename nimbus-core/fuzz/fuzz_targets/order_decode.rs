//! Untrusted entry bytes: parsing never panics, and whatever parses re-encodes to the same bytes (canonical form).
#![no_main]
use libfuzzer_sys::fuzz_target;
use nimbus_order::Entry;

fuzz_target!(|data: &[u8]| {
    if let Ok(e) = Entry::from_bytes(data) {
        assert_eq!(e.to_bytes(), data, "non-canonical encoding accepted");
        let _ = e.digest();
    }
});
