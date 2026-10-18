//! Any 32 bytes: never panics, and an accepted point re-encodes to the same bytes.
#![no_main]
use crypt_core::decode_point;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(bytes) = <[u8; 32]>::try_from(data) else { return };
    if let Ok(point) = decode_point(&bytes) {
        assert_eq!(point.compress().to_bytes(), bytes);
    }
});
