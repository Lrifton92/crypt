//! Any 320 bytes: decoding never panics, and every block it accepts is exactly what encoding that
//! secret with that salt produces (length field, secret, zero padding): nothing else decodes.
#![no_main]
use crypt_core::{decode_plaintext, PLAINTEXT_LEN, SALT_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(block) = <[u8; PLAINTEXT_LEN]>::try_from(data) else {
        return;
    };
    if let Ok(secret) = decode_plaintext(&block) {
        let mut rebuilt = [0u8; PLAINTEXT_LEN];
        rebuilt[..SALT_LEN].copy_from_slice(&block[..SALT_LEN]);
        rebuilt[SALT_LEN..SALT_LEN + 2].copy_from_slice(&(secret.len() as u16).to_le_bytes());
        rebuilt[SALT_LEN + 2..SALT_LEN + 2 + secret.len()].copy_from_slice(&secret);
        assert_eq!(rebuilt, block, "decoded a block encode_plaintext could not have made");
    }
});
