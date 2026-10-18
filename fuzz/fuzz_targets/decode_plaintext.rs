//! Any 320 bytes: decoding never panics, and what decodes re-encodes to a block with the same length
//! field and the same secret.
#![no_main]
use crypt_core::{decode_plaintext, PLAINTEXT_LEN, SALT_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(block) = <[u8; PLAINTEXT_LEN]>::try_from(data) else { return };
    if let Ok(secret) = decode_plaintext(&block) {
        let len = u16::from_le_bytes([block[SALT_LEN], block[SALT_LEN + 1]]) as usize;
        assert_eq!(secret.len(), len);
        assert_eq!(&block[SALT_LEN + 2..SALT_LEN + 2 + len], secret.as_slice());
    }
});
