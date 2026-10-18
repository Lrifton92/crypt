//! A buyer opening arbitrary deliveries: never panics, and the verified open never hands back a
//! secret unless the block really hashes to the commitment it was checked against.
#![no_main]
use crypt_core::{commitment_of, open, open_verified, Keypair, PLAINTEXT_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 32 + 64 + PLAINTEXT_LEN {
        return;
    }
    let Some(key) = Keypair::from_secret_bytes(&data[..32].try_into().unwrap()) else { return };
    let ephemeral: [u8; 32] = data[32..64].try_into().unwrap();
    let commitment: [u8; 64] = data[64..128].try_into().unwrap();
    let ciphertext: [u8; PLAINTEXT_LEN] = data[128..128 + PLAINTEXT_LEN].try_into().unwrap();
    let context = &data[128 + PLAINTEXT_LEN..];
    if open_verified(&key, context, &ephemeral, &ciphertext, &commitment).is_ok() {
        let block = open(&key, context, &ephemeral, &ciphertext).unwrap();
        assert_eq!(commitment_of(&block), commitment);
    }
});
