//! A buyer opening deliveries. A faithful delivery of the committed block always opens to its
//! secret; once the fuzzer has changed any byte of the ciphertext or of R, the verified open never
//! hands back a secret; nothing panics.
#![no_main]
use crypt_core::{commitment_of, encode_plaintext, open_verified, seal, Keypair, PLAINTEXT_LEN};
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, RngCore};

/// Deterministic randomness from the fuzz input, so every crash replays.
struct Rng(u64);
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for Rng {}

const CONTEXT: &[u8] = b"fuzz sale";

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let mut rng = Rng(u64::from_le_bytes(data[..8].try_into().unwrap()) | 1);
    let secret_len = usize::from(data[8]) % 65;
    let Some(secret) = data.get(9..9 + secret_len) else {
        return;
    };
    let block = encode_plaintext(secret, &mut rng).unwrap();
    let commitment = commitment_of(&block);
    let buyer = Keypair::generate(&mut rng);
    let original = seal(&block, &buyer.public(), CONTEXT, &mut rng).unwrap();
    let opened = open_verified(&buyer, CONTEXT, &original.ephemeral, &original.ciphertext, &commitment);
    assert_eq!(opened.as_deref(), Ok(secret), "a faithful delivery did not open");

    let mut tampered = original.clone();
    for change in data[9 + secret_len..].chunks_exact(3) {
        let at = usize::from(u16::from_le_bytes([change[0], change[1]])) % (PLAINTEXT_LEN + 32);
        if at < PLAINTEXT_LEN {
            tampered.ciphertext[at] ^= change[2];
        } else {
            tampered.ephemeral[at - PLAINTEXT_LEN] ^= change[2];
        }
    }
    if tampered != original {
        assert!(
            open_verified(&buyer, CONTEXT, &tampered.ephemeral, &tampered.ciphertext, &commitment).is_err(),
            "a tampered delivery opened as the committed secret"
        );
    }
});
