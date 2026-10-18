//! Arbitrary key, proof, context and message: verification never panics and never accepts. A
//! forgery would need a discrete log; libFuzzer finding one means the check is broken.
#![no_main]
use crypt_core::{verify_action, Proof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let proof = Proof { c: data[32..64].try_into().unwrap(), z: data[64..96].try_into().unwrap() };
    let rest = &data[96..];
    let (context, message) = rest.split_at(rest.len() / 2);
    assert!(!verify_action(&key, context, message, &proof), "an arbitrary proof verified");
});
