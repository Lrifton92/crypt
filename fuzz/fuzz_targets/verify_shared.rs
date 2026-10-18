//! Arbitrary points and proof: the DLEQ check never panics and never accepts.
#![no_main]
use crypt_core::{verify_shared, Proof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 160 {
        return;
    }
    let part = |i: usize| -> [u8; 32] { data[i * 32..(i + 1) * 32].try_into().unwrap() };
    let proof = Proof { c: part(3), z: part(4) };
    assert!(
        !verify_shared(&part(0), &part(1), &part(2), &data[160..], &proof),
        "an arbitrary DLEQ proof verified"
    );
});
