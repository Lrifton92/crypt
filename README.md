# Crypt

Sealed, verifiable delivery of a secret on the Tari Ootle. The buyer pays into escrow, the seller
delivers the secret encrypted to the buyer's key, and if the buyer says it is wrong, **the template
decrypts it and decides**. No arbiter, no oracle, no trusted third party.

Built for the Tari Ootle "Spooky Secrets" showcase (October 2026).

## How a sale works

```
seller                         template                          buyer
  | list(commitment, price,       |                                |
  |      bonds, windows) + bond ->|  escrow: seller bond           |
  |                               |<- buy(B, proof of possession)  |
  |                               |   + price + buyer bond         |
  | deliver(R, C) --------------->|  C = block XOR stream(S),      |
  |                               |  S = r·B, public on-chain      |
  |                               |                       open with S = b·R
  |                               |<----------- accept()           |   or
  |                               |<----------- dispute(S, DLEQ)   |
  |                               |  verify DLEQ, decrypt C,       |
  |                               |  hash, compare to commitment   |
```

| Ending | Seller gets | Buyer gets |
|---|---|---|
| `accept`, or no dispute before the deadline | price + seller bond | buyer bond |
| Dispute, delivery matches the commitment | price + both bonds | nothing |
| Dispute, delivery does not match | nothing | price + both bonds |
| No delivery before the deadline | nothing | price + both bonds |
| Seller cancels before a sale | seller bond | |

Each side then calls `withdraw` to collect what it is owed.

## What is hidden, what is proven

* The secret travels on-chain, encrypted. Only the buyer's key opens it.
* The commitment covers a fixed 320-byte block: 32-byte random salt, length, secret, zero padding.
  A short secret cannot be brute-forced from it, and its length does not leak.
* The buyer proves they hold the key they register (Schnorr proof of possession).
* A dispute reveals `S` with a Chaum-Pedersen DLEQ proof that `log_G(B) = log_R(S)`. The buyer cannot
  lie about `S`, and the seller cannot have delivered anything that decrypts differently for the template
  than for the buyer.
* Every proof and keystream is bound to the component address: nothing replays across sales.
* The component has no owner. Nobody can change its rules after creation.

The full list of attacks, each with the test that plays it, is in [THREAT_MODEL.md](THREAT_MODEL.md),
along with the limits: the template proves you got what was committed, not that it is worth the price,
and a dispute makes the secret public.

## Layout

* `src/lib.rs`: the template. Group arithmetic and hashing through the engine's intrinsics
  (`tari_template_lib` 0.34).
* `core/`: `crypt_core`, the client side (sealing, opening, both proofs) in `curve25519-dalek` + `sha2`.
* `tests/end_to_end.rs`: every sale outcome and every attack, against a simulated ledger, with the
  client code producing the inputs. If the client and the template ever disagree on a byte, a test fails.

## Build and test

```sh
cargo test -p crypt_core                                       # client cryptography, property tests
rustup target add wasm32-unknown-unknown
cargo build -p crypt --release --target wasm32-unknown-unknown # the template
cargo test -p crypt --test end_to_end                          # Linux/macOS: the engine's JIT does not build on Windows
```

## License

BSD-3-Clause.
