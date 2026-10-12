# Crypt

Sealed, verifiable delivery of a secret on the Tari Ootle. The buyer pays into escrow, the seller
delivers the secret encrypted to the buyer's key, and if the buyer says it is wrong, **the template
decrypts it and decides**. No arbiter, no oracle, no trusted third party.

Built for the Tari Ootle "Spooky Secrets" showcase (October 2026).

## How a sale works

```
seller                            template                              buyer
  | list(commitment, price, bonds,   |                                     |
  |      windows, K, payout) + bond->|  escrow: seller bond (XTM)          |
  |                                  |<- buy(B', payout, proof by B')      |
  |                                  |   + price + buyer bond              |
  |                                  |   (b' = H(b, sale), client-side)    |
  | deliver(R, proof of r,           |                                     |
  |         C, proof by K) --------->|  C = block XOR stream(S), S = r·B'  |
  |                                  |  R and C public, S is not           |
  |                                  |                     open with S = b'·R
  |                                  |<----------- accept(proof by B'      |
  |                                  |                    over R)          |   or
  |                                  |<----------- dispute(S, DLEQ)        |
  |                                  |  verify DLEQ, decrypt C, hash,      |
  |                                  |  check layout, compare              |
  |      pay_seller / pay_buyer: anyone, funds only to the registered accounts
```

| Ending | Seller gets | Buyer gets |
|---|---|---|
| `accept`, or no dispute before the deadline | price + seller bond | buyer bond |
| Dispute, delivery matches the commitment | price + both bonds | nothing |
| Dispute, delivery does not match or is not decodable | nothing | price + both bonds |
| No delivery before the deadline | nothing | price + both bonds |
| Seller cancels before a sale | seller bond | |

## What is hidden, what is proven

* The secret travels on-chain, encrypted. Only the buyer's sale key opens it. A test walks a whole sale
  and searches every transaction, result, event and state change for the secret, its salt and the
  shared point, as raw bytes, text, hex and byte lists: none appear.
* The commitment covers a fixed 320-byte block: 32-byte random salt, length, secret, zero padding.
  A short secret cannot be brute-forced from it, and its length does not leak.
* **No action is authorized by the transaction signer.** Buy, deliver, accept and cancel each carry a
  Schnorr proof by the acting side's Crypt key, bound to the sale and to the action's arguments. A
  hostile component the victim calls in the same transaction cannot act for them.
* A dispute reveals `S` with a Chaum-Pedersen DLEQ proof that `log_G(B') = log_R(S)`. The buyer cannot
  lie about `S`; the template decrypts what the seller posted and decides.
* The seller must prove knowledge of `r` for the `R` they deliver. So a dispute only ever publishes
  `r·B'`, a value the seller already had: no seller can use a dispute to pull another sale's secret
  out of a buyer, even one who reuses keys. (A second review pass found exactly that leak in an earlier
  design; the test that replays it is in `attacks.rs`.)
* Buyer sale keys are hashes of a base secret and the sale, so they are unrelated to each other.
* Only revealed XTM: no token whose issuer can recall or freeze funds can drain or lock the escrow.
* Payouts go only to the built-in accounts registered at listing and purchase; anyone can trigger them.
* The component has no owner. Nobody can change its rules after creation.

[THREAT_MODEL.md](THREAT_MODEL.md) lists every attack with the test that plays it, and the limits: the
template proves you got what was committed, not that it is worth the price, and a dispute makes the
secret public.

## Using it: the `crypt` CLI

`cli/` builds `crypt`, the offline half of a sale. It computes every value a transaction needs and
prints `name=hex` lines; you pass them to the template through your wallet. It never touches the
network, never takes a secret on the command line (secrets and keys live in files) and never
overwrites a key or block file.

Seller:

```sh
crypt keygen --out seller.key                         # prints public_key: the seller_key for `list`
crypt commit --secret-file secret.txt --out block.hex # prints the commitment; keep block.hex private
# list(commitment, price, buyer_bond, delivery_window, dispute_window, seller_key, payout, bond)
crypt seal --seller-key seller.key --block block.hex --component <crypt> --buyer-key <buyer_key>
# deliver(ephemeral, ephemeral_c, ephemeral_z, ciphertext, c, z)
crypt cancel --seller-key seller.key --component <crypt>   # cancel(c, z), before a sale only
```

Buyer:

```sh
crypt keygen --out buyer.key                          # a base key; each sale derives its own key
crypt buy --base-key buyer.key --component <crypt> --payout <account>
# buy(buyer_key, payout, c, z, payment)
crypt open --base-key buyer.key --component <crypt> --ephemeral <R> --ciphertext <C> --commitment <m>
# prints the secret, or exits with status 2: "dispute: ..."
crypt accept  --base-key buyer.key --component <crypt> --ephemeral <R>                       # accept(c, z)
crypt dispute --base-key buyer.key --component <crypt> --ephemeral <R> --registered <buyer_key>
# dispute(shared, c, z), sent well before the deadline
```

Anyone, once settled: `pay_seller()`, `pay_buyer()`. Once a window has passed: `claim_undelivered()`,
`claim_uncontested()`.

## Layout

* `src/lib.rs`: the template. Group arithmetic and hashing through the engine's intrinsics
  (`tari_template_lib` 0.34).
* `core/`: `crypt_core`, the client side (sealing, opening, the action proofs and the DLEQ proof) in
  `curve25519-dalek` + `sha2`.
* `cli/`: the `crypt` binary above, with a test that runs a whole sale through it.
* `tests/end_to_end.rs`: every way a sale can end, balances checked down to the accounts.
* `tests/attacks.rs`: the attack battery, including a hostile template (`tests/templates/evil`) and a
  scan of everything the ledger shows. The client code produces every input: if the client and the
  template ever disagree on a byte, a test fails.

## Build and test

```sh
cargo test -p crypt_core -p crypt_cli                          # client cryptography, property tests, CLI
rustup target add wasm32-unknown-unknown
cargo build -p crypt --release --target wasm32-unknown-unknown # the template
cargo test -p crypt --tests                                    # Linux/macOS: the engine's JIT does not build on Windows
```

## License

BSD-3-Clause.
