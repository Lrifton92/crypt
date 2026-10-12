# Crypt

**Sell a secret on the Tari Ootle without trusting anyone.** The buyer pays into escrow, the seller
delivers the secret encrypted to the buyer's key, and if the buyer says it is wrong, **the template
decrypts it and decides**. No arbiter, no oracle, no account: the money comes from stealth coins and
goes back into stealth outputs.

Built for the Tari Ootle "Spooky Secrets" showcase (October 2026).

## Tari's privacy, end to end

| What stays secret | How | Tari capability |
|---|---|---|
| The secret itself, on a public ledger | Encrypted to a per-sale key with a keystream from a Ristretto Diffie-Hellman point; only the buyer can derive it | Ristretto255 + SHA-512 engine intrinsics |
| Whether a delivery is honest, without an arbiter | The buyer reveals the shared point with a Chaum-Pedersen DLEQ proof; the template re-derives the key, decrypts, re-hashes and rules | Group arithmetic inside the template (`ristretto_mul`, `scalar_from_uniform_bytes`, …) |
| Who funds a sale | Both sides spend stealth UTXOs (hidden value, one-time spend key) into the escrow; no account is involved | Stealth XTM (TIP-0006), transaction-level `StealthTransfer` |
| Where the money goes | Each side is paid into fresh Pedersen-committed stealth outputs, signed for over the exact transfer, so nobody can redirect it | `Bucket::stealth_transfer` from inside the template |
| Who is acting | No action is authorised by the transaction signer: buy, deliver, accept, cancel and payouts each carry a Schnorr proof by a key derived for this listing or this purchase only | Schnorr over Ristretto, verified on-chain |
| The secret's length, and short secrets | Fixed 320-byte blocks with a 32-byte random salt under the commitment | |

## How a sale works

```
seller                              template                               buyer
  | list(commitment, price, bonds,     |                                      |
  |      windows, K, bond) ----------->|  bond from a stealth coin            |
  |                                    |<-- buy(B', proof by B', payment)     |
  |                                    |    payment from a stealth coin       |
  | deliver(R, proof of r,             |                                      |
  |         C, proof by K) ----------->|  C = block XOR stream(S), S = r·B'   |
  |                                    |  R and C public, S is not            |
  |                                    |                    open with S = b'·R
  |                                    |<----------- accept(proof by B')      |   or
  |                                    |<----------- dispute(S, DLEQ proof)   |
  |                                    |  verify, decrypt C, hash, compare    |
  | pay_seller(stealth transfer,       |                                      |
  |            proof by K) ----------->|<---- pay_buyer(stealth transfer, proof by B')
  |        fresh stealth outputs <-----|-----> fresh stealth outputs          |
```

`K` is the seller's key for this listing, `B'` the buyer's key for this purchase. Both are derived
client-side from a base key by hashing, so no two listings or purchases share a key.

| Ending | Seller gets | Buyer gets |
|---|---|---|
| `accept`, or no dispute before the deadline | price + seller bond | buyer bond |
| Dispute, delivery matches the commitment | price + both bonds | nothing |
| Dispute, delivery does not match or is not decodable | nothing | price + both bonds |
| No delivery before the deadline | nothing | price + both bonds |
| Seller cancels before a sale | seller bond | |

## What is proven, what is hidden, what is not

* **Proven by the template:** the secret delivered is exactly the one committed to when listing. It
  cannot prove the secret is worth the price.
* **Hidden:** the secret (until a dispute), its length, the parties' accounts (there are none), the
  link between a seller's listings or a buyer's purchases (fresh keys each time), and who receives
  each payout.
* **A dispute makes the secret public.** That is what lets anyone re-check the verdict.
* **Still visible**, as on any UTXO ledger without decoys: the amounts of the sale, the commitments of
  the coins spent into it and of the outputs paying out of it (which link to their holders' other
  transactions), and whoever signs and pays fees for each transaction. To keep that link weak: fund
  from fresh coins, pay fees from a coin used for nothing else, and split payouts into several outputs.

## Security

Three adversarial review passes; every finding is fixed with a test or listed as a limit in
[THREAT_MODEL.md](THREAT_MODEL.md), which maps each attack to the test that plays it. The second pass
found a real cross-sale leak in an earlier design (an additive key tweak let a seller pull another
sale's secret through a dispute); the fix is the proof of knowledge of `r` at delivery, and the
attack is replayed in `tests/attacks.rs`.

CI runs on every commit, from the committed `Cargo.lock`:

* `crypt_core`: unit and property tests of the client cryptography;
* `crypt` CLI: a whole sale driven through the binary;
* the template: wasm build and clippy with warnings denied;
* `tests/end_to_end.rs`: every way a sale can end, each payout actually spent afterwards to prove the
  payee controls exactly what it was owed;
* `tests/attacks.rs`: the attack battery, including a hostile template (`tests/templates/evil`) and a
  scan of everything the ledger shows for the secret, its salt, the shared point and accounts;
* formatting, and a RustSec audit of the dependency tree.

**Your Crypt key is the only way to collect what a sale owes you.** Back it up.

## Using it: the `crypt` CLI

`cli/` builds `crypt`, the offline half of a sale. It computes every value a transaction needs and
prints `name=hex` lines; your wallet submits them. It never touches the network, never takes a secret
on the command line, never overwrites a key or block file, and refuses to sign a payout the template
would refuse or that does not pay exactly what you are owed.

Seller:

```sh
crypt keygen --out seller.key            # base key: back it up
crypt commit --seller-key seller.key --secret-file secret.txt --out block.hex
# prints commitment and seller_key for list(commitment, price, buyer_bond, windows..., seller_key, bond)
crypt seal --seller-key seller.key --commitment <m> --block block.hex --component <crypt> --buyer-key <B'>
# deliver(ephemeral, ephemeral_c, ephemeral_z, ciphertext, c, z)
crypt payout --seller-key seller.key --commitment <m> --component <crypt> --statement transfer.hex --owed <n>
# pay_seller(transfer, c, z); transfer.hex is the stealth transfer your wallet builds to pay you
crypt cancel --seller-key seller.key --commitment <m> --component <crypt>   # cancel(c, z), unsold only
```

Buyer:

```sh
crypt keygen --out buyer.key             # base key: back it up
crypt buy --base-key buyer.key --component <crypt>                         # buy(buyer_key, c, z, payment)
crypt open --base-key buyer.key --component <crypt> --ephemeral <R> --ciphertext <C> --commitment <m>
# prints the secret, or exits with status 2: "dispute: ..."
crypt accept  --base-key buyer.key --component <crypt> --ephemeral <R>                       # accept(c, z)
crypt dispute --base-key buyer.key --component <crypt> --ephemeral <R> --registered <B'>
# dispute(shared, c, z), sent well before the deadline
crypt payout --base-key buyer.key --component <crypt> --statement transfer.hex --owed <n>  # pay_buyer
```

Anyone, once a window has passed: `claim_undelivered()`, `claim_uncontested()`.

## Layout

* `src/lib.rs`: the template (`tari_template_lib` 0.34).
* `core/`: `crypt_core`, the client side (keys, sealing, opening, the action proofs, the DLEQ proof, the
  payout digest) in `curve25519-dalek` + `sha2`.
* `cli/`: the `crypt` binary.
* `tests/`: the end-to-end suite, the attack battery and the hostile template. The client code produces
  every input: if the client and the template ever disagree on a byte, a test fails.

## Build and test

```sh
cargo test -p crypt_core -p crypt_cli                          # client cryptography, CLI
rustup target add wasm32-unknown-unknown
cargo build -p crypt --release --target wasm32-unknown-unknown # the template
cargo test -p crypt --tests                                    # Linux/macOS: the engine's JIT does not build on Windows
```

## License

BSD-3-Clause.
