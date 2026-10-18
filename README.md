# Crypt

**Sell a secret on the Tari Ootle without trusting anyone.** The buyer pays into escrow, the seller
delivers the secret encrypted to the buyer's key, and if the buyer says it is wrong, **the template
decrypts it and decides**. No arbiter, no oracle, no account: the money comes from stealth coins and
goes back into stealth outputs.

Built for the Tari Ootle "Spooky Secrets" showcase (October 2026).

## Play it

**[lrifton92.github.io/crypt](https://lrifton92.github.io/crypt/)**: a two-minute game in the browser, no wallet. Take a side (seller or buyer), play honest or cheat; a ghost plays the other side. Every step runs the real `crypt_core` client code compiled to WebAssembly, and the verdict comes from a port of the template's rules (`crypt_core::rules`) that CI checks against the template itself (`tests/equivalence.rs`): same calls, same accept or refuse, same split, after every call. The verdict screen shows what was checked: the seal, the keys, the shared point, the DLEQ proof, the hashes, the split.

## Live on esmeralda

The template is published on the Tari Ootle testnet and two sales were played for real with the same client code (`onchain/`). Links go to [Veil](https://explorer.tari.mw), an independent Ootle explorer.

* Template [`template_b7282faa09858bc1ca1257734d5e2739135c7ed29edec8a51d6b86d8225a61bf`](https://explorer.tari.mw/template/b7282faa09858bc1ca1257734d5e2739135c7ed29edec8a51d6b86d8225a61bf), [published](https://explorer.tari.mw/tx/6341ce51e6f1b31b694364dc4ec761dc780dccef294a03fadd65264f1530c7b2) from commit `320ffad`; `crypt.wasm` sha256 `9430bd57a58dc7a7be31972a57fff2de46fbfb9a39176f05118d4cedf0efe34b`.

| Sale | Transactions | Component |
|---|---|---|
| Honest: accepted, both sides paid | [list](https://explorer.tari.mw/tx/0d63f5c18883f4bf5df70a3ddb2b820bb08d0b4bbd00f1fa41e72ea6c787f085) → [buy](https://explorer.tari.mw/tx/423eb76f8ccff76fb6c0cbf3f39a3c1de33f843192707deb19825ee39fb22362) → [deliver](https://explorer.tari.mw/tx/cfb1cbba2a6c5381f0bc715dfd42f14c890f722160196537348036e555a2ac61) → [accept](https://explorer.tari.mw/tx/ddef75bde116908b339c20aaee5b69936b6663300d1f7fb20cb0165ee1cc4cc6) → [pay_seller](https://explorer.tari.mw/tx/5950ca94158c804a433bb7afcee1ad21e165fb409203f336f784fe6d2fed61da) → [pay_buyer](https://explorer.tari.mw/tx/1fddca4337b790844d1ddc54dee5c713e30444baa0dcfeb960320096e95373d8) | [component_4e37f76b…](https://explorer.tari.mw/substate/component_4e37f76b091bf0d5ea6560e2bb73adb08522dfd20ee3b13bd8e170e055733a8a) |
| Fake delivery: disputed, ruled `Fraud`, buyer paid everything | [list](https://explorer.tari.mw/tx/4542ee201d42989a6ae2bdcb67183031273ce949624b4efce76d67438ea3f099) → [buy](https://explorer.tari.mw/tx/6906f4cc68c6f43bb3881a1c0baed53b0b34b9206c1c6e8295232e67af0e8b0e) → [deliver](https://explorer.tari.mw/tx/3e070f69f0075c1de731e37c14774e06954a8da37cb2fb63239a1860e1ff6aa2) → [dispute](https://explorer.tari.mw/tx/7e3e2f1271cf2669a34ee0084931216e0f4abb02764aed349ad50c779c6ec59a) → [pay_buyer](https://explorer.tari.mw/tx/c0deacb7b6175c74a9e753ff4ea9fae0a381e86ec34f7608867c7a9a1583cb21) | [component_9ceea34f…](https://explorer.tari.mw/substate/component_9ceea34fb63c019e849c3d29cb9ac77d3c8ada043b59fea0066a87ba99cc84f8) |

Both sides of each sale used fresh Crypt keys; the transaction fees and the stealth coins came from one demo wallet, so this shows the contract working, not two independent people.

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
  | list(commitment, terms, K,         |                                      |
  |      proof by K, bond) ----------->|  bond from a stealth coin            |
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

Four adversarial review passes; every finding is fixed with a test or listed as a limit in
[THREAT_MODEL.md](THREAT_MODEL.md), which maps each attack to the test that plays it. The second pass
found a real cross-sale leak in an earlier design (an additive key tweak let a seller pull another
sale's secret through a dispute); the fix is the proof of knowledge of `r` at delivery, and the
attack is replayed in `tests/attacks.rs`. The fourth pass found that a listing never expired (anyone
could buy a seller's forgotten listing and claim the bond), that a listing could reuse another seller's
key at a price of 1, and that terms could be set to make delivering noise pay; listings now expire,
`list` takes a proof by the seller key over every term, and the bonds and windows are bounded.

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
crypt commit --seller-key seller.key --secret-file secret.txt --out block.hex \
  --price <µT> --buyer-bond <µT> --seller-bond <µT> --listing-window <epochs> --delivery-window <epochs> --dispute-window <epochs>
# prints commitment, seller_key and list_c/list_z for
# list(commitment, price, buyer_bond, listing_window, delivery_window, dispute_window, seller_key, list_c, list_z, bond)
crypt seal --seller-key seller.key --commitment <m> --block block.hex --component <crypt> \
  --buyer-key <B'> --buy-c <c> --buy-z <z>     # the buyer key and proof from the buy transaction
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
crypt accept  --base-key buyer.key --component <crypt> --ephemeral <R> --ciphertext <C> --commitment <m>  # accept(c, z)
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
* `core/src/rules.rs`: the template's settlement rules in plain Rust; `tests/equivalence.rs` plays the same
  sequences in the engine and in the port and requires identical results.
* `demo/wasm/`: the demo engine (`crypt_core` + the rules) for the browser; `demo/web/`: the game (Vite +
  TypeScript), with Playwright tests of every ending on a desktop and a 360 px phone.
* `onchain/`: plays real sales on esmeralda with `ootle-rs` and records every transaction.

## Build and test

```sh
cargo test -p crypt_core -p crypt_cli                          # client cryptography, CLI
rustup target add wasm32-unknown-unknown
cargo build -p crypt --release --target wasm32-unknown-unknown # the template
cargo test -p crypt --tests                                    # Linux/macOS: the engine's JIT does not build on Windows

# the demo
cargo build -p crypt_wasm --release --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/crypt_wasm.wasm --target web --out-dir demo/wasm/pkg
cd demo/web && npm ci && npm run build && npx playwright test
```

## License

BSD-3-Clause.
