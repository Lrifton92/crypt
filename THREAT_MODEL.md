# Threat model

Each line names an attack, what stops it, and the test in `tests/end_to_end.rs` (or `core/src/lib.rs`)
that plays it and checks it fails for that reason. A defence without a test is not listed.

## Actors

* **Seller**: wants the price without delivering the committed secret.
* **Buyer**: wants the secret without paying, or the payment back after reading the secret.
* **Third party**: anyone else on the network, including someone who watches every transaction.

Assumption: each party signs only transactions they built. A wallet that signs a malicious
transaction calling `accept` or `withdraw` on the user's behalf is outside what a template can stop.

## Seller attacks

| Attack | Defence | Test |
|---|---|---|
| Deliver a different secret than the one committed | Dispute: the template decrypts and re-hashes; mismatch = `Fraud`, buyer takes price + both bonds | `a_seller_who_delivers_something_else_loses_the_sale_and_the_bond` |
| Deliver bytes they cannot decrypt themselves | Same verdict: no keystream, no match | `a_seller_who_seals_garbage_without_the_key_loses_too` |
| Never deliver, keep the buyer's money locked | Delivery deadline; buyer reclaims everything, seller bond included | `delivery_closes_after_the_deadline_and_the_buyer_takes_everything` |
| Deliver late | `deliver` refused after the deadline | same |
| Change the access rules to lock the buyer out of `dispute` | Component created with `OwnerRule::None`: no owner, rules immutable | by construction (`list`) |
| Buy their own listing to fake volume or recycle bonds | Refused | `the_seller_cannot_buy_their_own_listing` |
| Reuse a delivery from another sale | Keystream and proofs bound to the component address | `a_dispute_proof_cannot_be_replayed_into_another_sale` |
| Post a malformed ephemeral key or ciphertext | Canonical, non-identity point; exactly 320 bytes | `malformed_deliveries_are_refused` |
| Cancel after being paid | `cancel` only while listed | `the_seller_can_cancel_only_before_a_sale` |

## Buyer attacks

| Attack | Defence | Test |
|---|---|---|
| Claim fraud with a made-up shared point | DLEQ proof that `S = b·R` for the registered `B` | `a_buyer_cannot_fake_a_fraud_with_a_made_up_shared_point` |
| Tamper with a valid proof | Fiat-Shamir challenge recomputed on-chain | same |
| Replay a proof from another sale | Challenge binds the component address | `a_dispute_proof_cannot_be_replayed_into_another_sale` |
| Non-canonical scalars (malleability) | `scalar_is_canonical` on `c` and `z` | `a_dispute_with_a_non_canonical_scalar_is_refused`, `non_canonical_scalars_are_rejected` |
| Read the secret, then dispute to get refunded | The template decrypts the honest delivery, it matches: `DisputeRejected`, buyer loses their bond | `a_false_dispute_pays_the_seller_and_costs_the_buyer_the_bond` |
| Dispute after the window | Refused | `the_dispute_window_is_exact_and_silence_pays_the_seller` |
| Underpay or overpay | Payment must be exactly price + bond | `payment_must_be_exact` |
| Register a key they do not hold (e.g. someone else's) | Proof of possession, bound to the sale | `the_buyer_must_hold_the_key_they_register` |
| Register the identity point or garbage as key | Refused | `identity_and_malformed_keys_are_refused` |

## Third-party attacks

| Attack | Defence | Test |
|---|---|---|
| Read the secret from the ledger | Only `S = b·R` opens it; `R`, `B` and the ciphertext reveal nothing | `another_key_opens_garbage` |
| Brute-force a short secret from the public commitment | 32-byte random salt inside the committed block | `the_salt_hides_short_secrets` |
| Learn the secret's length | Fixed 320-byte blocks | by construction |
| Link one buyer's purchases | Fresh encryption key per purchase (client) | client behaviour |
| Act for either side (accept, dispute, deliver, cancel, withdraw) | Every method checks the signer against the key that signed `list` or `buy` | `only_the_right_side_can_act` |
| Front-run a purchase | One sale per listing; the loser's transaction fails, nothing is taken | `a_listing_sells_once` |

## Settlement integrity

| Property | How | Test |
|---|---|---|
| A sale settles once | Single `settle` exit, stage checked first | `a_settled_sale_stays_settled_and_pays_out_once` |
| Payouts happen once | Owed amount zeroed before the vault withdraws | same |
| No funds stuck, none created | `settle` asserts `owed_seller + owed_buyer == escrow` | every settlement test ends at an empty escrow |
| Amounts readable | Public fungible resource only; overflow panics | `list` |
| Client and template agree byte for byte | Commitment, keystream and proofs computed by both | `the_template_and_the_client_hash_a_block_identically`, every happy path |

## Limits, stated plainly

* The template proves the delivered secret is the committed one. It cannot judge whether the secret
  is worth the price. The commitment is salted, so it carries no meaning on its own.
* A dispute publishes `S`, so the secret becomes public. That is what makes the verdict checkable by anyone.
* No professional audit. The cryptography is standard (Ristretto255, Chaum-Pedersen, SHA-512) and the
  engine's intrinsics do the group arithmetic, but this composition has only been reviewed by its author.
* Deadlines are in epochs; their wall-clock length depends on the network.
