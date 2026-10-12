# Threat model

Each line names an attack, what stops it, and the test that plays it and checks it fails for that
reason (`tests/attacks.rs` unless noted; `e2e` = `tests/end_to_end.rs`, `core` = `core/src/lib.rs`).
Defences enforced in code but not exercised by a test are marked *untested*.

## Actors

* **Seller**: wants the price without delivering the committed secret, or the escrow itself, or
  another sale's secret.
* **Buyer**: wants the secret without paying, or the payment back after reading the secret.
* **Third party**: anyone else, including someone who reads every transaction and every state change,
  and any **hostile component** a party calls in the same transaction.

Authorization never relies on the transaction signer. Each action carries a Schnorr proof by the
acting side's Crypt key (the seller key, or the buyer's sale key), held by the Crypt client and not the
wallet, and bound to the sale and to the action's arguments.

## What an observer sees

| Claim | Test |
|---|---|
| No transaction, result, event, log or state change contains the secret, its salt or the shared point, as raw bytes, text, hex or byte list, from listing to payout | `nothing_on_the_ledger_reveals_the_secret_salt_or_shared_point` |
| Two sales of the same secret share no commitment, key, ephemeral or ciphertext pattern | `two_sales_of_the_same_secret_share_nothing_visible` |
| After a dispute, anyone can read the secret (the documented price of a public verdict) | `after_a_dispute_anyone_can_read_the_secret` |
| A short secret cannot be brute-forced from its commitment (salted) | `the_salt_hides_short_secrets` (core) |

## Seller attacks

| Attack | Defence | Test |
|---|---|---|
| Deliver a different secret | Dispute: the template decrypts and re-hashes; mismatch = `Fraud` | `a_seller_who_delivers_something_else_loses_the_sale_and_the_bond` (e2e) |
| Commit to a block no client can decode, deliver it faithfully | Dispute also checks the block layout | `committing_to_an_undecodable_block_loses_the_dispute`, `a_length_field_past_the_block_loses_the_dispute` |
| Deliver noise | Nothing decrypts to the commitment | `noise_loses_the_dispute`, `random_deliveries_always_lose_the_dispute` |
| Repost another sale's `R` (or `λ·R + k·G`) so the buyer's dispute leaks that other sale | `deliver` requires a proof of knowledge of `r`, bound to the sale. A dispute then only publishes `r·B'`, which the seller already knew | `another_sales_ephemeral_key_cannot_be_reposted_to_extract_its_secret`, `a_dispute_reveals_nothing_the_seller_did_not_already_know`, `a_block_sealed_for_another_sale_is_refused_at_delivery` |
| List in a token they can recall or freeze, then drain or lock the escrow | Revealed XTM only | `a_token_the_seller_can_recall_is_refused` |
| Never deliver, keep the buyer's funds locked | Delivery deadline; buyer takes everything, seller bond included | `no_delivery_returns_everything_to_the_buyer` (e2e), `delivery_is_open_up_to_and_including_the_deadline_only` |
| Squeeze the buyer's time to check and dispute | Windows of at least 3 epochs | `listings_with_bad_terms_are_refused` |
| Cash in before the buyer can dispute | `claim_uncontested` only after the dispute window | `the_seller_cannot_cash_in_before_the_dispute_window_closes` |
| Malformed delivery (identity / non-canonical `R`, wrong length) | Refused | `malformed_deliveries_are_refused` |
| Cancel after being paid, or replay a cancellation | Listed-only, proof bound to the sale and the action | `cancellation_needs_the_seller_key_and_an_unsold_listing` |
| Bad terms (zero price or bond, windows out of range, invalid key, payout not an account) | Refused at `list` | `listings_with_bad_terms_are_refused` |
| Change the rules to lock the buyer out of `dispute` | No owner (`OwnerRule::None`) | by construction, *untested* |

## Buyer attacks

| Attack | Defence | Test |
|---|---|---|
| Claim fraud with a made-up `S`, a proof for another key, a bent or swapped proof, zero scalars | DLEQ verified on-chain against the registered sale key | `a_buyer_cannot_fake_a_fraud`, `random_dispute_attempts_never_succeed` |
| Non-canonical scalars (malleability), degenerate points | Canonical scalars, canonical non-identity points | `a_buyer_cannot_fake_a_fraud` |
| Replay a dispute proof from another sale | Challenge binds the component address | `a_dispute_proof_cannot_be_replayed_into_another_sale` |
| Read the secret, then dispute to be refunded | The honest delivery decrypts to the commitment: `DisputeRejected`, bond lost | `a_false_dispute_pays_the_seller_and_costs_the_buyer_the_bond` (e2e) |
| Dispute after the window | Refused; the last epoch is still open | `the_dispute_window_includes_its_last_epoch_and_nothing_after` |
| Underpay or overpay | Exactly price + bond | `payment_must_be_exact` |
| Pay in another token | XTM only | `payment_in_another_token_is_refused` |
| Pay with hidden (confidential) funds | `assert_contains_no_confidential_funds` | *untested* |
| Register a key they do not hold | Proof by the registered key | `a_buy_proof_is_bound_to_the_key_the_sale_and_the_payout_account` |
| Payout to a component that is not an account | Built-in accounts only | `a_buyer_payout_must_be_an_account` |

## Third parties and hostile components

| Attack | Defence | Test |
|---|---|---|
| Accept, cancel or deliver for a party, from a hostile component in that party's own transaction | Actions need the party's Crypt key, not the signer | `a_hostile_component_in_the_victims_transaction_cannot_act_for_them` |
| Accept with any key but the buyer's sale key, another action, another sale, another delivery | Proof bound to key, action, sale and `R` | `only_the_buyer_sale_key_can_accept_and_only_this_delivery`, `random_action_proofs_never_authorize_anything` |
| Deliver without the seller key, or reuse a delivery signature on other content | Proof covers `R` and the ciphertext | `only_the_seller_key_can_deliver`, `a_delivery_signature_does_not_cover_other_content` |
| Copy a buy proof from the mempool and take the purchase into their own account | Proof covers the payout account | `a_buy_proof_is_bound_to_the_key_the_sale_and_the_payout_account` |
| Trigger payouts to steal them | Payouts only go to the registered accounts | `a_stranger_can_only_trigger_payouts_to_their_rightful_owners`, hostile-component test |
| Buy a listing twice | One sale per listing | `a_listing_sells_once_and_a_replayed_buy_is_refused` |

## Settlement integrity

| Property | Test |
|---|---|
| A sale settles once, whatever is called afterwards | `a_settled_sale_cannot_be_settled_again` |
| Accept and dispute in one transaction: all or nothing | `accepting_then_disputing_in_one_transaction_is_all_or_nothing` |
| Each payout happens once, even twice in one transaction | `a_payout_happens_once_even_inside_one_transaction` |
| `owed_seller + owed_buyer == escrow` at settlement, escrow empty after payouts | asserted in `settle`; every e2e outcome ends with `pay_out`, which checks the escrow is empty |
| Exact balances reach the accounts | `an_honest_sale_pays_the_seller_and_returns_both_bonds`, `no_delivery_returns_everything_to_the_buyer` (e2e) |
| Client and template agree byte for byte (commitment, keystream, proofs) | `the_template_and_the_client_hash_a_block_identically`, `the_template_registers_the_buyer_sale_key` (e2e), every happy path |

## Client safeguards

| Mistake | Safeguard | Test |
|---|---|---|
| Disputing with a key that is not the one registered (it would be refused, but publish a shared point) | `prove_shared` refuses unless the key matches the on-chain buyer key and the proof verifies locally | `a_dispute_is_never_produced_with_the_wrong_key` (core) |
| Accepting a delivery that does not match the listing | `open_verified` returns `CommitmentMismatch` / `MalformedPlaintext` | `open_verified_flags_what_to_dispute` (core) |
| Sale keys of one base key being related | `b' = H(b, sale)`, a hash, not an offset | `sale_keys_are_unrelated_hashes_of_the_base_key` (core) |

## Supply chain

The build is pinned by the committed `Cargo.lock` and CI runs `cargo audit`. Five RustSec warnings
(unmaintained or unsound crates) are triaged in `.cargo/audit.toml`: all five sit in the ledger
simulator used by the tests or in the build-time metadata generator, none in the template or in
`crypt_core`. Vulnerabilities are never ignored.

## Limits, stated plainly

* The template proves the delivered secret is the committed one. It cannot judge whether the secret is
  worth the price.
* A dispute publishes `S`, so the secret becomes public. Dispute well before the deadline: a dispute
  that lands after it is refused, but `S` was already visible in the pending transaction.
* A seller can always make their own secret public, by publishing `r`, `S` or the block. Nothing
  on-chain can stop someone from leaking what they already know.
* Reusing a sale key across purchases links them on-chain. The client derives a fresh one per sale.
* The Crypt keys are the authority. Losing the seller key means the seller can no longer deliver or
  cancel (deadlines still release the funds); losing the buyer key means no accept or dispute (silence
  then pays the seller). Payouts themselves need no key.
* A payout to a built-in account that refuses deposits would only hold up that side's own payout;
  whether an account owner can make deposits fail was not verified.
* No professional audit. The primitives are standard (Ristretto255, Schnorr, Chaum-Pedersen, SHA-512)
  and the engine's intrinsics do the group arithmetic. The composition went through two adversarial
  review passes; the second found a cross-sale leak in the first design, closed by the proof of `r`
  and covered by the tests above.
* Deadlines are in epochs; their wall-clock length depends on the network.
