# Threat model

Each line names an attack, what stops it, and the test that plays it and checks it fails for that
reason (`tests/attacks.rs` unless noted; `e2e` = `tests/end_to_end.rs`, `core` = `core/src/lib.rs`,
`cli` = `cli/tests/flow.rs`). Defences enforced in code but not exercised by a test are marked
*untested*.

## Actors and keys

* **Seller**: wants the price without delivering the committed secret, the escrow itself, or another
  sale's secret.
* **Buyer**: wants the secret without paying, or the payment back after reading the secret.
* **Third party**: anyone else, including someone who reads every transaction and state change, and any
  **hostile component** a party calls in the same transaction.

Every action is authorised by a Schnorr proof from a Crypt key, never by the transaction signer: the
seller's key for this listing (`K`, derived from a base key and the salted commitment) or the buyer's
key for this purchase (`B'`, derived from a base key and the component address). Funds enter the
escrow from stealth coins and leave it into stealth outputs.

## What an observer sees

| Claim | Test |
|---|---|
| No transaction or result of the sale contains the secret, its salt or the shared point (raw bytes, text, hex, byte list), and no account appears in the sale's own transactions | `nothing_on_the_ledger_reveals_the_secret_and_no_account_appears_in_the_sale` |
| Two sales of the same secret share no commitment, key, ephemeral or ciphertext pattern | `two_sales_of_the_same_secret_share_nothing_visible` |
| A seller's listings do not share a key | `every_listing_gets_its_own_seller_key` (cli), `sale_keys_are_unrelated_hashes_of_the_base_key` (core) |
| A short secret cannot be brute-forced from its commitment | `the_salt_hides_short_secrets` (core) |
| After a dispute, anyone can read the secret (the documented price of a public verdict) | `after_a_dispute_anyone_can_read_the_secret` |

## Seller attacks

| Attack | Defence | Test |
|---|---|---|
| Deliver a different secret | Dispute: the template decrypts and re-hashes; mismatch = `Fraud` | `a_seller_who_delivers_something_else_loses_the_sale_and_the_bond` (e2e) |
| Commit to a block no client can decode, deliver it faithfully | Dispute also checks the block layout | `committing_to_an_undecodable_block_loses_the_dispute`, `a_length_field_past_the_block_loses_the_dispute` |
| Deliver noise | Nothing decrypts to the commitment | `noise_loses_the_dispute`, `random_deliveries_always_lose_the_dispute` |
| Repost another sale's `R` (or `λ·R + k·G`) so the buyer's dispute leaks that sale | `deliver` requires a proof of knowledge of `r`, bound to the sale; a dispute then only publishes `r·B'`, which the seller already knew | `another_sales_ephemeral_key_cannot_be_reposted_to_extract_its_secret`, `a_dispute_reveals_nothing_the_seller_did_not_already_know`, `a_block_sealed_for_another_sale_is_refused_at_delivery` |
| List in a token they can recall or freeze, then drain or lock the escrow | XTM only | `a_token_the_seller_can_recall_is_refused` |
| Never deliver, keep the buyer's funds locked | Delivery deadline; the buyer is owed everything, seller bond included | `no_delivery_returns_everything_to_the_buyer` (e2e), `delivery_is_open_up_to_and_including_the_deadline_only` |
| Squeeze the buyer's time to check and dispute | Windows of at least 3 epochs | `listings_with_bad_terms_are_refused` |
| Cash in before the buyer can dispute | `claim_uncontested` and payouts only after settlement | `the_seller_cannot_cash_in_before_the_dispute_window_closes` |
| Malformed delivery (identity / non-canonical `R`, wrong length) | Refused | `malformed_deliveries_are_refused` |
| Cancel after being paid, or replay a cancellation | Listed-only, proof bound to the sale and the action | `cancellation_needs_the_seller_key_and_an_unsold_listing` |
| Bad terms (zero price or bond, windows out of range, invalid key) | Refused at `list` | `listings_with_bad_terms_are_refused` |
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
| Register a key they do not hold, or the base key in place of the sale key | Proof by the registered key, bound to the sale | `a_buy_proof_is_bound_to_the_key_and_the_sale` |

## Payouts

| Attack | Defence | Test |
|---|---|---|
| Collect someone else's share, or the other side's | Payout signed by the payee's key, per action | `a_payout_must_be_signed_by_its_payee` |
| Swap the outputs of a signed payout (mempool) | The signature covers the digest of the whole canonical transfer | `a_signed_payout_cannot_be_redirected` |
| Take more or less than owed | `revealed_amount` must equal what is owed | `a_payout_spends_exactly_what_is_owed_into_stealth_outputs_only` |
| Reveal part of a payout to someone else | No revealed output; stealth outputs only | `a_payout_spends_exactly_what_is_owed_into_stealth_outputs_only` |
| Mix outside coins or covenant claims into a payout | No stealth inputs, no covenant claims | `a_payout_cannot_carry_other_stealth_inputs`, `a_payout_carries_no_covenant_claims` |
| Collect twice, or after losing | Owed amount zeroed before the transfer; nothing owed to the losing side | `each_payout_happens_once`, `a_payout_happens_once_even_inside_one_transaction`, `the_loser_gets_nothing`, `nothing_is_owed_to_a_buyer_who_never_was` |
| Get a payee to sign a transfer to someone else (a fake helper, a compromised wallet) | The CLI signs only transfers the template accepts for exactly `--owed`, and prints every output and its spend authorisation first; the payee must still check the outputs are theirs | `payout_signs_only_a_transfer_the_template_would_accept` (cli) |
| Client and template disagree on the digest | Both decode and re-encode the transfer before hashing | `the_template_and_the_client_digest_a_payout_identically` (e2e) |

## Third parties and hostile components

| Attack | Defence | Test |
|---|---|---|
| Accept, cancel, deliver or take a payout for a party, from a hostile component in that party's own transaction | Actions need the party's Crypt key, not the signer | `a_hostile_component_in_the_victims_transaction_cannot_act_for_them` |
| Accept with any key but the buyer's sale key, another action, another sale, another delivery | Proof bound to key, action, sale and `R` | `only_the_buyer_sale_key_can_accept_and_only_this_delivery`, `random_action_proofs_never_authorize_anything` |
| Deliver without the seller key, or reuse a delivery signature on other content | Proof covers `R` and the ciphertext | `only_the_seller_key_can_deliver`, `a_delivery_signature_does_not_cover_other_content` |
| Buy a listing twice | One sale per listing | `a_listing_sells_once_and_a_replayed_buy_is_refused` |

## Settlement integrity

| Property | Test |
|---|---|
| A sale settles once, whatever is called afterwards | `a_settled_sale_cannot_be_settled_again` |
| Accept and dispute in one transaction: all or nothing | `accepting_then_disputing_in_one_transaction_is_all_or_nothing` |
| `owed_seller + owed_buyer == escrow` at settlement; escrow empty after payouts | asserted in `settle`; every e2e outcome ends with `pay_out`, which checks the escrow is empty |
| Each payee really controls exactly what it was owed | every e2e outcome: each payout output is spent back and the amount checked |
| Client and template agree byte for byte (commitment, keys, keystream, proofs, payout digest) | `the_template_and_the_client_hash_a_block_identically`, `the_template_registers_the_buyer_sale_key`, `the_template_and_the_client_digest_a_payout_identically` (e2e), every happy path |

## Client safeguards

| Mistake | Safeguard | Test |
|---|---|---|
| Disputing with a key that is not the one registered (it would be refused, but publish a shared point) | `prove_shared` refuses unless the key matches the on-chain buyer key and the proof verifies locally | `a_dispute_is_never_produced_with_the_wrong_key` (core), `a_dispute_is_refused_with_a_key_that_is_not_the_registered_one` (cli) |
| Accepting a delivery that does not match the listing | `open_verified` / `crypt open` say to dispute | `open_verified_flags_what_to_dispute` (core), `open_says_to_dispute_a_delivery_that_is_not_the_listing` (cli) |
| Overwriting a key file | Never overwritten; keygen says to back it up | `keys_and_blocks_are_never_overwritten` (cli) |

## Supply chain

The build is pinned by the committed `Cargo.lock` and CI runs `cargo audit`. Five RustSec warnings
(unmaintained or unsound crates) are triaged in `.cargo/audit.toml`: all sit in the ledger simulator the
tests use or in the build-time metadata generator, none in the template, `crypt_core` or the CLI.
Vulnerabilities are never ignored.

## Limits, stated plainly

* The template proves the delivered secret is the committed one. It cannot judge whether the secret is
  worth the price.
* A dispute publishes `S`, so the secret becomes public. Dispute well before the deadline: a dispute
  that lands after it is refused, but `S` was already visible in the pending transaction.
* A seller can always make their own secret public, by publishing `r`, `S` or the block.
* **The Crypt key is the only way to collect what a sale owes you.** A lost key leaves that share in
  escrow for good. The deadlines still settle a sale without the key, but the payout needs it.
* Privacy is that of stealth XTM, without decoys: the coins spent into a sale and the outputs paid out
  of it are visible commitments that link to their holders' other transactions, and every transaction
  shows who signed it and who paid its fee. The amounts of a sale are public, so a payout in a single
  output reveals its value; split payouts. If XTM carries a view key on the target network, its holder
  sees the amounts.
* The template understands the `StealthTransferStatement` format of `tari_template_lib` 0.34. A future
  incompatible change to that format would block payouts from deployed components until the clients
  and the network agree on it again.
* No professional audit. The primitives are standard (Ristretto255, Schnorr, Chaum-Pedersen, SHA-512,
  Pedersen commitments) and the engine's intrinsics do the group arithmetic. The composition went
  through three adversarial review passes; the second found a cross-sale leak in an earlier design,
  closed by the proof of `r` and covered by the tests above.
* Deadlines are in epochs; their wall-clock length depends on the network.
