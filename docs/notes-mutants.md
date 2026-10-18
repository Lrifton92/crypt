# Mutation testing (`cargo mutants -p crypt_core`)

Run by `.github/workflows/offense.yml`. First run, 18 October 2026: 247 mutants, 174 caught,
59 unviable, 1 timeout (counted as caught: the mutant loops forever), 13 missed.

| Missed mutant | What it showed | Now |
|---|---|---|
| `msg_deliver` returns `vec![]`, `vec![0]`, `vec![1]` | The client signs and checks with the same function, so a change agrees with itself; only the engine tests (Linux, not run here) saw the template disagree | Layout pinned: `the_delivery_message_and_the_hash_framing_are_pinned` |
| `len_prefix` returns `[0; 8]`, `[1; 8]` | Same: every hash frames its domain the same wrong way on both client sides | Commitment checked against SHA-512 written out by hand, same test |
| `Sale::commitment`, `Sale::listing_deadline`, `Sale::buyer_key` return constants | Accessors of the rules port no test read (the equivalence test reads the template's) | Asserted in `honest_sale_pays_price_and_seller_bond_to_seller` |
| `impl Drop for Keypair` does nothing | **Equivalent mutant.** It only wipes the secret scalar from memory; no safe test can observe freed memory. Kept as defence in depth | No test |
