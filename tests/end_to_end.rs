//! Crypt against a simulated Ootle ledger, driven by the real client code in `crypt_core`.
//!
//! Every way a sale can end, funded from stealth coins and paid out into fresh stealth outputs that
//! are then actually spent, so each test proves the right party ends up controlling the right amount.
//! The happy paths double as cross-implementation checks: the client derives keys, seals, proves and
//! digests with `curve25519-dalek` + `sha2`, the template verifies with engine intrinsics, so any
//! divergence breaks a test instead of a sale. The attacks are in `attacks.rs`.
//!
//! Linux/macOS only: `tari_template_test_tooling` pulls the engine, whose Cranelift JIT does not build
//! on Windows. CI runs it.

mod common;
use common::*;

#[test]
fn the_template_and_the_client_hash_a_block_identically() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let on_chain: Hash64 =
        m.test
            .call_function("Crypt", "commitment_of", args![Bytes::from_vec(block.to_vec())], vec![]);
    assert_eq!(on_chain, Hash64::from(client::commitment_of(&block)));
}

#[test]
fn the_template_and_the_client_digest_a_payout_identically() {
    let mut m = Market::new();
    let statement = payout_statement(1_234).statement;
    let on_chain: Hash64 = m
        .test
        .call_function("Crypt", "payout_digest", args![statement.clone()], vec![]);
    assert_eq!(on_chain, Hash64::from(digest_of(&statement)));
}

#[test]
fn the_template_registers_the_buyer_sale_key() {
    let mut m = Market::new();
    let sale = m.paid();
    let on_chain: Option<RistrettoPublicKeyBytes> = m.test.call_method(sale.crypt, "buyer_key", args![], vec![]);
    assert_eq!(on_chain, Some(point(sale.buyer_key.public())));
}

#[test]
fn an_honest_sale_pays_the_seller_and_returns_both_bonds() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();

    // The buyer reads the delivery from the ledger and opens it off-chain, checked against the listing.
    let (ephemeral, ciphertext): (RistrettoPublicKeyBytes, Bytes) = m
        .test
        .call_method::<Option<_>>(sale.crypt, "delivery", args![], vec![])
        .unwrap();
    let ciphertext: client::Block = ciphertext.as_slice().try_into().unwrap();
    let commitment: Hash64 = m.test.call_method(sale.crypt, "commitment", args![], vec![]);
    let commitment: [u8; 64] = commitment.as_ref().try_into().unwrap();
    let secret = client::open_verified(
        &sale.buyer_key,
        &context(sale.crypt),
        &ephemeral.into_array(),
        &ciphertext,
        &commitment,
    )
    .unwrap();
    assert_eq!(secret, SECRET);

    let args = m.accept_args(&sale);
    m.ok(sale.crypt, "accept", args);
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Accepted"));
    assert_eq!(m.owed(sale.crypt), (a(PRICE + SELLER_BOND), a(BUYER_BOND)));
    m.pay_out(&sale);
}

#[test]
fn a_false_dispute_pays_the_seller_and_costs_the_buyer_the_bond() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(sale.crypt, "dispute", args);

    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("DisputeRejected"));
    assert_eq!(
        m.owed(sale.crypt),
        (a(PRICE + SELLER_BOND + BUYER_BOND), Amount::zero())
    );
    m.pay_out(&sale);
}

#[test]
fn a_seller_who_delivers_something_else_loses_the_sale_and_the_bond() {
    let mut m = Market::new();
    let sale = m.paid();
    let other = client::encode_plaintext(b"not what you paid for", &mut OsRng).unwrap();
    let sealed = m.seal(&sale, &other);
    let args = m.deliver_args(sale.crypt, &sealed);
    m.ok(sale.crypt, "deliver", args);

    // The client flags it before the buyer does anything.
    let commitment = client::commitment_of(&sale.block);
    assert_eq!(
        client::open_verified(
            &sale.buyer_key,
            &context(sale.crypt),
            &sealed.ephemeral,
            &sealed.ciphertext,
            &commitment
        ),
        Err(client::Error::CommitmentMismatch)
    );

    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(sale.crypt, "dispute", args);
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Fraud"));
    assert_eq!(
        m.owed(sale.crypt),
        (Amount::zero(), a(PRICE + BUYER_BOND + SELLER_BOND))
    );
    m.pay_out(&sale);
}

#[test]
fn silence_after_delivery_pays_the_seller() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    m.epoch(START_EPOCH + DISPUTE_WINDOW + 1);
    m.ok(sale.crypt, "claim_uncontested", args![]);
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Uncontested"));
    assert_eq!(m.owed(sale.crypt), (a(PRICE + SELLER_BOND), a(BUYER_BOND)));
    m.pay_out(&sale);
}

#[test]
fn no_delivery_returns_everything_to_the_buyer() {
    let mut m = Market::new();
    let sale = m.paid();
    m.epoch(START_EPOCH + DELIVERY_WINDOW + 1);
    m.ok(sale.crypt, "claim_undelivered", args![]);
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Undelivered"));
    assert_eq!(
        m.owed(sale.crypt),
        (Amount::zero(), a(PRICE + BUYER_BOND + SELLER_BOND))
    );
    m.pay_out(&sale);
}

#[test]
fn the_seller_can_cancel_before_a_sale() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let args = m.cancel_args(crypt);
    m.ok(crypt, "cancel", args);
    assert_eq!(m.owed(crypt), (a(SELLER_BOND), Amount::zero()));
    let unsold = Sale {
        crypt,
        block,
        buyer_key: Keypair::generate(&mut OsRng),
    };
    m.pay_out(&unsold);
}
