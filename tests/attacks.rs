//! The attack battery. Each test plays one attack against the template, through the real client or
//! by hand-crafting what a hostile client would send, and checks that it fails, and fails for the
//! stated reason. A rejected attack must also leave the sale exactly as it was.
//!
//! Sections: what the ledger shows, seller attacks, buyer attacks, payouts, third parties and hostile
//! components, settlement integrity, random inputs.

mod common;
use common::*;

use tari_template_lib_types::stealth::CovenantBalanceClaim;

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::CompressedRistretto, scalar::Scalar};

fn random_point() -> [u8; 32] {
    (Scalar::random(&mut OsRng) * G).compress().to_bytes()
}

fn random_scalar() -> [u8; 32] {
    Scalar::random(&mut OsRng).to_bytes()
}

/// `l`, the group order: canonical encodings stop at `l - 1`, so `l` itself is the smallest
/// non-canonical scalar, the one a malleability attack would use.
const GROUP_ORDER: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn deliver_raw(ephemeral: [u8; 32], ephemeral_proof: Proof, ciphertext: Vec<u8>, seller_proof: Proof) -> Vec<NamedArg> {
    args![
        point(ephemeral),
        scalar(ephemeral_proof.c),
        scalar(ephemeral_proof.z),
        Bytes::from_vec(ciphertext),
        scalar(seller_proof.c),
        scalar(seller_proof.z)
    ]
}

fn decrypt(ciphertext: &client::Block, stream: &client::Block) -> client::Block {
    let mut out = *ciphertext;
    out.iter_mut().zip(stream.iter()).for_each(|(c, k)| *c ^= k);
    out
}

/// A sale that ended with the buyer accepting: the seller is owed price + bond, the buyer their bond.
fn accepted(m: &mut Market) -> Sale {
    let (sale, _) = m.delivered();
    let args = m.accept_args(&sale);
    m.ok(sale.crypt, "accept", args);
    sale
}

// ================================================================================================
// What the ledger shows
// ================================================================================================

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decimal_list(bytes: &[u8]) -> String {
    bytes.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// Every representation of `needle` an indexer, an explorer or a log could plausibly show.
fn assert_nowhere(label: &str, raw: &[u8], text: &str, needle: &[u8], what: &str) {
    assert!(!contains(raw, needle), "{label}: {what} found in the raw encoding");
    assert!(
        !text.contains(&*String::from_utf8_lossy(needle)),
        "{label}: {what} found as text"
    );
    assert!(!text.contains(&hex(needle)), "{label}: {what} found as hex");
    assert!(
        !text.contains(&decimal_list(needle)),
        "{label}: {what} found as a byte list"
    );
}

/// A whole sale, list to payout, inspecting every transaction of the sale and every result as an
/// observer of the network would. Nothing may reveal the secret, its salt or the shared point, and no
/// account appears in the sale's own transactions: the parties pay from stealth coins and are paid
/// into stealth outputs. (The coins themselves still link to the transactions that created them; see
/// THREAT_MODEL.md.)
#[test]
fn nothing_on_the_ledger_reveals_the_secret_and_no_account_appears_in_the_sale() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let salt = block[..client::SALT_LEN].to_vec();
    let mut seen: Vec<(String, Vec<u8>, String)> = vec![];
    let mut run = |m: &mut Market, label: &str, tx: Transaction| {
        let tx_text = format!("{tx:?}");
        let result = m.test.execute_expect_success(tx, vec![]);
        let raw = minicbor::to_vec(&result).unwrap();
        seen.push((label.to_string(), raw, format!("{result:?} {tx_text}")));
        result
    };

    let seller = copy_key(&m.seller_key);
    let tx = m.list_tx(
        Hash64::from(client::commitment_of(&block)),
        seller.public(),
        &seller,
        SELLER_BOND,
        PRICE,
        BUYER_BOND,
        (LISTING_WINDOW, DELIVERY_WINDOW, DISPUTE_WINDOW),
    );
    let result = run(&mut m, "list", tx);
    let crypt = result
        .finalize
        .execution_results
        .iter()
        .find_map(|r| r.decode::<ComponentAddress>().ok())
        .unwrap();

    let ctx = context(crypt);
    let sale_key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&sale_key, &ctx, client::MSG_BUY, &mut OsRng);
    let tx = m.buy_tx(crypt, sale_key.public(), proof, PRICE + BUYER_BOND);
    run(&mut m, "buy", tx);

    let sealed = client::seal(&block, &sale_key.public(), &ctx, &mut OsRng).unwrap();
    let shared = client::shared_point(&sale_key, &sealed.ephemeral).unwrap();
    let tx = m.call_tx(crypt, "deliver", m.deliver_args(crypt, &sealed));
    run(&mut m, "deliver", tx);

    let accept = proof_args(client::prove_action(
        &sale_key,
        &ctx,
        &client::msg_accept(&sealed.ephemeral),
        &mut OsRng,
    ));
    let tx = m.call_tx(crypt, "accept", accept);
    run(&mut m, "accept", tx);

    let seller_payout = payout_statement(PRICE + SELLER_BOND);
    let tx = m.call_tx(
        crypt,
        "pay_seller",
        payout_args(&m.seller_key, crypt, Side::Seller, &seller_payout.statement),
    );
    run(&mut m, "pay_seller", tx);
    let buyer_payout = payout_statement(BUYER_BOND);
    let tx = m.call_tx(
        crypt,
        "pay_buyer",
        payout_args(&sale_key, crypt, Side::Buyer, &buyer_payout.statement),
    );
    run(&mut m, "pay_buyer", tx);

    let bank = m.bank.account;
    for (label, raw, text) in &seen {
        assert_nowhere(label, raw, text, SECRET, "the secret");
        assert_nowhere(label, raw, text, &salt, "the salt");
        assert_nowhere(label, raw, text, &shared, "the shared point");
        assert_nowhere(label, raw, text, bank.as_bytes(), "the funding account");
    }
    let state: Option<(RistrettoPublicKeyBytes, Bytes)> = m.test.call_method(crypt, "delivery", args![], vec![]);
    assert!(!contains(state.unwrap().1.as_slice(), SECRET));
    let revealed: Option<RistrettoPublicKeyBytes> = m.test.call_method(crypt, "shared", args![], vec![]);
    assert_eq!(revealed, None, "S stays private when there is no dispute");

    // Each payout really belongs to its payee.
    m.redeem(&Coin {
        data: seller_payout,
        value: PRICE + SELLER_BOND,
    });
    m.redeem(&Coin {
        data: buyer_payout,
        value: BUYER_BOND,
    });
}

#[test]
fn two_sales_of_the_same_secret_share_nothing_visible() {
    let mut m = Market::new();
    let mut seen = vec![];
    for _ in 0..2 {
        let (sale, sealed) = m.delivered();
        seen.push((
            client::commitment_of(&sale.block),
            sale.buyer_key.public(),
            sealed.ephemeral,
            sealed.ciphertext,
        ));
    }
    let (c1, b1, r1, x1) = &seen[0];
    let (c2, b2, r2, x2) = &seen[1];
    assert_ne!(c1, c2, "salted commitments differ");
    assert_ne!(b1, b2, "sale keys differ");
    assert_ne!(r1, r2, "ephemeral keys differ");
    let common_bytes = x1.iter().zip(x2.iter()).filter(|(a, b)| a == b).count();
    assert!(
        common_bytes < 16,
        "ciphertexts look unrelated ({common_bytes} equal bytes of 320)"
    );
}

/// The documented price of a dispute: once `S` is public, anyone can read the secret. This test
/// exists so the README cannot quietly overclaim.
#[test]
fn after_a_dispute_anyone_can_read_the_secret() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(sale.crypt, "dispute", args);

    let shared: Option<RistrettoPublicKeyBytes> = m.test.call_method(sale.crypt, "shared", args![], vec![]);
    let key: Option<RistrettoPublicKeyBytes> = m.test.call_method(sale.crypt, "buyer_key", args![], vec![]);
    let stream = client::keystream(
        &context(sale.crypt),
        &key.unwrap().into_array(),
        &sealed.ephemeral,
        &shared.unwrap().into_array(),
    );
    assert_eq!(
        client::decode_plaintext(&decrypt(&sealed.ciphertext, &stream)).unwrap(),
        SECRET
    );
}

// ================================================================================================
// Seller attacks
// ================================================================================================

#[test]
fn committing_to_an_undecodable_block_loses_the_dispute() {
    // Hash matches, layout does not: the buyer would hold nothing readable.
    let mut m = Market::new();
    let mut block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    block[client::PLAINTEXT_LEN - 1] = 0x01;
    let crypt = m.list(&block);
    let buyer_key = m.buy(crypt);
    let sale = Sale {
        crypt,
        block,
        buyer_key,
    };
    let sealed = m.seal(&sale, &sale.block);
    let args = m.deliver_args(crypt, &sealed);
    m.ok(crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(crypt, "dispute", args);
    assert_eq!(m.outcome(crypt).as_deref(), Some("Fraud"));
}

#[test]
fn a_length_field_past_the_block_loses_the_dispute() {
    let mut m = Market::new();
    let mut block = client::encode_plaintext(b"", &mut OsRng).unwrap();
    block[client::SALT_LEN..client::SALT_LEN + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    let crypt = m.list(&block);
    let buyer_key = m.buy(crypt);
    let sale = Sale {
        crypt,
        block,
        buyer_key,
    };
    let sealed = m.seal(&sale, &sale.block);
    let args = m.deliver_args(crypt, &sealed);
    m.ok(crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(crypt, "dispute", args);
    assert_eq!(m.outcome(crypt).as_deref(), Some("Fraud"));
}

#[test]
fn noise_loses_the_dispute() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = Market::noise(sale.crypt);
    let args = m.deliver_args(sale.crypt, &sealed);
    m.ok(sale.crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(sale.crypt, "dispute", args);
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Fraud"));
}

#[test]
fn a_block_sealed_for_another_sale_is_refused_at_delivery() {
    // Its proof of r is bound to the other sale.
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = client::seal(&sale.block, &sale.buyer_key.public(), b"some other sale", &mut OsRng).unwrap();
    let args = m.deliver_args(sale.crypt, &sealed);
    m.refused(sale.crypt, "deliver", args, "invalid ephemeral proof");
}

/// The attack the second review found against an earlier, additive key tweak: a seller reposts sale
/// A's `R` in sale B so that the buyer's dispute in B publishes something from which anyone computes
/// sale A's shared point. Every such repost is refused, including variants of `R` derived from `R_A`,
/// because the seller must prove knowledge of `r` for this sale.
#[test]
fn another_sales_ephemeral_key_cannot_be_reposted_to_extract_its_secret() {
    let mut m = Market::new();

    let block_a = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt_a = m.list(&block_a);
    let key_a = m.buy(crypt_a);
    let sale_a = Sale {
        crypt: crypt_a,
        block: block_a,
        buyer_key: key_a,
    };
    let sealed_a = m.seal(&sale_a, &sale_a.block);
    let args = m.deliver_args(crypt_a, &sealed_a);
    m.ok(crypt_a, "deliver", args);

    // Sale B, by the attacker. Everything about sale A they use is public.
    let crypt_b = m.list(&client::encode_plaintext(b"bait", &mut OsRng).unwrap());
    m.buy(crypt_b);
    let ctx_b = context(crypt_b);
    let r_a = CompressedRistretto(sealed_a.ephemeral).decompress().unwrap();
    let derived = (Scalar::from(3u64) * r_a + Scalar::from(5u64) * G)
        .compress()
        .to_bytes();
    let any_key_proof = || {
        client::prove_action(
            &Keypair::generate(&mut OsRng),
            &ctx_b,
            client::MSG_EPHEMERAL,
            &mut OsRng,
        )
    };
    let attempts = [
        (sealed_a.ephemeral, sealed_a.ephemeral_proof),
        (sealed_a.ephemeral, any_key_proof()),
        (derived, any_key_proof()),
    ];
    for (ephemeral, ephemeral_proof) in attempts {
        let seller_proof = client::prove_action(
            &m.seller_key,
            &ctx_b,
            &client::msg_deliver(&ephemeral, &sealed_a.ciphertext),
            &mut OsRng,
        );
        let args = deliver_raw(ephemeral, ephemeral_proof, sealed_a.ciphertext.to_vec(), seller_proof);
        m.refused(crypt_b, "deliver", args, "invalid ephemeral proof");
    }
    assert_eq!(m.stage(crypt_b), "Paid", "nothing was delivered in sale B");
}

/// With a known `r`, a dispute only reveals what the seller could compute anyway: `r·B'`.
#[test]
fn a_dispute_reveals_nothing_the_seller_did_not_already_know() {
    let mut m = Market::new();
    let sale = m.paid();
    let r = Keypair::generate(&mut OsRng);
    let ctx = context(sale.crypt);
    let sealed = client::Sealed {
        ephemeral: r.public(),
        ephemeral_proof: client::prove_action(&r, &ctx, client::MSG_EPHEMERAL, &mut OsRng),
        ciphertext: [0x13; client::PLAINTEXT_LEN],
    };
    let args = m.deliver_args(sale.crypt, &sealed);
    m.ok(sale.crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(sale.crypt, "dispute", args);

    let published: Option<RistrettoPublicKeyBytes> = m.test.call_method(sale.crypt, "shared", args![], vec![]);
    let seller_side = client::shared_point(&r, &sale.buyer_key.public()).unwrap();
    assert_eq!(
        published.unwrap().into_array(),
        seller_side,
        "S = r·B', known to the seller beforehand"
    );
}

#[test]
fn only_the_seller_key_can_deliver() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = m.seal(&sale, &sale.block);
    let impostor = Keypair::generate(&mut OsRng);
    for signer in [&impostor, &sale.buyer_key] {
        let args = Market::deliver_args_signed_by(signer, sale.crypt, &sealed);
        m.refused(sale.crypt, "deliver", args, "invalid seller proof");
    }
    assert_eq!(m.stage(sale.crypt), "Paid");
}

#[test]
fn a_delivery_signature_does_not_cover_other_content() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = m.seal(&sale, &sale.block);
    let ctx = context(sale.crypt);
    let signed = client::prove_action(
        &m.seller_key,
        &ctx,
        &client::msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
        &mut OsRng,
    );
    let mut swapped = sealed.ciphertext;
    swapped[0] ^= 1;
    let args = deliver_raw(sealed.ephemeral, sealed.ephemeral_proof, swapped.to_vec(), signed);
    m.refused(sale.crypt, "deliver", args, "invalid seller proof");

    // Another R the seller does know, with the signature over the original R.
    let r = Keypair::generate(&mut OsRng);
    let r_proof = client::prove_action(&r, &ctx, client::MSG_EPHEMERAL, &mut OsRng);
    let args = deliver_raw(r.public(), r_proof, sealed.ciphertext.to_vec(), signed);
    m.refused(sale.crypt, "deliver", args, "invalid seller proof");
}

#[test]
fn malformed_deliveries_are_refused() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = m.seal(&sale, &sale.block);
    let ctx = context(sale.crypt);
    let mut bad = |ephemeral: [u8; 32], ciphertext: Vec<u8>, reason: &str| {
        let seller_proof = client::prove_action(
            &m.seller_key,
            &ctx,
            &client::msg_deliver(&ephemeral, &ciphertext),
            &mut OsRng,
        );
        let args = deliver_raw(ephemeral, sealed.ephemeral_proof, ciphertext, seller_proof);
        m.refused(sale.crypt, "deliver", args, reason);
    };
    bad([0u8; 32], sealed.ciphertext.to_vec(), "must not be the identity point");
    bad(
        [0xff; 32],
        sealed.ciphertext.to_vec(),
        "not a canonical Ristretto point",
    );
    bad(sealed.ephemeral, sealed.ciphertext[..319].to_vec(), "exactly 320 bytes");
    bad(
        sealed.ephemeral,
        [sealed.ciphertext.as_slice(), &[0]].concat(),
        "exactly 320 bytes",
    );
    bad(sealed.ephemeral, vec![], "exactly 320 bytes");
    assert_eq!(m.stage(sale.crypt), "Paid");
}

#[test]
fn delivery_is_open_up_to_and_including_the_deadline_only() {
    let mut m = Market::new();
    let deadline = START_EPOCH + DELIVERY_WINDOW;

    let on_time = m.paid();
    m.epoch(deadline);
    let sealed = m.seal(&on_time, &on_time.block);
    let args = m.deliver_args(on_time.crypt, &sealed);
    m.ok(on_time.crypt, "deliver", args);

    m.epoch(START_EPOCH);
    let late = m.paid();
    m.epoch(deadline);
    m.refused(
        late.crypt,
        "claim_undelivered",
        args![],
        "the delivery window is still open",
    );
    m.epoch(deadline + 1);
    let sealed = m.seal(&late, &late.block);
    let args = m.deliver_args(late.crypt, &sealed);
    m.refused(late.crypt, "deliver", args, "delivery deadline passed");
}

#[test]
fn the_seller_cannot_cash_in_before_the_dispute_window_closes() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    m.refused(
        sale.crypt,
        "claim_uncontested",
        args![],
        "the dispute window is still open",
    );
    m.epoch(START_EPOCH + DISPUTE_WINDOW);
    m.refused(
        sale.crypt,
        "claim_uncontested",
        args![],
        "the dispute window is still open",
    );
    m.refused(sale.crypt, "claim_undelivered", args![], "not awaiting delivery");
    let statement = payout_statement(PRICE + SELLER_BOND).statement;
    let args = payout_args(&m.seller_key, sale.crypt, Side::Seller, &statement);
    m.refused(sale.crypt, "pay_seller", args, "not settled");
}

#[test]
fn cancellation_needs_the_seller_key_and_an_unsold_listing() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let other = m.list(&block);
    let ctx = context(crypt);

    let impostor = Keypair::generate(&mut OsRng);
    let forged = proof_args(client::prove_action(&impostor, &ctx, client::MSG_CANCEL, &mut OsRng));
    m.refused(crypt, "cancel", forged, "invalid seller proof");
    let for_other = m.cancel_args(other);
    m.refused(crypt, "cancel", for_other, "invalid seller proof");
    let wrong_action = proof_args(client::prove_action(&m.seller_key, &ctx, b"accept", &mut OsRng));
    m.refused(crypt, "cancel", wrong_action, "invalid seller proof");

    m.buy(crypt);
    let args = m.cancel_args(crypt);
    m.refused(crypt, "cancel", args, "already sold");
}

#[test]
fn listings_with_bad_terms_are_refused() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let commitment = Hash64::from(client::commitment_of(&block));
    let seller = copy_key(&m.seller_key);
    let key = seller.public();
    let w = (LISTING_WINDOW, DELIVERY_WINDOW, DISPUTE_WINDOW);
    let mut bad = |key: [u8; 32], bond: u64, price: u64, buyer_bond: u64, windows: (u64, u64, u64), reason: &str| {
        let tx = m.list_tx(commitment, key, &seller, bond, price, buyer_bond, windows);
        assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), reason);
    };
    bad(key, SELLER_BOND, 0, BUYER_BOND, w, "price must be positive");
    bad(key, SELLER_BOND, PRICE, 0, w, "buyer bond must be positive");
    for windows in [
        (LISTING_WINDOW, 0, DISPUTE_WINDOW),
        (LISTING_WINDOW, 2, DISPUTE_WINDOW),
        (LISTING_WINDOW, DELIVERY_WINDOW, 2),
        (LISTING_WINDOW, 10_001, 10_001),
        (2, DELIVERY_WINDOW, DISPUTE_WINDOW),
        (10_001, DELIVERY_WINDOW, DISPUTE_WINDOW),
    ] {
        bad(key, SELLER_BOND, PRICE, BUYER_BOND, windows, "windows must be between");
    }
    // A bond too small to deter delivering noise, a buyer bond that turns a dispute into a trap, and a
    // dispute window shorter than the time the buyer must already watch for a delivery.
    bad(
        key,
        PRICE / 10 - 1,
        PRICE,
        BUYER_BOND,
        w,
        "seller bond must be at least 10% of the price",
    );
    bad(
        key,
        SELLER_BOND,
        PRICE,
        PRICE + 1,
        w,
        "buyer bond must not exceed the price",
    );
    bad(
        key,
        SELLER_BOND,
        PRICE,
        BUYER_BOND,
        (LISTING_WINDOW, DISPUTE_WINDOW + 1, DISPUTE_WINDOW),
        "the dispute window must be at least the delivery window",
    );
    bad(
        [0u8; 32],
        SELLER_BOND,
        PRICE,
        BUYER_BOND,
        w,
        "must not be the identity point",
    );
    bad(
        [0xff; 32],
        SELLER_BOND,
        PRICE,
        BUYER_BOND,
        w,
        "not a canonical Ristretto point",
    );
}

#[test]
fn terms_at_the_bounds_are_accepted() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let commitment = Hash64::from(client::commitment_of(&block));
    let seller = copy_key(&m.seller_key);
    let tx = m.list_tx(
        commitment,
        seller.public(),
        &seller,
        PRICE / 10,
        PRICE,
        PRICE,
        (3, 3, 3),
    );
    m.test.execute_expect_success(tx, vec![]);
}

#[test]
fn a_listing_cannot_reuse_another_sellers_key() {
    // Mallory copies a real listing's commitment and seller key at a price of 1, buys her clone and
    // asks the seller to deliver to it: the seller's key would sign a delivery for almost nothing
    // (fourth review, T1). Listing now takes a proof by the seller key over every term.
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let commitment = Hash64::from(client::commitment_of(&block));
    m.list(&block);
    let victim = m.seller_key.public();
    let mallory = Keypair::generate(&mut OsRng);
    let tx = m.list_tx(commitment, victim, &mallory, 1, 1, 1, (3, 3, 3));
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "invalid seller proof");
}

#[test]
fn a_list_proof_is_bound_to_its_terms() {
    // A proof the seller made for one set of terms cannot list another (here: a lower price).
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let commitment = client::commitment_of(&block);
    let seller = copy_key(&m.seller_key);
    let honest = client::msg_list(
        &commitment,
        u128::from(PRICE),
        u128::from(BUYER_BOND),
        u128::from(SELLER_BOND),
        LISTING_WINDOW,
        DELIVERY_WINDOW,
        DISPUTE_WINDOW,
    );
    let proof = client::prove_action(&seller, client::LIST_CONTEXT, &honest, &mut OsRng);
    let coin = m.coin(SELLER_BOND);
    let template = m.test.get_template_address("Crypt");
    let tx = m
        .test
        .transaction()
        .stealth_transfer(TARI_TOKEN, coin.spend_to_bucket())
        .put_last_instruction_output_on_workspace("bond")
        .call_function(
            template,
            "list",
            args![
                Hash64::from(commitment),
                Amount::from_u64(PRICE - 1),
                Amount::from_u64(BUYER_BOND),
                LISTING_WINDOW,
                DELIVERY_WINDOW,
                DISPUTE_WINDOW,
                point(seller.public()),
                scalar(proof.c),
                scalar(proof.z),
                Workspace("bond")
            ],
        )
        .build_and_seal(coin.key());
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "invalid seller proof");
}

#[test]
fn a_listing_cannot_be_bought_after_it_expires() {
    // A seller who stopped watching must not lose their bond to whoever buys a stale listing and
    // claims it undelivered (fourth review, F1).
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let late = m.list(&block);
    m.epoch(START_EPOCH + LISTING_WINDOW + 1);
    let ctx = context(late);
    let sale_key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&sale_key, &ctx, client::MSG_BUY, &mut OsRng);
    let tx = m.buy_tx(late, sale_key.public(), proof, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "listing expired");
    assert_eq!(m.stage(late), "Listed");
    // The seller can still take the bond back.
    let args = m.cancel_args(late);
    m.ok(late, "cancel", args);
    assert_eq!(m.owed(late), (a(SELLER_BOND), Amount::zero()));
}

#[test]
fn a_listing_can_be_bought_up_to_and_including_its_last_epoch() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    m.epoch(START_EPOCH + LISTING_WINDOW);
    m.buy(crypt);
    assert_eq!(m.stage(crypt), "Paid");
}

#[test]
fn a_token_the_seller_can_recall_is_refused() {
    let mut m = Market::with_templates(&[".", "tests/templates/evil"]);
    let evil = m.test.get_template_address("Evil");
    let crypt_template = m.test.get_template_address("Crypt");
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let tx = m
        .test
        .transaction()
        .call_function(evil, "mint_recallable", args![Amount::from_u64(SELLER_BOND)])
        .put_last_instruction_output_on_workspace("bond")
        .call_function(
            crypt_template,
            "list",
            args![
                Hash64::from(client::commitment_of(&block)),
                Amount::from_u64(PRICE),
                Amount::from_u64(BUYER_BOND),
                LISTING_WINDOW,
                DELIVERY_WINDOW,
                DISPUTE_WINDOW,
                point(m.seller_key.public()),
                scalar([0u8; 32]),
                scalar([0u8; 32]),
                Workspace("bond")
            ],
        )
        .build_and_seal(m.test.secret_key());
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "only XTM is accepted");
}

// ================================================================================================
// Buyer attacks
// ================================================================================================

#[test]
fn a_buyer_cannot_fake_a_fraud() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let ctx = context(sale.crypt);

    // A shared point from another key, with a valid proof for that other key.
    let (s, p) = forged_dispute(&Keypair::generate(&mut OsRng), sale.crypt, &sealed.ephemeral);
    m.refused(
        sale.crypt,
        "dispute",
        dispute_args(s, p),
        "invalid proof that the shared point",
    );

    let registered = sale.buyer_key.public();
    let (shared, proof) =
        client::prove_shared(&sale.buyer_key, &registered, &ctx, &sealed.ephemeral, &mut OsRng).unwrap();
    let mut bent = proof;
    bent.z[1] ^= 1;
    let attempts = [
        (shared, bent),
        (random_point(), proof),
        (shared, Proof { c: proof.z, z: proof.c }),
        (shared, Proof { c: [0; 32], z: [0; 32] }),
    ];
    for (s, p) in attempts {
        m.refused(
            sale.crypt,
            "dispute",
            dispute_args(s, p),
            "invalid proof that the shared point",
        );
    }
    // Malleability: same scalar, non-canonical encoding.
    for p in [
        Proof {
            c: proof.c,
            z: GROUP_ORDER,
        },
        Proof {
            c: GROUP_ORDER,
            z: proof.z,
        },
    ] {
        m.refused(
            sale.crypt,
            "dispute",
            dispute_args(shared, p),
            "proof scalars must be canonical",
        );
    }
    m.refused(
        sale.crypt,
        "dispute",
        dispute_args([0u8; 32], proof),
        "must not be the identity point",
    );
    m.refused(
        sale.crypt,
        "dispute",
        dispute_args([0xff; 32], proof),
        "not a canonical Ristretto point",
    );

    assert_eq!(
        m.stage(sale.crypt),
        "Delivered",
        "every rejected dispute left the sale untouched"
    );
    let revealed: Option<RistrettoPublicKeyBytes> = m.test.call_method(sale.crypt, "shared", args![], vec![]);
    assert_eq!(revealed, None);
}

#[test]
fn a_dispute_proof_cannot_be_replayed_into_another_sale() {
    let mut m = Market::new();
    let (first, sealed) = m.delivered();
    let (second, _) = m.delivered();
    let args = m.dispute_args(&first, &sealed.ephemeral);
    m.refused(second.crypt, "dispute", args, "invalid proof that the shared point");
}

#[test]
fn the_dispute_window_includes_its_last_epoch_and_nothing_after() {
    let mut m = Market::new();
    let deadline = START_EPOCH + DISPUTE_WINDOW;

    let (on_time, sealed) = m.delivered();
    m.epoch(deadline);
    let args = m.dispute_args(&on_time, &sealed.ephemeral);
    m.ok(on_time.crypt, "dispute", args);

    m.epoch(START_EPOCH);
    let (late, sealed) = m.delivered();
    m.epoch(deadline + 1);
    let args = m.dispute_args(&late, &sealed.ephemeral);
    m.refused(late.crypt, "dispute", args, "dispute deadline passed");
    let args = m.accept_args(&late);
    m.ok(late.crypt, "accept", args);
}

#[test]
fn only_the_buyer_sale_key_can_accept_and_only_this_delivery() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let (other, other_sealed) = m.delivered();
    let ctx = context(sale.crypt);
    let this = client::msg_accept(&sealed.ephemeral);
    let sign = |k: &Keypair, ctx: &[u8], msg: &[u8]| proof_args(client::prove_action(k, ctx, msg, &mut OsRng));

    let attempts = [
        sign(&Keypair::generate(&mut OsRng), &ctx, &this),
        sign(&m.seller_key, &ctx, &this),
        sign(&sale.buyer_key, &ctx, client::MSG_CANCEL),
        sign(&sale.buyer_key, &ctx, &client::msg_accept(&other_sealed.ephemeral)),
        sign(&sale.buyer_key, &context(other.crypt), &this),
        sign(
            &other.buyer_key,
            &context(other.crypt),
            &client::msg_accept(&other_sealed.ephemeral),
        ),
    ];
    for args in attempts {
        m.refused(sale.crypt, "accept", args, "invalid buyer proof");
    }
    assert_eq!(m.stage(sale.crypt), "Delivered");
}

#[test]
fn payment_must_be_exact() {
    let mut m = Market::new();
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let ctx = context(crypt);
    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    for amount in [PRICE + BUYER_BOND - 1, PRICE + BUYER_BOND + 1, PRICE, 1] {
        let proof = client::prove_action(&key, &ctx, client::MSG_BUY, &mut OsRng);
        let tx = m.buy_tx(crypt, key.public(), proof, amount);
        assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "payment must be exactly");
    }
    assert_eq!(m.stage(crypt), "Listed");
}

#[test]
fn payment_in_another_token_is_refused() {
    let mut m = Market::with_templates(&[".", "tests/templates/evil"]);
    let evil = m.test.get_template_address("Evil");
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let ctx = context(crypt);
    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&key, &ctx, client::MSG_BUY, &mut OsRng);
    let tx = m
        .test
        .transaction()
        .call_function(evil, "mint_recallable", args![Amount::from_u64(PRICE + BUYER_BOND)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(
            crypt,
            "buy",
            args![
                point(key.public()),
                scalar(proof.c),
                scalar(proof.z),
                Workspace("payment")
            ],
        )
        .build_and_seal(m.test.secret_key());
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "only XTM is accepted");
}

#[test]
fn a_buy_proof_is_bound_to_the_key_and_the_sale() {
    let mut m = Market::new();
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let base = Keypair::generate(&mut OsRng);
    let ctx = context(crypt);
    let key = base.for_sale(&ctx);
    let due = PRICE + BUYER_BOND;
    let mut refuse = |registered: [u8; 32], proof: Proof, reason: &str| {
        let tx = m.buy_tx(crypt, registered, proof, due);
        assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), reason);
    };

    let honest = client::prove_action(&key, &ctx, client::MSG_BUY, &mut OsRng);
    let by_base = client::prove_action(&base, &ctx, client::MSG_BUY, &mut OsRng);
    let elsewhere = client::prove_action(&key, b"x", client::MSG_BUY, &mut OsRng);
    let wrong_action = client::prove_action(&key, &ctx, client::MSG_CANCEL, &mut OsRng);
    refuse(key.public(), by_base, "invalid buyer proof");
    refuse(Keypair::generate(&mut OsRng).public(), honest, "invalid buyer proof");
    refuse(key.public(), elsewhere, "invalid buyer proof");
    refuse(key.public(), wrong_action, "invalid buyer proof");
    refuse([0u8; 32], honest, "must not be the identity point");
    refuse([0xff; 32], honest, "not a canonical Ristretto point");
    assert_eq!(m.stage(crypt), "Listed");
}

#[test]
fn a_listing_sells_once_and_a_replayed_buy_is_refused() {
    let mut m = Market::new();
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let ctx = context(crypt);
    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&key, &ctx, client::MSG_BUY, &mut OsRng);
    let tx = m.buy_tx(crypt, key.public(), proof, PRICE + BUYER_BOND);
    m.test.execute_expect_success(tx.clone(), vec![]);
    // Not executing the same transaction twice is the ledger's job (and the coin it spends is gone);
    // this only checks that whatever the simulator does, the replay changes nothing.
    let replay = m.test.try_execute(tx, vec![]);
    assert!(
        replay.map(|r| r.finalize.any_reject().is_some()).unwrap_or(true),
        "a replayed purchase must not go through"
    );

    let other = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&other, &ctx, client::MSG_BUY, &mut OsRng);
    let tx = m.buy_tx(crypt, other.public(), proof, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "not for sale");
}

// ================================================================================================
// Payouts: only to the payee, only into stealth outputs, only what is owed, only once
// ================================================================================================

#[test]
fn a_payout_must_be_signed_by_its_payee() {
    let mut m = Market::new();
    let sale = accepted(&mut m);
    let seller_statement = payout_statement(PRICE + SELLER_BOND).statement;
    let buyer_statement = payout_statement(BUYER_BOND).statement;
    let stranger = Keypair::generate(&mut OsRng);

    m.refused(
        sale.crypt,
        "pay_seller",
        payout_args(&stranger, sale.crypt, Side::Seller, &seller_statement),
        "invalid seller proof",
    );
    m.refused(
        sale.crypt,
        "pay_seller",
        payout_args(&sale.buyer_key, sale.crypt, Side::Seller, &seller_statement),
        "invalid seller proof",
    );
    m.refused(
        sale.crypt,
        "pay_buyer",
        payout_args(&m.seller_key, sale.crypt, Side::Buyer, &buyer_statement),
        "invalid buyer proof",
    );
    // A seller payout signature presented as a buyer payout, and the other way round.
    let as_seller = payout_args(&sale.buyer_key, sale.crypt, Side::Seller, &buyer_statement);
    m.refused(sale.crypt, "pay_buyer", as_seller, "invalid buyer proof");
    assert_eq!(
        m.owed(sale.crypt),
        (a(PRICE + SELLER_BOND), a(BUYER_BOND)),
        "nothing moved"
    );
    m.pay_out(&sale);
}

#[test]
fn a_signed_payout_cannot_be_redirected() {
    // Someone sees the seller's signed payout in the mempool and swaps in their own outputs.
    let mut m = Market::new();
    let sale = accepted(&mut m);
    let owed = PRICE + SELLER_BOND;
    let honest = payout_statement(owed).statement;
    let proof = client::prove_action(
        &m.seller_key,
        &context(sale.crypt),
        &client::msg_pay(client::MSG_PAY_SELLER, &digest_of(&honest)),
        &mut OsRng,
    );
    let thief = payout_statement(owed).statement;
    let args = args![thief, scalar(proof.c), scalar(proof.z)];
    m.refused(sale.crypt, "pay_seller", args, "invalid seller proof");
    assert_eq!(m.owed(sale.crypt).0, a(owed), "the seller is still owed everything");
}

#[test]
fn a_payout_spends_exactly_what_is_owed_into_stealth_outputs_only() {
    let mut m = Market::new();
    let sale = accepted(&mut m);
    let owed = PRICE + SELLER_BOND;
    let key = Keypair::from_secret_bytes(&m.seller_key.secret_bytes()).unwrap();
    let someone_else = RistrettoPublicKey::from_secret_key(m.test.secret_key()).to_byte_type();
    let mut refuse = |statement: StealthTransferStatement, reason: &str| {
        let args = payout_args(&key, sale.crypt, Side::Seller, &statement);
        m.refused(sale.crypt, "pay_seller", args, reason);
    };

    // More than owed (it would eat the buyer's bond), and less.
    refuse(payout_statement(owed + BUYER_BOND).statement, "exactly the amount owed");
    refuse(payout_statement(owed - 1).statement, "exactly the amount owed");
    // Part of it revealed into a bucket for someone else to take.
    let leaky = generate_transfer_data_to(NO_INPUTS, a(owed), [owed - 100], a(100), someone_else);
    refuse(leaky.statement, "stealth outputs only");
    assert_eq!(m.owed(sale.crypt).0, a(owed));
}

#[test]
fn a_payout_cannot_carry_other_stealth_inputs() {
    // Mixing an outside coin into the payout transfer is refused: the payout spends the escrow only.
    let mut m = Market::new();
    let sale = accepted(&mut m);
    let owed = PRICE + SELLER_BOND;
    let outside = m.coin(50);
    let mixed = generate_transfer_data(
        [outside.data.input_spec_for(0, outside.value)],
        a(owed),
        [owed + outside.value],
        Amount::zero(),
    );
    let args = payout_args(&m.seller_key, sale.crypt, Side::Seller, &mixed.statement);
    m.refused(sale.crypt, "pay_seller", args, "no stealth inputs");
}

#[test]
fn each_payout_happens_once() {
    let mut m = Market::new();
    let sale = accepted(&mut m);
    let owed = PRICE + SELLER_BOND;
    let first = payout_statement(owed).statement;
    let args = payout_args(&m.seller_key, sale.crypt, Side::Seller, &first);
    m.ok(sale.crypt, "pay_seller", args);
    // The very same signed payout again, and a fresh one.
    let again = payout_args(&m.seller_key, sale.crypt, Side::Seller, &first);
    m.refused(sale.crypt, "pay_seller", again, "nothing owed");
    let fresh = payout_statement(owed).statement;
    let args = payout_args(&m.seller_key, sale.crypt, Side::Seller, &fresh);
    m.refused(sale.crypt, "pay_seller", args, "nothing owed");
    // The buyer's share is untouched.
    assert_eq!(m.owed(sale.crypt), (Amount::zero(), a(BUYER_BOND)));
}

#[test]
fn a_payout_carries_no_covenant_claims() {
    let mut m = Market::new();
    let sale = accepted(&mut m);
    let mut statement = payout_statement(PRICE + SELLER_BOND).statement;
    let signature = statement.balance_proof.clone().unwrap();
    statement.covenant_claims.push(CovenantBalanceClaim {
        partition_input_index: 0,
        revealed_amount: Amount::zero(),
        signature,
    });
    let args = payout_args(&m.seller_key, sale.crypt, Side::Seller, &statement);
    m.refused(sale.crypt, "pay_seller", args, "a payout carries no covenant claims");
}

#[test]
fn nothing_is_owed_to_a_buyer_who_never_was() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let args = m.cancel_args(crypt);
    m.ok(crypt, "cancel", args);
    let statement = payout_statement(1).statement;
    let args = payout_args(&Keypair::generate(&mut OsRng), crypt, Side::Buyer, &statement);
    m.refused(crypt, "pay_buyer", args, "nothing owed");
}

#[test]
fn the_loser_gets_nothing() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = Market::noise(sale.crypt);
    let args = m.deliver_args(sale.crypt, &sealed);
    m.ok(sale.crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(sale.crypt, "dispute", args);
    let statement = payout_statement(1).statement;
    let args = payout_args(&m.seller_key, sale.crypt, Side::Seller, &statement);
    m.refused(sale.crypt, "pay_seller", args, "nothing owed");
    m.pay_out(&sale);
}

// ================================================================================================
// Third parties and hostile components
// ================================================================================================

#[test]
fn a_hostile_component_in_the_victims_transaction_cannot_act_for_them() {
    let mut m = Market::with_templates(&[".", "tests/templates/evil"]);
    let evil = m.test.get_template_address("Evil");
    let (sale, sealed) = m.delivered();
    let hostile = |m: &mut Market, function: &str, args: Vec<NamedArg>, reason: &str| {
        let tx = m
            .test
            .transaction()
            .call_function(evil, function, args)
            .build_and_seal(m.test.secret_key());
        assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), reason);
    };

    hostile(&mut m, "force_accept", args![sale.crypt], "invalid buyer proof");
    let listed = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    hostile(&mut m, "force_cancel", args![listed], "invalid seller proof");
    let pending = m.paid();
    hostile(
        &mut m,
        "force_deliver",
        args![pending.crypt, point(sealed.ephemeral)],
        "invalid ephemeral proof",
    );
    // A payout it would like to keep: its own outputs, no valid signature.
    m.epoch(START_EPOCH + DELIVERY_WINDOW + 1);
    m.ok(pending.crypt, "claim_undelivered", args![]);
    let theft = payout_statement(PRICE + BUYER_BOND + SELLER_BOND).statement;
    hostile(
        &mut m,
        "steal_payout",
        args![pending.crypt, theft],
        "invalid buyer proof",
    );

    assert_eq!(m.stage(sale.crypt), "Delivered");
    assert_eq!(m.stage(listed), "Listed");
    m.pay_out(&pending);
}

// ================================================================================================
// Settlement integrity
// ================================================================================================

#[test]
fn accepting_then_disputing_in_one_transaction_is_all_or_nothing() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let accept = m.accept_args(&sale);
    let dispute = m.dispute_args(&sale, &sealed.ephemeral);
    let tx = m
        .test
        .transaction()
        .call_method(sale.crypt, "accept", accept)
        .call_method(sale.crypt, "dispute", dispute)
        .build_and_seal(m.test.secret_key());
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "nothing to dispute");
    assert_eq!(m.stage(sale.crypt), "Delivered", "the acceptance was rolled back too");
}

#[test]
fn a_payout_happens_once_even_inside_one_transaction() {
    let mut m = Market::new();
    let sale = accepted(&mut m);
    let owed = PRICE + SELLER_BOND;
    let first = payout_statement(owed).statement;
    let second = payout_statement(owed).statement;
    let tx = m
        .test
        .transaction()
        .call_method(
            sale.crypt,
            "pay_seller",
            payout_args(&m.seller_key, sale.crypt, Side::Seller, &first),
        )
        .call_method(
            sale.crypt,
            "pay_seller",
            payout_args(&m.seller_key, sale.crypt, Side::Seller, &second),
        )
        .build_and_seal(m.test.secret_key());
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![]), "nothing owed");
    assert_eq!(m.owed(sale.crypt).0, a(owed), "the first payout was rolled back too");
    m.pay_out(&sale);
}

#[test]
fn a_settled_sale_cannot_be_settled_again() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let args = m.accept_args(&sale);
    m.ok(sale.crypt, "accept", args);
    let args = m.accept_args(&sale);
    m.refused(sale.crypt, "accept", args, "nothing to accept");
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.refused(sale.crypt, "dispute", args, "nothing to dispute");
    m.epoch(START_EPOCH + DISPUTE_WINDOW + 1);
    m.refused(sale.crypt, "claim_uncontested", args![], "not awaiting acceptance");
    m.refused(sale.crypt, "claim_undelivered", args![], "not awaiting delivery");
    let args = m.cancel_args(sale.crypt);
    m.refused(sale.crypt, "cancel", args, "already sold");
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Accepted"));
}

// ================================================================================================
// Random inputs
// ================================================================================================

#[test]
fn random_dispute_attempts_never_succeed() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    for _ in 0..24 {
        let attempt = dispute_args(
            random_point(),
            Proof {
                c: random_scalar(),
                z: random_scalar(),
            },
        );
        m.refused(sale.crypt, "dispute", attempt, "invalid proof that the shared point");
    }
    assert_eq!(m.stage(sale.crypt), "Delivered");
}

#[test]
fn random_action_proofs_never_authorize_anything() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    for _ in 0..24 {
        let proof = Proof {
            c: random_scalar(),
            z: random_scalar(),
        };
        m.refused(sale.crypt, "accept", proof_args(proof), "invalid buyer proof");
    }
    assert_eq!(m.stage(sale.crypt), "Delivered");
}

#[test]
fn random_deliveries_always_lose_the_dispute() {
    let mut m = Market::new();
    for _ in 0..3 {
        let sale = m.paid();
        let sealed = Market::noise(sale.crypt);
        let args = m.deliver_args(sale.crypt, &sealed);
        m.ok(sale.crypt, "deliver", args);
        let args = m.dispute_args(&sale, &sealed.ephemeral);
        m.ok(sale.crypt, "dispute", args);
        assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Fraud"));
        m.pay_out(&sale);
    }
}

/// What the escrow owes each side when a sale settles with `outcome`, as `(seller, buyer)`.
fn expected_split(outcome: &str, paid: bool) -> (u64, u64) {
    let (price, buyer_bond) = if paid { (PRICE, BUYER_BOND) } else { (0, 0) };
    match outcome {
        "Cancelled" => (SELLER_BOND, 0),
        "Accepted" | "Uncontested" => (price + SELLER_BOND, buyer_bond),
        "DisputeRejected" => (price + SELLER_BOND + buyer_bond, 0),
        "Undelivered" | "Fraud" => (0, price + buyer_bond + SELLER_BOND),
        other => panic!("unknown outcome {other}"),
    }
}

fn pick(n: u32) -> u32 {
    rand_core::RngCore::next_u32(&mut OsRng) % n
}

#[test]
fn random_hostile_games_keep_the_money_straight() {
    // Random games mixing honest moves, forged moves and jumps in time. Forged moves never succeed;
    // whatever happens, the escrow never holds more than was paid in, the sale settles at most once,
    // the split matches the outcome, a true delivery never loses a dispute and noise never wins one,
    // and after settlement `owed_seller + owed_buyer == escrow` through every payout.
    let mut m = Market::new();
    for _ in 0..12 {
        let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
        let crypt = m.list(&block);
        let ctx = context(crypt);
        let mut epoch = START_EPOCH;
        m.epoch(epoch);
        let mut buyer: Option<Keypair> = None;
        let mut delivered_honestly: Option<bool> = None;
        let mut settled: Option<String> = None;

        for _ in 0..16 {
            match pick(13) {
                0 if buyer.is_none() => {
                    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
                    let proof = client::prove_action(&key, &ctx, client::MSG_BUY, &mut OsRng);
                    let tx = m.buy_tx(crypt, key.public(), proof, PRICE + BUYER_BOND);
                    if m.attempt_tx(tx) {
                        buyer = Some(key);
                    }
                }
                1 => {
                    let proof = Proof {
                        c: random_scalar(),
                        z: random_scalar(),
                    };
                    let tx = m.buy_tx(crypt, random_point(), proof, PRICE + BUYER_BOND);
                    assert!(!m.attempt_tx(tx), "a forged buy succeeded");
                }
                2 | 3 if buyer.is_some() => {
                    let honest = pick(2) == 0;
                    let sealed = if honest {
                        client::seal(&block, &buyer.as_ref().unwrap().public(), &ctx, &mut OsRng).unwrap()
                    } else {
                        Market::noise(crypt)
                    };
                    let args = m.deliver_args(crypt, &sealed);
                    if m.attempt(crypt, "deliver", args) {
                        delivered_honestly = Some(honest);
                    }
                }
                4 if delivered_honestly.is_some() => {
                    let sale = Sale {
                        crypt,
                        block,
                        buyer_key: copy_key(buyer.as_ref().unwrap()),
                    };
                    let args = m.accept_args(&sale);
                    m.attempt(crypt, "accept", args);
                }
                5 if delivered_honestly.is_some() => {
                    let sale = Sale {
                        crypt,
                        block,
                        buyer_key: copy_key(buyer.as_ref().unwrap()),
                    };
                    let ephemeral = m.delivered_ephemeral(crypt);
                    let args = m.dispute_args(&sale, &ephemeral);
                    if m.attempt(crypt, "dispute", args) {
                        let expected = if delivered_honestly == Some(true) {
                            "DisputeRejected"
                        } else {
                            "Fraud"
                        };
                        assert_eq!(m.outcome(crypt).as_deref(), Some(expected));
                    }
                }
                6 => {
                    let forged = Proof {
                        c: random_scalar(),
                        z: random_scalar(),
                    };
                    for method in ["accept", "cancel"] {
                        assert!(
                            !m.attempt(crypt, method, proof_args(forged)),
                            "a forged {method} succeeded"
                        );
                    }
                    let dispute = dispute_args(random_point(), forged);
                    assert!(!m.attempt(crypt, "dispute", dispute), "a forged dispute succeeded");
                }
                7 => {
                    m.attempt(crypt, "claim_undelivered", args![]);
                }
                8 => {
                    m.attempt(crypt, "claim_uncontested", args![]);
                }
                9 => {
                    let args = m.cancel_args(crypt);
                    m.attempt(crypt, "cancel", args);
                }
                10 => {
                    epoch += u64::from(pick(3)) + 1;
                    m.epoch(epoch);
                }
                11 => {
                    let stranger = Keypair::generate(&mut OsRng);
                    for side in [Side::Seller, Side::Buyer] {
                        let data = payout_statement(1);
                        let args = payout_args(&stranger, crypt, side, &data.statement);
                        assert!(!m.attempt(crypt, side.method(), args), "a stranger collected a payout");
                    }
                }
                12 if settled.is_some() => {
                    let (seller, buyer_owed) = m.owed(crypt);
                    if seller.is_positive() {
                        let key = copy_key(&m.seller_key);
                        m.pay(crypt, Side::Seller, &key, seller.to_u64_checked().unwrap());
                    } else if buyer_owed.is_positive() {
                        let key = copy_key(buyer.as_ref().unwrap());
                        m.pay(crypt, Side::Buyer, &key, buyer_owed.to_u64_checked().unwrap());
                    }
                }
                _ => {}
            }

            let escrow = m.escrow(crypt);
            assert!(
                escrow <= a(PRICE + BUYER_BOND + SELLER_BOND),
                "the escrow holds more than was paid in"
            );
            match (&settled, m.outcome(crypt)) {
                (None, Some(outcome)) => {
                    let (seller, buyer_owed) = expected_split(&outcome, buyer.is_some());
                    assert_eq!(m.owed(crypt), (a(seller), a(buyer_owed)), "split for {outcome}");
                    settled = Some(outcome);
                }
                (Some(before), now) => assert_eq!(now.as_deref(), Some(before.as_str()), "settled twice"),
                (None, None) => {}
            }
            if settled.is_some() {
                let (seller, buyer_owed) = m.owed(crypt);
                assert_eq!(seller + buyer_owed, escrow, "owed and escrow diverged");
            }
        }
    }
}
