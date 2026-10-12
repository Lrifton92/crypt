//! The attack battery. Each test plays one attack against the template, through the real client or
//! by hand-crafting what a hostile client would send, and checks that it fails, and fails for the
//! stated reason. A rejected attack must also leave the sale exactly as it was.
//!
//! Sections: what the ledger shows, seller attacks, buyer attacks, third parties and hostile
//! components, settlement integrity, random inputs.

mod common;
use common::*;

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

/// Every representation of `secret` an indexer, an explorer or a log could plausibly show.
fn assert_nowhere(label: &str, raw: &[u8], text: &str, secret: &[u8]) {
    assert!(
        !contains(raw, secret),
        "{label}: secret bytes found in the raw encoding"
    );
    assert!(
        !text.contains(&*String::from_utf8_lossy(secret)),
        "{label}: secret found as text"
    );
    assert!(!text.contains(&hex(secret)), "{label}: secret found as hex");
    assert!(
        !text.contains(&decimal_list(secret)),
        "{label}: secret found as a byte list"
    );
}

/// A whole sale, list to payout, inspecting every transaction and every result as an observer of the
/// network would. Up to the payout, nothing may reveal the secret, the salt or the shared point.
#[test]
fn nothing_on_the_ledger_reveals_the_secret_salt_or_shared_point() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let salt = block[..client::SALT_LEN].to_vec();
    let mut seen: Vec<(String, Vec<u8>, String)> = vec![];
    let mut run = |m: &mut Market, label: &str, tx: Transaction, proof: NonFungibleAddress| {
        let tx_text = format!("{tx:?}");
        let result = m.test.execute_expect_success(tx, vec![proof]);
        let raw = minicbor::to_vec(&result).unwrap();
        seen.push((label.to_string(), raw, format!("{result:?} {tx_text}")));
        result
    };

    let seller = m.seller.clone();
    let buyer = m.buyer.clone();
    let tx = m.list_tx(
        Hash64::from(client::commitment_of(&block)),
        m.seller_key.public(),
        seller.account,
        SELLER_BOND,
        PRICE,
        BUYER_BOND,
        (DELIVERY_WINDOW, DISPUTE_WINDOW),
    );
    let result = run(&mut m, "list", tx, seller.proof.clone());
    let crypt = result
        .finalize
        .execution_results
        .iter()
        .find_map(|r| r.decode::<ComponentAddress>().ok())
        .unwrap();

    let ctx = context(crypt);
    let sale_key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&sale_key, &ctx, &client::msg_buy(buyer.account.as_bytes()), &mut OsRng);
    let tx = m.buy_tx(
        &buyer,
        crypt,
        sale_key.public(),
        buyer.account,
        proof,
        PRICE + BUYER_BOND,
    );
    run(&mut m, "buy", tx, buyer.proof.clone());

    let sealed = client::seal(&block, &sale_key.public(), &ctx, &mut OsRng).unwrap();
    let shared = client::shared_point(&sale_key, &sealed.ephemeral).unwrap();
    let tx = m.call_tx(&seller, crypt, "deliver", m.deliver_args(crypt, &sealed));
    run(&mut m, "deliver", tx, seller.proof.clone());

    let accept = proof_args(client::prove_action(
        &sale_key,
        &ctx,
        &client::msg_accept(&sealed.ephemeral),
        &mut OsRng,
    ));
    let tx = m.call_tx(&buyer, crypt, "accept", accept);
    run(&mut m, "accept", tx, buyer.proof.clone());
    for method in ["pay_seller", "pay_buyer"] {
        let tx = m.call_tx(&buyer, crypt, method, args![]);
        run(&mut m, method, tx, buyer.proof.clone());
    }

    for (label, raw, text) in &seen {
        assert_nowhere(label, raw, text, SECRET);
        assert_nowhere(label, raw, text, &salt);
        assert_nowhere(label, raw, text, &shared);
    }
    let state: Option<(RistrettoPublicKeyBytes, Bytes)> = m.test.call_method(crypt, "delivery", args![], vec![]);
    assert!(!contains(state.unwrap().1.as_slice(), SECRET));
    let revealed: Option<RistrettoPublicKeyBytes> = m.test.call_method(crypt, "shared", args![], vec![]);
    assert_eq!(revealed, None, "S stays private when there is no dispute");
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
    let buyer = m.buyer.clone();
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(&buyer, sale.crypt, "dispute", args);

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
    let (seller, buyer) = (m.seller.clone(), m.buyer.clone());
    let args = m.deliver_args(crypt, &sealed);
    m.ok(&seller, crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(&buyer, crypt, "dispute", args);
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
    let (seller, buyer) = (m.seller.clone(), m.buyer.clone());
    let args = m.deliver_args(crypt, &sealed);
    m.ok(&seller, crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(&buyer, crypt, "dispute", args);
    assert_eq!(m.outcome(crypt).as_deref(), Some("Fraud"));
}

#[test]
fn noise_loses_the_dispute() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = Market::noise(sale.crypt);
    let (seller, buyer) = (m.seller.clone(), m.buyer.clone());
    let args = m.deliver_args(sale.crypt, &sealed);
    m.ok(&seller, sale.crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(&buyer, sale.crypt, "dispute", args);
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Fraud"));
}

#[test]
fn a_block_sealed_for_another_sale_is_refused_at_delivery() {
    // Its proof of r is bound to the other sale.
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = client::seal(&sale.block, &sale.buyer_key.public(), b"some other sale", &mut OsRng).unwrap();
    let seller = m.seller.clone();
    let args = m.deliver_args(sale.crypt, &sealed);
    m.refused(&seller, sale.crypt, "deliver", args, "invalid ephemeral proof");
}

/// The attack the second review found against the earlier, additive key tweak: a seller reposts
/// sale A's `R` in sale B so that the buyer's dispute in B publishes something from which anyone
/// computes sale A's shared point. Every such repost is now refused, including variants of `R`
/// derived from `R_A`, because the seller must prove knowledge of `r` for this sale.
#[test]
fn another_sales_ephemeral_key_cannot_be_reposted_to_extract_its_secret() {
    let mut m = Market::new();
    let seller = m.seller.clone();

    // Sale A.
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
    m.ok(&seller, crypt_a, "deliver", args);

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
        // R_A itself, with sale A's proof of r.
        (sealed_a.ephemeral, sealed_a.ephemeral_proof),
        // R_A with a proof by a key the attacker holds.
        (sealed_a.ephemeral, any_key_proof()),
        // 3·R_A + 5·G: the attacker knows 3 and 5, not the discrete log.
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
        m.refused(&seller, crypt_b, "deliver", args, "invalid ephemeral proof");
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
    let (seller, buyer) = (m.seller.clone(), m.buyer.clone());
    let args = m.deliver_args(sale.crypt, &sealed);
    m.ok(&seller, sale.crypt, "deliver", args);
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.ok(&buyer, sale.crypt, "dispute", args);

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
    let stranger = m.stranger.clone();
    let impostor = Keypair::generate(&mut OsRng);
    for signer in [&impostor, &sale.buyer_key] {
        let args = Market::deliver_args_signed_by(signer, sale.crypt, &sealed);
        m.refused(&stranger, sale.crypt, "deliver", args, "invalid seller proof");
    }
    assert_eq!(m.stage(sale.crypt), "Paid");
}

#[test]
fn a_delivery_signature_does_not_cover_other_content() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = m.seal(&sale, &sale.block);
    let seller = m.seller.clone();
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
    m.refused(&seller, sale.crypt, "deliver", args, "invalid seller proof");

    // Another R the seller does know, with the signature over the original R.
    let r = Keypair::generate(&mut OsRng);
    let r_proof = client::prove_action(&r, &ctx, client::MSG_EPHEMERAL, &mut OsRng);
    let args = deliver_raw(r.public(), r_proof, sealed.ciphertext.to_vec(), signed);
    m.refused(&seller, sale.crypt, "deliver", args, "invalid seller proof");
}

#[test]
fn malformed_deliveries_are_refused() {
    let mut m = Market::new();
    let sale = m.paid();
    let sealed = m.seal(&sale, &sale.block);
    let seller = m.seller.clone();
    let ctx = context(sale.crypt);
    let mut bad = |ephemeral: [u8; 32], ciphertext: Vec<u8>, reason: &str| {
        let seller_proof = client::prove_action(
            &m.seller_key,
            &ctx,
            &client::msg_deliver(&ephemeral, &ciphertext),
            &mut OsRng,
        );
        let args = deliver_raw(ephemeral, sealed.ephemeral_proof, ciphertext, seller_proof);
        m.refused(&seller, sale.crypt, "deliver", args, reason);
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
    let seller = m.seller.clone();

    let on_time = m.paid();
    m.epoch(deadline);
    let sealed = m.seal(&on_time, &on_time.block);
    let args = m.deliver_args(on_time.crypt, &sealed);
    m.ok(&seller, on_time.crypt, "deliver", args);

    m.epoch(START_EPOCH);
    let late = m.paid();
    let stranger = m.stranger.clone();
    m.epoch(deadline);
    m.refused(
        &stranger,
        late.crypt,
        "claim_undelivered",
        args![],
        "the delivery window is still open",
    );
    m.epoch(deadline + 1);
    let sealed = m.seal(&late, &late.block);
    let args = m.deliver_args(late.crypt, &sealed);
    m.refused(&seller, late.crypt, "deliver", args, "delivery deadline passed");
}

#[test]
fn the_seller_cannot_cash_in_before_the_dispute_window_closes() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    let seller = m.seller.clone();
    m.refused(
        &seller,
        sale.crypt,
        "claim_uncontested",
        args![],
        "the dispute window is still open",
    );
    m.epoch(START_EPOCH + DISPUTE_WINDOW);
    m.refused(
        &seller,
        sale.crypt,
        "claim_uncontested",
        args![],
        "the dispute window is still open",
    );
    m.refused(
        &seller,
        sale.crypt,
        "claim_undelivered",
        args![],
        "not awaiting delivery",
    );
    m.refused(&seller, sale.crypt, "pay_seller", args![], "not settled");
}

#[test]
fn cancellation_needs_the_seller_key_and_an_unsold_listing() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let other = m.list(&block);
    let stranger = m.stranger.clone();
    let ctx = context(crypt);

    let impostor = Keypair::generate(&mut OsRng);
    let forged = proof_args(client::prove_action(&impostor, &ctx, client::MSG_CANCEL, &mut OsRng));
    m.refused(&stranger, crypt, "cancel", forged, "invalid seller proof");
    let for_other = m.cancel_args(other);
    m.refused(&stranger, crypt, "cancel", for_other, "invalid seller proof");
    let wrong_action = proof_args(client::prove_action(&m.seller_key, &ctx, b"accept", &mut OsRng));
    m.refused(&stranger, crypt, "cancel", wrong_action, "invalid seller proof");

    m.buy(crypt);
    let args = m.cancel_args(crypt);
    m.refused(&stranger, crypt, "cancel", args, "already sold");
}

#[test]
fn listings_with_bad_terms_are_refused() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let commitment = Hash64::from(client::commitment_of(&block));
    let key = m.seller_key.public();
    let account = m.seller.account;
    let proof = m.seller.proof.clone();
    let w = (DELIVERY_WINDOW, DISPUTE_WINDOW);
    let mut bad =
        |key: [u8; 32], payout: ComponentAddress, price: u64, buyer_bond: u64, windows: (u64, u64), reason: &str| {
            let tx = m.list_tx(commitment, key, payout, SELLER_BOND, price, buyer_bond, windows);
            assert_reject_reason(m.test.execute_expect_failure(tx, vec![proof.clone()]), reason);
        };
    bad(key, account, 0, BUYER_BOND, w, "price must be positive");
    bad(key, account, PRICE, 0, w, "buyer bond must be positive");
    bad(
        key,
        account,
        PRICE,
        BUYER_BOND,
        (0, DISPUTE_WINDOW),
        "windows must be between",
    );
    bad(
        key,
        account,
        PRICE,
        BUYER_BOND,
        (2, DISPUTE_WINDOW),
        "windows must be between",
    );
    bad(
        key,
        account,
        PRICE,
        BUYER_BOND,
        (DELIVERY_WINDOW, 2),
        "windows must be between",
    );
    bad(
        key,
        account,
        PRICE,
        BUYER_BOND,
        (10_001, DISPUTE_WINDOW),
        "windows must be between",
    );
    bad(
        [0u8; 32],
        account,
        PRICE,
        BUYER_BOND,
        w,
        "must not be the identity point",
    );
    bad(
        [0xff; 32],
        account,
        PRICE,
        BUYER_BOND,
        w,
        "not a canonical Ristretto point",
    );
    let not_an_account = m.list(&block);
    let tx = m.list_tx(commitment, key, not_an_account, SELLER_BOND, PRICE, BUYER_BOND, w);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![m.seller.proof.clone()]),
        "must be a built-in account",
    );
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
                DELIVERY_WINDOW,
                DISPUTE_WINDOW,
                point(m.seller_key.public()),
                m.seller.account,
                Workspace("bond")
            ],
        )
        .build_and_seal(&m.seller.key);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![m.seller.proof.clone()]),
        "only XTM is accepted",
    );
}

// ================================================================================================
// Buyer attacks
// ================================================================================================

#[test]
fn a_buyer_cannot_fake_a_fraud() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let buyer = m.buyer.clone();
    let ctx = context(sale.crypt);

    // A shared point from another key, with a valid proof for that other key.
    let (s, p) = forged_dispute(&Keypair::generate(&mut OsRng), sale.crypt, &sealed.ephemeral);
    m.refused(
        &buyer,
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
            &buyer,
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
            &buyer,
            sale.crypt,
            "dispute",
            dispute_args(shared, p),
            "proof scalars must be canonical",
        );
    }
    m.refused(
        &buyer,
        sale.crypt,
        "dispute",
        dispute_args([0u8; 32], proof),
        "must not be the identity point",
    );
    m.refused(
        &buyer,
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
    let buyer = m.buyer.clone();
    let args = m.dispute_args(&first, &sealed.ephemeral);
    m.refused(
        &buyer,
        second.crypt,
        "dispute",
        args,
        "invalid proof that the shared point",
    );
}

#[test]
fn the_dispute_window_includes_its_last_epoch_and_nothing_after() {
    let mut m = Market::new();
    let deadline = START_EPOCH + DISPUTE_WINDOW;
    let buyer = m.buyer.clone();

    let (on_time, sealed) = m.delivered();
    m.epoch(deadline);
    let args = m.dispute_args(&on_time, &sealed.ephemeral);
    m.ok(&buyer, on_time.crypt, "dispute", args);

    m.epoch(START_EPOCH);
    let (late, sealed) = m.delivered();
    m.epoch(deadline + 1);
    let args = m.dispute_args(&late, &sealed.ephemeral);
    m.refused(&buyer, late.crypt, "dispute", args, "dispute deadline passed");
    let args = m.accept_args(&late);
    m.ok(&buyer, late.crypt, "accept", args);
}

#[test]
fn only_the_buyer_sale_key_can_accept_and_only_this_delivery() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let (other, other_sealed) = m.delivered();
    let stranger = m.stranger.clone();
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
        m.refused(&stranger, sale.crypt, "accept", args, "invalid buyer proof");
    }
    assert_eq!(m.stage(sale.crypt), "Delivered");
}

#[test]
fn payment_must_be_exact() {
    let mut m = Market::new();
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let buyer = m.buyer.clone();
    let ctx = context(crypt);
    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    for amount in [PRICE + BUYER_BOND - 1, PRICE + BUYER_BOND + 1, PRICE, 1] {
        let proof = client::prove_action(&key, &ctx, &client::msg_buy(buyer.account.as_bytes()), &mut OsRng);
        let tx = m.buy_tx(&buyer, crypt, key.public(), buyer.account, proof, amount);
        assert_reject_reason(
            m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]),
            "payment must be exactly",
        );
    }
    assert_eq!(m.stage(crypt), "Listed");
}

#[test]
fn payment_in_another_token_is_refused() {
    let mut m = Market::with_templates(&[".", "tests/templates/evil"]);
    let evil = m.test.get_template_address("Evil");
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let buyer = m.buyer.clone();
    let ctx = context(crypt);
    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&key, &ctx, &client::msg_buy(buyer.account.as_bytes()), &mut OsRng);
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
                buyer.account,
                scalar(proof.c),
                scalar(proof.z),
                Workspace("payment")
            ],
        )
        .build_and_seal(&buyer.key);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]),
        "only XTM is accepted",
    );
}

#[test]
fn a_buy_proof_is_bound_to_the_key_the_sale_and_the_payout_account() {
    let mut m = Market::new();
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let (buyer, stranger) = (m.buyer.clone(), m.stranger.clone());
    let base = Keypair::generate(&mut OsRng);
    let ctx = context(crypt);
    let key = base.for_sale(&ctx);
    let due = PRICE + BUYER_BOND;
    let mut refuse = |payer: &Party, registered: [u8; 32], payout: ComponentAddress, proof: Proof, reason: &str| {
        let tx = m.buy_tx(payer, crypt, registered, payout, proof, due);
        assert_reject_reason(m.test.execute_expect_failure(tx, vec![payer.proof.clone()]), reason);
    };

    let honest = client::prove_action(&key, &ctx, &client::msg_buy(buyer.account.as_bytes()), &mut OsRng);
    // Copied from the mempool by a front-runner who wants the purchase paid out to themselves.
    refuse(&stranger, key.public(), stranger.account, honest, "invalid buyer proof");
    // The sale key registered, the base key signing.
    let by_base = client::prove_action(&base, &ctx, &client::msg_buy(buyer.account.as_bytes()), &mut OsRng);
    refuse(&buyer, key.public(), buyer.account, by_base, "invalid buyer proof");
    // Someone else's key with my proof.
    refuse(
        &buyer,
        Keypair::generate(&mut OsRng).public(),
        buyer.account,
        honest,
        "invalid buyer proof",
    );
    // A proof made for another sale.
    let elsewhere = client::prove_action(&key, b"x", &client::msg_buy(buyer.account.as_bytes()), &mut OsRng);
    refuse(&buyer, key.public(), buyer.account, elsewhere, "invalid buyer proof");
    refuse(
        &buyer,
        [0u8; 32],
        buyer.account,
        honest,
        "must not be the identity point",
    );
    refuse(
        &buyer,
        [0xff; 32],
        buyer.account,
        honest,
        "not a canonical Ristretto point",
    );
    assert_eq!(m.stage(crypt), "Listed");
}

#[test]
fn a_buyer_payout_must_be_an_account() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let not_an_account = m.list(&block);
    let buyer = m.buyer.clone();
    let ctx = context(crypt);
    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&key, &ctx, &client::msg_buy(not_an_account.as_bytes()), &mut OsRng);
    let tx = m.buy_tx(&buyer, crypt, key.public(), not_an_account, proof, PRICE + BUYER_BOND);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]),
        "must be a built-in account",
    );
}

#[test]
fn a_listing_sells_once_and_a_replayed_buy_is_refused() {
    let mut m = Market::new();
    let crypt = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let buyer = m.buyer.clone();
    let ctx = context(crypt);
    let key = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&key, &ctx, &client::msg_buy(buyer.account.as_bytes()), &mut OsRng);
    let tx = m.buy_tx(&buyer, crypt, key.public(), buyer.account, proof, PRICE + BUYER_BOND);
    m.test.execute_expect_success(tx.clone(), vec![buyer.proof.clone()]);
    // Not executing the same transaction twice is the ledger's job; this only checks that whatever
    // the simulator does, the replay changes nothing. The real check is the second buyer below.
    let replay = m.test.try_execute(tx, vec![buyer.proof.clone()]);
    assert!(
        replay.map(|r| r.finalize.any_reject().is_some()).unwrap_or(true),
        "a replayed purchase must not go through"
    );

    // A second, honest buyer with a fresh key and a valid proof: the listing is gone.
    let stranger = m.stranger.clone();
    let other = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&other, &ctx, &client::msg_buy(stranger.account.as_bytes()), &mut OsRng);
    let tx = m.buy_tx(
        &stranger,
        crypt,
        other.public(),
        stranger.account,
        proof,
        PRICE + BUYER_BOND,
    );
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![stranger.proof.clone()]),
        "not for sale",
    );
}

// ================================================================================================
// Third parties and hostile components
// ================================================================================================

#[test]
fn a_hostile_component_in_the_victims_transaction_cannot_act_for_them() {
    let mut m = Market::with_templates(&[".", "tests/templates/evil"]);
    let evil = m.test.get_template_address("Evil");
    let (sale, sealed) = m.delivered();
    let (buyer, seller) = (m.buyer.clone(), m.seller.clone());

    // The buyer signs a transaction that also calls a hostile "airdrop".
    let tx = m
        .test
        .transaction()
        .call_function(evil, "force_accept", args![sale.crypt])
        .build_and_seal(&buyer.key);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]),
        "invalid buyer proof",
    );
    // A seller with an unsold listing does the same.
    let listed = m.list(&client::encode_plaintext(SECRET, &mut OsRng).unwrap());
    let tx = m
        .test
        .transaction()
        .call_function(evil, "force_cancel", args![listed])
        .build_and_seal(&seller.key);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![seller.proof.clone()]),
        "invalid seller proof",
    );
    // And a seller with a pending sale.
    let pending = m.paid();
    let tx = m
        .test
        .transaction()
        .call_function(evil, "force_deliver", args![pending.crypt, point(sealed.ephemeral)])
        .build_and_seal(&seller.key);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![seller.proof.clone()]),
        "invalid ephemeral proof",
    );
    assert_eq!(m.stage(sale.crypt), "Delivered");
    assert_eq!(m.stage(listed), "Listed");
    assert_eq!(m.stage(pending.crypt), "Paid");

    // Payouts triggered from hostile code still land in the registered account.
    m.epoch(START_EPOCH + DELIVERY_WINDOW + 1);
    let stranger = m.stranger.clone();
    m.ok(&stranger, pending.crypt, "claim_undelivered", args![]);
    let before = m.balance(buyer.account);
    let tx = m
        .test
        .transaction()
        .call_function(evil, "trigger_payout", args![pending.crypt])
        .build_and_seal(&stranger.key);
    m.test.execute_expect_success(tx, vec![stranger.proof.clone()]);
    assert_eq!(m.balance(buyer.account), before + a(PRICE + BUYER_BOND + SELLER_BOND));
}

#[test]
fn a_stranger_can_only_trigger_payouts_to_their_rightful_owners() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    let (buyer, stranger) = (m.buyer.clone(), m.stranger.clone());
    let args = m.accept_args(&sale);
    m.ok(&buyer, sale.crypt, "accept", args);
    let stranger_before = m.balance(stranger.account);
    let seller_before = m.balance(m.seller.account);
    m.pay_out(sale.crypt);
    assert_eq!(m.balance(stranger.account), stranger_before, "the caller gets nothing");
    assert_eq!(m.balance(m.seller.account), seller_before + a(PRICE + SELLER_BOND));
}

// ================================================================================================
// Settlement integrity
// ================================================================================================

#[test]
fn accepting_then_disputing_in_one_transaction_is_all_or_nothing() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let buyer = m.buyer.clone();
    let accept = m.accept_args(&sale);
    let dispute = m.dispute_args(&sale, &sealed.ephemeral);
    let tx = m
        .test
        .transaction()
        .call_method(sale.crypt, "accept", accept)
        .call_method(sale.crypt, "dispute", dispute)
        .build_and_seal(&buyer.key);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]),
        "nothing to dispute",
    );
    assert_eq!(m.stage(sale.crypt), "Delivered", "the acceptance was rolled back too");
}

#[test]
fn a_payout_happens_once_even_inside_one_transaction() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    let (buyer, stranger) = (m.buyer.clone(), m.stranger.clone());
    let args = m.accept_args(&sale);
    m.ok(&buyer, sale.crypt, "accept", args);
    let tx = m
        .test
        .transaction()
        .call_method(sale.crypt, "pay_seller", args![])
        .call_method(sale.crypt, "pay_seller", args![])
        .build_and_seal(&stranger.key);
    assert_reject_reason(
        m.test.execute_expect_failure(tx, vec![stranger.proof.clone()]),
        "nothing owed",
    );
    m.ok(&stranger, sale.crypt, "pay_seller", args![]);
    m.refused(&stranger, sale.crypt, "pay_seller", args![], "nothing owed");
}

#[test]
fn a_settled_sale_cannot_be_settled_again() {
    let mut m = Market::new();
    let (sale, sealed) = m.delivered();
    let buyer = m.buyer.clone();
    let args = m.accept_args(&sale);
    m.ok(&buyer, sale.crypt, "accept", args);
    let args = m.accept_args(&sale);
    m.refused(&buyer, sale.crypt, "accept", args, "nothing to accept");
    let args = m.dispute_args(&sale, &sealed.ephemeral);
    m.refused(&buyer, sale.crypt, "dispute", args, "nothing to dispute");
    m.epoch(START_EPOCH + DISPUTE_WINDOW + 1);
    m.refused(
        &buyer,
        sale.crypt,
        "claim_uncontested",
        args![],
        "not awaiting acceptance",
    );
    m.refused(
        &buyer,
        sale.crypt,
        "claim_undelivered",
        args![],
        "not awaiting delivery",
    );
    let args = m.cancel_args(sale.crypt);
    m.refused(&buyer, sale.crypt, "cancel", args, "already sold");
    assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Accepted"));
}

// ================================================================================================
// Random inputs
// ================================================================================================

#[test]
fn random_dispute_attempts_never_succeed() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    let buyer = m.buyer.clone();
    for _ in 0..24 {
        let attempt = dispute_args(
            random_point(),
            Proof {
                c: random_scalar(),
                z: random_scalar(),
            },
        );
        m.refused(
            &buyer,
            sale.crypt,
            "dispute",
            attempt,
            "invalid proof that the shared point",
        );
    }
    assert_eq!(m.stage(sale.crypt), "Delivered");
}

#[test]
fn random_action_proofs_never_authorize_anything() {
    let mut m = Market::new();
    let (sale, _) = m.delivered();
    let stranger = m.stranger.clone();
    for _ in 0..24 {
        let proof = Proof {
            c: random_scalar(),
            z: random_scalar(),
        };
        m.refused(
            &stranger,
            sale.crypt,
            "accept",
            proof_args(proof),
            "invalid buyer proof",
        );
    }
    assert_eq!(m.stage(sale.crypt), "Delivered");
}

#[test]
fn random_deliveries_always_lose_the_dispute() {
    let mut m = Market::new();
    let (seller, buyer) = (m.seller.clone(), m.buyer.clone());
    for _ in 0..3 {
        let sale = m.paid();
        let sealed = Market::noise(sale.crypt);
        let args = m.deliver_args(sale.crypt, &sealed);
        m.ok(&seller, sale.crypt, "deliver", args);
        let args = m.dispute_args(&sale, &sealed.ephemeral);
        m.ok(&buyer, sale.crypt, "dispute", args);
        assert_eq!(m.outcome(sale.crypt).as_deref(), Some("Fraud"));
        m.pay_out(sale.crypt);
    }
}
