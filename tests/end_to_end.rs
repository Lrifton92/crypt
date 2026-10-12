//! Crypt against a simulated Ootle ledger, driven by the real client code in `crypt_core`.
//!
//! Every attack listed in THREAT_MODEL.md has a test here that plays it and checks it fails, and
//! fails for the stated reason. The happy paths double as cross-implementation checks: the client
//! seals and proves with `curve25519-dalek` + `sha2`, the template verifies with engine intrinsics,
//! so any divergence between the two breaks a test instead of a sale.
//!
//! Linux/macOS only: `tari_template_test_tooling` pulls the engine, whose Cranelift JIT does not build
//! on Windows. CI runs it.

use crypt_core::{self as client, Keypair, Proof};
use rand_core::OsRng;
use tari_template_lib_types::{
    bytes::Bytes,
    constants::TARI_TOKEN,
    crypto::{RistrettoPublicKeyBytes, Scalar32Bytes},
    Amount, ComponentAddress, Hash64, NonFungibleAddress,
};
use tari_template_test_tooling::{
    crypto::RistrettoSecretKey,
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    support::assert_error::assert_reject_reason,
    transaction::{args, builder::named_args::NamedArg, Transaction},
    TemplateTest,
};

const PRICE: u64 = 1_000;
const SELLER_BOND: u64 = 300;
const BUYER_BOND: u64 = 200;
const DELIVERY_WINDOW: u64 = 3;
const DISPUTE_WINDOW: u64 = 4;
const START_EPOCH: u64 = 10;
const SECRET: &[u8] = b"vault combination: 31-04-77";

struct Party {
    account: ComponentAddress,
    proof: NonFungibleAddress,
    key: RistrettoSecretKey,
}

struct Market {
    test: TemplateTest,
    seller: Party,
    buyer: Party,
    stranger: Party,
}

fn set_epoch(test: &mut TemplateTest, epoch: u64) {
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(epoch));
}

fn point(bytes: [u8; 32]) -> RistrettoPublicKeyBytes {
    RistrettoPublicKeyBytes::from_bytes(&bytes).unwrap()
}

fn scalar(bytes: [u8; 32]) -> Scalar32Bytes {
    Scalar32Bytes::from_bytes(&bytes).unwrap()
}

fn context(crypt: ComponentAddress) -> Vec<u8> {
    crypt.as_bytes().to_vec()
}

impl Market {
    fn new() -> Self {
        let mut test = TemplateTest::new_cwd(["."]);
        set_epoch(&mut test, START_EPOCH);
        let party = |test: &mut TemplateTest| {
            let (account, proof, key) = test.create_funded_account();
            Party { account, proof, key }
        };
        let seller = party(&mut test);
        let buyer = party(&mut test);
        let stranger = party(&mut test);
        Self { test, seller, buyer, stranger }
    }

    fn epoch(&mut self, epoch: u64) {
        set_epoch(&mut self.test, epoch);
    }

    fn list(&mut self, block: &client::Block) -> ComponentAddress {
        let template = self.test.get_template_address("Crypt");
        let commitment = Hash64::from(client::commitment_of(block));
        let tx = self
            .test
            .transaction()
            .call_method(self.seller.account, "withdraw", args![TARI_TOKEN, Amount::from_u64(SELLER_BOND)])
            .put_last_instruction_output_on_workspace("bond")
            .call_function(template, "list", args![
                commitment,
                Amount::from_u64(PRICE),
                Amount::from_u64(BUYER_BOND),
                DELIVERY_WINDOW,
                DISPUTE_WINDOW,
                Workspace("bond")
            ])
            .build_and_seal(&self.seller.key);
        let result = self.test.execute_expect_success(tx, vec![self.seller.proof.clone()]);
        result
            .finalize
            .execution_results
            .iter()
            .find_map(|r| r.decode::<ComponentAddress>().ok())
            .expect("list returns the component address")
    }

    fn buy_tx(&self, who: &Party, crypt: ComponentAddress, key: [u8; 32], pop: Proof, amount: u64) -> Transaction {
        self.test
            .transaction()
            .call_method(who.account, "withdraw", args![TARI_TOKEN, Amount::from_u64(amount)])
            .put_last_instruction_output_on_workspace("payment")
            .call_method(crypt, "buy", args![point(key), scalar(pop.c), scalar(pop.z), Workspace("payment")])
            .build_and_seal(&who.key)
    }

    fn buy(&mut self, crypt: ComponentAddress, buyer_key: &Keypair) {
        let pop = client::prove_possession(buyer_key, &context(crypt), &mut OsRng);
        let tx = self.buy_tx(&self.buyer, crypt, buyer_key.public(), pop, PRICE + BUYER_BOND);
        self.test.execute_expect_success(tx, vec![self.buyer.proof.clone()]);
    }

    fn call_tx(&self, who: &Party, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>) -> Transaction {
        self.test.transaction().call_method(crypt, method, args).build_and_seal(&who.key)
    }

    fn ok(&mut self, who: &Party, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>) {
        let tx = self.call_tx(who, crypt, method, args);
        self.test.execute_expect_success(tx, vec![who.proof.clone()]);
    }

    fn refused(&mut self, who: &Party, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>, reason: &str) {
        let tx = self.call_tx(who, crypt, method, args);
        let rejected = self.test.execute_expect_failure(tx, vec![who.proof.clone()]);
        assert_reject_reason(rejected, reason);
    }

    fn deliver_args(sealed: &client::Sealed) -> Vec<NamedArg> {
        args![point(sealed.ephemeral), Bytes::from_vec(sealed.ciphertext.to_vec())]
    }

    fn withdraw(&mut self, who: &Party, crypt: ComponentAddress) {
        let tx = self
            .test
            .transaction()
            .call_method(crypt, "withdraw", args![])
            .put_last_instruction_output_on_workspace("payout")
            .call_method(who.account, "deposit", args![Workspace("payout")])
            .build_and_seal(&who.key);
        self.test.execute_expect_success(tx, vec![who.proof.clone()]);
    }

    fn stage(&mut self, crypt: ComponentAddress) -> String {
        self.test.call_method(crypt, "stage", args![], vec![])
    }

    fn outcome(&mut self, crypt: ComponentAddress) -> Option<String> {
        self.test.call_method(crypt, "outcome", args![], vec![])
    }

    fn owed(&mut self, crypt: ComponentAddress) -> (Amount, Amount) {
        self.test.call_method(crypt, "owed", args![], vec![])
    }

    fn escrow(&mut self, crypt: ComponentAddress) -> Amount {
        self.test.call_method(crypt, "escrow_balance", args![], vec![])
    }

    /// list -> buy -> honest delivery. Returns what the later steps need.
    fn delivered(&mut self) -> (ComponentAddress, Keypair, client::Block, client::Sealed) {
        let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
        let crypt = self.list(&block);
        let buyer_key = Keypair::generate(&mut OsRng);
        self.buy(crypt, &buyer_key);
        let sealed = client::seal(&block, &buyer_key.public(), &context(crypt), &mut OsRng).unwrap();
        let seller = self.seller_clone();
        self.ok(&seller, crypt, "deliver", Self::deliver_args(&sealed));
        (crypt, buyer_key, block, sealed)
    }

    fn seller_clone(&self) -> Party {
        Party { account: self.seller.account, proof: self.seller.proof.clone(), key: self.seller.key.clone() }
    }

    fn buyer_clone(&self) -> Party {
        Party { account: self.buyer.account, proof: self.buyer.proof.clone(), key: self.buyer.key.clone() }
    }

    fn stranger_clone(&self) -> Party {
        Party { account: self.stranger.account, proof: self.stranger.proof.clone(), key: self.stranger.key.clone() }
    }
}

fn dispute_args(shared: [u8; 32], proof: Proof) -> Vec<NamedArg> {
    args![point(shared), scalar(proof.c), scalar(proof.z)]
}

fn a(v: u64) -> Amount {
    Amount::from_u64(v)
}

// ------------------------------------------------------------------------------------------------
// Happy paths, which are also the cross-implementation checks.
// ------------------------------------------------------------------------------------------------

#[test]
fn the_template_and_the_client_hash_a_block_identically() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let on_chain: Hash64 = m.test.call_function("Crypt", "commitment_of", args![Bytes::from_vec(block.to_vec())], vec![]);
    assert_eq!(on_chain, Hash64::from(client::commitment_of(&block)));
}

#[test]
fn an_honest_sale_pays_the_seller_and_returns_both_bonds() {
    let mut m = Market::new();
    let (crypt, buyer_key, block, _) = m.delivered();
    let buyer = m.buyer_clone();
    let seller = m.seller_clone();

    // The buyer reads the delivery from the ledger and opens it off-chain.
    let (ephemeral, ciphertext): (RistrettoPublicKeyBytes, Bytes) =
        m.test.call_method::<Option<_>>(crypt, "delivery", args![], vec![]).unwrap();
    let ciphertext: client::Block = ciphertext.as_slice().try_into().unwrap();
    let opened = client::open(&buyer_key, &context(crypt), &ephemeral.into_array(), &ciphertext).unwrap();
    assert_eq!(opened, block);
    assert_eq!(client::decode_plaintext(&opened).unwrap(), SECRET);

    m.ok(&buyer, crypt, "accept", args![]);
    assert_eq!(m.outcome(crypt).as_deref(), Some("Accepted"));
    assert_eq!(m.owed(crypt), (a(PRICE + SELLER_BOND), a(BUYER_BOND)));

    m.withdraw(&seller, crypt);
    m.withdraw(&buyer, crypt);
    assert_eq!(m.escrow(crypt), Amount::zero(), "everything paid out, nothing stuck");
}

// ------------------------------------------------------------------------------------------------
// Disputes: the template must reach the same verdict anyone re-checking it would.
// ------------------------------------------------------------------------------------------------

#[test]
fn a_seller_who_delivers_something_else_loses_the_sale_and_the_bond() {
    let mut m = Market::new();
    let committed = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&committed);
    let buyer_key = Keypair::generate(&mut OsRng);
    m.buy(crypt, &buyer_key);

    // Delivers a properly sealed block, just not the committed one.
    let other = client::encode_plaintext(b"not what you paid for", &mut OsRng).unwrap();
    let sealed = client::seal(&other, &buyer_key.public(), &context(crypt), &mut OsRng).unwrap();
    let seller = m.seller_clone();
    let buyer = m.buyer_clone();
    m.ok(&seller, crypt, "deliver", Market::deliver_args(&sealed));

    let (shared, proof) = client::prove_shared(&buyer_key, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();
    m.ok(&buyer, crypt, "dispute", dispute_args(shared, proof));

    assert_eq!(m.outcome(crypt).as_deref(), Some("Fraud"));
    assert_eq!(m.owed(crypt), (Amount::zero(), a(PRICE + BUYER_BOND + SELLER_BOND)));
    m.refused(&seller, crypt, "withdraw", args![], "nothing owed");
    m.withdraw(&buyer, crypt);
    assert_eq!(m.escrow(crypt), Amount::zero());
}

#[test]
fn a_seller_who_seals_garbage_without_the_key_loses_too() {
    let mut m = Market::new();
    let committed = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&committed);
    let buyer_key = Keypair::generate(&mut OsRng);
    m.buy(crypt, &buyer_key);

    // Random R, random bytes: the seller cannot know the keystream, so nothing can match.
    let ephemeral = Keypair::generate(&mut OsRng).public();
    let sealed = client::Sealed { ephemeral, ciphertext: [0x42; client::PLAINTEXT_LEN] };
    let seller = m.seller_clone();
    let buyer = m.buyer_clone();
    m.ok(&seller, crypt, "deliver", Market::deliver_args(&sealed));

    let (shared, proof) = client::prove_shared(&buyer_key, &context(crypt), &ephemeral, &mut OsRng).unwrap();
    m.ok(&buyer, crypt, "dispute", dispute_args(shared, proof));
    assert_eq!(m.outcome(crypt).as_deref(), Some("Fraud"));
}

#[test]
fn a_false_dispute_pays_the_seller_and_costs_the_buyer_the_bond() {
    let mut m = Market::new();
    let (crypt, buyer_key, _, sealed) = m.delivered();
    let buyer = m.buyer_clone();
    let seller = m.seller_clone();

    let (shared, proof) = client::prove_shared(&buyer_key, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();
    m.ok(&buyer, crypt, "dispute", dispute_args(shared, proof));

    assert_eq!(m.outcome(crypt).as_deref(), Some("DisputeRejected"));
    assert_eq!(m.owed(crypt), (a(PRICE + SELLER_BOND + BUYER_BOND), Amount::zero()));
    let revealed: Option<RistrettoPublicKeyBytes> = m.test.call_method(crypt, "shared", args![], vec![]);
    assert_eq!(revealed, Some(point(shared)), "S is public so anyone can re-check the verdict");
    m.refused(&buyer, crypt, "withdraw", args![], "nothing owed");
    m.withdraw(&seller, crypt);
}

#[test]
fn a_buyer_cannot_fake_a_fraud_with_a_made_up_shared_point() {
    let mut m = Market::new();
    let (crypt, buyer_key, _, sealed) = m.delivered();
    let buyer = m.buyer_clone();

    // A point the buyer controls, with a valid-looking proof built for it under another key.
    let impostor = Keypair::generate(&mut OsRng);
    let (fake_shared, fake_proof) = client::prove_shared(&impostor, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();
    m.refused(&buyer, crypt, "dispute", dispute_args(fake_shared, fake_proof), "invalid proof that the shared point");

    // The true S with a proof bent by one bit.
    let (shared, mut proof) = client::prove_shared(&buyer_key, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();
    proof.z[1] ^= 1;
    m.refused(&buyer, crypt, "dispute", dispute_args(shared, proof), "invalid proof that the shared point");

    assert_eq!(m.stage(crypt), "Delivered", "a rejected dispute changes nothing");
}

#[test]
fn a_dispute_proof_cannot_be_replayed_into_another_sale() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    // Same buyer key on purpose (the client never does this) to isolate the context binding.
    let buyer_key = Keypair::generate(&mut OsRng);
    let seller = m.seller_clone();
    let buyer = m.buyer_clone();

    let first = m.list(&block);
    m.buy(first, &buyer_key);
    let sealed_first = client::seal(&block, &buyer_key.public(), &context(first), &mut OsRng).unwrap();
    m.ok(&seller, first, "deliver", Market::deliver_args(&sealed_first));

    let second = m.list(&block);
    m.buy(second, &buyer_key);
    // The seller reuses the first delivery's R and ciphertext in the second sale.
    m.ok(&seller, second, "deliver", Market::deliver_args(&sealed_first));

    let (shared, proof) = client::prove_shared(&buyer_key, &context(first), &sealed_first.ephemeral, &mut OsRng).unwrap();
    m.refused(&buyer, second, "dispute", dispute_args(shared, proof), "invalid proof that the shared point");
}

#[test]
fn a_dispute_with_a_non_canonical_scalar_is_refused() {
    let mut m = Market::new();
    let (crypt, buyer_key, _, sealed) = m.delivered();
    let buyer = m.buyer_clone();
    let (shared, mut proof) = client::prove_shared(&buyer_key, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();
    proof.z = [0xff; 32];
    m.refused(&buyer, crypt, "dispute", dispute_args(shared, proof), "proof scalars must be canonical");
}

// ------------------------------------------------------------------------------------------------
// Buying: exact payment, a key the buyer really holds, no self-dealing.
// ------------------------------------------------------------------------------------------------

#[test]
fn payment_must_be_exact() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let key = Keypair::generate(&mut OsRng);
    for amount in [PRICE + BUYER_BOND - 1, PRICE + BUYER_BOND + 1, PRICE] {
        let pop = client::prove_possession(&key, &context(crypt), &mut OsRng);
        let tx = m.buy_tx(&m.buyer_clone(), crypt, key.public(), pop, amount);
        let rejected = m.test.execute_expect_failure(tx, vec![m.buyer.proof.clone()]);
        assert_reject_reason(rejected, "payment must be exactly");
    }
    assert_eq!(m.stage(crypt), "Listed");
}

#[test]
fn the_buyer_must_hold_the_key_they_register() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let mine = Keypair::generate(&mut OsRng);
    let someone_else = Keypair::generate(&mut OsRng);
    let buyer = m.buyer_clone();

    // Proof for my key, presented for someone else's.
    let pop = client::prove_possession(&mine, &context(crypt), &mut OsRng);
    let tx = m.buy_tx(&buyer, crypt, someone_else.public(), pop, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]), "invalid proof of possession");

    // Proof made for another sale.
    let pop = client::prove_possession(&mine, b"another component", &mut OsRng);
    let tx = m.buy_tx(&buyer, crypt, mine.public(), pop, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]), "invalid proof of possession");
}

#[test]
fn identity_and_malformed_keys_are_refused() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let buyer = m.buyer_clone();
    let pop = Proof { c: [0; 32], z: [0; 32] };

    let tx = m.buy_tx(&buyer, crypt, [0u8; 32], pop, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]), "must not be the identity point");

    let tx = m.buy_tx(&buyer, crypt, [0xff; 32], pop, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![buyer.proof.clone()]), "not a canonical Ristretto point");
}

#[test]
fn the_seller_cannot_buy_their_own_listing() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let key = Keypair::generate(&mut OsRng);
    let pop = client::prove_possession(&key, &context(crypt), &mut OsRng);
    let seller = m.seller_clone();
    let tx = m.buy_tx(&seller, crypt, key.public(), pop, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![seller.proof.clone()]), "cannot buy their own listing");
}

#[test]
fn a_listing_sells_once() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    m.buy(crypt, &Keypair::generate(&mut OsRng));
    let key = Keypair::generate(&mut OsRng);
    let pop = client::prove_possession(&key, &context(crypt), &mut OsRng);
    let stranger = m.stranger_clone();
    let tx = m.buy_tx(&stranger, crypt, key.public(), pop, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![stranger.proof.clone()]), "not for sale");
}

// ------------------------------------------------------------------------------------------------
// Roles: each action belongs to exactly one side.
// ------------------------------------------------------------------------------------------------

#[test]
fn only_the_right_side_can_act() {
    let mut m = Market::new();
    let (crypt, buyer_key, _, sealed) = m.delivered();
    let seller = m.seller_clone();
    let buyer = m.buyer_clone();
    let stranger = m.stranger_clone();
    let (shared, proof) = client::prove_shared(&buyer_key, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();

    for who in [&seller, &stranger] {
        m.refused(who, crypt, "accept", args![], "only the buyer");
        m.refused(who, crypt, "dispute", dispute_args(shared, proof), "only the buyer");
        m.refused(who, crypt, "claim_undelivered", args![], "only the buyer");
    }
    for who in [&buyer, &stranger] {
        m.refused(who, crypt, "deliver", Market::deliver_args(&sealed), "only the seller");
        m.refused(who, crypt, "claim_uncontested", args![], "only the seller");
        m.refused(who, crypt, "cancel", args![], "only the seller");
    }

    m.ok(&buyer, crypt, "accept", args![]);
    m.refused(&stranger, crypt, "withdraw", args![], "only the seller or the buyer");
}

// ------------------------------------------------------------------------------------------------
// Delivery: well-formed, once, on time.
// ------------------------------------------------------------------------------------------------

#[test]
fn malformed_deliveries_are_refused() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let buyer_key = Keypair::generate(&mut OsRng);
    m.buy(crypt, &buyer_key);
    let seller = m.seller_clone();
    let sealed = client::seal(&block, &buyer_key.public(), &context(crypt), &mut OsRng).unwrap();

    m.refused(&seller, crypt, "deliver", args![point([0u8; 32]), Bytes::from_vec(sealed.ciphertext.to_vec())], "must not be the identity point");
    m.refused(&seller, crypt, "deliver", args![point(sealed.ephemeral), Bytes::from_vec(sealed.ciphertext[..319].to_vec())], "exactly 320 bytes");
    let mut long = sealed.ciphertext.to_vec();
    long.push(0);
    m.refused(&seller, crypt, "deliver", args![point(sealed.ephemeral), Bytes::from_vec(long)], "exactly 320 bytes");

    m.ok(&seller, crypt, "deliver", Market::deliver_args(&sealed));
    m.refused(&seller, crypt, "deliver", Market::deliver_args(&sealed), "nothing to deliver");
}

#[test]
fn delivery_closes_after_the_deadline_and_the_buyer_takes_everything() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let buyer_key = Keypair::generate(&mut OsRng);
    m.buy(crypt, &buyer_key);
    let seller = m.seller_clone();
    let buyer = m.buyer_clone();
    let deadline = START_EPOCH + DELIVERY_WINDOW;

    m.epoch(deadline);
    m.refused(&buyer, crypt, "claim_undelivered", args![], "still open");

    m.epoch(deadline + 1);
    let sealed = client::seal(&block, &buyer_key.public(), &context(crypt), &mut OsRng).unwrap();
    m.refused(&seller, crypt, "deliver", Market::deliver_args(&sealed), "delivery deadline passed");
    m.ok(&buyer, crypt, "claim_undelivered", args![]);
    assert_eq!(m.outcome(crypt).as_deref(), Some("Undelivered"));
    assert_eq!(m.owed(crypt), (Amount::zero(), a(PRICE + BUYER_BOND + SELLER_BOND)));
}

#[test]
fn delivery_on_the_last_epoch_is_accepted() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let crypt = m.list(&block);
    let buyer_key = Keypair::generate(&mut OsRng);
    m.buy(crypt, &buyer_key);
    let seller = m.seller_clone();
    m.epoch(START_EPOCH + DELIVERY_WINDOW);
    let sealed = client::seal(&block, &buyer_key.public(), &context(crypt), &mut OsRng).unwrap();
    m.ok(&seller, crypt, "deliver", Market::deliver_args(&sealed));
}

// ------------------------------------------------------------------------------------------------
// Dispute window and settlement finality.
// ------------------------------------------------------------------------------------------------

#[test]
fn the_dispute_window_is_exact_and_silence_pays_the_seller() {
    let mut m = Market::new();
    let (crypt, buyer_key, _, sealed) = m.delivered();
    let seller = m.seller_clone();
    let buyer = m.buyer_clone();
    let deadline = START_EPOCH + DISPUTE_WINDOW;

    m.epoch(deadline);
    m.refused(&seller, crypt, "claim_uncontested", args![], "still open");

    m.epoch(deadline + 1);
    let (shared, proof) = client::prove_shared(&buyer_key, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();
    m.refused(&buyer, crypt, "dispute", dispute_args(shared, proof), "dispute deadline passed");
    m.ok(&seller, crypt, "claim_uncontested", args![]);
    assert_eq!(m.outcome(crypt).as_deref(), Some("Uncontested"));
    assert_eq!(m.owed(crypt), (a(PRICE + SELLER_BOND), a(BUYER_BOND)));
}

#[test]
fn a_settled_sale_stays_settled_and_pays_out_once() {
    let mut m = Market::new();
    let (crypt, buyer_key, _, sealed) = m.delivered();
    let seller = m.seller_clone();
    let buyer = m.buyer_clone();
    m.ok(&buyer, crypt, "accept", args![]);

    let (shared, proof) = client::prove_shared(&buyer_key, &context(crypt), &sealed.ephemeral, &mut OsRng).unwrap();
    m.refused(&buyer, crypt, "accept", args![], "nothing to accept");
    m.refused(&buyer, crypt, "dispute", dispute_args(shared, proof), "nothing to dispute");
    m.epoch(START_EPOCH + DISPUTE_WINDOW + 1);
    m.refused(&seller, crypt, "claim_uncontested", args![], "not awaiting acceptance");

    m.withdraw(&seller, crypt);
    m.refused(&seller, crypt, "withdraw", args![], "nothing owed");
    assert_eq!(m.owed(crypt), (Amount::zero(), a(BUYER_BOND)));
}

#[test]
fn the_seller_can_cancel_only_before_a_sale() {
    let mut m = Market::new();
    let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
    let seller = m.seller_clone();

    let crypt = m.list(&block);
    m.refused(&seller, crypt, "withdraw", args![], "not settled");
    m.ok(&seller, crypt, "cancel", args![]);
    assert_eq!(m.owed(crypt), (a(SELLER_BOND), Amount::zero()));
    m.withdraw(&seller, crypt);
    let key = Keypair::generate(&mut OsRng);
    let pop = client::prove_possession(&key, &context(crypt), &mut OsRng);
    let tx = m.buy_tx(&m.buyer_clone(), crypt, key.public(), pop, PRICE + BUYER_BOND);
    assert_reject_reason(m.test.execute_expect_failure(tx, vec![m.buyer.proof.clone()]), "not for sale");

    let sold = m.list(&block);
    m.buy(sold, &Keypair::generate(&mut OsRng));
    m.refused(&seller, sold, "cancel", args![], "already sold");
}
