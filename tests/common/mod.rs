//! Shared harness for the end-to-end and attack suites.
//!
//! Authorization in Crypt is by proofs from the parties' Crypt keys, not by the transaction signer,
//! so the harness keeps two things per party: a funded wallet account (to pay and be paid) and the
//! client keys `crypt_core` would hold.
#![allow(dead_code)]

pub use crypt_core::{self as client, Keypair, Proof};
pub use rand_core::OsRng;
pub use tari_template_lib_types::{
    bytes::Bytes,
    constants::TARI_TOKEN,
    crypto::{RistrettoPublicKeyBytes, Scalar32Bytes},
    Amount, ComponentAddress, Hash64, NonFungibleAddress,
};
pub use tari_template_test_tooling::{
    crypto::RistrettoSecretKey,
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    support::assert_error::assert_reject_reason,
    transaction::{args, builder::named_args::NamedArg, Transaction},
    TemplateTest,
};

pub const PRICE: u64 = 1_000;
pub const SELLER_BOND: u64 = 300;
pub const BUYER_BOND: u64 = 200;
pub const DELIVERY_WINDOW: u64 = 3;
pub const DISPUTE_WINDOW: u64 = 4;
pub const START_EPOCH: u64 = 10;
pub const SECRET: &[u8] = b"vault combination: 31-04-77";

#[derive(Clone)]
pub struct Party {
    pub account: ComponentAddress,
    pub proof: NonFungibleAddress,
    pub key: RistrettoSecretKey,
}

pub struct Market {
    pub test: TemplateTest,
    pub seller: Party,
    pub buyer: Party,
    pub stranger: Party,
    /// The seller's Crypt key (signs deliveries and cancellation).
    pub seller_key: Keypair,
}

/// One sale in progress, with what each side's client knows.
pub struct Sale {
    pub crypt: ComponentAddress,
    pub block: client::Block,
    /// The buyer's per-sale key, derived from a base key.
    pub buyer_key: Keypair,
}

pub fn set_epoch(test: &mut TemplateTest, epoch: u64) {
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(epoch));
}

pub fn point(bytes: [u8; 32]) -> RistrettoPublicKeyBytes {
    RistrettoPublicKeyBytes::from_bytes(&bytes).unwrap()
}

pub fn scalar(bytes: [u8; 32]) -> Scalar32Bytes {
    Scalar32Bytes::from_bytes(&bytes).unwrap()
}

pub fn context(crypt: ComponentAddress) -> Vec<u8> {
    crypt.as_bytes().to_vec()
}

pub fn a(v: u64) -> Amount {
    Amount::from_u64(v)
}

pub fn proof_args(proof: Proof) -> Vec<NamedArg> {
    args![scalar(proof.c), scalar(proof.z)]
}

pub fn dispute_args(shared: [u8; 32], proof: Proof) -> Vec<NamedArg> {
    args![point(shared), scalar(proof.c), scalar(proof.z)]
}

impl Market {
    pub fn new() -> Self {
        Self::with_templates(&["."])
    }

    pub fn with_templates(paths: &[&str]) -> Self {
        let mut test = TemplateTest::new_cwd(paths.iter().copied());
        set_epoch(&mut test, START_EPOCH);
        let party = |test: &mut TemplateTest| {
            let (account, proof, key) = test.create_funded_account();
            Party { account, proof, key }
        };
        let seller = party(&mut test);
        let buyer = party(&mut test);
        let stranger = party(&mut test);
        Self { test, seller, buyer, stranger, seller_key: Keypair::generate(&mut OsRng) }
    }

    pub fn epoch(&mut self, epoch: u64) {
        set_epoch(&mut self.test, epoch);
    }

    pub fn list_tx(&self, commitment: Hash64, seller_key: [u8; 32], payout: ComponentAddress, bond: u64, price: u64, buyer_bond: u64, windows: (u64, u64)) -> Transaction {
        let template = self.test.get_template_address("Crypt");
        self.test
            .transaction()
            .call_method(self.seller.account, "withdraw", args![TARI_TOKEN, Amount::from_u64(bond)])
            .put_last_instruction_output_on_workspace("bond")
            .call_function(template, "list", args![
                commitment,
                Amount::from_u64(price),
                Amount::from_u64(buyer_bond),
                windows.0,
                windows.1,
                point(seller_key),
                payout,
                Workspace("bond")
            ])
            .build_and_seal(&self.seller.key)
    }

    pub fn list(&mut self, block: &client::Block) -> ComponentAddress {
        let tx = self.list_tx(
            Hash64::from(client::commitment_of(block)),
            self.seller_key.public(),
            self.seller.account,
            SELLER_BOND,
            PRICE,
            BUYER_BOND,
            (DELIVERY_WINDOW, DISPUTE_WINDOW),
        );
        let result = self.test.execute_expect_success(tx, vec![self.seller.proof.clone()]);
        result
            .finalize
            .execution_results
            .iter()
            .find_map(|r| r.decode::<ComponentAddress>().ok())
            .expect("list returns the component address")
    }

    pub fn buy_tx(&self, payer: &Party, crypt: ComponentAddress, base: [u8; 32], payout: ComponentAddress, proof: Proof, amount: u64) -> Transaction {
        self.test
            .transaction()
            .call_method(payer.account, "withdraw", args![TARI_TOKEN, Amount::from_u64(amount)])
            .put_last_instruction_output_on_workspace("payment")
            .call_method(crypt, "buy", args![point(base), payout, scalar(proof.c), scalar(proof.z), Workspace("payment")])
            .build_and_seal(&payer.key)
    }

    /// The honest buyer's client: derive the sale key, sign "buy || payout", pay exactly.
    pub fn buy_with(&mut self, crypt: ComponentAddress, base: &Keypair) -> Keypair {
        let ctx = context(crypt);
        let sale_key = base.for_sale(&ctx);
        let proof = client::prove_action(&sale_key, &ctx, &client::msg_buy(self.buyer.account.as_bytes()), &mut OsRng);
        let tx = self.buy_tx(&self.buyer.clone(), crypt, base.public(), self.buyer.account, proof, PRICE + BUYER_BOND);
        self.test.execute_expect_success(tx, vec![self.buyer.proof.clone()]);
        sale_key
    }

    pub fn buy(&mut self, crypt: ComponentAddress) -> Keypair {
        self.buy_with(crypt, &Keypair::generate(&mut OsRng))
    }

    /// Any party sends one call; the proofs inside the arguments are what authorize it.
    pub fn call_tx(&self, who: &Party, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>) -> Transaction {
        self.test.transaction().call_method(crypt, method, args).build_and_seal(&who.key)
    }

    pub fn ok(&mut self, who: &Party, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>) {
        let tx = self.call_tx(who, crypt, method, args);
        self.test.execute_expect_success(tx, vec![who.proof.clone()]);
    }

    pub fn refused(&mut self, who: &Party, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>, reason: &str) {
        let tx = self.call_tx(who, crypt, method, args);
        let rejected = self.test.execute_expect_failure(tx, vec![who.proof.clone()]);
        assert_reject_reason(rejected, reason);
    }

    pub fn seal(&self, sale: &Sale, block: &client::Block) -> client::Sealed {
        client::seal(block, &sale.buyer_key.public(), &context(sale.crypt), &mut OsRng).unwrap()
    }

    pub fn deliver_args_signed_by(signer: &Keypair, crypt: ComponentAddress, sealed: &client::Sealed) -> Vec<NamedArg> {
        let proof = client::prove_action(signer, &context(crypt), &client::msg_deliver(&sealed.ephemeral, &sealed.ciphertext), &mut OsRng);
        args![point(sealed.ephemeral), Bytes::from_vec(sealed.ciphertext.to_vec()), scalar(proof.c), scalar(proof.z)]
    }

    pub fn deliver_args(&self, crypt: ComponentAddress, sealed: &client::Sealed) -> Vec<NamedArg> {
        Self::deliver_args_signed_by(&self.seller_key, crypt, sealed)
    }

    pub fn accept_args(&self, sale: &Sale) -> Vec<NamedArg> {
        proof_args(client::prove_action(&sale.buyer_key, &context(sale.crypt), client::MSG_ACCEPT, &mut OsRng))
    }

    pub fn cancel_args(&self, crypt: ComponentAddress) -> Vec<NamedArg> {
        proof_args(client::prove_action(&self.seller_key, &context(crypt), client::MSG_CANCEL, &mut OsRng))
    }

    pub fn dispute_args(&self, sale: &Sale, ephemeral: &[u8; 32]) -> Vec<NamedArg> {
        let (shared, proof) = client::prove_shared(&sale.buyer_key, &context(sale.crypt), ephemeral, &mut OsRng).unwrap();
        dispute_args(shared, proof)
    }

    pub fn stage(&mut self, crypt: ComponentAddress) -> String {
        self.test.call_method(crypt, "stage", args![], vec![])
    }

    pub fn outcome(&mut self, crypt: ComponentAddress) -> Option<String> {
        self.test.call_method(crypt, "outcome", args![], vec![])
    }

    pub fn owed(&mut self, crypt: ComponentAddress) -> (Amount, Amount) {
        self.test.call_method(crypt, "owed", args![], vec![])
    }

    pub fn escrow(&mut self, crypt: ComponentAddress) -> Amount {
        self.test.call_method(crypt, "escrow_balance", args![], vec![])
    }

    pub fn balance(&mut self, account: ComponentAddress) -> Amount {
        self.test.call_method(account, "balance", args![TARI_TOKEN], vec![])
    }

    /// Pays out every side still owed something, triggered by a stranger: payouts need nobody's key.
    pub fn pay_out(&mut self, crypt: ComponentAddress) {
        let stranger = self.stranger.clone();
        let (seller, buyer) = self.owed(crypt);
        if seller.is_positive() {
            self.ok(&stranger, crypt, "pay_seller", args![]);
        }
        if buyer.is_positive() {
            self.ok(&stranger, crypt, "pay_buyer", args![]);
        }
        assert_eq!(self.escrow(crypt), Amount::zero(), "everything paid out, nothing stuck");
    }

    /// list -> buy, no delivery yet.
    pub fn paid(&mut self) -> Sale {
        let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
        let crypt = self.list(&block);
        let buyer_key = self.buy(crypt);
        Sale { crypt, block, buyer_key }
    }

    /// list -> buy -> honest delivery.
    pub fn delivered(&mut self) -> (Sale, client::Sealed) {
        let sale = self.paid();
        let sealed = self.seal(&sale, &sale.block);
        let seller = self.seller.clone();
        let args = self.deliver_args(sale.crypt, &sealed);
        self.ok(&seller, sale.crypt, "deliver", args);
        (sale, sealed)
    }
}
