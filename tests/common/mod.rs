//! Shared harness for the end-to-end and attack suites.
//!
//! The parties have no accounts. A test "bank" mints stealth coins (what a real participant would
//! already hold in their wallet); each party funds its side of a sale by spending such a coin in a
//! transaction signed by the coin's own one-time key, and is paid back into fresh stealth outputs,
//! which the harness then redeems to prove the payee really controls exactly what it was owed.
//! Authorization inside the sale comes from the Crypt keys `crypt_core` holds, never from a signer.
#![allow(dead_code)]

pub use crypt_core::{self as client, Keypair, Proof};
pub use rand_core::OsRng;
pub use tari_template_lib_types::{
    bytes::Bytes,
    constants::TARI_TOKEN,
    crypto::{RistrettoPublicKeyBytes, Scalar32Bytes},
    stealth::StealthTransferStatement,
    Amount, ComponentAddress, Hash64, NonFungibleAddress,
};
pub use tari_template_test_tooling::{
    byte_type::ToByteType,
    crypto::{PublicKey, RistrettoPublicKey, RistrettoSecretKey},
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    support::{
        assert_error::assert_reject_reason,
        stealth::{generate_transfer_data, generate_transfer_data_to, StealthSecretTransferData, NO_INPUTS},
    },
    transaction::{args, builder::named_args::NamedArg, Transaction},
    TemplateTest,
};

pub const PRICE: u64 = 1_000;
pub const SELLER_BOND: u64 = 300;
pub const BUYER_BOND: u64 = 200;
pub const DELIVERY_WINDOW: u64 = 3;
pub const DISPUTE_WINDOW: u64 = 4;
pub const LISTING_WINDOW: u64 = 5;
pub const START_EPOCH: u64 = 10;
pub const SECRET: &[u8] = b"vault combination: 31-04-77";

/// The faucet-funded account the test mints coins from. Never part of a sale.
#[derive(Clone)]
pub struct Bank {
    pub account: ComponentAddress,
    pub proof: NonFungibleAddress,
    pub key: RistrettoSecretKey,
}

/// A stealth UTXO a party holds: its value and the secrets (mask, one-time spend key) to spend it.
pub struct Coin {
    pub data: StealthSecretTransferData,
    pub value: u64,
}

impl Coin {
    /// The one-time key that authorises spending this coin (key path from the mask).
    pub fn key(&self) -> &RistrettoSecretKey {
        &self.data.output_masks[0]
    }

    pub fn public(&self) -> RistrettoPublicKeyBytes {
        RistrettoPublicKey::from_secret_key(self.key()).to_byte_type()
    }

    /// Spends the whole coin into a revealed bucket taken by the coin's own key.
    pub fn spend_to_bucket(&self) -> StealthTransferStatement {
        generate_transfer_data_to(
            [self.data.input_spec_for(0, self.value)],
            Amount::zero(),
            Vec::<u64>::new(),
            Amount::from_u64(self.value),
            self.public(),
        )
        .statement
    }
}

pub struct Market {
    pub test: TemplateTest,
    pub bank: Bank,
    /// The seller's Crypt key (signs deliveries, cancellation, the seller's payout).
    pub seller_key: Keypair,
}

/// One sale in progress, with what each side's client knows.
pub struct Sale {
    pub crypt: ComponentAddress,
    pub block: client::Block,
    /// The buyer's per-sale key.
    pub buyer_key: Keypair,
}

/// Which side a payout goes to.
#[derive(Clone, Copy)]
pub enum Side {
    Seller,
    Buyer,
}

impl Side {
    pub fn method(self) -> &'static str {
        match self {
            Side::Seller => "pay_seller",
            Side::Buyer => "pay_buyer",
        }
    }

    pub fn action(self) -> &'static [u8] {
        match self {
            Side::Seller => client::MSG_PAY_SELLER,
            Side::Buyer => client::MSG_PAY_BUYER,
        }
    }
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

/// The digest a payee signs, computed the way the client does it.
pub fn digest_of(statement: &StealthTransferStatement) -> [u8; 64] {
    client::statement_digest(&tari_bor::encode(statement).unwrap())
}

/// A payout statement for `amount`: no stealth inputs, the amount revealed in from the escrow, one
/// fresh stealth output for the payee.
pub fn payout_statement(amount: u64) -> StealthSecretTransferData {
    generate_transfer_data(NO_INPUTS, Amount::from_u64(amount), [amount], Amount::zero())
}

pub fn payout_args(
    signer: &Keypair,
    crypt: ComponentAddress,
    side: Side,
    statement: &StealthTransferStatement,
) -> Vec<NamedArg> {
    let proof = client::prove_action(
        signer,
        &context(crypt),
        &client::msg_pay(side.action(), &digest_of(statement)),
        &mut OsRng,
    );
    args![statement.clone(), scalar(proof.c), scalar(proof.z)]
}

/// A DLEQ proof made by `key` for itself, with none of the honest client's checks against the
/// registered buyer key: what a hostile client would submit.
pub fn forged_dispute(key: &Keypair, crypt: ComponentAddress, ephemeral: &[u8; 32]) -> ([u8; 32], Proof) {
    client::prove_shared(key, &key.public(), &context(crypt), ephemeral, &mut OsRng).unwrap()
}

impl Market {
    pub fn new() -> Self {
        Self::with_templates(&["."])
    }

    pub fn with_templates(paths: &[&str]) -> Self {
        let mut test = TemplateTest::new_cwd(paths.iter().copied());
        set_epoch(&mut test, START_EPOCH);
        let (account, proof, key) = test.create_funded_account();
        Self {
            test,
            bank: Bank { account, proof, key },
            seller_key: Keypair::generate(&mut OsRng),
        }
    }

    pub fn epoch(&mut self, epoch: u64) {
        set_epoch(&mut self.test, epoch);
    }

    /// Mints a stealth coin worth `value` out of the bank.
    pub fn coin(&mut self, value: u64) -> Coin {
        let data = generate_transfer_data(NO_INPUTS, Amount::from_u64(value), [value], Amount::zero());
        let bank = self.bank.clone();
        let tx = self
            .test
            .transaction()
            .call_method(bank.account, "withdraw", args![TARI_TOKEN, Amount::from_u64(value)])
            .put_last_instruction_output_on_workspace("funds")
            .stealth_transfer_with_input_bucket(TARI_TOKEN, data.statement.clone(), "funds")
            .build_and_seal(&bank.key);
        self.test.execute_expect_success(tx, vec![bank.proof]);
        Coin { data, value }
    }

    /// Lists, with the seller's bond paid out of a stealth coin, in a transaction signed by that coin's
    /// one-time key.
    pub fn list_tx(
        &mut self,
        commitment: Hash64,
        seller_key: [u8; 32],
        bond: u64,
        price: u64,
        buyer_bond: u64,
        windows: (u64, u64, u64),
    ) -> Transaction {
        let coin = self.coin(bond);
        let template = self.test.get_template_address("Crypt");
        self.test
            .transaction()
            .stealth_transfer(TARI_TOKEN, coin.spend_to_bucket())
            .put_last_instruction_output_on_workspace("bond")
            .call_function(
                template,
                "list",
                args![
                    commitment,
                    Amount::from_u64(price),
                    Amount::from_u64(buyer_bond),
                    windows.0,
                    windows.1,
                    windows.2,
                    point(seller_key),
                    Workspace("bond")
                ],
            )
            .build_and_seal(coin.key())
    }

    pub fn list(&mut self, block: &client::Block) -> ComponentAddress {
        let tx = self.list_tx(
            Hash64::from(client::commitment_of(block)),
            self.seller_key.public(),
            SELLER_BOND,
            PRICE,
            BUYER_BOND,
            (LISTING_WINDOW, DELIVERY_WINDOW, DISPUTE_WINDOW),
        );
        let result = self.test.execute_expect_success(tx, vec![]);
        result
            .finalize
            .execution_results
            .iter()
            .find_map(|r| r.decode::<ComponentAddress>().ok())
            .expect("list returns the component address")
    }

    /// Buys with a stealth coin worth `amount`, in a transaction signed by that coin's one-time key.
    pub fn buy_tx(&mut self, crypt: ComponentAddress, buyer_key: [u8; 32], proof: Proof, amount: u64) -> Transaction {
        let coin = self.coin(amount);
        self.test
            .transaction()
            .stealth_transfer(TARI_TOKEN, coin.spend_to_bucket())
            .put_last_instruction_output_on_workspace("payment")
            .call_method(
                crypt,
                "buy",
                args![point(buyer_key), scalar(proof.c), scalar(proof.z), Workspace("payment")],
            )
            .build_and_seal(coin.key())
    }

    /// The honest buyer's client: derive the sale key from a base key, prove it, pay exactly.
    pub fn buy_with(&mut self, crypt: ComponentAddress, base: &Keypair) -> Keypair {
        let ctx = context(crypt);
        let sale_key = base.for_sale(&ctx);
        let proof = client::prove_action(&sale_key, &ctx, client::MSG_BUY, &mut OsRng);
        let tx = self.buy_tx(crypt, sale_key.public(), proof, PRICE + BUYER_BOND);
        self.test.execute_expect_success(tx, vec![]);
        sale_key
    }

    pub fn buy(&mut self, crypt: ComponentAddress) -> Keypair {
        self.buy_with(crypt, &Keypair::generate(&mut OsRng))
    }

    /// One call. Who signs does not matter: the proofs inside the arguments are what authorize it.
    pub fn call_tx(&self, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>) -> Transaction {
        self.test
            .transaction()
            .call_method(crypt, method, args)
            .build_and_seal(self.test.secret_key())
    }

    pub fn ok(&mut self, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>) {
        let tx = self.call_tx(crypt, method, args);
        self.test.execute_expect_success(tx, vec![]);
    }

    pub fn refused(&mut self, crypt: ComponentAddress, method: &str, args: Vec<NamedArg>, reason: &str) {
        let tx = self.call_tx(crypt, method, args);
        let rejected = self.test.execute_expect_failure(tx, vec![]);
        assert_reject_reason(rejected, reason);
    }

    pub fn seal(&self, sale: &Sale, block: &client::Block) -> client::Sealed {
        client::seal(block, &sale.buyer_key.public(), &context(sale.crypt), &mut OsRng).unwrap()
    }

    pub fn deliver_args_signed_by(signer: &Keypair, crypt: ComponentAddress, sealed: &client::Sealed) -> Vec<NamedArg> {
        let proof = client::prove_action(
            signer,
            &context(crypt),
            &client::msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
            &mut OsRng,
        );
        args![
            point(sealed.ephemeral),
            scalar(sealed.ephemeral_proof.c),
            scalar(sealed.ephemeral_proof.z),
            Bytes::from_vec(sealed.ciphertext.to_vec()),
            scalar(proof.c),
            scalar(proof.z)
        ]
    }

    pub fn deliver_args(&self, crypt: ComponentAddress, sealed: &client::Sealed) -> Vec<NamedArg> {
        Self::deliver_args_signed_by(&self.seller_key, crypt, sealed)
    }

    /// Bytes nobody can decrypt, delivered by a seller who does know `r` (so the template accepts the
    /// delivery itself): what a cheating seller who simply sends noise would post.
    pub fn noise(crypt: ComponentAddress) -> client::Sealed {
        let r = Keypair::generate(&mut OsRng);
        let mut ciphertext = [0u8; client::PLAINTEXT_LEN];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut ciphertext);
        client::Sealed {
            ephemeral: r.public(),
            ephemeral_proof: client::prove_action(&r, &context(crypt), client::MSG_EPHEMERAL, &mut OsRng),
            ciphertext,
        }
    }

    /// The `R` of the delivery on the ledger.
    pub fn delivered_ephemeral(&mut self, crypt: ComponentAddress) -> [u8; 32] {
        let delivery: Option<(RistrettoPublicKeyBytes, Bytes)> =
            self.test.call_method(crypt, "delivery", args![], vec![]);
        delivery.expect("delivered").0.into_array()
    }

    /// The honest buyer's acceptance of the delivery currently on the ledger.
    pub fn accept_args(&mut self, sale: &Sale) -> Vec<NamedArg> {
        let ephemeral = self.delivered_ephemeral(sale.crypt);
        proof_args(client::prove_action(
            &sale.buyer_key,
            &context(sale.crypt),
            &client::msg_accept(&ephemeral),
            &mut OsRng,
        ))
    }

    pub fn cancel_args(&self, crypt: ComponentAddress) -> Vec<NamedArg> {
        proof_args(client::prove_action(
            &self.seller_key,
            &context(crypt),
            client::MSG_CANCEL,
            &mut OsRng,
        ))
    }

    pub fn dispute_args(&self, sale: &Sale, ephemeral: &[u8; 32]) -> Vec<NamedArg> {
        let registered = sale.buyer_key.public();
        let (shared, proof) = client::prove_shared(
            &sale.buyer_key,
            &registered,
            &context(sale.crypt),
            ephemeral,
            &mut OsRng,
        )
        .unwrap();
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

    pub fn bank_balance(&mut self) -> Amount {
        self.test
            .call_method(self.bank.account, "balance", args![TARI_TOKEN], vec![])
    }

    /// Pays `side` its share into a fresh stealth output, signed by `signer`, and returns the coin the
    /// payee now holds.
    pub fn pay(&mut self, crypt: ComponentAddress, side: Side, signer: &Keypair, amount: u64) -> Coin {
        let data = payout_statement(amount);
        let args = payout_args(signer, crypt, side, &data.statement);
        self.ok(crypt, side.method(), args);
        Coin { data, value: amount }
    }

    /// Spends `coin` back into the bank: succeeds only if the holder really controls exactly `value`.
    pub fn redeem(&mut self, coin: &Coin) {
        let before = self.bank_balance();
        let tx = self
            .test
            .transaction()
            .stealth_transfer(TARI_TOKEN, coin.spend_to_bucket())
            .put_last_instruction_output_on_workspace("redeemed")
            .call_method(self.bank.account, "deposit", args![Workspace("redeemed")])
            .build_and_seal(coin.key());
        self.test.execute_expect_success(tx, vec![]);
        assert_eq!(
            self.bank_balance(),
            before + a(coin.value),
            "the payee controls exactly what it was owed"
        );
    }

    /// Pays out every side still owed something, redeems each payout, and checks the escrow is empty.
    pub fn pay_out(&mut self, sale: &Sale) {
        let (seller, buyer) = self.owed(sale.crypt);
        let seller_key = Keypair::from_secret_bytes(&self.seller_key.secret_bytes()).unwrap();
        for (owed, side, key) in [
            (seller, Side::Seller, &seller_key),
            (buyer, Side::Buyer, &sale.buyer_key),
        ] {
            if owed.is_positive() {
                let coin = self.pay(sale.crypt, side, key, owed.to_u64_checked().unwrap());
                self.redeem(&coin);
            }
        }
        assert_eq!(
            self.escrow(sale.crypt),
            Amount::zero(),
            "everything paid out, nothing stuck"
        );
    }

    /// list -> buy, no delivery yet.
    pub fn paid(&mut self) -> Sale {
        let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
        let crypt = self.list(&block);
        let buyer_key = self.buy(crypt);
        Sale {
            crypt,
            block,
            buyer_key,
        }
    }

    /// list -> buy -> honest delivery.
    pub fn delivered(&mut self) -> (Sale, client::Sealed) {
        let sale = self.paid();
        let sealed = self.seal(&sale, &sale.block);
        let args = self.deliver_args(sale.crypt, &sealed);
        self.ok(sale.crypt, "deliver", args);
        (sale, sealed)
    }
}
