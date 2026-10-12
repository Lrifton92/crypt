// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! # Crypt
//!
//! Sealed, verifiable delivery of a secret on the Tari Ootle, with disputes settled by the template
//! itself. No arbiter, no oracle, no trusted third party.
//!
//! 1. `list`: the seller publishes `commitment = H(salt || len || secret || padding)`, a price, a
//!    bond for each side, and puts their own bond in escrow.
//! 2. `buy`: the buyer pays price + bond into escrow and registers a fresh encryption key `B`,
//!    proving they hold its secret.
//! 3. `deliver`: the seller posts `R = r·G` and the block encrypted under a keystream derived from
//!    `S = r·B`. Only the buyer can compute `S = b·R`; the ciphertext is public, the secret is not.
//! 4. The buyer `accept`s, or `dispute`s by publishing `S` with a DLEQ proof that `S = b·R`. The
//!    template then derives the keystream itself, decrypts, re-hashes and compares:
//!    * mismatch: the seller delivered something other than what they committed to. The buyer gets
//!      the price and both bonds back;
//!    * match: the dispute was false. The seller gets the price and both bonds.
//! 5. Deadlines, in epochs, release the escrow if either side goes quiet.
//!
//! What this guarantees: the secret delivered is the secret committed to. What it cannot guarantee:
//! that the committed secret is worth anything. A dispute makes the secret public, that is the
//! price of a verdict anyone can re-check. See THREAT_MODEL.md.
//!
//! The component has no owner (`OwnerRule::None`): nobody, the seller included, can change its access
//! rules after creation and lock the buyer out of `dispute`. Authorization is checked inside each
//! method against the keys that signed `list` and `buy`.

use tari_template_lib::prelude::*;

/// Size of every plaintext block and every ciphertext. Must match `crypt_core::PLAINTEXT_LEN`.
pub const PLAINTEXT_LEN: usize = 320;
/// Longest dispute or delivery window a seller may set, in epochs. Bounds how long funds can be
/// locked and keeps `now + window` far from overflow.
pub const MAX_WINDOW: u64 = 10_000;

// Must stay byte-for-byte identical to the constants in `crypt_core`.
const DOMAIN_COMMIT: &[u8] = b"tari.ootle.crypt.commitment.v1";
const DOMAIN_KEY: &[u8] = b"tari.ootle.crypt.key.v1";
const DOMAIN_STREAM: &[u8] = b"tari.ootle.crypt.stream.v1";
const DOMAIN_DLEQ: &[u8] = b"tari.ootle.crypt.dleq.v1";
const DOMAIN_POP: &[u8] = b"tari.ootle.crypt.pop.v1";

fn len_prefix(data: &[u8]) -> [u8; 8] {
    (data.len() as u64).to_le_bytes()
}

fn to_array64(hash: &Hash64) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(hash.as_ref());
    out
}

/// The commitment over a whole plaintext block.
pub fn commitment_of(block: &[u8]) -> Hash64 {
    intrinsics::hash_sha512_parts(&[&len_prefix(DOMAIN_COMMIT), DOMAIN_COMMIT, block])
}

/// Rejects anything that is not the canonical encoding of a non-identity Ristretto point. Every other
/// Ristretto intrinsic panics on non-canonical input, and the identity as a key or nonce would make
/// the shared secret public.
fn assert_valid_point(point: &RistrettoPublicKeyBytes, what: &str) {
    assert!(intrinsics::ristretto_is_canonical(point), "{} is not a canonical Ristretto point", what);
    assert!(!intrinsics::ristretto_is_identity(point), "{} must not be the identity point", what);
}

fn challenge(domain: &[u8], context: &[u8], points: &[&RistrettoPublicKeyBytes]) -> Scalar32Bytes {
    let dlen = len_prefix(domain);
    let clen = len_prefix(context);
    let mut parts: Vec<&[u8]> = vec![&dlen, domain, &clen, context];
    parts.extend(points.iter().map(|p| p.as_bytes()));
    intrinsics::scalar_from_uniform_bytes(&to_array64(&intrinsics::hash_sha512_parts(&parts)))
}

/// `z·base - c·point`, the commitment a compact Schnorr proof implies.
fn implied_nonce(
    base: Option<&RistrettoPublicKeyBytes>,
    point: &RistrettoPublicKeyBytes,
    c: &Scalar32Bytes,
    z: &Scalar32Bytes,
) -> RistrettoPublicKeyBytes {
    let zb = match base {
        Some(base) => intrinsics::ristretto_mul(base, z),
        None => intrinsics::ristretto_mul_base(z),
    };
    intrinsics::ristretto_sub(&zb, &intrinsics::ristretto_mul(point, c))
}

fn assert_canonical_scalars(c: &Scalar32Bytes, z: &Scalar32Bytes) {
    assert!(
        intrinsics::scalar_is_canonical(c) && intrinsics::scalar_is_canonical(z),
        "proof scalars must be canonical"
    );
}

/// Proof that the caller knows `b` with `B = b·G`, bound to this sale.
fn verify_possession(context: &[u8], key: &RistrettoPublicKeyBytes, c: &Scalar32Bytes, z: &Scalar32Bytes) -> bool {
    assert_canonical_scalars(c, z);
    let a = implied_nonce(None, key, c, z);
    challenge(DOMAIN_POP, context, &[key, &a]) == *c
}

/// Chaum-Pedersen proof that `log_G(B) = log_R(S)`, bound to this sale.
fn verify_shared(
    context: &[u8],
    key: &RistrettoPublicKeyBytes,
    ephemeral: &RistrettoPublicKeyBytes,
    shared: &RistrettoPublicKeyBytes,
    c: &Scalar32Bytes,
    z: &Scalar32Bytes,
) -> bool {
    assert_canonical_scalars(c, z);
    let a1 = implied_nonce(None, key, c, z);
    let a2 = implied_nonce(Some(ephemeral), shared, c, z);
    challenge(DOMAIN_DLEQ, context, &[key, ephemeral, shared, &a1, &a2]) == *c
}

fn keystream(
    context: &[u8],
    key: &RistrettoPublicKeyBytes,
    ephemeral: &RistrettoPublicKeyBytes,
    shared: &RistrettoPublicKeyBytes,
) -> Vec<u8> {
    let k = intrinsics::hash_sha512_parts(&[
        &len_prefix(DOMAIN_KEY),
        DOMAIN_KEY,
        &len_prefix(context),
        context,
        key.as_bytes(),
        ephemeral.as_bytes(),
        shared.as_bytes(),
    ]);
    let mut stream = Vec::with_capacity(PLAINTEXT_LEN);
    for i in 0..(PLAINTEXT_LEN / 64) as u8 {
        let block = intrinsics::hash_sha512_parts(&[&len_prefix(DOMAIN_STREAM), DOMAIN_STREAM, k.as_ref(), &[i]]);
        stream.extend_from_slice(block.as_ref());
    }
    stream
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, minicbor::Encode, minicbor::Decode, minicbor::CborLen)]
pub enum Stage {
    /// Listed, waiting for a buyer. The seller may cancel.
    #[n(0)]
    Listed,
    /// Paid, waiting for delivery.
    #[n(1)]
    Paid,
    /// Delivered, waiting for the buyer to accept or dispute.
    #[n(2)]
    Delivered,
    /// Final. Each side withdraws what it is owed.
    #[n(3)]
    Settled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, minicbor::Encode, minicbor::Decode, minicbor::CborLen)]
pub enum Outcome {
    /// The seller cancelled before anyone paid.
    #[n(0)]
    Cancelled,
    /// The buyer accepted the delivery.
    #[n(1)]
    Accepted,
    /// The dispute window closed without a dispute.
    #[n(2)]
    Uncontested,
    /// The delivery window closed without a delivery. The seller forfeits their bond.
    #[n(3)]
    Undelivered,
    /// The template decrypted the delivery and it matched the commitment. The buyer forfeits
    /// their bond.
    #[n(4)]
    DisputeRejected,
    /// The template decrypted the delivery and it did not match. The seller forfeits their bond.
    #[n(5)]
    Fraud,
}

#[template]
mod crypt {
    use super::*;

    pub struct Crypt {
        /// Key that signed `list`. Only it may deliver, cancel, or claim an uncontested sale.
        seller: RistrettoPublicKeyBytes,
        /// Key that signed `buy`. Only it may accept, dispute, or claim an undelivered sale.
        buyer: Option<RistrettoPublicKeyBytes>,
        /// The buyer's encryption key `B`, distinct from the signing key and fresh for each purchase.
        buyer_key: Option<RistrettoPublicKeyBytes>,
        commitment: Hash64,
        price: Amount,
        seller_bond: Amount,
        buyer_bond: Amount,
        delivery_window: u64,
        dispute_window: u64,
        delivery_deadline: Option<u64>,
        dispute_deadline: Option<u64>,
        /// `R`, posted with the delivery.
        ephemeral: Option<RistrettoPublicKeyBytes>,
        ciphertext: Option<Bytes>,
        /// `S`, public only once a dispute has been filed.
        shared: Option<RistrettoPublicKeyBytes>,
        escrow: Vault,
        owed_seller: Amount,
        owed_buyer: Amount,
        stage: Stage,
        outcome: Option<Outcome>,
    }

    impl Crypt {
        /// Lists a secret for sale. `seller_bond` goes into escrow now and is lost to the buyer if
        /// the seller never delivers or delivers something other than what `commitment` binds.
        pub fn list(
            commitment: Hash64,
            price: Amount,
            buyer_bond: Amount,
            delivery_window: u64,
            dispute_window: u64,
            seller_bond: Bucket,
        ) -> Component<Self> {
            assert!(price.is_positive(), "price must be positive");
            assert!(buyer_bond.is_positive(), "buyer bond must be positive");
            assert!(
                seller_bond.amount().is_positive(),
                "seller bond must be positive and revealed"
            );
            assert!(
                (1..=MAX_WINDOW).contains(&delivery_window) && (1..=MAX_WINDOW).contains(&dispute_window),
                "windows must be between 1 and {} epochs",
                MAX_WINDOW
            );

            // Escrow accounting relies on amounts the template can read. A confidential resource
            // hides them, a non-fungible one has no meaningful partial amounts.
            assert!(
                ResourceManager::get(seller_bond.resource_address()).resource_type() == ResourceType::Fungible,
                "the payment resource must be a public fungible resource"
            );

            let escrow = Vault::new_empty(seller_bond.resource_address());
            let bond = seller_bond.amount();
            escrow.deposit(seller_bond);

            Component::new(Self {
                seller: CallerContext::transaction_signer_public_key(),
                buyer: None,
                buyer_key: None,
                commitment,
                price,
                seller_bond: bond,
                buyer_bond,
                delivery_window,
                dispute_window,
                delivery_deadline: None,
                dispute_deadline: None,
                ephemeral: None,
                ciphertext: None,
                shared: None,
                escrow,
                owed_seller: Amount::zero(),
                owed_buyer: Amount::zero(),
                stage: Stage::Listed,
                outcome: None,
            })
            .with_access_rules(AccessRules::allow_all())
            .with_owner_rule(OwnerRule::None)
            .create()
        }

        /// Buys. `payment` must be exactly price + buyer bond, in the listed resource. `buyer_key`
        /// is the key the secret will be sealed to; `(pop_c, pop_z)` proves the caller holds it.
        pub fn buy(
            &mut self,
            buyer_key: RistrettoPublicKeyBytes,
            pop_c: Scalar32Bytes,
            pop_z: Scalar32Bytes,
            payment: Bucket,
        ) {
            assert!(self.stage == Stage::Listed, "not for sale");
            let signer = CallerContext::transaction_signer_public_key();
            assert!(signer != self.seller, "the seller cannot buy their own listing");

            assert_valid_point(&buyer_key, "buyer key");
            assert!(
                verify_possession(&self.context(), &buyer_key, &pop_c, &pop_z),
                "invalid proof of possession of the buyer key"
            );

            assert!(
                payment.resource_address() == self.escrow.resource_address(),
                "wrong payment resource"
            );
            let due = self.price + self.buyer_bond;
            assert!(payment.amount() == due, "payment must be exactly {}", due);
            self.escrow.deposit(payment);

            let now = Consensus::current_epoch();
            self.buyer = Some(signer);
            self.buyer_key = Some(buyer_key);
            self.delivery_deadline = Some(now + self.delivery_window);
            self.stage = Stage::Paid;
            emit_event("crypt_bought", metadata! { "epoch" => now.to_string() });
        }

        /// Delivers the sealed secret. Allowed up to and including the delivery deadline.
        pub fn deliver(&mut self, ephemeral: RistrettoPublicKeyBytes, ciphertext: Bytes) {
            self.assert_signer_is_seller();
            assert!(self.stage == Stage::Paid, "nothing to deliver");
            let now = Consensus::current_epoch();
            assert!(now <= self.delivery_deadline.unwrap(), "delivery deadline passed");

            assert_valid_point(&ephemeral, "ephemeral key");
            assert!(
                ciphertext.len() == PLAINTEXT_LEN,
                "ciphertext must be exactly {} bytes",
                PLAINTEXT_LEN
            );

            self.ephemeral = Some(ephemeral);
            self.ciphertext = Some(ciphertext);
            self.dispute_deadline = Some(now + self.dispute_window);
            self.stage = Stage::Delivered;
            emit_event("crypt_delivered", metadata! { "epoch" => now.to_string() });
        }

        /// The buyer is satisfied: the seller gets the price, each side its bond back.
        pub fn accept(&mut self) {
            self.assert_signer_is_buyer();
            assert!(self.stage == Stage::Delivered, "nothing to accept");
            self.settle(Outcome::Accepted);
        }

        /// Files a dispute. Allowed up to and including the dispute deadline. Publishes `S`: anyone
        /// can then decrypt the delivery and re-check the verdict, so the secret becomes public.
        pub fn dispute(&mut self, shared: RistrettoPublicKeyBytes, c: Scalar32Bytes, z: Scalar32Bytes) {
            self.assert_signer_is_buyer();
            assert!(self.stage == Stage::Delivered, "nothing to dispute");
            assert!(
                Consensus::current_epoch() <= self.dispute_deadline.unwrap(),
                "dispute deadline passed"
            );

            assert_valid_point(&shared, "shared point");
            let context = self.context();
            let key = self.buyer_key.unwrap();
            let ephemeral = self.ephemeral.unwrap();
            assert!(
                verify_shared(&context, &key, &ephemeral, &shared, &c, &z),
                "invalid proof that the shared point is the buyer's"
            );

            let stream = keystream(&context, &key, &ephemeral, &shared);
            let block: Vec<u8> = self
                .ciphertext
                .as_ref()
                .unwrap()
                .iter()
                .zip(stream.iter())
                .map(|(c, k)| c ^ k)
                .collect();

            self.shared = Some(shared);
            if commitment_of(&block) == self.commitment {
                self.settle(Outcome::DisputeRejected);
            } else {
                self.settle(Outcome::Fraud);
            }
        }

        /// The seller never delivered: the buyer takes back the price, their bond, and the seller's.
        pub fn claim_undelivered(&mut self) {
            self.assert_signer_is_buyer();
            assert!(self.stage == Stage::Paid, "not awaiting delivery");
            assert!(
                Consensus::current_epoch() > self.delivery_deadline.unwrap(),
                "the delivery window is still open"
            );
            self.settle(Outcome::Undelivered);
        }

        /// The buyer never answered the delivery: same split as an acceptance.
        pub fn claim_uncontested(&mut self) {
            self.assert_signer_is_seller();
            assert!(self.stage == Stage::Delivered, "not awaiting acceptance");
            assert!(
                Consensus::current_epoch() > self.dispute_deadline.unwrap(),
                "the dispute window is still open"
            );
            self.settle(Outcome::Uncontested);
        }

        /// Withdraws the listing before anyone pays.
        pub fn cancel(&mut self) {
            self.assert_signer_is_seller();
            assert!(self.stage == Stage::Listed, "already sold");
            self.settle(Outcome::Cancelled);
        }

        /// Pays out whatever the signer is owed. Pull rather than push: a settlement never depends on
        /// the other side being able to receive.
        pub fn withdraw(&mut self) -> Bucket {
            assert!(self.stage == Stage::Settled, "not settled");
            let signer = CallerContext::transaction_signer_public_key();
            let amount = if signer == self.seller {
                let owed = self.owed_seller;
                self.owed_seller = Amount::zero();
                owed
            } else if Some(signer) == self.buyer {
                let owed = self.owed_buyer;
                self.owed_buyer = Amount::zero();
                owed
            } else {
                panic!("only the seller or the buyer can withdraw");
            };
            assert!(amount.is_positive(), "nothing owed");
            self.escrow.withdraw(amount)
        }

        /// The commitment a block must hash to. Exposed so a buyer can check a delivery off-chain.
        pub fn commitment_of(block: Bytes) -> Hash64 {
            super::commitment_of(&block)
        }

        /// Current stage, as its name (`"Listed"`, `"Paid"`, `"Delivered"`, `"Settled"`).
        pub fn stage(&self) -> String {
            format!("{:?}", self.stage)
        }

        /// How the sale ended, as its name, once settled.
        pub fn outcome(&self) -> Option<String> {
            self.outcome.map(|o| format!("{:?}", o))
        }

        pub fn commitment(&self) -> Hash64 {
            self.commitment
        }

        pub fn terms(&self) -> (Amount, Amount, Amount, u64, u64) {
            (self.price, self.seller_bond, self.buyer_bond, self.delivery_window, self.dispute_window)
        }

        pub fn deadlines(&self) -> (Option<u64>, Option<u64>) {
            (self.delivery_deadline, self.dispute_deadline)
        }

        pub fn buyer_key(&self) -> Option<RistrettoPublicKeyBytes> {
            self.buyer_key
        }

        pub fn delivery(&self) -> Option<(RistrettoPublicKeyBytes, Bytes)> {
            self.ephemeral.zip(self.ciphertext.clone())
        }

        pub fn shared(&self) -> Option<RistrettoPublicKeyBytes> {
            self.shared
        }

        pub fn owed(&self) -> (Amount, Amount) {
            (self.owed_seller, self.owed_buyer)
        }

        pub fn escrow_balance(&self) -> Amount {
            self.escrow.balance()
        }

        /// The sale's context, bound into every proof and keystream: this component's address.
        fn context(&self) -> Vec<u8> {
            CallerContext::current_component_address().as_bytes().to_vec()
        }

        fn assert_signer_is_seller(&self) {
            assert!(
                CallerContext::transaction_signer_public_key() == self.seller,
                "only the seller can do this"
            );
        }

        fn assert_signer_is_buyer(&self) {
            assert!(
                Some(CallerContext::transaction_signer_public_key()) == self.buyer,
                "only the buyer can do this"
            );
        }

        /// The single exit from every non-final stage. Distributes the whole escrow between the two
        /// sides, so after settlement `escrow == owed_seller + owed_buyer` holds by construction.
        fn settle(&mut self, outcome: Outcome) {
            assert!(self.stage != Stage::Settled, "already settled");
            let paid = self.stage != Stage::Listed;
            let price = if paid { self.price } else { Amount::zero() };
            let buyer_bond = if paid { self.buyer_bond } else { Amount::zero() };

            let (seller, buyer) = match outcome {
                Outcome::Cancelled => (self.seller_bond, Amount::zero()),
                Outcome::Accepted | Outcome::Uncontested => (price + self.seller_bond, buyer_bond),
                Outcome::DisputeRejected => (price + self.seller_bond + buyer_bond, Amount::zero()),
                Outcome::Undelivered | Outcome::Fraud => (Amount::zero(), price + buyer_bond + self.seller_bond),
            };
            assert!(seller + buyer == self.escrow.balance(), "escrow accounting mismatch");

            self.owed_seller = seller;
            self.owed_buyer = buyer;
            self.stage = Stage::Settled;
            self.outcome = Some(outcome);
            emit_event("crypt_settled", metadata! {
                "outcome" => format!("{:?}", outcome),
                "epoch" => Consensus::current_epoch().to_string(),
            });
        }
    }
}
