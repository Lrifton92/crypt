// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! # Crypt
//!
//! Sealed, verifiable delivery of a secret on the Tari Ootle, with disputes settled by the template
//! itself. No arbiter, no oracle, no trusted third party.
//!
//! 1. `list`: the seller publishes `commitment = H(salt || len || secret || padding)`, a price, a
//!    bond for each side, a seller key `K` and a payout account, and puts their own bond in escrow.
//! 2. `buy`: the buyer pays price + bond and registers a sale key `B'` (derived client-side from a
//!    base secret by hashing, never reused) and a payout account, proving they hold `B'`.
//! 3. `deliver`: the seller posts `R = r·G` with a proof of knowledge of `r`, and the block encrypted
//!    under a keystream derived from `S = r·B'`, all signed with `K`. Only the buyer can compute
//!    `S = b'·R`; the ciphertext is public, the secret is not.
//! 4. The buyer `accept`s, or `dispute`s by publishing `S` with a DLEQ proof that `S = b'·R`. The
//!    template then derives the keystream itself, decrypts, re-hashes, checks the layout and compares:
//!    * mismatch or undecodable block: the seller delivered something other than what they committed
//!      to. The buyer gets the price and both bonds;
//!    * match: the dispute was false. The seller gets the price and both bonds.
//! 5. Deadlines, in epochs, release the escrow if either side goes quiet.
//! 6. Payouts go to the accounts registered at `list` and `buy`, never to the caller.
//!
//! **Authorization never uses the transaction signer.** Every action carries a proof by the acting
//! side's Crypt key (the seller key `K`, the buyer's sale key `B'`), which lives in the Crypt client,
//! not in the wallet. A hostile component called in
//! the same transaction cannot accept, deliver, cancel or redirect a payout on anyone's behalf. The
//! component has no owner (`OwnerRule::None`), so nobody can change its rules after creation.
//!
//! The proof of `r` is what keeps a dispute from leaking anything: it publishes `b'·R`, and since the
//! seller had to know `r`, that is `r·B'`, a value the seller already had. Without it, a seller could
//! post another sale's `R` and let the buyer's dispute decrypt that other sale.
//!
//! Only revealed XTM is accepted: a token whose issuer can recall or freeze funds could empty or lock
//! the escrow.
//!
//! What this guarantees: the secret delivered is the secret committed to. What it cannot guarantee:
//! that the committed secret is worth anything. A dispute makes the secret public, that is the price
//! of a verdict anyone can re-check. See THREAT_MODEL.md.

use tari_template_lib::prelude::*;

/// Size of every plaintext block and every ciphertext. Must match `crypt_core::PLAINTEXT_LEN`.
pub const PLAINTEXT_LEN: usize = 320;
const SALT_LEN: usize = 32;
const MAX_SECRET_LEN: usize = PLAINTEXT_LEN - SALT_LEN - 2;
/// Shortest delivery or dispute window, in epochs: a seller cannot squeeze the buyer's time to check
/// a delivery and dispute it.
pub const MIN_WINDOW: u64 = 3;
/// Longest window, in epochs. Bounds how long funds can be locked and keeps `now + window` far from
/// overflow.
pub const MAX_WINDOW: u64 = 10_000;

// The keystream is whole SHA-512 blocks indexed by a single byte.
const _: () = assert!(PLAINTEXT_LEN.is_multiple_of(64) && PLAINTEXT_LEN / 64 <= 256);

// Must stay byte-for-byte identical to the constants in `crypt_core`.
const DOMAIN_COMMIT: &[u8] = b"tari.ootle.crypt.commitment.v1";
const DOMAIN_KEY: &[u8] = b"tari.ootle.crypt.key.v1";
const DOMAIN_STREAM: &[u8] = b"tari.ootle.crypt.stream.v1";
const DOMAIN_DLEQ: &[u8] = b"tari.ootle.crypt.dleq.v1";
const DOMAIN_AUTH: &[u8] = b"tari.ootle.crypt.auth.v1";
const MSG_CANCEL: &[u8] = b"cancel";
const MSG_EPHEMERAL: &[u8] = b"ephemeral";

fn len_prefix(data: &[u8]) -> [u8; 8] {
    (data.len() as u64).to_le_bytes()
}

fn to_array64(hash: &Hash64) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(hash.as_ref());
    out
}

/// Same layout check as `crypt_core::decode_plaintext`: `salt (32) || len (u16 LE) || secret || zeros`.
/// Without it a seller could commit to a block no client can decode, deliver it faithfully, and win
/// the dispute on a matching hash while the buyer holds nothing readable.
fn is_well_formed(block: &[u8]) -> bool {
    if block.len() != PLAINTEXT_LEN {
        return false;
    }
    let len = u16::from_le_bytes([block[SALT_LEN], block[SALT_LEN + 1]]) as usize;
    len <= MAX_SECRET_LEN && block[SALT_LEN + 2 + len..].iter().all(|&b| b == 0)
}

/// The commitment over a whole plaintext block.
pub fn commitment_of(block: &[u8]) -> Hash64 {
    intrinsics::hash_sha512_parts(&[&len_prefix(DOMAIN_COMMIT), DOMAIN_COMMIT, block])
}

/// Rejects anything that is not the canonical encoding of a non-identity Ristretto point. Every other
/// Ristretto intrinsic panics on non-canonical input, and the identity as a key or nonce would make
/// the shared secret public.
fn assert_valid_point(point: &RistrettoPublicKeyBytes, what: &str) {
    assert!(
        intrinsics::ristretto_is_canonical(point),
        "{} is not a canonical Ristretto point",
        what
    );
    assert!(
        !intrinsics::ristretto_is_identity(point),
        "{} must not be the identity point",
        what
    );
}

/// Fiat-Shamir challenge over the domain, the sale's context, an action message and the points.
fn challenge(domain: &[u8], context: &[u8], message: &[u8], points: &[&RistrettoPublicKeyBytes]) -> Scalar32Bytes {
    let dlen = len_prefix(domain);
    let clen = len_prefix(context);
    let mlen = len_prefix(message);
    let mut parts: Vec<&[u8]> = vec![&dlen, domain, &clen, context, &mlen, message];
    parts.extend(points.iter().map(|p| p.as_bytes()));
    intrinsics::scalar_from_uniform_bytes(&to_array64(&intrinsics::hash_sha512_parts(&parts)))
}

/// `z·base - c·point`, the nonce commitment a compact Schnorr proof implies.
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

/// Schnorr proof by `key` over `message`, bound to this sale.
fn assert_authorized(
    context: &[u8],
    key: &RistrettoPublicKeyBytes,
    message: &[u8],
    c: &Scalar32Bytes,
    z: &Scalar32Bytes,
    who: &str,
) {
    assert_canonical_scalars(c, z);
    let a = implied_nonce(None, key, c, z);
    assert!(
        challenge(DOMAIN_AUTH, context, message, &[key, &a]) == *c,
        "not authorized: invalid {} proof",
        who
    );
}

/// Chaum-Pedersen proof that `log_G(B') = log_R(S)`, bound to this sale.
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
    challenge(DOMAIN_DLEQ, context, &[], &[key, ephemeral, shared, &a1, &a2]) == *c
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

/// Payouts only go to plain built-in accounts, so no custom code runs when the escrow pays out. Each
/// side is paid by its own call, so a payout that fails for any reason only ever holds up that side.
fn assert_is_account(address: &ComponentAddress, who: &str) {
    assert!(
        ComponentManager::get(*address).get_template_address() == BuiltinTemplate::Account.address(),
        "the {} payout address must be a built-in account",
        who
    );
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
    /// Final. Each side's payout can be sent to its account.
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
    /// The template decrypted the delivery and it did not match, or was not a decodable block.
    /// The seller forfeits their bond.
    #[n(5)]
    Fraud,
}

#[template]
mod crypt {
    use super::*;

    pub struct Crypt {
        /// Signs deliveries and cancellation. Held by the seller's Crypt client.
        seller_key: RistrettoPublicKeyBytes,
        seller_payout: ComponentAddress,
        buyer_payout: Option<ComponentAddress>,
        /// The buyer's sale key `B'`, registered at `buy`.
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
        /// Lists a secret for sale. `seller_bond` (revealed XTM) goes into escrow now and is lost to
        /// the buyer if the seller never delivers or delivers something other than `commitment`.
        #[allow(clippy::too_many_arguments)]
        pub fn list(
            commitment: Hash64,
            price: Amount,
            buyer_bond: Amount,
            delivery_window: u64,
            dispute_window: u64,
            seller_key: RistrettoPublicKeyBytes,
            seller_payout: ComponentAddress,
            seller_bond: Bucket,
        ) -> Component<Self> {
            assert!(price.is_positive(), "price must be positive");
            assert!(buyer_bond.is_positive(), "buyer bond must be positive");
            assert!(
                (MIN_WINDOW..=MAX_WINDOW).contains(&delivery_window)
                    && (MIN_WINDOW..=MAX_WINDOW).contains(&dispute_window),
                "windows must be between {} and {} epochs",
                MIN_WINDOW,
                MAX_WINDOW
            );
            // A token whose issuer keeps recall, freeze or an authorization hook could empty or lock
            // the escrow, and a template cannot read those rules. Native XTM has none of them.
            assert!(seller_bond.resource_address() == TARI_TOKEN, "only XTM is accepted");
            // Revealed funds only: escrow accounting counts revealed amounts, nothing hidden may enter.
            seller_bond.assert_contains_no_confidential_funds();
            assert!(seller_bond.amount().is_positive(), "seller bond must be positive");
            assert_valid_point(&seller_key, "seller key");
            assert_is_account(&seller_payout, "seller");

            let escrow = Vault::new_empty(TARI_TOKEN);
            let bond = seller_bond.amount();
            escrow.deposit(seller_bond);

            Component::new(Self {
                seller_key,
                seller_payout,
                buyer_payout: None,
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

        /// Buys. `payment` must be exactly price + buyer bond, in revealed XTM. `(c, z)` is a proof by
        /// `buyer_key` over `"buy" || buyer_payout`: it shows the buyer holds the key, and a copy of it
        /// cannot be used to buy into another account.
        pub fn buy(
            &mut self,
            buyer_key: RistrettoPublicKeyBytes,
            buyer_payout: ComponentAddress,
            c: Scalar32Bytes,
            z: Scalar32Bytes,
            payment: Bucket,
        ) {
            assert!(self.stage == Stage::Listed, "not for sale");
            assert_valid_point(&buyer_key, "buyer key");
            let message = [b"buy".as_slice(), buyer_payout.as_bytes()].concat();
            assert_authorized(&Self::context(), &buyer_key, &message, &c, &z, "buyer");
            assert_is_account(&buyer_payout, "buyer");

            assert!(payment.resource_address() == TARI_TOKEN, "only XTM is accepted");
            payment.assert_contains_no_confidential_funds();
            let due = self.price + self.buyer_bond;
            assert!(payment.amount() == due, "payment must be exactly {}", due);
            self.escrow.deposit(payment);

            let now = Consensus::current_epoch();
            self.buyer_key = Some(buyer_key);
            self.buyer_payout = Some(buyer_payout);
            self.delivery_deadline = Some(now + self.delivery_window);
            self.stage = Stage::Paid;
            emit_event("crypt_bought", metadata! { "epoch" => now.to_string() });
        }

        /// Delivers the sealed secret. `(rc, rz)` proves knowledge of `r` for `R`, bound to this sale;
        /// `(c, z)` is the seller key's signature over `"deliver" || R || C`. Allowed up to and
        /// including the delivery deadline.
        #[allow(clippy::too_many_arguments)]
        pub fn deliver(
            &mut self,
            ephemeral: RistrettoPublicKeyBytes,
            rc: Scalar32Bytes,
            rz: Scalar32Bytes,
            ciphertext: Bytes,
            c: Scalar32Bytes,
            z: Scalar32Bytes,
        ) {
            assert!(self.stage == Stage::Paid, "nothing to deliver");
            let now = Consensus::current_epoch();
            assert!(now <= self.delivery_deadline.unwrap(), "delivery deadline passed");
            assert_valid_point(&ephemeral, "ephemeral key");
            assert!(
                ciphertext.len() == PLAINTEXT_LEN,
                "ciphertext must be exactly {} bytes",
                PLAINTEXT_LEN
            );
            let context = Self::context();
            assert_authorized(&context, &ephemeral, MSG_EPHEMERAL, &rc, &rz, "ephemeral");
            let message = [b"deliver".as_slice(), ephemeral.as_bytes(), &ciphertext].concat();
            assert_authorized(&context, &self.seller_key, &message, &c, &z, "seller");

            self.ephemeral = Some(ephemeral);
            self.ciphertext = Some(ciphertext);
            self.dispute_deadline = Some(now + self.dispute_window);
            self.stage = Stage::Delivered;
            emit_event("crypt_delivered", metadata! { "epoch" => now.to_string() });
        }

        /// The buyer is satisfied: the seller gets the price, each side its bond back. Signed by the
        /// buyer's sale key over `"accept" || R`, so it can only accept this delivery.
        pub fn accept(&mut self, c: Scalar32Bytes, z: Scalar32Bytes) {
            assert!(self.stage == Stage::Delivered, "nothing to accept");
            let message = [b"accept".as_slice(), self.ephemeral.unwrap().as_bytes()].concat();
            assert_authorized(&Self::context(), &self.buyer_key.unwrap(), &message, &c, &z, "buyer");
            self.settle(Outcome::Accepted);
        }

        /// Files a dispute. Allowed up to and including the dispute deadline. The DLEQ proof is the
        /// authorization: only the holder of the buyer's sale key can produce it. Publishes `S`: anyone
        /// can then decrypt the delivery and re-check the verdict, so the secret becomes public.
        pub fn dispute(&mut self, shared: RistrettoPublicKeyBytes, c: Scalar32Bytes, z: Scalar32Bytes) {
            assert!(self.stage == Stage::Delivered, "nothing to dispute");
            assert!(
                Consensus::current_epoch() <= self.dispute_deadline.unwrap(),
                "dispute deadline passed"
            );

            assert_valid_point(&shared, "shared point");
            let context = Self::context();
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
            // The seller wins only by delivering exactly what they committed to, in a form the
            // buyer's client can decode.
            if commitment_of(&block) == self.commitment && is_well_formed(&block) {
                self.settle(Outcome::DisputeRejected);
            } else {
                self.settle(Outcome::Fraud);
            }
        }

        /// The seller never delivered. Anyone may trigger it once the window is over; the funds can
        /// only go to the buyer's account.
        pub fn claim_undelivered(&mut self) {
            assert!(self.stage == Stage::Paid, "not awaiting delivery");
            assert!(
                Consensus::current_epoch() > self.delivery_deadline.unwrap(),
                "the delivery window is still open"
            );
            self.settle(Outcome::Undelivered);
        }

        /// The buyer never answered the delivery: same split as an acceptance. Anyone may trigger it.
        pub fn claim_uncontested(&mut self) {
            assert!(self.stage == Stage::Delivered, "not awaiting acceptance");
            assert!(
                Consensus::current_epoch() > self.dispute_deadline.unwrap(),
                "the dispute window is still open"
            );
            self.settle(Outcome::Uncontested);
        }

        /// Withdraws the listing before anyone pays. Signed by the seller key.
        pub fn cancel(&mut self, c: Scalar32Bytes, z: Scalar32Bytes) {
            assert!(self.stage == Stage::Listed, "already sold");
            assert_authorized(&Self::context(), &self.seller_key, MSG_CANCEL, &c, &z, "seller");
            self.settle(Outcome::Cancelled);
        }

        /// Sends the seller's share to the seller's account. Anyone may call it.
        pub fn pay_seller(&mut self) {
            assert!(self.stage == Stage::Settled, "not settled");
            let amount = self.owed_seller;
            self.owed_seller = Amount::zero();
            self.pay(self.seller_payout, amount);
        }

        /// Sends the buyer's share to the buyer's account. Anyone may call it. Separate from
        /// `pay_seller`, so a problem on one side can never hold the other side's funds.
        pub fn pay_buyer(&mut self) {
            assert!(self.stage == Stage::Settled, "not settled");
            let amount = self.owed_buyer;
            self.owed_buyer = Amount::zero();
            self.pay(self.buyer_payout.expect("no buyer"), amount);
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
            (
                self.price,
                self.seller_bond,
                self.buyer_bond,
                self.delivery_window,
                self.dispute_window,
            )
        }

        pub fn deadlines(&self) -> (Option<u64>, Option<u64>) {
            (self.delivery_deadline, self.dispute_deadline)
        }

        /// The buyer's sale key `B'`: what the seller seals to.
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
        fn context() -> Vec<u8> {
            CallerContext::current_component_address().as_bytes().to_vec()
        }

        fn pay(&self, account: ComponentAddress, amount: Amount) {
            assert!(amount.is_positive(), "nothing owed");
            let funds = self.escrow.withdraw(amount);
            ComponentManager::get(account).invoke("deposit", args![funds]);
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
            emit_event(
                "crypt_settled",
                metadata! {
                    "outcome" => format!("{:?}", outcome),
                    "epoch" => Consensus::current_epoch().to_string(),
                },
            );
        }
    }
}
