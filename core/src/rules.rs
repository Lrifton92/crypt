// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! The template's settlement rules, in plain Rust.
//!
//! Same checks, in the same order, as `src/lib.rs`: the terms accepted at `list`, the proofs each
//! action needs, the deadlines (inclusive for `buy`, `deliver` and `dispute`, strictly after for the
//! `claim_*` calls) and the split of the escrow at settlement. The demo runs a whole sale through it,
//! and the end-to-end tests play the same sequences in the Ootle engine and here, so the two cannot
//! drift apart unnoticed. Amounts are plain `u64`: the demo never needs more, and the template's
//! `Amount` converts losslessly. One known difference follows: terms whose total (price plus both
//! bonds) does not fit in a `u64` are refused here as `BadTerms`, while the template, which counts in
//! `u128`, accepts them.

use crate::{
    commitment_of, decode_plaintext, decode_point, keystream, msg_accept, msg_deliver, msg_list, verify_action,
    verify_shared, xor, Block, Proof, Sealed, LIST_CONTEXT, MSG_BUY, MSG_CANCEL, MSG_EPHEMERAL,
};

/// Shortest window, in epochs, the template accepts.
pub const MIN_WINDOW: u64 = 3;
/// Longest window, in epochs, the template accepts.
pub const MAX_WINDOW: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Listed,
    Paid,
    Delivered,
    Settled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Cancelled,
    Accepted,
    Uncontested,
    Undelivered,
    DisputeRejected,
    Fraud,
}

/// Why the template would refuse a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleError {
    /// Terms the template refuses at `list`.
    BadTerms,
    /// The call does not exist at this stage.
    WrongStage,
    /// Past the last epoch the call is accepted.
    DeadlinePassed,
    /// A `claim_*` before its window is over.
    WindowOpen,
    /// A signature by the wrong key, or over the wrong message.
    Unauthorized,
    /// Not exactly price + buyer bond.
    BadPayment,
    /// A key or point that is not a canonical, non-identity Ristretto point.
    InvalidPoint,
    /// The proof of the ephemeral secret, or the dispute's DLEQ proof, does not verify.
    BadProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terms {
    pub price: u64,
    pub buyer_bond: u64,
    pub seller_bond: u64,
    pub listing_window: u64,
    pub delivery_window: u64,
    pub dispute_window: u64,
}

impl Terms {
    /// What the seller key signs at `list`, under `LIST_CONTEXT`.
    #[must_use]
    pub fn list_message(&self, commitment: &[u8; 64]) -> Vec<u8> {
        msg_list(
            commitment,
            u128::from(self.price),
            u128::from(self.buyer_bond),
            u128::from(self.seller_bond),
            self.listing_window,
            self.delivery_window,
            self.dispute_window,
        )
    }
}

/// One sale, as the template's component holds it.
#[derive(Debug, Clone)]
pub struct Sale {
    context: Vec<u8>,
    commitment: [u8; 64],
    terms: Terms,
    seller_key: [u8; 32],
    buyer_key: Option<[u8; 32]>,
    listing_deadline: u64,
    delivery_deadline: Option<u64>,
    dispute_deadline: Option<u64>,
    delivery: Option<Sealed>,
    revealed: Option<Block>,
    escrow: u64,
    owed: (u64, u64),
    stage: Stage,
    outcome: Option<Outcome>,
}

impl Sale {
    /// `context` stands for the component's address, which every later proof is bound to.
    ///
    /// # Errors
    /// `BadTerms`, `InvalidPoint` or `Unauthorized`, as the template's `list`.
    pub fn list(
        context: &[u8],
        epoch: u64,
        commitment: [u8; 64],
        terms: Terms,
        seller_key: [u8; 32],
        proof: &Proof,
    ) -> Result<Sale, RuleError> {
        let windows_ok = [terms.listing_window, terms.delivery_window, terms.dispute_window]
            .iter()
            .all(|w| (MIN_WINDOW..=MAX_WINDOW).contains(w));
        let escrow = terms
            .price
            .checked_add(terms.buyer_bond)
            .and_then(|due| due.checked_add(terms.seller_bond));
        if terms.price == 0
            || terms.buyer_bond == 0
            || !windows_ok
            || terms.dispute_window < terms.delivery_window
            || terms.buyer_bond > terms.price
            || terms.seller_bond == 0
            || u128::from(terms.seller_bond) * 10 < u128::from(terms.price)
            || escrow.is_none()
        {
            return Err(RuleError::BadTerms);
        }
        decode_point(&seller_key).map_err(|_| RuleError::InvalidPoint)?;
        if !verify_action(&seller_key, LIST_CONTEXT, &terms.list_message(&commitment), proof) {
            return Err(RuleError::Unauthorized);
        }
        Ok(Sale {
            context: context.to_vec(),
            commitment,
            terms,
            seller_key,
            buyer_key: None,
            listing_deadline: epoch.saturating_add(terms.listing_window),
            delivery_deadline: None,
            dispute_deadline: None,
            delivery: None,
            revealed: None,
            escrow: terms.seller_bond,
            owed: (0, 0),
            stage: Stage::Listed,
            outcome: None,
        })
    }

    /// # Errors
    /// As the template's `buy`.
    pub fn buy(&mut self, epoch: u64, buyer_key: [u8; 32], proof: &Proof, paid: u64) -> Result<(), RuleError> {
        self.expect(Stage::Listed)?;
        if epoch > self.listing_deadline {
            return Err(RuleError::DeadlinePassed);
        }
        decode_point(&buyer_key).map_err(|_| RuleError::InvalidPoint)?;
        if !verify_action(&buyer_key, &self.context, MSG_BUY, proof) {
            return Err(RuleError::Unauthorized);
        }
        if paid != self.terms.price + self.terms.buyer_bond {
            return Err(RuleError::BadPayment);
        }
        self.escrow += paid;
        self.buyer_key = Some(buyer_key);
        self.delivery_deadline = Some(epoch.saturating_add(self.terms.delivery_window));
        self.stage = Stage::Paid;
        Ok(())
    }

    /// # Errors
    /// As the template's `deliver`.
    pub fn deliver(&mut self, epoch: u64, sealed: &Sealed, proof: &Proof) -> Result<(), RuleError> {
        self.expect(Stage::Paid)?;
        if epoch > self.delivery_deadline.expect("set at buy") {
            return Err(RuleError::DeadlinePassed);
        }
        decode_point(&sealed.ephemeral).map_err(|_| RuleError::InvalidPoint)?;
        if !verify_action(&sealed.ephemeral, &self.context, MSG_EPHEMERAL, &sealed.ephemeral_proof) {
            return Err(RuleError::BadProof);
        }
        let message = msg_deliver(&sealed.ephemeral, &sealed.ciphertext);
        if !verify_action(&self.seller_key, &self.context, &message, proof) {
            return Err(RuleError::Unauthorized);
        }
        self.delivery = Some(sealed.clone());
        self.dispute_deadline = Some(epoch.saturating_add(self.terms.dispute_window));
        self.stage = Stage::Delivered;
        Ok(())
    }

    /// # Errors
    /// As the template's `accept`.
    pub fn accept(&mut self, proof: &Proof) -> Result<(), RuleError> {
        self.expect(Stage::Delivered)?;
        let message = msg_accept(&self.delivered().ephemeral);
        if !verify_action(&self.buyer(), &self.context, &message, proof) {
            return Err(RuleError::Unauthorized);
        }
        self.settle(Outcome::Accepted);
        Ok(())
    }

    /// Decrypts the delivery with `shared` and settles on what it finds.
    ///
    /// # Errors
    /// As the template's `dispute`.
    pub fn dispute(&mut self, epoch: u64, shared: [u8; 32], proof: &Proof) -> Result<Outcome, RuleError> {
        self.expect(Stage::Delivered)?;
        if epoch > self.dispute_deadline.expect("set at deliver") {
            return Err(RuleError::DeadlinePassed);
        }
        decode_point(&shared).map_err(|_| RuleError::InvalidPoint)?;
        let key = self.buyer();
        let delivery = self.delivered();
        if !verify_shared(&key, &delivery.ephemeral, &shared, &self.context, proof) {
            return Err(RuleError::BadProof);
        }
        let block = xor(
            &delivery.ciphertext,
            &keystream(&self.context, &key, &delivery.ephemeral, &shared),
        );
        // Same verdict as the template: exactly the committed block, in a form a client can decode.
        let outcome = if commitment_of(&block) == self.commitment && decode_plaintext(&block).is_ok() {
            Outcome::DisputeRejected
        } else {
            Outcome::Fraud
        };
        self.revealed = Some(block);
        self.settle(outcome);
        Ok(outcome)
    }

    /// # Errors
    /// As the template's `claim_undelivered`.
    pub fn claim_undelivered(&mut self, epoch: u64) -> Result<(), RuleError> {
        self.expect(Stage::Paid)?;
        if epoch <= self.delivery_deadline.expect("set at buy") {
            return Err(RuleError::WindowOpen);
        }
        self.settle(Outcome::Undelivered);
        Ok(())
    }

    /// # Errors
    /// As the template's `claim_uncontested`.
    pub fn claim_uncontested(&mut self, epoch: u64) -> Result<(), RuleError> {
        self.expect(Stage::Delivered)?;
        if epoch <= self.dispute_deadline.expect("set at deliver") {
            return Err(RuleError::WindowOpen);
        }
        self.settle(Outcome::Uncontested);
        Ok(())
    }

    /// # Errors
    /// As the template's `cancel`.
    pub fn cancel(&mut self, proof: &Proof) -> Result<(), RuleError> {
        self.expect(Stage::Listed)?;
        if !verify_action(&self.seller_key, &self.context, MSG_CANCEL, proof) {
            return Err(RuleError::Unauthorized);
        }
        self.settle(Outcome::Cancelled);
        Ok(())
    }

    #[must_use]
    pub fn stage(&self) -> Stage {
        self.stage
    }

    #[must_use]
    pub fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    #[must_use]
    pub fn terms(&self) -> Terms {
        self.terms
    }

    #[must_use]
    pub fn commitment(&self) -> [u8; 64] {
        self.commitment
    }

    #[must_use]
    pub fn listing_deadline(&self) -> u64 {
        self.listing_deadline
    }

    /// `(delivery deadline, dispute deadline)`, each set once its stage starts.
    #[must_use]
    pub fn deadlines(&self) -> (Option<u64>, Option<u64>) {
        (self.delivery_deadline, self.dispute_deadline)
    }

    #[must_use]
    pub fn buyer_key(&self) -> Option<[u8; 32]> {
        self.buyer_key
    }

    #[must_use]
    pub fn delivery(&self) -> Option<&Sealed> {
        self.delivery.as_ref()
    }

    /// `(seller, buyer)`, set at settlement.
    #[must_use]
    pub fn owed(&self) -> (u64, u64) {
        self.owed
    }

    #[must_use]
    pub fn escrow(&self) -> u64 {
        self.escrow
    }

    /// The block a dispute decrypted, for display.
    #[must_use]
    pub fn revealed_block(&self) -> Option<Block> {
        self.revealed
    }
    fn expect(&self, stage: Stage) -> Result<(), RuleError> {
        if self.stage == stage {
            Ok(())
        } else {
            Err(RuleError::WrongStage)
        }
    }

    fn buyer(&self) -> [u8; 32] {
        self.buyer_key.expect("set at buy")
    }

    fn delivered(&self) -> &Sealed {
        self.delivery.as_ref().expect("set at deliver")
    }

    /// The template's `settle`: the whole escrow goes to one side or is split, never more, never less.
    fn settle(&mut self, outcome: Outcome) {
        let paid = self.stage != Stage::Listed;
        let price = if paid { self.terms.price } else { 0 };
        let buyer_bond = if paid { self.terms.buyer_bond } else { 0 };
        let seller_bond = self.terms.seller_bond;
        self.owed = match outcome {
            Outcome::Cancelled => (seller_bond, 0),
            Outcome::Accepted | Outcome::Uncontested => (price + seller_bond, buyer_bond),
            Outcome::DisputeRejected => (price + seller_bond + buyer_bond, 0),
            Outcome::Undelivered | Outcome::Fraud => (0, price + buyer_bond + seller_bond),
        };
        debug_assert_eq!(self.owed.0 + self.owed.1, self.escrow);
        self.stage = Stage::Settled;
        self.outcome = Some(outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_plaintext, prove_action, prove_shared, seal, Keypair};
    use proptest::prelude::*;
    use rand_core::OsRng;

    const CONTEXT: &[u8] = b"a demo sale";
    const TERMS: Terms = Terms {
        price: 1_000,
        buyer_bond: 100,
        seller_bond: 200,
        listing_window: 5,
        delivery_window: 5,
        dispute_window: 5,
    };

    struct Game {
        seller: Keypair,
        buyer: Keypair,
        block: Block,
        sale: Sale,
    }

    fn block_of(secret: &[u8]) -> Block {
        encode_plaintext(secret, &mut OsRng).unwrap()
    }

    fn list_signed(terms: Terms, seller: &Keypair, commitment: [u8; 64]) -> Result<Sale, RuleError> {
        let proof = prove_action(seller, LIST_CONTEXT, &terms.list_message(&commitment), &mut OsRng);
        Sale::list(CONTEXT, 0, commitment, terms, seller.public(), &proof)
    }

    fn listed_with(terms: Terms) -> Game {
        let block = block_of(b"the vault code is 4242");
        let seller = Keypair::generate(&mut OsRng);
        let sale = list_signed(terms, &seller, commitment_of(&block)).unwrap();
        let buyer = Keypair::generate(&mut OsRng).for_sale(CONTEXT);
        Game {
            seller,
            buyer,
            block,
            sale,
        }
    }

    fn listed() -> Game {
        listed_with(TERMS)
    }

    impl Game {
        fn buy(&mut self, epoch: u64) -> Result<(), RuleError> {
            let proof = prove_action(&self.buyer, CONTEXT, MSG_BUY, &mut OsRng);
            let due = self.sale.terms().price + self.sale.terms().buyer_bond;
            self.sale.buy(epoch, self.buyer.public(), &proof, due)
        }

        fn deliver_block(&mut self, epoch: u64, block: &Block) -> Result<(), RuleError> {
            let sealed = seal(block, &self.buyer.public(), CONTEXT, &mut OsRng).unwrap();
            let message = msg_deliver(&sealed.ephemeral, &sealed.ciphertext);
            let proof = prove_action(&self.seller, CONTEXT, &message, &mut OsRng);
            self.sale.deliver(epoch, &sealed, &proof)
        }

        fn deliver(&mut self, epoch: u64) -> Result<(), RuleError> {
            let block = self.block;
            self.deliver_block(epoch, &block)
        }

        fn ephemeral(&self) -> [u8; 32] {
            self.sale.delivery().unwrap().ephemeral
        }

        fn accept(&mut self) -> Result<(), RuleError> {
            let proof = prove_action(&self.buyer, CONTEXT, &msg_accept(&self.ephemeral()), &mut OsRng);
            self.sale.accept(&proof)
        }

        fn dispute(&mut self, epoch: u64) -> Result<Outcome, RuleError> {
            let (shared, proof) = prove_shared(
                &self.buyer,
                &self.buyer.public(),
                CONTEXT,
                &self.ephemeral(),
                &mut OsRng,
            )
            .unwrap();
            self.sale.dispute(epoch, shared, &proof)
        }

        fn cancel(&mut self) -> Result<(), RuleError> {
            let proof = prove_action(&self.seller, CONTEXT, MSG_CANCEL, &mut OsRng);
            self.sale.cancel(&proof)
        }
    }

    #[test]
    fn honest_sale_pays_price_and_seller_bond_to_seller() {
        let mut game = listed();
        assert_eq!(game.sale.escrow(), 200);
        assert_eq!(game.sale.commitment(), commitment_of(&game.block));
        assert_eq!(game.sale.listing_deadline(), TERMS.listing_window);
        assert_eq!(game.sale.buyer_key(), None);
        game.buy(1).unwrap();
        assert_eq!(game.sale.buyer_key(), Some(game.buyer.public()));
        assert_eq!((game.sale.stage(), game.sale.escrow()), (Stage::Paid, 1_300));
        game.deliver(2).unwrap();
        assert_eq!(game.sale.stage(), Stage::Delivered);
        game.accept().unwrap();
        assert_eq!(game.sale.outcome(), Some(Outcome::Accepted));
        assert_eq!(game.sale.owed(), (1_200, 100));
    }

    #[test]
    fn silence_after_delivery_pays_like_an_acceptance() {
        let mut game = listed();
        game.buy(1).unwrap();
        game.deliver(2).unwrap();
        game.sale.claim_uncontested(8).unwrap();
        assert_eq!(game.sale.outcome(), Some(Outcome::Uncontested));
        assert_eq!(game.sale.owed(), (1_200, 100));
    }

    #[test]
    fn fraud_pays_everything_to_buyer() {
        let mut game = listed();
        game.buy(1).unwrap();
        let junk = block_of(b"not what was listed");
        game.deliver_block(2, &junk).unwrap();
        assert_eq!(game.dispute(3), Ok(Outcome::Fraud));
        assert_eq!(game.sale.owed(), (0, 1_300));
        assert_eq!(game.sale.revealed_block(), Some(junk));
    }

    #[test]
    fn an_undecodable_block_is_fraud_even_if_committed() {
        let mut block = [0u8; crate::PLAINTEXT_LEN];
        block[crate::PLAINTEXT_LEN - 1] = 1;
        let seller = Keypair::generate(&mut OsRng);
        let sale = list_signed(TERMS, &seller, commitment_of(&block)).unwrap();
        let buyer = Keypair::generate(&mut OsRng).for_sale(CONTEXT);
        let mut game = Game {
            seller,
            buyer,
            block,
            sale,
        };
        game.buy(1).unwrap();
        game.deliver(2).unwrap();
        assert_eq!(game.dispute(3), Ok(Outcome::Fraud));
    }

    #[test]
    fn false_dispute_pays_everything_to_seller() {
        let mut game = listed();
        game.buy(1).unwrap();
        game.deliver(2).unwrap();
        assert_eq!(game.dispute(3), Ok(Outcome::DisputeRejected));
        assert_eq!(game.sale.owed(), (1_300, 0));
        assert_eq!(game.sale.revealed_block(), Some(game.block));
    }

    #[test]
    fn undelivered_pays_everything_to_buyer() {
        let mut game = listed();
        game.buy(1).unwrap();
        assert_eq!(game.sale.claim_undelivered(6), Err(RuleError::WindowOpen));
        game.sale.claim_undelivered(7).unwrap();
        assert_eq!(game.sale.outcome(), Some(Outcome::Undelivered));
        assert_eq!(game.sale.owed(), (0, 1_300));
    }

    #[test]
    fn cancel_returns_seller_bond() {
        let mut game = listed();
        game.cancel().unwrap();
        assert_eq!(game.sale.outcome(), Some(Outcome::Cancelled));
        assert_eq!((game.sale.owed(), game.sale.escrow()), ((200, 0), 200));

        let mut sold = listed();
        sold.buy(1).unwrap();
        assert_eq!(sold.cancel(), Err(RuleError::WrongStage));
    }

    #[test]
    fn deadlines_are_inclusive_for_actions_exclusive_for_claims() {
        // Listed at epoch 0 with a 5-epoch listing window: buy up to epoch 5.
        let mut late = listed();
        assert_eq!(late.buy(6), Err(RuleError::DeadlinePassed));
        let mut game = listed();
        game.buy(5).unwrap();
        assert_eq!(game.sale.deadlines(), (Some(10), None));

        let mut too_late = game.sale.clone();
        let sealed = seal(&game.block, &game.buyer.public(), CONTEXT, &mut OsRng).unwrap();
        let proof = prove_action(
            &game.seller,
            CONTEXT,
            &msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
            &mut OsRng,
        );
        assert_eq!(too_late.deliver(11, &sealed, &proof), Err(RuleError::DeadlinePassed));
        assert_eq!(too_late.claim_undelivered(10), Err(RuleError::WindowOpen));
        too_late.claim_undelivered(11).unwrap();

        game.deliver(10).unwrap();
        assert_eq!(game.sale.deadlines(), (Some(10), Some(15)));
        let mut silent = game.sale.clone();
        assert_eq!(game.dispute(16), Err(RuleError::DeadlinePassed));
        assert_eq!(game.dispute(15), Ok(Outcome::DisputeRejected));
        assert_eq!(silent.claim_uncontested(15), Err(RuleError::WindowOpen));
        silent.claim_uncontested(16).unwrap();
    }

    #[test]
    fn list_refuses_the_terms_the_template_refuses() {
        let block = block_of(b"x");
        let seller = Keypair::generate(&mut OsRng);
        let bad = [
            Terms { price: 0, ..TERMS },
            Terms { buyer_bond: 0, ..TERMS },
            Terms {
                seller_bond: 0,
                ..TERMS
            },
            Terms {
                buyer_bond: 1_001,
                ..TERMS
            },
            Terms {
                seller_bond: 99,
                ..TERMS
            },
            Terms {
                listing_window: MIN_WINDOW - 1,
                ..TERMS
            },
            Terms {
                delivery_window: MAX_WINDOW + 1,
                dispute_window: MAX_WINDOW + 1,
                ..TERMS
            },
            Terms {
                delivery_window: 6,
                ..TERMS
            },
        ];
        for terms in bad {
            assert_eq!(
                list_signed(terms, &seller, commitment_of(&block)).err(),
                Some(RuleError::BadTerms),
                "{terms:?}"
            );
        }
        // The edges themselves are fine.
        let edge = Terms {
            buyer_bond: 1_000,
            seller_bond: 100,
            listing_window: MIN_WINDOW,
            ..TERMS
        };
        assert!(list_signed(edge, &seller, commitment_of(&block)).is_ok());

        // A proof over other terms does not list these.
        let proof = prove_action(
            &seller,
            LIST_CONTEXT,
            &TERMS.list_message(&commitment_of(&block)),
            &mut OsRng,
        );
        let cheaper = Terms { price: 900, ..TERMS };
        assert_eq!(
            Sale::list(CONTEXT, 0, commitment_of(&block), cheaper, seller.public(), &proof).err(),
            Some(RuleError::Unauthorized)
        );
        assert_eq!(
            Sale::list(CONTEXT, 0, commitment_of(&block), TERMS, [0u8; 32], &proof).err(),
            Some(RuleError::InvalidPoint)
        );
    }

    #[test]
    fn every_action_needs_the_right_key() {
        let mut game = listed();
        let stranger = Keypair::generate(&mut OsRng);
        let proof = prove_action(&stranger, CONTEXT, MSG_CANCEL, &mut OsRng);
        assert_eq!(game.sale.cancel(&proof), Err(RuleError::Unauthorized));

        let proof = prove_action(&game.buyer, CONTEXT, MSG_BUY, &mut OsRng);
        assert_eq!(
            game.sale.buy(1, stranger.public(), &proof, 1_100),
            Err(RuleError::Unauthorized)
        );
        assert_eq!(
            game.sale.buy(1, game.buyer.public(), &proof, 1_099),
            Err(RuleError::BadPayment)
        );
        game.buy(1).unwrap();

        let sealed = seal(&game.block, &game.buyer.public(), CONTEXT, &mut OsRng).unwrap();
        let by_stranger = prove_action(
            &stranger,
            CONTEXT,
            &msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
            &mut OsRng,
        );
        assert_eq!(
            game.sale.deliver(2, &sealed, &by_stranger),
            Err(RuleError::Unauthorized)
        );
        let mut forged = sealed.clone();
        forged.ephemeral_proof.z[0] ^= 1;
        let signed = prove_action(
            &game.seller,
            CONTEXT,
            &msg_deliver(&forged.ephemeral, &forged.ciphertext),
            &mut OsRng,
        );
        assert_eq!(game.sale.deliver(2, &forged, &signed), Err(RuleError::BadProof));
        game.deliver(2).unwrap();

        let proof = prove_action(&stranger, CONTEXT, &msg_accept(&game.ephemeral()), &mut OsRng);
        assert_eq!(game.sale.accept(&proof), Err(RuleError::Unauthorized));
        let (shared, mut proof) = prove_shared(
            &game.buyer,
            &game.buyer.public(),
            CONTEXT,
            &game.ephemeral(),
            &mut OsRng,
        )
        .unwrap();
        proof.c[0] ^= 1;
        assert_eq!(game.sale.dispute(3, shared, &proof), Err(RuleError::BadProof));
        assert_eq!(game.sale.stage(), Stage::Delivered);
    }

    #[test]
    fn a_settled_sale_takes_no_more_calls() {
        let mut game = listed();
        game.buy(1).unwrap();
        game.deliver(2).unwrap();
        game.accept().unwrap();
        assert_eq!(game.accept(), Err(RuleError::WrongStage));
        assert_eq!(game.dispute(3), Err(RuleError::WrongStage));
        assert_eq!(game.sale.claim_uncontested(100), Err(RuleError::WrongStage));
        assert_eq!(game.cancel(), Err(RuleError::WrongStage));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn escrow_always_equals_owed_after_settlement(
            price in 1u64..=1_000_000_000,
            bond_pct in 1u64..=100,
            seller_extra in 0u64..=1_000_000,
            ending in 0u8..6,
        ) {
            let buyer_bond = (price * bond_pct / 100).max(1);
            let terms = Terms { price, buyer_bond, seller_bond: price.div_ceil(10) + seller_extra, ..TERMS };
            let mut game = listed_with(terms);
            if ending == 0 {
                game.cancel().unwrap();
            } else {
                game.buy(1).unwrap();
                match ending {
                    1 => game.sale.claim_undelivered(7).unwrap(),
                    2 => { game.deliver(2).unwrap(); game.accept().unwrap(); }
                    3 => { game.deliver(2).unwrap(); game.sale.claim_uncontested(8).unwrap(); }
                    4 => { game.deliver(2).unwrap(); game.dispute(3).unwrap(); }
                    _ => {
                        let junk = block_of(b"junk");
                        game.deliver_block(2, &junk).unwrap();
                        game.dispute(3).unwrap();
                    }
                }
            }
            let (seller, buyer) = game.sale.owed();
            prop_assert_eq!(game.sale.stage(), Stage::Settled);
            prop_assert_eq!(seller + buyer, game.sale.escrow());
        }
    }
}
