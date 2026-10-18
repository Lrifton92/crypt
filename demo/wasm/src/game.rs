// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! One sale between a demo seller and a demo buyer. Every step runs the real client code
//! (`crypt_core`: sealing, opening, action proofs, the DLEQ proof) and then the template's rules
//! (`crypt_core::rules`), so each verdict the page shows comes out of the same computation as the
//! contract's. Everything returned is plain data (hex strings, numbers) for the page to display.

use crypt_core::rules::{RuleError, Sale, Terms};
use crypt_core::{
    commitment_of, decode_plaintext, encode_plaintext, msg_accept, msg_deliver, open, prove_action, prove_shared, seal,
    Block, Keypair, Proof, LIST_CONTEXT, MAX_SECRET_LEN, MSG_BUY,
};
use rand_core::{OsRng, RngCore};
use serde::Serialize;

pub const LISTING_WINDOW: u64 = 10;
pub const DELIVERY_WINDOW: u64 = 3;
pub const DISPUTE_WINDOW: u64 = 3;
const START_EPOCH: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofHex {
    pub c: String,
    pub z: String,
}

impl From<&Proof> for ProofHex {
    fn from(proof: &Proof) -> Self {
        Self {
            c: hex::encode(proof.c),
            z: hex::encode(proof.z),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct State {
    /// `None` before anything is listed.
    pub stage: Option<String>,
    pub outcome: Option<String>,
    /// `[seller, buyer]`.
    pub owed: [u64; 2],
    pub escrow: u64,
    pub epoch: u64,
    pub listing_deadline: Option<u64>,
    pub delivery_deadline: Option<u64>,
    pub dispute_deadline: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listed {
    pub commitment: String,
    pub seller_key: String,
    pub secret_bytes: usize,
    pub state: State,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bought {
    pub buyer_key: String,
    pub paid: u64,
    pub state: State,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Delivered {
    pub ephemeral: String,
    pub ephemeral_proof: ProofHex,
    pub ciphertext: String,
    pub state: State,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Opened {
    /// The secret, only when the delivery is exactly what was listed.
    pub secret: Option<String>,
    /// `"ok"`, `"mismatch"` (not the committed block) or `"malformed"` (committed, but not decodable).
    pub verdict: String,
    pub delivered_hash: String,
    pub promised_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disputed {
    pub outcome: String,
    pub shared: String,
    pub proof: ProofHex,
    pub delivered_hash: String,
    pub promised_hash: String,
    /// What the template decrypted, when it decodes as a secret.
    pub revealed: Option<String>,
    pub state: State,
}

/// What the page shows when the template would refuse a step.
#[must_use]
pub fn rule_message(error: RuleError) -> String {
    match error {
        RuleError::BadTerms => {
            "the template refuses these terms: price and bonds must be positive, the buyer bond at most the \
             price, the seller bond at least 10% of it"
        }
        RuleError::WrongStage => "this step is not possible at this stage of the sale",
        RuleError::DeadlinePassed => "too late: the deadline for this step has passed",
        RuleError::WindowOpen => "too early: the window is still open",
        RuleError::Unauthorized => "refused: signed by the wrong key",
        RuleError::BadPayment => "refused: the payment must be exactly the price plus the buyer bond",
        RuleError::InvalidPoint => "refused: not a valid key",
        RuleError::BadProof => "refused: the proof does not verify",
    }
    .to_string()
}

pub struct Game {
    /// Stands for the component's address.
    context: Vec<u8>,
    epoch: u64,
    seller: Keypair,
    listing_key: Option<Keypair>,
    /// The buyer's key for this sale.
    buyer: Keypair,
    block: Option<Block>,
    sale: Option<Sale>,
}

impl Default for Game {
    fn default() -> Self {
        Self::new()
    }
}

impl Game {
    #[must_use]
    pub fn new() -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let context = [b"demo-component-".as_slice(), hex::encode(id).as_bytes()].concat();
        let buyer = Keypair::generate(&mut OsRng).for_sale(&context);
        Self {
            context,
            epoch: START_EPOCH,
            seller: Keypair::generate(&mut OsRng),
            listing_key: None,
            buyer,
            block: None,
            sale: None,
        }
    }

    /// # Errors
    /// A secret longer than a block holds, a second listing, or terms the template refuses.
    pub fn list(&mut self, secret: &str, price: u64, buyer_bond: u64, seller_bond: u64) -> Result<Listed, String> {
        if self.sale.is_some() {
            return Err("this game already has a listing".into());
        }
        let block = block_of(secret)?;
        let commitment = commitment_of(&block);
        let listing_key = self.seller.for_listing(&commitment);
        let terms = Terms {
            price,
            buyer_bond,
            seller_bond,
            listing_window: LISTING_WINDOW,
            delivery_window: DELIVERY_WINDOW,
            dispute_window: DISPUTE_WINDOW,
        };
        let proof = prove_action(&listing_key, LIST_CONTEXT, &terms.list_message(&commitment), &mut OsRng);
        let sale = Sale::list(
            &self.context,
            self.epoch,
            commitment,
            terms,
            listing_key.public(),
            &proof,
        )
        .map_err(rule_message)?;
        let seller_key = hex::encode(listing_key.public());
        self.sale = Some(sale);
        self.listing_key = Some(listing_key);
        self.block = Some(block);
        Ok(Listed {
            commitment: hex::encode(commitment),
            seller_key,
            secret_bytes: secret.len(),
            state: self.state(),
        })
    }

    /// # Errors
    /// Whatever the template's `buy` would refuse.
    pub fn buy(&mut self) -> Result<Bought, String> {
        let (epoch, key) = (self.epoch, self.buyer.public());
        let proof = prove_action(&self.buyer, &self.context, MSG_BUY, &mut OsRng);
        let sale = self.sale_mut()?;
        let paid = sale.terms().price + sale.terms().buyer_bond;
        sale.buy(epoch, key, &proof, paid).map_err(rule_message)?;
        Ok(Bought {
            buyer_key: hex::encode(key),
            paid,
            state: self.state(),
        })
    }

    /// # Errors
    /// Whatever the template's `deliver` would refuse.
    pub fn deliver_honest(&mut self) -> Result<Delivered, String> {
        let block = self.block.ok_or_else(not_listed)?;
        self.deliver_block(&block)
    }

    /// Seals another secret than the listed one: what a cheating seller would send.
    ///
    /// # Errors
    /// A fake secret too long for a block, or whatever `deliver` would refuse.
    pub fn deliver_fake(&mut self, fake_secret: &str) -> Result<Delivered, String> {
        let block = block_of(fake_secret)?;
        self.deliver_block(&block)
    }

    /// The buyer's client opens the delivery and checks it against the commitment.
    ///
    /// # Errors
    /// Nothing delivered yet.
    pub fn buyer_open(&self) -> Result<Opened, String> {
        let sale = self.sale.as_ref().ok_or_else(not_listed)?;
        let delivery = sale.delivery().ok_or("nothing has been delivered yet")?;
        let block = open(&self.buyer, &self.context, &delivery.ephemeral, &delivery.ciphertext)
            .map_err(|e| format!("cannot open the delivery: {e:?}"))?;
        let delivered = commitment_of(&block);
        let (verdict, secret) = if delivered != sale.commitment() {
            ("mismatch", None)
        } else {
            match decode_plaintext(&block) {
                Ok(secret) => ("ok", Some(String::from_utf8_lossy(&secret).into_owned())),
                Err(_) => ("malformed", None),
            }
        };
        Ok(Opened {
            secret,
            verdict: verdict.into(),
            delivered_hash: hex::encode(delivered),
            promised_hash: hex::encode(sale.commitment()),
        })
    }

    /// # Errors
    /// Whatever the template's `accept` would refuse.
    pub fn accept(&mut self) -> Result<State, String> {
        let ephemeral = self.delivered_ephemeral()?;
        let proof = prove_action(&self.buyer, &self.context, &msg_accept(&ephemeral), &mut OsRng);
        self.sale_mut()?.accept(&proof).map_err(rule_message)?;
        Ok(self.state())
    }

    /// # Errors
    /// Whatever the template's `dispute` would refuse.
    pub fn dispute(&mut self) -> Result<Disputed, String> {
        let ephemeral = self.delivered_ephemeral()?;
        let (shared, proof) = prove_shared(&self.buyer, &self.buyer.public(), &self.context, &ephemeral, &mut OsRng)
            .map_err(|e| format!("cannot prove the shared point: {e:?}"))?;
        let epoch = self.epoch;
        let sale = self.sale_mut()?;
        let outcome = sale.dispute(epoch, shared, &proof).map_err(rule_message)?;
        let block = sale.revealed_block().expect("a dispute reveals the block");
        let revealed = decode_plaintext(&block)
            .ok()
            .map(|secret| String::from_utf8_lossy(&secret).into_owned());
        let promised = sale.commitment();
        Ok(Disputed {
            outcome: format!("{outcome:?}"),
            shared: hex::encode(shared),
            proof: ProofHex::from(&proof),
            delivered_hash: hex::encode(commitment_of(&block)),
            promised_hash: hex::encode(promised),
            revealed,
            state: self.state(),
        })
    }

    pub fn advance_epochs(&mut self, n: u64) {
        self.epoch = self.epoch.saturating_add(n);
    }

    /// # Errors
    /// Whatever the template's `claim_undelivered` would refuse.
    pub fn claim_undelivered(&mut self) -> Result<State, String> {
        let epoch = self.epoch;
        self.sale_mut()?.claim_undelivered(epoch).map_err(rule_message)?;
        Ok(self.state())
    }

    /// # Errors
    /// Whatever the template's `claim_uncontested` would refuse.
    pub fn claim_uncontested(&mut self) -> Result<State, String> {
        let epoch = self.epoch;
        self.sale_mut()?.claim_uncontested(epoch).map_err(rule_message)?;
        Ok(self.state())
    }

    #[must_use]
    pub fn state(&self) -> State {
        let Some(sale) = &self.sale else {
            return State {
                stage: None,
                outcome: None,
                owed: [0, 0],
                escrow: 0,
                epoch: self.epoch,
                listing_deadline: None,
                delivery_deadline: None,
                dispute_deadline: None,
            };
        };
        let (seller, buyer) = sale.owed();
        let (delivery_deadline, dispute_deadline) = sale.deadlines();
        State {
            stage: Some(format!("{:?}", sale.stage())),
            outcome: sale.outcome().map(|o| format!("{o:?}")),
            owed: [seller, buyer],
            escrow: sale.escrow(),
            epoch: self.epoch,
            listing_deadline: Some(sale.listing_deadline()),
            delivery_deadline,
            dispute_deadline,
        }
    }
    fn sale_mut(&mut self) -> Result<&mut Sale, String> {
        self.sale.as_mut().ok_or_else(not_listed)
    }

    /// The `R` on the ledger. Before any delivery the template refuses accept and dispute by stage.
    fn delivered_ephemeral(&self) -> Result<[u8; 32], String> {
        let sale = self.sale.as_ref().ok_or_else(not_listed)?;
        sale.delivery()
            .map(|d| d.ephemeral)
            .ok_or_else(|| rule_message(RuleError::WrongStage))
    }

    fn deliver_block(&mut self, block: &Block) -> Result<Delivered, String> {
        let sale = self.sale.as_ref().ok_or_else(not_listed)?;
        let buyer_key = sale.buyer_key().ok_or_else(|| rule_message(RuleError::WrongStage))?;
        let sealed = seal(block, &buyer_key, &self.context, &mut OsRng).map_err(|e| format!("cannot seal: {e:?}"))?;
        let seller = self.listing_key.as_ref().expect("set at list");
        let message = msg_deliver(&sealed.ephemeral, &sealed.ciphertext);
        let proof = prove_action(seller, &self.context, &message, &mut OsRng);
        let epoch = self.epoch;
        self.sale_mut()?.deliver(epoch, &sealed, &proof).map_err(rule_message)?;
        Ok(Delivered {
            ephemeral: hex::encode(sealed.ephemeral),
            ephemeral_proof: ProofHex::from(&sealed.ephemeral_proof),
            ciphertext: hex::encode(sealed.ciphertext),
            state: self.state(),
        })
    }
}

fn not_listed() -> String {
    "list a secret first".into()
}

fn block_of(secret: &str) -> Result<Block, String> {
    encode_plaintext(secret.as_bytes(), &mut OsRng).map_err(|_| {
        format!(
            "the secret is {} bytes; a block holds at most {} bytes",
            secret.len(),
            MAX_SECRET_LEN
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "the vault code is 4242";

    fn listed(secret: &str) -> Game {
        let mut game = Game::new();
        game.list(secret, 1_000, 100, 200).unwrap();
        game
    }

    fn bought() -> Game {
        let mut game = listed(SECRET);
        game.buy().unwrap();
        game
    }

    fn outcome(game: &Game) -> Option<String> {
        game.state().outcome
    }

    #[test]
    fn an_honest_sale_ends_accepted() {
        let mut game = Game::new();
        assert_eq!(game.state().stage, None);
        let listed = game.list(SECRET, 1_000, 100, 200).unwrap();
        assert_eq!((listed.state.escrow, listed.secret_bytes), (200, SECRET.len()));
        let bought = game.buy().unwrap();
        assert_eq!((bought.paid, bought.state.escrow), (1_100, 1_300));
        let delivered = game.deliver_honest().unwrap();
        assert_eq!(delivered.ciphertext.len(), 2 * crypt_core::PLAINTEXT_LEN);
        let opened = game.buyer_open().unwrap();
        assert_eq!(
            (opened.verdict.as_str(), opened.secret.as_deref()),
            ("ok", Some(SECRET))
        );
        assert_eq!(opened.delivered_hash, opened.promised_hash);
        let state = game.accept().unwrap();
        assert_eq!((state.outcome.as_deref(), state.owed), (Some("Accepted"), [1_200, 100]));
    }

    #[test]
    fn a_silent_buyer_pays_like_an_acceptance() {
        let mut game = bought();
        game.deliver_honest().unwrap();
        game.advance_epochs(DISPUTE_WINDOW);
        assert_eq!(game.claim_uncontested(), Err(rule_message(RuleError::WindowOpen)));
        game.advance_epochs(1);
        assert_eq!(game.claim_uncontested().unwrap().owed, [1_200, 100]);
        assert_eq!(outcome(&game).as_deref(), Some("Uncontested"));
    }

    #[test]
    fn an_absent_seller_loses_the_bond() {
        let mut game = bought();
        game.advance_epochs(DELIVERY_WINDOW + 1);
        assert_eq!(
            game.deliver_honest().err(),
            Some(rule_message(RuleError::DeadlinePassed))
        );
        assert_eq!(game.claim_undelivered().unwrap().owed, [0, 1_300]);
        assert_eq!(outcome(&game).as_deref(), Some("Undelivered"));
    }

    #[test]
    fn a_fake_delivery_is_caught_and_disputed_as_fraud() {
        let mut game = bought();
        game.deliver_fake("nothing in here").unwrap();
        let opened = game.buyer_open().unwrap();
        assert_eq!((opened.verdict.as_str(), opened.secret), ("mismatch", None));
        assert_ne!(opened.delivered_hash, opened.promised_hash);
        let disputed = game.dispute().unwrap();
        assert_eq!(disputed.outcome, "Fraud");
        assert_eq!(disputed.revealed.as_deref(), Some("nothing in here"));
        assert_eq!(disputed.delivered_hash, opened.delivered_hash);
        assert_eq!(disputed.state.owed, [0, 1_300]);
    }

    #[test]
    fn a_false_dispute_costs_the_buyer_the_bond() {
        let mut game = bought();
        game.deliver_honest().unwrap();
        let disputed = game.dispute().unwrap();
        assert_eq!(disputed.outcome, "DisputeRejected");
        assert_eq!(disputed.revealed.as_deref(), Some(SECRET));
        assert_eq!(disputed.delivered_hash, disputed.promised_hash);
        assert_eq!(disputed.state.owed, [1_300, 0]);
    }

    #[test]
    fn an_empty_secret_is_a_valid_listing() {
        let mut game = listed("");
        game.buy().unwrap();
        game.deliver_honest().unwrap();
        assert_eq!(game.buyer_open().unwrap().secret.as_deref(), Some(""));
    }

    #[test]
    fn secrets_are_measured_in_bytes() {
        let too_long = "a".repeat(288);
        let error = Game::new().list(&too_long, 1_000, 100, 200).unwrap_err();
        assert!(
            error.contains("288 bytes") && error.contains(&MAX_SECRET_LEN.to_string()),
            "{error}"
        );

        // 72 skulls are 72 characters but 288 bytes.
        let skulls = "\u{1F480}".repeat(72);
        let error = Game::new().list(&skulls, 1_000, 100, 200).unwrap_err();
        assert!(error.contains("288 bytes"), "{error}");
        let fits = "\u{1F480}".repeat(71);
        let mut game = listed(&fits);
        game.buy().unwrap();
        game.deliver_honest().unwrap();
        assert_eq!(game.buyer_open().unwrap().secret, Some(fits));

        let mut game = bought();
        assert!(game.deliver_fake(&too_long).unwrap_err().contains("288 bytes"));
    }

    #[test]
    fn steps_out_of_order_are_refused_readably() {
        let mut game = Game::new();
        assert!(game.buy().unwrap_err().contains("list a secret first"));
        assert!(game.buyer_open().is_err());
        let mut game = listed(SECRET);
        assert!(game.list(SECRET, 1_000, 100, 200).is_err());
        assert_eq!(game.deliver_honest().err(), Some(rule_message(RuleError::WrongStage)));
        assert_eq!(game.dispute().err(), Some(rule_message(RuleError::WrongStage)));
        assert_eq!(
            Game::new().list(SECRET, 1_000, 100, 99).err(),
            Some(rule_message(RuleError::BadTerms))
        );
    }
}
