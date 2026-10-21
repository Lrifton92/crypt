// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! A real sale on esmeralda, played by the visitor on both sides and paid from their own Tari
//! wallet. This side does only what the Crypt client does: keys, sealing, opening and the action
//! proofs. The page turns the returned values into transactions and the wallet signs and pays them.
//! The keys never leave this object, so a reload abandons the sale (the escrow keeps the funds).

use crypt_core::rules::Terms;
use crypt_core::{
    commitment_of, encode_plaintext, msg_accept, msg_deliver, open_verified, prove_action, seal, Block, Keypair, Proof,
    LIST_CONTEXT, MAX_SECRET_LEN, MSG_BUY,
};
use rand_core::OsRng;
use serde::Serialize;

use crate::game::ProofHex;

/// One XTM in the resource's native units (divisibility 6).
pub const XTM: u64 = 1_000_000;
/// The amounts of the two sales already played on esmeralda by `crypt_onchain`.
pub const PRICE: u64 = 10 * XTM;
pub const BUYER_BOND: u64 = 2 * XTM;
pub const SELLER_BOND: u64 = 3 * XTM;
/// Epochs. Wide enough for a visitor who leaves the tab open.
pub const LISTING_WINDOW: u64 = 200;
pub const DELIVERY_WINDOW: u64 = 100;
pub const DISPUTE_WINDOW: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListArgs {
    pub commitment: String,
    pub price: u64,
    pub buyer_bond: u64,
    pub seller_bond: u64,
    pub listing_window: u64,
    pub delivery_window: u64,
    pub dispute_window: u64,
    pub seller_key: String,
    pub proof: ProofHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuyArgs {
    pub buyer_key: String,
    pub proof: ProofHex,
    pub payment: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeliverArgs {
    pub ephemeral: String,
    pub ephemeral_proof: ProofHex,
    pub ciphertext: String,
    pub proof: ProofHex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptArgs {
    pub secret: String,
    pub proof: ProofHex,
}

pub struct LiveSale {
    block: Block,
    commitment: [u8; 64],
    terms: Terms,
    seller: Keypair,
    buyer_base: Keypair,
    /// The component's address bytes, known once `list` has landed.
    context: Option<Vec<u8>>,
    buyer: Option<Keypair>,
    delivery: Option<([u8; 32], Block)>,
}

fn hex_of(proof: &Proof) -> ProofHex {
    ProofHex::from(proof)
}

impl LiveSale {
    /// # Errors
    /// A secret too long for a block.
    pub fn new(secret: &str) -> Result<Self, String> {
        let block = encode_plaintext(secret.as_bytes(), &mut OsRng).map_err(|_| {
            format!(
                "the secret is {} bytes; a block holds at most {} bytes",
                secret.len(),
                MAX_SECRET_LEN
            )
        })?;
        let commitment = commitment_of(&block);
        Ok(Self {
            block,
            commitment,
            terms: Terms {
                price: PRICE,
                buyer_bond: BUYER_BOND,
                seller_bond: SELLER_BOND,
                listing_window: LISTING_WINDOW,
                delivery_window: DELIVERY_WINDOW,
                dispute_window: DISPUTE_WINDOW,
            },
            seller: Keypair::generate(&mut OsRng).for_listing(&commitment),
            buyer_base: Keypair::generate(&mut OsRng),
            context: None,
            buyer: None,
            delivery: None,
        })
    }

    #[must_use]
    pub fn list(&self) -> ListArgs {
        let proof = prove_action(
            &self.seller,
            LIST_CONTEXT,
            &self.terms.list_message(&self.commitment),
            &mut OsRng,
        );
        ListArgs {
            commitment: hex::encode(self.commitment),
            price: self.terms.price,
            buyer_bond: self.terms.buyer_bond,
            seller_bond: self.terms.seller_bond,
            listing_window: self.terms.listing_window,
            delivery_window: self.terms.delivery_window,
            dispute_window: self.terms.dispute_window,
            seller_key: hex::encode(self.seller.public()),
            proof: hex_of(&proof),
        }
    }

    /// `component` is the 32 address bytes of the listed component, in hex: the sale's context.
    ///
    /// # Errors
    /// Not 32 bytes of hex.
    pub fn buy(&mut self, component: &str) -> Result<BuyArgs, String> {
        let context = hex::decode(component).map_err(|_| "the component address is not hex".to_string())?;
        if context.len() != 32 {
            return Err("the component address must be 32 bytes".into());
        }
        let buyer = self.buyer_base.for_sale(&context);
        let proof = prove_action(&buyer, &context, MSG_BUY, &mut OsRng);
        let args = BuyArgs {
            buyer_key: hex::encode(buyer.public()),
            proof: hex_of(&proof),
            payment: self.terms.price + self.terms.buyer_bond,
        };
        self.context = Some(context);
        self.buyer = Some(buyer);
        Ok(args)
    }

    /// The seller seals the listed secret to the buyer's sale key.
    ///
    /// # Errors
    /// Called before `buy`.
    pub fn deliver(&mut self) -> Result<DeliverArgs, String> {
        let (context, buyer) = self.bought()?;
        let sealed = seal(&self.block, &buyer.public(), context, &mut OsRng).map_err(|e| format!("{e:?}"))?;
        let proof = prove_action(
            &self.seller,
            context,
            &msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
            &mut OsRng,
        );
        let args = DeliverArgs {
            ephemeral: hex::encode(sealed.ephemeral),
            ephemeral_proof: hex_of(&sealed.ephemeral_proof),
            ciphertext: hex::encode(sealed.ciphertext),
            proof: hex_of(&proof),
        };
        self.delivery = Some((sealed.ephemeral, sealed.ciphertext));
        Ok(args)
    }

    /// The buyer opens the delivery, checks it against the listed commitment, and only then signs
    /// the acceptance.
    ///
    /// # Errors
    /// Called before `deliver`, or a delivery that does not open to the listed secret.
    pub fn accept(&self) -> Result<AcceptArgs, String> {
        let (context, buyer) = self.bought()?;
        let (ephemeral, ciphertext) = self.delivery.as_ref().ok_or("nothing has been delivered yet")?;
        let secret = open_verified(buyer, context, ephemeral, ciphertext, &self.commitment)
            .map_err(|e| format!("the delivery does not open to the listed secret: {e:?}"))?;
        let proof = prove_action(buyer, context, &msg_accept(ephemeral), &mut OsRng);
        Ok(AcceptArgs {
            secret: String::from_utf8_lossy(&secret).into_owned(),
            proof: hex_of(&proof),
        })
    }

    fn bought(&self) -> Result<(&[u8], &Keypair), String> {
        match (&self.context, &self.buyer) {
            (Some(context), Some(buyer)) => Ok((context, buyer)),
            _ => Err("nothing has been bought yet".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypt_core::rules::{Outcome, Sale, Stage};
    use crypt_core::Sealed;

    fn arr<const N: usize>(hex_str: &str) -> [u8; N] {
        hex::decode(hex_str).unwrap().try_into().unwrap()
    }
    fn proof(p: &ProofHex) -> Proof {
        Proof {
            c: arr(&p.c),
            z: arr(&p.z),
        }
    }

    /// The four steps, fed to the template's rules exactly as the page sends them.
    #[test]
    fn a_live_sale_passes_the_template_rules() {
        let component = [7u8; 32];
        let mut live = LiveSale::new("pumpkin-lantern").unwrap();
        let l = live.list();
        assert_eq!(l.price, 10 * XTM);
        let mut sale = Sale::list(
            &component,
            1,
            arr(&l.commitment),
            live.terms,
            arr(&l.seller_key),
            &proof(&l.proof),
        )
        .unwrap();
        let b = live.buy(&hex::encode(component)).unwrap();
        assert_eq!(b.payment, 12 * XTM);
        sale.buy(2, arr(&b.buyer_key), &proof(&b.proof), b.payment).unwrap();
        let d = live.deliver().unwrap();
        let sealed = Sealed {
            ephemeral: arr(&d.ephemeral),
            ephemeral_proof: proof(&d.ephemeral_proof),
            ciphertext: arr(&d.ciphertext),
        };
        sale.deliver(3, &sealed, &proof(&d.proof)).unwrap();
        let a = live.accept().unwrap();
        assert_eq!(a.secret, "pumpkin-lantern");
        sale.accept(&proof(&a.proof)).unwrap();
        assert_eq!(sale.stage(), Stage::Settled);
        assert_eq!(sale.outcome(), Some(Outcome::Accepted));
    }

    #[test]
    fn steps_out_of_order_are_refused() {
        let mut live = LiveSale::new("x").unwrap();
        assert!(live.deliver().is_err());
        assert!(live.accept().is_err());
        assert!(live.buy("abcd").is_err());
        live.buy(&"00".repeat(32)).unwrap();
        assert!(live.accept().is_err());
    }

    #[test]
    fn a_secret_too_long_is_refused() {
        assert!(LiveSale::new(&"a".repeat(MAX_SECRET_LEN + 1)).is_err());
    }
}
