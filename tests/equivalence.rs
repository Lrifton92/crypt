//! The rules port (`crypt_core::rules`) against the template. The same calls, with proofs made by the
//! same keys, are played in the Ootle engine and in the port: each must succeed or fail in both, and
//! leave the same stage, outcome, deadlines, split and escrow. The demo shows the port's verdicts, so
//! this test is what lets it say "same check as the contract".

mod common;

use common::*;
use crypt_core::rules::{self, Terms};

const TERMS: Terms = Terms {
    price: PRICE,
    buyer_bond: BUYER_BOND,
    seller_bond: SELLER_BOND,
    listing_window: LISTING_WINDOW,
    delivery_window: DELIVERY_WINDOW,
    dispute_window: DISPUTE_WINDOW,
};

fn pick(n: u32) -> u32 {
    rand_core::RngCore::next_u32(&mut OsRng) % n
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Buy(u64),
    /// `true`: the listed block sealed to the buyer; `false`: noise.
    Deliver(u64, bool),
    Accept,
    Dispute(u64),
    ClaimUndelivered(u64),
    ClaimUncontested(u64),
    Cancel,
}

/// One sale, held both by the engine and by the port.
struct Twin {
    crypt: ComponentAddress,
    block: client::Block,
    port: rules::Sale,
    buyer: Keypair,
    log: Vec<Step>,
}

impl Twin {
    fn list(m: &mut Market) -> Self {
        m.epoch(START_EPOCH);
        let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
        let crypt = m.list(&block);
        let ctx = context(crypt);
        let commitment = client::commitment_of(&block);
        let proof = client::prove_action(
            &m.seller_key,
            client::LIST_CONTEXT,
            &TERMS.list_message(&commitment),
            &mut OsRng,
        );
        let port = rules::Sale::list(&ctx, START_EPOCH, commitment, TERMS, m.seller_key.public(), &proof).unwrap();
        let listing_deadline: u64 = m.test.call_method(crypt, "listing_deadline", args![], vec![]);
        assert_eq!(listing_deadline, port.listing_deadline());
        let twin = Self {
            crypt,
            block,
            port,
            buyer: Keypair::generate(&mut OsRng).for_sale(&ctx),
            log: Vec::new(),
        };
        twin.check(m);
        twin
    }

    /// The `R` both sides would sign over: the delivered one, or a stranger's before any delivery.
    fn ephemeral(&self) -> [u8; 32] {
        self.port
            .delivery()
            .map_or_else(|| Keypair::generate(&mut OsRng).public(), |d| d.ephemeral)
    }

    fn play(&mut self, m: &mut Market, step: Step) {
        let ctx = context(self.crypt);
        let crypt = self.crypt;
        self.log.push(step);
        let (engine, port) = match step {
            Step::Buy(epoch) => {
                m.epoch(epoch);
                let due = PRICE + BUYER_BOND;
                let proof = client::prove_action(&self.buyer, &ctx, client::MSG_BUY, &mut OsRng);
                let tx = m.buy_tx(crypt, self.buyer.public(), proof, due);
                (m.attempt_tx(tx), self.port.buy(epoch, self.buyer.public(), &proof, due))
            }
            Step::Deliver(epoch, honest) => {
                m.epoch(epoch);
                let sealed = if honest {
                    client::seal(&self.block, &self.buyer.public(), &ctx, &mut OsRng).unwrap()
                } else {
                    Market::noise(crypt)
                };
                let proof = client::prove_action(
                    &m.seller_key,
                    &ctx,
                    &client::msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
                    &mut OsRng,
                );
                let args = m.deliver_args(crypt, &sealed);
                (
                    m.attempt(crypt, "deliver", args),
                    self.port.deliver(epoch, &sealed, &proof),
                )
            }
            Step::Accept => {
                let message = client::msg_accept(&self.ephemeral());
                let proof = client::prove_action(&self.buyer, &ctx, &message, &mut OsRng);
                (m.attempt(crypt, "accept", proof_args(proof)), self.port.accept(&proof))
            }
            Step::Dispute(epoch) => {
                m.epoch(epoch);
                let (shared, proof) = forged_dispute(&self.buyer, crypt, &self.ephemeral());
                (
                    m.attempt(crypt, "dispute", dispute_args(shared, proof)),
                    self.port.dispute(epoch, shared, &proof).map(drop),
                )
            }
            Step::ClaimUndelivered(epoch) => {
                m.epoch(epoch);
                (
                    m.attempt(crypt, "claim_undelivered", args![]),
                    self.port.claim_undelivered(epoch),
                )
            }
            Step::ClaimUncontested(epoch) => {
                m.epoch(epoch);
                (
                    m.attempt(crypt, "claim_uncontested", args![]),
                    self.port.claim_uncontested(epoch),
                )
            }
            Step::Cancel => {
                let proof = client::prove_action(&m.seller_key, &ctx, client::MSG_CANCEL, &mut OsRng);
                (m.attempt(crypt, "cancel", proof_args(proof)), self.port.cancel(&proof))
            }
        };
        assert_eq!(
            engine,
            port.is_ok(),
            "engine and port disagree on {:?} (port: {:?})",
            self.log,
            port
        );
        self.check(m);
    }

    fn check(&self, m: &mut Market) {
        let crypt = self.crypt;
        let log = &self.log;
        assert_eq!(
            m.stage(crypt),
            format!("{:?}", self.port.stage()),
            "stage after {log:?}"
        );
        assert_eq!(
            m.outcome(crypt),
            self.port.outcome().map(|o| format!("{o:?}")),
            "outcome after {log:?}"
        );
        let (seller, buyer) = self.port.owed();
        assert_eq!(m.owed(crypt), (a(seller), a(buyer)), "owed after {log:?}");
        assert_eq!(m.escrow(crypt), a(self.port.escrow()), "escrow after {log:?}");
        let deadlines: (Option<u64>, Option<u64>) = m.test.call_method(crypt, "deadlines", args![], vec![]);
        assert_eq!(deadlines, self.port.deadlines(), "deadlines after {log:?}");
    }

    /// An epoch right around one of the sale's deadlines: one before, on it, or one after.
    fn near_a_deadline(&self) -> u64 {
        let (delivery, dispute) = self.port.deadlines();
        let anchors: Vec<u64> = [Some(self.port.listing_deadline()), delivery, dispute]
            .into_iter()
            .flatten()
            .collect();
        anchors[pick(anchors.len() as u32) as usize] + u64::from(pick(3)) - 1
    }
}

#[test]
fn the_rules_port_matches_the_template_on_every_scripted_outcome() {
    use Step::*;
    // Listed at 10: buy until 15. Bought at 10: deliver until 13. Delivered at 11: dispute until 15.
    let scripts: [&[Step]; 8] = [
        &[Cancel],
        &[Buy(10), Deliver(11, true), Accept],
        &[Buy(10), Deliver(11, true), ClaimUncontested(15), ClaimUncontested(16)],
        &[Buy(10), ClaimUndelivered(13), ClaimUndelivered(14)],
        &[Buy(10), Deliver(13, true), Dispute(17)],
        &[Buy(15), Deliver(18, false), Dispute(22)],
        &[Buy(16), Cancel],
        &[
            Buy(10),
            Deliver(14, true),
            Deliver(13, false),
            Dispute(18),
            Dispute(17),
            Accept,
        ],
    ];
    let mut m = Market::new();
    for script in scripts {
        let mut twin = Twin::list(&mut m);
        for &step in script {
            twin.play(&mut m, step);
        }
        assert_eq!(
            twin.port.stage(),
            rules::Stage::Settled,
            "every script ends settled: {script:?}"
        );
    }
}

#[test]
fn the_rules_port_matches_the_template_on_random_sequences() {
    let mut m = Market::new();
    for _ in 0..64 {
        let mut twin = Twin::list(&mut m);
        for _ in 0..8 {
            let epoch = twin.near_a_deadline();
            let step = match pick(7) {
                0 => Step::Buy(epoch),
                1 => Step::Deliver(epoch, pick(2) == 0),
                2 => Step::Accept,
                3 => Step::Dispute(epoch),
                4 => Step::ClaimUndelivered(epoch),
                5 => Step::ClaimUncontested(epoch),
                _ => Step::Cancel,
            };
            twin.play(&mut m, step);
        }
    }
}

#[test]
fn the_rules_port_refuses_the_listings_the_template_refuses() {
    let mut m = Market::new();
    let stranger = Keypair::generate(&mut OsRng);
    let cases = [
        (TERMS, true),
        (Terms { buyer_bond: 0, ..TERMS }, true),
        (
            Terms {
                buyer_bond: PRICE + 1,
                ..TERMS
            },
            true,
        ),
        (
            Terms {
                buyer_bond: PRICE,
                ..TERMS
            },
            true,
        ),
        (
            Terms {
                seller_bond: PRICE / 10 - 1,
                ..TERMS
            },
            true,
        ),
        (
            Terms {
                seller_bond: PRICE / 10,
                ..TERMS
            },
            true,
        ),
        (
            Terms {
                listing_window: 2,
                ..TERMS
            },
            true,
        ),
        (
            Terms {
                delivery_window: DISPUTE_WINDOW + 1,
                ..TERMS
            },
            true,
        ),
        (
            Terms {
                dispute_window: 10_001,
                ..TERMS
            },
            true,
        ),
        (TERMS, false),
    ];
    for (terms, signed_by_seller) in cases {
        m.epoch(START_EPOCH);
        let block = client::encode_plaintext(SECRET, &mut OsRng).unwrap();
        let commitment = client::commitment_of(&block);
        let seller = copy_key(&m.seller_key);
        let signer = if signed_by_seller { &seller } else { &stranger };
        let tx = m.list_tx(
            Hash64::from(commitment),
            seller.public(),
            signer,
            terms.seller_bond,
            terms.price,
            terms.buyer_bond,
            (terms.listing_window, terms.delivery_window, terms.dispute_window),
        );
        let engine = m.attempt_tx(tx);
        let proof = client::prove_action(
            signer,
            client::LIST_CONTEXT,
            &terms.list_message(&commitment),
            &mut OsRng,
        );
        let port = rules::Sale::list(
            b"not yet listed",
            START_EPOCH,
            commitment,
            terms,
            seller.public(),
            &proof,
        );
        assert_eq!(
            engine,
            port.is_ok(),
            "{terms:?} signed by seller: {signed_by_seller} (port: {:?})",
            port.err()
        );
    }
}
