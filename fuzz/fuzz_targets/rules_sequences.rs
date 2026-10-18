//! Random sales on the rules port: honest moves (with real proofs) mixed with forged ones, at
//! arbitrary epochs. A forged move never changes anything, a sale settles at most once, the escrow is
//! split exactly once settled, and a dispute's verdict matches what was really delivered.
#![no_main]
use crypt_core::{
    commitment_of, encode_plaintext, msg_accept, msg_deliver, prove_action, prove_shared,
    rules::{Outcome, Sale, Stage, Terms},
    seal, Keypair, Proof, Sealed, LIST_CONTEXT, MSG_BUY, MSG_CANCEL, PLAINTEXT_LEN,
};
use libfuzzer_sys::fuzz_target;
use rand_core::{CryptoRng, RngCore};

/// Deterministic randomness from the fuzz input, so every crash replays.
struct Rng(u64);
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for b in dest {
            *b = self.next_u64() as u8;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for Rng {}

fn take<const N: usize>(data: &mut &[u8]) -> Option<[u8; N]> {
    let (head, tail) = data.split_first_chunk::<N>()?;
    *data = tail;
    Some(*head)
}

const CONTEXT: &[u8] = b"fuzz sale";

fuzz_target!(|bytes: &[u8]| {
    let mut data = bytes;
    let Some(t) = take::<16>(&mut data) else { return };
    let mut rng = Rng(u64::from_le_bytes(t[..8].try_into().unwrap()) | 1);
    let n = |i: usize| u64::from(u16::from_le_bytes([t[i], t[i + 1]]));
    let price = n(8) % 5000 + 1;
    let delivery_window = 3 + n(12) % 8;
    let terms = Terms {
        price,
        buyer_bond: 1 + n(10) % price,
        seller_bond: price.div_ceil(10) + n(14) % 100,
        listing_window: 3 + u64::from(t[9]) % 8,
        delivery_window,
        dispute_window: delivery_window + u64::from(t[11]) % 5,
    };

    let block = encode_plaintext(b"the real secret", &mut rng).unwrap();
    let fake = encode_plaintext(b"something else", &mut rng).unwrap();
    let commitment = commitment_of(&block);
    let seller = Keypair::generate(&mut rng);
    let buyer = Keypair::generate(&mut rng);

    // A proof nobody signed never lists.
    let forged = Proof {
        c: [t[0]; 32],
        z: [t[1]; 32],
    };
    assert!(Sale::list(CONTEXT, 0, commitment, terms, seller.public(), &forged).is_err());
    let proof = prove_action(&seller, LIST_CONTEXT, &terms.list_message(&commitment), &mut rng);
    let mut sale = Sale::list(CONTEXT, 0, commitment, terms, seller.public(), &proof).expect("valid terms list");

    let mut delivered_true: Option<bool> = None;
    let mut settlements = 0;
    while let Some([op, epoch]) = take::<2>(&mut data) {
        let epoch = u64::from(epoch % 40);
        let before = sale.stage();
        let junk = Proof {
            c: [op; 32],
            z: [epoch as u8; 32],
        };
        let honest_seal = |b: &[u8; PLAINTEXT_LEN], rng: &mut Rng| seal(b, &buyer.public(), CONTEXT, rng).unwrap();
        let (forged_move, result) = match op % 10 {
            0 => {
                let p = prove_action(&buyer, CONTEXT, MSG_BUY, &mut rng);
                let due = terms.price + terms.buyer_bond;
                let paid = if op & 0x10 == 0 { due } else { due + 1 };
                (paid != due, sale.buy(epoch, buyer.public(), &p, paid))
            }
            1 => (
                true,
                sale.buy(epoch, seller.public(), &junk, terms.price + terms.buyer_bond),
            ),
            2 | 3 => {
                let real = op % 10 == 2;
                let sealed = honest_seal(if real { &block } else { &fake }, &mut rng);
                let p = prove_action(
                    &seller,
                    CONTEXT,
                    &msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
                    &mut rng,
                );
                let r = sale.deliver(epoch, &sealed, &p);
                if r.is_ok() {
                    delivered_true = Some(real);
                }
                (false, r)
            }
            4 => {
                let sealed = Sealed {
                    ephemeral: buyer.public(),
                    ephemeral_proof: junk,
                    ciphertext: [op; PLAINTEXT_LEN],
                };
                (true, sale.deliver(epoch, &sealed, &junk))
            }
            5 => {
                let eph = sale.delivery().map_or([1; 32], |d| d.ephemeral);
                let p = prove_action(&buyer, CONTEXT, &msg_accept(&eph), &mut rng);
                (false, sale.accept(&p))
            }
            6 => match sale.delivery().map(|d| d.ephemeral) {
                Some(eph) => {
                    let (shared, p) = prove_shared(&buyer, &buyer.public(), CONTEXT, &eph, &mut rng).unwrap();
                    let r = sale.dispute(epoch, shared, &p);
                    if let Ok(outcome) = r {
                        let expected = if delivered_true == Some(true) {
                            Outcome::DisputeRejected
                        } else {
                            Outcome::Fraud
                        };
                        assert_eq!(outcome, expected, "the verdict does not match the delivery");
                    }
                    (false, r.map(drop))
                }
                None => (true, sale.dispute(epoch, buyer.public(), &junk).map(drop)),
            },
            7 => (false, sale.claim_undelivered(epoch)),
            8 => (false, sale.claim_uncontested(epoch)),
            _ => {
                let p = prove_action(&seller, CONTEXT, MSG_CANCEL, &mut rng);
                (false, sale.cancel(&p))
            }
        };
        if forged_move {
            assert!(result.is_err(), "a forged move succeeded");
            assert_eq!(sale.stage(), before, "a forged move changed the sale");
        }
        if before != Stage::Settled && sale.stage() == Stage::Settled {
            settlements += 1;
        }
        if sale.stage() == Stage::Settled {
            let (s, b) = sale.owed();
            assert_eq!(s + b, sale.escrow(), "escrow not split exactly");
        }
    }
    assert!(settlements <= 1);
});
