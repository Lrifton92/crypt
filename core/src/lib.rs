// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! # `crypt_core`
//!
//! Everything the parties of a Crypt sale compute off-chain, written so that every byte the template
//! re-derives on-chain is derived here the same way:
//!
//! * the seller fills a fixed-size **plaintext block** (random salt, length, secret, zero padding)
//!   and publishes `commitment_of(block)` when listing;
//! * the buyer derives a **sale key** `b' = H(b, sale)` from a base secret, and registers `B' = b'·G`;
//! * once paid, the seller **seals** the block to `B'`: an ephemeral `R = r·G` with a proof that they
//!   know `r`, a shared point `S = r·B'`, and a keystream derived from `S` and the sale's context;
//! * the buyer **opens** it with `S = b'·R`;
//! * if the block does not match the commitment, the buyer publishes `S` with a **DLEQ proof** that
//!   `S = b'·R`. The template re-derives the keystream, decrypts, re-hashes and settles;
//! * each side is paid into fresh stealth outputs, with a proof by its key over the digest of the
//!   stealth transfer (`statement_digest`), so no one can redirect a payout;
//! * buy, deliver, accept, cancel and payouts carry a Schnorr proof by the acting side's key (the buyer's sale
//!   key, the seller's key) over the action and its arguments. Nothing is authorized by the
//!   transaction signer, so a hostile component called in the same transaction cannot act for either
//!   side.
//!
//! Why the proof of `r`: a dispute publishes `b'·R`. If a seller could post an `R` whose discrete log
//! they do not know (say, another sale's `R`), the dispute would hand them `b'·R`, a value they could
//! not compute, and possibly another sale's secret. Requiring proof of `r` means a dispute only ever
//! publishes `r·B'`, which the seller already knew.
//!
//! The template uses the engine's intrinsics; this crate uses `curve25519-dalek` and `sha2`. The
//! end-to-end tests feed the output of this crate to the template, so any drift between the two
//! implementations fails CI instead of failing a sale.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Size of every plaintext block, hence of every ciphertext. Fixed so a ciphertext says nothing about
/// how long the secret is, and so the template's decryption cost is bounded.
pub const PLAINTEXT_LEN: usize = 320;
/// Random salt at the head of the block. Without it a short secret (a PIN, a password) could be
/// brute-forced from the public commitment before anyone paid for it.
pub const SALT_LEN: usize = 32;
const LEN_PREFIX: usize = 2;
/// Longest secret a block can carry.
pub const MAX_SECRET_LEN: usize = PLAINTEXT_LEN - SALT_LEN - LEN_PREFIX;

// Domain separators. Each hash in the protocol has its own, so no output of one can be replayed as
// the input of another. All but DOMAIN_SALE_KEY must stay byte-for-byte identical to the template's.
pub const DOMAIN_COMMIT: &[u8] = b"tari.ootle.crypt.commitment.v1";
pub const DOMAIN_KEY: &[u8] = b"tari.ootle.crypt.key.v1";
pub const DOMAIN_STREAM: &[u8] = b"tari.ootle.crypt.stream.v1";
pub const DOMAIN_DLEQ: &[u8] = b"tari.ootle.crypt.dleq.v1";
pub const DOMAIN_AUTH: &[u8] = b"tari.ootle.crypt.auth.v1";
pub const DOMAIN_STATEMENT: &[u8] = b"tari.ootle.crypt.statement.v1";
/// Client-only: derivation of a buyer's sale key from their base secret.
pub const DOMAIN_SALE_KEY: &[u8] = b"tari.ootle.crypt.sale-key.v1";
/// Client-only: derivation of a seller's listing key from their base secret.
pub const DOMAIN_LISTING_KEY: &[u8] = b"tari.ootle.crypt.listing-key.v1";

// The keystream is whole SHA-512 blocks indexed by a single byte.
const _: () = assert!(PLAINTEXT_LEN.is_multiple_of(64) && PLAINTEXT_LEN / 64 <= 256);

/// Action messages. Each proof signs one of these, length-prefixed inside the challenge, so a proof
/// for one action never verifies as another.
pub const MSG_BUY: &[u8] = b"buy";
pub const MSG_CANCEL: &[u8] = b"cancel";
pub const MSG_PAY_SELLER: &[u8] = b"pay_seller";
pub const MSG_PAY_BUYER: &[u8] = b"pay_buyer";
/// Signed by the ephemeral key `R` itself: proves the seller knows `r`.
pub const MSG_EPHEMERAL: &[u8] = b"ephemeral";

/// Digest of a payout's stealth transfer: SHA-512 over the canonical CBOR encoding of the whole
/// `StealthTransferStatement`, exactly as the template re-encodes it.
#[must_use]
pub fn statement_digest(encoded_statement: &[u8]) -> [u8; 64] {
    sha512_parts(&[&len_prefix(DOMAIN_STATEMENT), DOMAIN_STATEMENT, encoded_statement])
}

/// A payout is signed over its action (`MSG_PAY_SELLER` / `MSG_PAY_BUYER`) and the statement digest.
#[must_use]
pub fn msg_pay(action: &[u8], digest: &[u8; 64]) -> Vec<u8> {
    [action, digest.as_slice()].concat()
}

/// `deliver` binds `R` and the ciphertext, so only the seller's key can put a delivery on the ledger.
#[must_use]
pub fn msg_deliver(ephemeral: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    [b"deliver".as_slice(), ephemeral, ciphertext].concat()
}

/// `accept` binds the delivery being accepted.
#[must_use]
pub fn msg_accept(ephemeral: &[u8; 32]) -> Vec<u8> {
    [b"accept".as_slice(), ephemeral].concat()
}

pub type Block = [u8; PLAINTEXT_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    SecretTooLong,
    /// Not the canonical encoding of a Ristretto point.
    InvalidPoint,
    /// The identity point: as a key it would make the shared secret public.
    IdentityPoint,
    /// Opened, but the length field or the padding is not what `encode_plaintext` produces.
    MalformedPlaintext,
    /// Opened, but it does not hash to the listed commitment: grounds for a dispute.
    CommitmentMismatch,
    /// The key used is not the buyer key registered on-chain for this sale. A dispute made with it
    /// would be refused and would still publish a shared point.
    WrongKey,
}

/// A two-scalar Schnorr-style proof `(c, z)`, in the compact form the template verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    pub c: [u8; 32],
    pub z: [u8; 32],
}

/// What the seller hands to `deliver`, minus the seller's own authorization proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub ephemeral: [u8; 32],
    /// Proof of knowledge of `r`, bound to the sale.
    pub ephemeral_proof: Proof,
    pub ciphertext: Block,
}

/// A secret key. The seller uses one directly; a buyer keeps a base key and uses
/// `for_sale` to get the key of each purchase.
pub struct Keypair {
    secret: Scalar,
    public: [u8; 32],
}

impl Keypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let secret = Scalar::random(rng);
            if secret != Scalar::ZERO {
                return Self::from_scalar(secret);
            }
        }
    }

    /// Restores a key from its 32 secret bytes. `None` unless the bytes are a canonical, non-zero scalar.
    #[must_use]
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let secret: Option<Scalar> = Scalar::from_canonical_bytes(*bytes).into();
        secret.filter(|s| *s != Scalar::ZERO).map(Self::from_scalar)
    }

    fn from_scalar(secret: Scalar) -> Self {
        let public = (secret * G).compress().to_bytes();
        Self { secret, public }
    }

    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The secret, wiped from memory when the returned value is dropped.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// The key this base key becomes in the sale identified by `context`: `b' = H(b, context)`.
    /// A hash, not an offset: sale keys of one base key have no algebraic relation an observer could
    /// use, and the base key itself never appears on-chain.
    #[must_use]
    pub fn for_sale(&self, context: &[u8]) -> Self {
        self.derive(DOMAIN_SALE_KEY, context)
    }

    /// The seller's key for the listing whose commitment is `commitment` (unique, as it is salted).
    /// One key per listing, so an observer cannot group a seller's listings by key.
    #[must_use]
    pub fn for_listing(&self, commitment: &[u8; 64]) -> Self {
        self.derive(DOMAIN_LISTING_KEY, commitment)
    }

    fn derive(&self, domain: &[u8], context: &[u8]) -> Self {
        let mut secret = self.secret.to_bytes();
        let wide = sha512_parts(&[&len_prefix(domain), domain, &secret, &len_prefix(context), context]);
        secret.zeroize();
        let derived = Scalar::from_bytes_mod_order_wide(&wide);
        // A zero scalar is a 2^-252 event; deriving again under a marker keeps the function total.
        if derived == Scalar::ZERO {
            return self.derive(domain, &[context, b" ".as_slice()].concat());
        }
        Self::from_scalar(derived)
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

fn len_prefix(data: &[u8]) -> [u8; 8] {
    (data.len() as u64).to_le_bytes()
}

fn sha512_parts(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Decodes an untrusted point: canonical encoding, and never the identity.
///
/// # Errors
/// `InvalidPoint` for a non-canonical encoding, `IdentityPoint` for the identity.
pub fn decode_point(bytes: &[u8; 32]) -> Result<RistrettoPoint, Error> {
    let point = CompressedRistretto(*bytes).decompress().ok_or(Error::InvalidPoint)?;
    if point == RistrettoPoint::identity() {
        return Err(Error::IdentityPoint);
    }
    Ok(point)
}

/// Fiat-Shamir challenge. Binds the domain, the sale's context (its component address), the action
/// message and every point of the statement and of the commitment, so a proof cannot be moved to
/// another sale, another deployment, another action, or another statement.
fn challenge(domain: &[u8], context: &[u8], message: &[u8], points: &[&[u8; 32]]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(len_prefix(domain));
    hasher.update(domain);
    hasher.update(len_prefix(context));
    hasher.update(context);
    hasher.update(len_prefix(message));
    hasher.update(message);
    for point in points {
        hasher.update(point);
    }
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

/// Lays out a plaintext block: `salt || len (u16 LE) || secret || zero padding`.
///
/// # Errors
/// `SecretTooLong` past `MAX_SECRET_LEN` bytes.
pub fn encode_plaintext<R: RngCore + CryptoRng>(secret: &[u8], rng: &mut R) -> Result<Block, Error> {
    if secret.len() > MAX_SECRET_LEN {
        return Err(Error::SecretTooLong);
    }
    let mut block = [0u8; PLAINTEXT_LEN];
    rng.fill_bytes(&mut block[..SALT_LEN]);
    let len = u16::try_from(secret.len()).expect("bounded by MAX_SECRET_LEN");
    block[SALT_LEN..SALT_LEN + LEN_PREFIX].copy_from_slice(&len.to_le_bytes());
    block[SALT_LEN + LEN_PREFIX..SALT_LEN + LEN_PREFIX + secret.len()].copy_from_slice(secret);
    Ok(block)
}

/// Extracts the secret from an opened block, refusing any block `encode_plaintext` could not have made.
///
/// # Errors
/// `MalformedPlaintext` if the length field or the padding is off.
pub fn decode_plaintext(block: &Block) -> Result<Vec<u8>, Error> {
    let len = u16::from_le_bytes([block[SALT_LEN], block[SALT_LEN + 1]]) as usize;
    if len > MAX_SECRET_LEN {
        return Err(Error::MalformedPlaintext);
    }
    let start = SALT_LEN + LEN_PREFIX;
    if block[start + len..].iter().any(|&b| b != 0) {
        return Err(Error::MalformedPlaintext);
    }
    Ok(block[start..start + len].to_vec())
}

/// The commitment published at listing time. Covers the whole block, salt and padding included.
#[must_use]
pub fn commitment_of(block: &Block) -> [u8; 64] {
    sha512_parts(&[&len_prefix(DOMAIN_COMMIT), DOMAIN_COMMIT, block])
}

/// `PLAINTEXT_LEN` bytes of keystream for one sale. The key binds the context and both public keys as
/// well as the shared point, so the same `S` never yields the same keystream in two sales.
#[must_use]
pub fn keystream(context: &[u8], buyer_key: &[u8; 32], ephemeral: &[u8; 32], shared: &[u8; 32]) -> Block {
    let key = sha512_parts(&[
        &len_prefix(DOMAIN_KEY),
        DOMAIN_KEY,
        &len_prefix(context),
        context,
        buyer_key,
        ephemeral,
        shared,
    ]);
    let mut stream = [0u8; PLAINTEXT_LEN];
    for (i, chunk) in (0u8..).zip(stream.chunks_mut(64)) {
        let block = sha512_parts(&[&len_prefix(DOMAIN_STREAM), DOMAIN_STREAM, &key, &[i]]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    stream
}

fn xor(a: &Block, b: &Block) -> Block {
    let mut out = [0u8; PLAINTEXT_LEN];
    for ((o, x), y) in out.iter_mut().zip(a).zip(b) {
        *o = x ^ y;
    }
    out
}

fn schnorr<R: RngCore + CryptoRng>(
    secret: &Scalar,
    public: &[u8; 32],
    context: &[u8],
    message: &[u8],
    rng: &mut R,
) -> Proof {
    let mut w = Scalar::random(rng);
    let a = (w * G).compress().to_bytes();
    let c = challenge(DOMAIN_AUTH, context, message, &[public, &a]);
    let z = w + c * secret;
    w.zeroize();
    Proof {
        c: c.to_bytes(),
        z: z.to_bytes(),
    }
}

/// Seller side: encrypts `block` to the buyer's sale key for the sale identified by `context`, and
/// proves knowledge of the ephemeral secret.
///
/// # Errors
/// `InvalidPoint` / `IdentityPoint` if `buyer_key` is not a usable key.
pub fn seal<R: RngCore + CryptoRng>(
    block: &Block,
    buyer_key: &[u8; 32],
    context: &[u8],
    rng: &mut R,
) -> Result<Sealed, Error> {
    let buyer_point = decode_point(buyer_key)?;
    let mut r = Scalar::random(rng);
    let ephemeral = (r * G).compress().to_bytes();
    let shared = (r * buyer_point).compress().to_bytes();
    let ephemeral_proof = schnorr(&r, &ephemeral, context, MSG_EPHEMERAL, rng);
    r.zeroize();
    let ciphertext = xor(block, &keystream(context, buyer_key, &ephemeral, &shared));
    Ok(Sealed {
        ephemeral,
        ephemeral_proof,
        ciphertext,
    })
}

/// Buyer side: `S = b'·R`.
///
/// # Errors
/// `InvalidPoint` / `IdentityPoint` if `ephemeral` is not a usable point.
pub fn shared_point(sale_key: &Keypair, ephemeral: &[u8; 32]) -> Result<[u8; 32], Error> {
    Ok((sale_key.secret * decode_point(ephemeral)?).compress().to_bytes())
}

/// Buyer side: decrypts a delivery and returns the secret only if it is exactly what was listed.
/// `CommitmentMismatch` or `MalformedPlaintext` means: dispute, do not accept. Dispute well before the
/// deadline: the dispute transaction publishes `S`, and if it lands after the deadline the secret is
/// public without a verdict.
///
/// # Errors
/// As `open`, plus `CommitmentMismatch` and `MalformedPlaintext`.
pub fn open_verified(
    sale_key: &Keypair,
    context: &[u8],
    ephemeral: &[u8; 32],
    ciphertext: &Block,
    commitment: &[u8; 64],
) -> Result<Vec<u8>, Error> {
    let block = open(sale_key, context, ephemeral, ciphertext)?;
    if commitment_of(&block) != *commitment {
        return Err(Error::CommitmentMismatch);
    }
    decode_plaintext(&block)
}

/// Buyer side: decrypts a delivery without checking it. Prefer `open_verified`.
///
/// # Errors
/// `InvalidPoint` / `IdentityPoint` if `ephemeral` is not a usable point.
pub fn open(sale_key: &Keypair, context: &[u8], ephemeral: &[u8; 32], ciphertext: &Block) -> Result<Block, Error> {
    let shared = shared_point(sale_key, ephemeral)?;
    Ok(xor(
        ciphertext,
        &keystream(context, &sale_key.public, ephemeral, &shared),
    ))
}

/// Schnorr proof by `keypair` over `message`, bound to the sale. Authorizes buy (by the buyer's sale
/// key, which doubles as proof the buyer holds it), deliver and cancel (seller key), accept (sale key).
#[must_use]
pub fn prove_action<R: RngCore + CryptoRng>(keypair: &Keypair, context: &[u8], message: &[u8], rng: &mut R) -> Proof {
    schnorr(&keypair.secret, &keypair.public, context, message, rng)
}

/// Mirror of the template's check, for tests and for clients that want to pre-flight a transaction.
#[must_use]
pub fn verify_action(public: &[u8; 32], context: &[u8], message: &[u8], proof: &Proof) -> bool {
    let Ok(b) = decode_point(public) else { return false };
    let (Some(c), Some(z)) = (canonical(&proof.c), canonical(&proof.z)) else {
        return false;
    };
    let a = (z * G - c * b).compress().to_bytes();
    challenge(DOMAIN_AUTH, context, message, &[public, &a]) == c
}

/// Dispute side: reveals `S` with a Chaum-Pedersen proof that `log_G(B') = log_R(S)`.
///
/// `registered_key` is the buyer key read from the ledger. The proof is only produced if `sale_key`
/// is that key and the result verifies locally: a dispute with the wrong key would be refused on-chain
/// but would still have published a shared point.
///
/// # Errors
/// `WrongKey` if `sale_key` is not the registered key; point errors as `shared_point`.
pub fn prove_shared<R: RngCore + CryptoRng>(
    sale_key: &Keypair,
    registered_key: &[u8; 32],
    context: &[u8],
    ephemeral: &[u8; 32],
    rng: &mut R,
) -> Result<([u8; 32], Proof), Error> {
    if sale_key.public != *registered_key {
        return Err(Error::WrongKey);
    }
    let r_point = decode_point(ephemeral)?;
    let shared = (sale_key.secret * r_point).compress().to_bytes();
    let mut w = Scalar::random(rng);
    let a1 = (w * G).compress().to_bytes();
    let a2 = (w * r_point).compress().to_bytes();
    let c = challenge(
        DOMAIN_DLEQ,
        context,
        &[],
        &[&sale_key.public, ephemeral, &shared, &a1, &a2],
    );
    let z = w + c * sale_key.secret;
    w.zeroize();
    let proof = Proof {
        c: c.to_bytes(),
        z: z.to_bytes(),
    };
    if !verify_shared(registered_key, ephemeral, &shared, context, &proof) {
        return Err(Error::WrongKey);
    }
    Ok((shared, proof))
}

/// Mirror of the template's DLEQ check.
#[must_use]
pub fn verify_shared(
    buyer_key: &[u8; 32],
    ephemeral: &[u8; 32],
    shared: &[u8; 32],
    context: &[u8],
    proof: &Proof,
) -> bool {
    let (Ok(b), Ok(r), Ok(s)) = (decode_point(buyer_key), decode_point(ephemeral), decode_point(shared)) else {
        return false;
    };
    let (Some(c), Some(z)) = (canonical(&proof.c), canonical(&proof.z)) else {
        return false;
    };
    let a1 = (z * G - c * b).compress().to_bytes();
    let a2 = (z * r - c * s).compress().to_bytes();
    challenge(DOMAIN_DLEQ, context, &[], &[buyer_key, ephemeral, shared, &a1, &a2]) == c
}

fn canonical(bytes: &[u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(*bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_core::OsRng;

    const CTX: &[u8] = b"component_0123456789abcdef";
    const OTHER_CTX: &[u8] = b"component_fedcba9876543210";

    fn sale(secret: &[u8]) -> (Keypair, Block, Sealed) {
        let buyer = Keypair::generate(&mut OsRng).for_sale(CTX);
        let block = encode_plaintext(secret, &mut OsRng).unwrap();
        let sealed = seal(&block, &buyer.public(), CTX, &mut OsRng).unwrap();
        (buyer, block, sealed)
    }

    #[test]
    fn the_buyer_opens_exactly_what_was_committed() {
        let (buyer, block, sealed) = sale(b"correct horse battery staple");
        let opened = open(&buyer, CTX, &sealed.ephemeral, &sealed.ciphertext).unwrap();
        assert_eq!(commitment_of(&opened), commitment_of(&block));
        assert_eq!(decode_plaintext(&opened).unwrap(), b"correct horse battery staple");
    }

    #[test]
    fn another_key_opens_garbage() {
        let (_, block, sealed) = sale(b"secret");
        let intruder = Keypair::generate(&mut OsRng);
        let opened = open(&intruder, CTX, &sealed.ephemeral, &sealed.ciphertext).unwrap();
        assert_ne!(commitment_of(&opened), commitment_of(&block));
    }

    #[test]
    fn the_same_block_opened_under_another_sale_is_garbage() {
        let (buyer, block, sealed) = sale(b"secret");
        let opened = open(&buyer, OTHER_CTX, &sealed.ephemeral, &sealed.ciphertext).unwrap();
        assert_ne!(commitment_of(&opened), commitment_of(&block));
    }

    #[test]
    fn the_salt_hides_short_secrets() {
        let a = encode_plaintext(b"1234", &mut OsRng).unwrap();
        let b = encode_plaintext(b"1234", &mut OsRng).unwrap();
        assert_ne!(commitment_of(&a), commitment_of(&b), "same PIN, different commitments");
    }

    #[test]
    fn oversized_secrets_are_refused() {
        assert_eq!(
            encode_plaintext(&[1u8; MAX_SECRET_LEN + 1], &mut OsRng),
            Err(Error::SecretTooLong)
        );
        assert!(encode_plaintext(&[1u8; MAX_SECRET_LEN], &mut OsRng).is_ok());
    }

    #[test]
    fn tampered_padding_or_length_is_malformed() {
        let mut block = encode_plaintext(b"abc", &mut OsRng).unwrap();
        block[PLAINTEXT_LEN - 1] = 1;
        assert_eq!(decode_plaintext(&block), Err(Error::MalformedPlaintext));

        let mut block = encode_plaintext(b"abc", &mut OsRng).unwrap();
        let too_long = u16::try_from(MAX_SECRET_LEN + 1).unwrap();
        block[SALT_LEN..SALT_LEN + 2].copy_from_slice(&too_long.to_le_bytes());
        assert_eq!(decode_plaintext(&block), Err(Error::MalformedPlaintext));
    }

    #[test]
    fn action_proofs_verify_only_for_their_key_sale_and_action() {
        let kp = Keypair::generate(&mut OsRng);
        let r = [7u8; 32];
        let proof = prove_action(&kp, CTX, &msg_accept(&r), &mut OsRng);
        assert!(verify_action(&kp.public(), CTX, &msg_accept(&r), &proof));
        assert!(
            !verify_action(&kp.public(), OTHER_CTX, &msg_accept(&r), &proof),
            "replayed into another sale"
        );
        assert!(
            !verify_action(&kp.public(), CTX, MSG_CANCEL, &proof),
            "replayed as another action"
        );
        assert!(
            !verify_action(&kp.public(), CTX, &msg_accept(&[8u8; 32]), &proof),
            "for another delivery"
        );
        let other = Keypair::generate(&mut OsRng);
        assert!(
            !verify_action(&other.public(), CTX, &msg_accept(&r), &proof),
            "claimed for another key"
        );
        let pay = prove_action(
            &kp,
            CTX,
            &msg_pay(MSG_PAY_SELLER, &statement_digest(b"one")),
            &mut OsRng,
        );
        assert!(
            !verify_action(
                &kp.public(),
                CTX,
                &msg_pay(MSG_PAY_SELLER, &statement_digest(b"two")),
                &pay
            ),
            "a payout signature covers one statement only"
        );
        assert!(
            !verify_action(
                &kp.public(),
                CTX,
                &msg_pay(MSG_PAY_BUYER, &statement_digest(b"one")),
                &pay
            ),
            "a seller payout signature is not a buyer payout signature"
        );
    }

    #[test]
    fn a_sealed_delivery_proves_knowledge_of_r_for_its_sale_only() {
        let (_, _, sealed) = sale(b"secret");
        assert!(verify_action(
            &sealed.ephemeral,
            CTX,
            MSG_EPHEMERAL,
            &sealed.ephemeral_proof
        ));
        assert!(!verify_action(
            &sealed.ephemeral,
            OTHER_CTX,
            MSG_EPHEMERAL,
            &sealed.ephemeral_proof
        ));
    }

    #[test]
    fn sale_keys_are_unrelated_hashes_of_the_base_key() {
        let base = Keypair::generate(&mut OsRng);
        let a = base.for_sale(CTX);
        let b = base.for_sale(OTHER_CTX);
        assert_ne!(a.public(), b.public());
        assert_ne!(a.public(), base.public());
        assert_eq!(
            base.for_sale(CTX).public(),
            a.public(),
            "deterministic, so the buyer can recover it"
        );
        assert_ne!(a.secret_bytes(), base.secret_bytes());
        let listing = base.for_listing(&[1u8; 64]);
        assert_ne!(
            listing.public(),
            base.for_listing(&[2u8; 64]).public(),
            "one key per listing"
        );
        assert_ne!(
            listing.public(),
            base.for_sale(&[1u8; 64]).public(),
            "listing and sale keys never coincide"
        );
    }

    #[test]
    fn open_verified_flags_what_to_dispute() {
        let (buyer, block, sealed) = sale(b"secret");
        let commitment = commitment_of(&block);
        assert_eq!(
            open_verified(&buyer, CTX, &sealed.ephemeral, &sealed.ciphertext, &commitment).unwrap(),
            b"secret"
        );
        let other = commitment_of(&encode_plaintext(b"secret", &mut OsRng).unwrap());
        assert_eq!(
            open_verified(&buyer, CTX, &sealed.ephemeral, &sealed.ciphertext, &other),
            Err(Error::CommitmentMismatch)
        );
    }

    #[test]
    fn dleq_proof_verifies_only_for_the_true_shared_point() {
        let (buyer, _, sealed) = sale(b"secret");
        let (shared, proof) = prove_shared(&buyer, &buyer.public(), CTX, &sealed.ephemeral, &mut OsRng).unwrap();
        assert!(verify_shared(&buyer.public(), &sealed.ephemeral, &shared, CTX, &proof));
        assert!(!verify_shared(
            &buyer.public(),
            &sealed.ephemeral,
            &shared,
            OTHER_CTX,
            &proof
        ));

        let liar = (Scalar::from(7u64) * G).compress().to_bytes();
        assert!(!verify_shared(&buyer.public(), &sealed.ephemeral, &liar, CTX, &proof));

        let mut bent = proof;
        bent.z[0] ^= 1;
        assert!(!verify_shared(&buyer.public(), &sealed.ephemeral, &shared, CTX, &bent));
    }

    #[test]
    fn a_dispute_is_never_produced_with_the_wrong_key() {
        let (buyer, _, sealed) = sale(b"secret");
        let base = Keypair::generate(&mut OsRng);
        assert_eq!(
            prove_shared(&base, &buyer.public(), CTX, &sealed.ephemeral, &mut OsRng).unwrap_err(),
            Error::WrongKey
        );
    }

    #[test]
    fn non_canonical_scalars_are_rejected() {
        let kp = Keypair::generate(&mut OsRng);
        let mut proof = prove_action(&kp, CTX, MSG_CANCEL, &mut OsRng);
        proof.z = [0xff; 32];
        assert!(!verify_action(&kp.public(), CTX, MSG_CANCEL, &proof));
    }

    #[test]
    fn identity_and_garbage_points_are_rejected() {
        let identity = RistrettoPoint::identity().compress().to_bytes();
        assert_eq!(decode_point(&identity).unwrap_err(), Error::IdentityPoint);
        assert_eq!(decode_point(&[0xff; 32]).unwrap_err(), Error::InvalidPoint);
        let block = encode_plaintext(b"x", &mut OsRng).unwrap();
        assert!(seal(&block, &identity, CTX, &mut OsRng).is_err());
    }

    #[test]
    fn keys_round_trip_through_their_secret_bytes() {
        let kp = Keypair::generate(&mut OsRng);
        let restored = Keypair::from_secret_bytes(&kp.secret_bytes()).unwrap();
        assert_eq!(restored.public(), kp.public());
        assert!(Keypair::from_secret_bytes(&[0u8; 32]).is_none());
        assert!(Keypair::from_secret_bytes(&[0xff; 32]).is_none());
    }

    proptest! {
        #[test]
        fn any_secret_round_trips(secret in proptest::collection::vec(any::<u8>(), 0..=MAX_SECRET_LEN)) {
            let (buyer, block, sealed) = sale(&secret);
            let opened = open(&buyer, CTX, &sealed.ephemeral, &sealed.ciphertext).unwrap();
            prop_assert_eq!(opened, block);
            prop_assert_eq!(decode_plaintext(&opened).unwrap(), secret);
        }

        #[test]
        fn any_single_bit_flip_in_the_ciphertext_breaks_the_commitment(byte in 0..PLAINTEXT_LEN, bit in 0u8..8) {
            let (buyer, block, mut sealed) = sale(b"secret");
            sealed.ciphertext[byte] ^= 1 << bit;
            let opened = open(&buyer, CTX, &sealed.ephemeral, &sealed.ciphertext).unwrap();
            prop_assert_ne!(commitment_of(&opened), commitment_of(&block));
        }
    }
}
