//! `crypt_onchain address`: prints the esmeralda address of the demo wallet, creating its key on first use.
//! The key lives in the file named by `CRYPT_DEMO_KEY` (never in this repository): testnet funds only.

mod l1proof;
mod sale;

use std::{env, fs, path::PathBuf};

use ootle_rs::{
    Network, TransactionRequest, claim_burn::ClaimBurn, default_indexer_url, key_provider::PrivateKeyProvider,
    keys::OotleSecretKey, provider::ProviderBuilder, template_types::EncryptedData, transaction::TransactionSigner,
    wallet::OotleWallet,
};
use rand_core::{OsRng, RngCore};
use tari_crypto::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    tari_utilities::hex::Hex,
};
use tari_ootle_transaction::Epoch;

fn key_path() -> PathBuf {
    PathBuf::from(env::var("CRYPT_DEMO_KEY").expect("set CRYPT_DEMO_KEY to the demo wallet key file"))
}

fn secret(bytes: &[u8]) -> RistrettoSecretKey {
    RistrettoSecretKey::from_uniform_bytes(bytes).expect("64 uniform bytes")
}

fn read_seed() -> Vec<u8> {
    let seed = hex::decode(fs::read_to_string(key_path()).expect("read key file").trim()).expect("hex key file");
    assert_eq!(seed.len(), 128, "key file must hold 128 bytes");
    seed
}

/// The account public key an L1 burn must be addressed to, checked against the one inside the
/// account's own address before it is printed: a wrong claim key burns the funds for good.
fn claim_key() -> String {
    let provider = load_or_create();
    let from_secret = RistrettoPublicKey::from_secret_key(&secret(&read_seed()[..64])).to_hex();
    let from_address = hex::encode(provider.address().account_public_key().as_bytes());
    assert_eq!(from_secret, from_address, "claim key and address disagree");
    from_secret
}

fn load_or_create() -> PrivateKeyProvider {
    let path = key_path();
    if !path.exists() {
        let mut seed = [0u8; 128];
        OsRng.fill_bytes(&mut seed);
        // Never overwrites, never follows a planted link, owner-only on Unix.
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).expect("create key file");
        std::io::Write::write_all(&mut file, hex::encode(seed).as_bytes()).expect("write key file");
        file.sync_all().expect("sync key file");
    }
    let seed = hex::decode(fs::read_to_string(&path).expect("read key file").trim()).expect("hex key file");
    assert_eq!(seed.len(), 128, "key file must hold 128 bytes");
    PrivateKeyProvider::new(OotleSecretKey::new(
        Network::Esmeralda,
        secret(&seed[..64]),
        secret(&seed[64..]),
    ))
}

/// Claims an L1 burn into the demo account: dry run first, then the real transaction.
async fn claim(proof_path: &str) {
    let l1: tari_sidechain::CompleteClaimBurnProof =
        serde_json::from_str(&fs::read_to_string(proof_path).expect("read burn proof"))
            .expect("parse the L1 burn proof");
    let claim_proof = l1proof::claim_proof_from_l1(&l1.claim_proof).expect("convert the burn proof");
    let encrypted_data = EncryptedData::try_from(l1.encrypted_data).expect("encrypted data length");
    // The output carries a one-time key derived from the claim key; the proof names the claim key
    // itself, which is how the wallet daemon finds the account a burn belongs to.
    assert_eq!(
        l1.claim_proof.burn_public_key.to_string(),
        claim_key(),
        "this burn was not made to the demo account"
    );
    println!("burn_value={}", claim_proof.value);
    let wallet = OotleWallet::from(load_or_create());
    let mut provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(default_indexer_url(Network::Esmeralda))
        .await
        .expect("connect to the esmeralda indexer");
    let max_epoch = Epoch(provider.get_epoch().await.expect("epoch").as_u64() + 10);
    let (unsigned_tx, sealer) = ClaimBurn::new(&provider, claim_proof, encrypted_data, max_epoch)
        .with_max_fee(20_000u64)
        .prepare()
        .await
        .expect("prepare the claim");
    let dry_run = provider
        .sign_and_send_dry_run_with(&sealer, unsigned_tx.clone())
        .await
        .expect("dry run");
    dry_run.expect_success();
    let tx = TransactionRequest::default()
        .with_transaction(unsigned_tx)
        .build(&sealer)
        .await
        .expect("seal the claim");
    let pending = provider.send_transaction(tx).await.expect("submit the claim");
    println!("claim_tx={}", pending.tx_id());
    println!("outcome={:?}", pending.watch().await.expect("claim outcome"));
}

#[tokio::main]
async fn main() {
    match env::args().nth(1).as_deref() {
        Some("address") => println!("{}", load_or_create().address()),
        Some("claim-key") => println!("{}", claim_key()),
        Some("claim") => claim(&env::args().nth(2).expect("burn proof file")).await,
        Some(cmd @ ("utxo-from-claim" | "split" | "publish" | "play")) => {
            let mut provider = ProviderBuilder::new()
                .wallet(OotleWallet::from(load_or_create()))
                .connect(default_indexer_url(Network::Esmeralda))
                .await
                .expect("connect to the esmeralda indexer");
            let arg = |i: usize| {
                env::args()
                    .nth(i)
                    .unwrap_or_else(|| panic!("{cmd}: missing argument {i}"))
            };
            match cmd {
                "utxo-from-claim" => {
                    sale::utxo_from_claim(&mut provider, &arg(2), arg(3).parse().expect("value in µT")).await
                }
                "split" => sale::split(&mut provider).await,
                "publish" => sale::publish(&mut provider, &arg(2), arg(3).parse().expect("fee budget in µT")).await,
                _ => sale::play(&mut provider, &arg(2), arg(3) == "honest").await,
            }
        }
        _ => eprintln!(
            "usage: crypt_onchain address | claim-key | claim <burn_proof.json> | utxo-from-claim <tx> <value> | split | publish <crypt.wasm> <fee budget> | play <name> honest|fraud"
        ),
    }
}
