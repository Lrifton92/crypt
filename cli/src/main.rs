// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! `crypt`: the offline side of a Crypt sale.
//!
//! Every value a transaction needs (keys, commitment, sealed delivery, proofs) is computed here,
//! printed as `name=hex` lines, and passed to the template through the wallet. Nothing here talks to
//! the network, and no secret is ever taken from the command line: secrets and keys live in files,
//! so they stay out of shell history and process listings.
//!
//! Seller: `keygen` (a base key) → `commit` → list → `seal` → deliver → `payout`. Buyer: `keygen` (a base key) →
//! `buy` → `open` → `accept`, or `dispute` if `open` says so → `payout` if owed anything.
//!
//! Funds come from and go back to stealth outputs: the wallet builds the stealth transfers, this tool
//! signs the payout transfer's digest with the payee's Crypt key.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use clap::{Parser, Subcommand};
use crypt_core::{self as core, Keypair, Proof};
use rand_core::OsRng;
use tari_template_lib_types::{
    stealth::{SpendAuthorization, StealthTransferStatement},
    Amount, ComponentAddress,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "crypt", version, about = "Offline client for Crypt sales on the Tari Ootle")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a base key file, for a seller or a buyer. Every listing and every purchase derives its
    /// own key from it. Never overwrites a file. Back it up: it is the only way to collect what a
    /// sale owes you.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Prints the public key of a key file.
    Public {
        #[arg(long)]
        key: PathBuf,
    },
    /// Seller: lays the secret out in a salted block, writes the block to `--out` (keep it private
    /// until delivery), and prints the commitment and this listing's seller key for `list`.
    Commit {
        #[arg(long)]
        seller_key: PathBuf,
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Buyer: derives this sale's key from the base key and proves it for `buy`.
    Buy {
        #[arg(long)]
        base_key: PathBuf,
        #[arg(long)]
        component: String,
    },
    /// Seller: seals the block to the buyer's sale key and signs the delivery.
    Seal {
        #[arg(long)]
        seller_key: PathBuf,
        /// The listing's commitment, which selects the listing key.
        #[arg(long)]
        commitment: String,
        #[arg(long)]
        block: PathBuf,
        #[arg(long)]
        component: String,
        /// The `buyer_key` the template shows for this sale.
        #[arg(long)]
        buyer_key: String,
    },
    /// Buyer: opens the delivery. Writes the secret to stdout if it is exactly what was listed;
    /// otherwise exits with status 2 and says why: dispute, do not accept.
    Open {
        #[arg(long)]
        base_key: PathBuf,
        #[arg(long)]
        component: String,
        #[arg(long)]
        ephemeral: String,
        #[arg(long)]
        ciphertext: String,
        #[arg(long)]
        commitment: String,
    },
    /// Buyer: proof for `accept`, bound to this delivery.
    Accept {
        #[arg(long)]
        base_key: PathBuf,
        #[arg(long)]
        component: String,
        #[arg(long)]
        ephemeral: String,
    },
    /// Buyer: shared point and DLEQ proof for `dispute`. Refuses unless the derived sale key is the
    /// one registered on-chain: a wrong-key dispute would be refused and still publish a point.
    /// Send it well before the deadline.
    Dispute {
        #[arg(long)]
        base_key: PathBuf,
        #[arg(long)]
        component: String,
        #[arg(long)]
        ephemeral: String,
        /// The `buyer_key` the template shows for this sale.
        #[arg(long)]
        registered: String,
    },
    /// Seller: proof for `cancel`.
    Cancel {
        #[arg(long)]
        seller_key: PathBuf,
        #[arg(long)]
        commitment: String,
        #[arg(long)]
        component: String,
    },
    /// Either side, once settled: checks and signs the stealth transfer that pays you, as built by
    /// your wallet (hex-encoded CBOR `StealthTransferStatement` in `--statement`). Refuses anything the
    /// template would refuse or that does not pay exactly `--owed` into stealth outputs, and prints
    /// what it signs. Check those outputs are yours: a signature sends the funds where they say.
    Payout {
        #[arg(
            long,
            conflicts_with = "base_key",
            required_unless_present = "base_key",
            requires = "commitment"
        )]
        seller_key: Option<PathBuf>,
        /// Seller only: the listing's commitment, which selects the listing key.
        #[arg(long)]
        commitment: Option<String>,
        #[arg(long)]
        base_key: Option<PathBuf>,
        #[arg(long)]
        component: String,
        #[arg(long)]
        statement: PathBuf,
        /// What the template's `owed()` shows for your side.
        #[arg(long)]
        owed: u64,
    },
}

/// Exit status of `open` when the delivery must be disputed.
const DISPUTE: u8 = 2;

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<ExitCode, String> {
    match command {
        Command::Keygen { out } => {
            let key = Keypair::generate(&mut OsRng);
            write_private(&out, &Zeroizing::new(hex::encode(*key.secret_bytes())))?;
            eprintln!(
                "back up {}: it is the only way to collect what a sale owes you",
                out.display()
            );
            print_hex("public_key", &key.public());
        }
        Command::Public { key } => print_hex("public_key", &read_key(&key)?.public()),
        Command::Commit {
            seller_key,
            secret_file,
            out,
        } => {
            let base = read_key(&seller_key)?;
            let secret = Zeroizing::new(fs::read(&secret_file).map_err(|e| io_error(&secret_file, &e))?);
            let block = Zeroizing::new(core::encode_plaintext(&secret, &mut OsRng).map_err(describe)?);
            write_private(&out, &Zeroizing::new(hex::encode(*block)))?;
            let commitment = core::commitment_of(&block);
            print_hex("commitment", &commitment);
            print_hex("seller_key", &base.for_listing(&commitment).public());
        }
        Command::Buy { base_key, component } => {
            let ctx = context(&component)?;
            let key = read_key(&base_key)?.for_sale(&ctx);
            print_hex("buyer_key", &key.public());
            print_proof("", &core::prove_action(&key, &ctx, core::MSG_BUY, &mut OsRng));
        }
        Command::Seal {
            seller_key,
            commitment,
            block,
            component,
            buyer_key,
        } => {
            let ctx = context(&component)?;
            let seller = read_key(&seller_key)?.for_listing(&hex_array(&commitment, "commitment")?);
            let block = read_block(&block)?;
            let sealed = core::seal(&block, &hex32(&buyer_key, "buyer key")?, &ctx, &mut OsRng).map_err(describe)?;
            let signature = core::prove_action(
                &seller,
                &ctx,
                &core::msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
                &mut OsRng,
            );
            print_hex("ephemeral", &sealed.ephemeral);
            print_proof("ephemeral_", &sealed.ephemeral_proof);
            print_hex("ciphertext", &sealed.ciphertext);
            print_proof("", &signature);
        }
        Command::Open {
            base_key,
            component,
            ephemeral,
            ciphertext,
            commitment,
        } => {
            let ctx = context(&component)?;
            let key = read_key(&base_key)?.for_sale(&ctx);
            let ciphertext: core::Block = hex_array(&ciphertext, "ciphertext")?;
            let commitment: [u8; 64] = hex_array(&commitment, "commitment")?;
            let ephemeral = hex32(&ephemeral, "ephemeral key")?;
            match core::open_verified(&key, &ctx, &ephemeral, &ciphertext, &commitment) {
                Ok(secret) => {
                    let secret = Zeroizing::new(secret);
                    std::io::stdout().write_all(&secret).map_err(|e| e.to_string())?;
                }
                Err(e @ (core::Error::CommitmentMismatch | core::Error::MalformedPlaintext)) => {
                    eprintln!("dispute: {}", describe(e));
                    return Ok(ExitCode::from(DISPUTE));
                }
                Err(e) => return Err(describe(e)),
            }
        }
        Command::Accept {
            base_key,
            component,
            ephemeral,
        } => {
            let ctx = context(&component)?;
            let key = read_key(&base_key)?.for_sale(&ctx);
            let ephemeral = hex32(&ephemeral, "ephemeral key")?;
            print_proof(
                "",
                &core::prove_action(&key, &ctx, &core::msg_accept(&ephemeral), &mut OsRng),
            );
        }
        Command::Dispute {
            base_key,
            component,
            ephemeral,
            registered,
        } => {
            let ctx = context(&component)?;
            let key = read_key(&base_key)?.for_sale(&ctx);
            let registered = hex32(&registered, "registered key")?;
            let ephemeral = hex32(&ephemeral, "ephemeral key")?;
            let (shared, proof) =
                core::prove_shared(&key, &registered, &ctx, &ephemeral, &mut OsRng).map_err(describe)?;
            print_hex("shared", &shared);
            print_proof("", &proof);
        }
        Command::Payout {
            seller_key,
            commitment,
            base_key,
            component,
            statement,
            owed,
        } => payout(seller_key, commitment, base_key, &component, &statement, owed)?,
        Command::Cancel {
            seller_key,
            commitment,
            component,
        } => {
            let ctx = context(&component)?;
            let seller = read_key(&seller_key)?.for_listing(&hex_array(&commitment, "commitment")?);
            print_proof("", &core::prove_action(&seller, &ctx, core::MSG_CANCEL, &mut OsRng));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn payout(
    seller_key: Option<PathBuf>,
    commitment: Option<String>,
    base_key: Option<PathBuf>,
    component: &str,
    statement: &Path,
    owed: u64,
) -> Result<(), String> {
    let ctx = context(component)?;
    let (key, action) = match (seller_key, commitment, base_key) {
        (Some(path), Some(commitment), None) => (
            read_key(&path)?.for_listing(&hex_array(&commitment, "commitment")?),
            core::MSG_PAY_SELLER,
        ),
        (None, _, Some(path)) => (read_key(&path)?.for_sale(&ctx), core::MSG_PAY_BUYER),
        _ => return Err("give --seller-key with --commitment, or --base-key".into()),
    };
    let text = fs::read_to_string(statement).map_err(|e| io_error(statement, &e))?;
    let bytes = hex::decode(text.trim()).map_err(|e| format!("{}: not hex ({e})", statement.display()))?;
    // Decoded and re-encoded, so the digest is over the canonical encoding the template computes.
    let decoded: StealthTransferStatement =
        tari_bor::decode(&bytes).map_err(|e| format!("{}: not a stealth transfer ({e})", statement.display()))?;
    check_payout(&decoded, owed)?;
    for (i, output) in decoded.outputs_statement.outputs.iter().enumerate() {
        let auth = match &output.auth {
            SpendAuthorization::Key(k) => format!("key {}", hex::encode(k.as_bytes())),
            SpendAuthorization::Script(root) => format!("script {}", hex::encode(root)),
            other => format!("{other:?}"),
        };
        eprintln!(
            "output {i}: commitment {} spendable by {auth}",
            hex::encode(output.commitment().as_bytes())
        );
    }
    let digest = core::statement_digest(&tari_bor::encode(&decoded).map_err(|e| e.to_string())?);
    print_hex("digest", &digest);
    print_proof(
        "",
        &core::prove_action(&key, &ctx, &core::msg_pay(action, &digest), &mut OsRng),
    );
    Ok(())
}

/// The template's own payout rules, checked before signing: a signature is only ever produced for a
/// transfer the template would accept, that pays exactly what is owed, into stealth outputs only.
fn check_payout(statement: &StealthTransferStatement, owed: u64) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("refusing to sign: {why}"));
    if !statement.inputs_statement.inputs.is_empty() {
        return refuse("the transfer spends stealth inputs; a payout spends the escrow only");
    }
    if statement.inputs_statement.revealed_amount != Amount::from_u64(owed) {
        return refuse(&format!(
            "the transfer takes {} from the escrow, not the {owed} owed",
            statement.inputs_statement.revealed_amount
        ));
    }
    if statement.outputs_statement.revealed_output.is_some() {
        return refuse("the transfer reveals funds to someone; a payout goes to stealth outputs only");
    }
    if statement.outputs_statement.outputs.is_empty() {
        return refuse("the transfer has no stealth outputs");
    }
    if !statement.covenant_claims.is_empty() {
        return refuse("the transfer carries covenant claims");
    }
    Ok(())
}

fn describe(e: core::Error) -> String {
    match e {
        core::Error::SecretTooLong => format!("the secret is longer than {} bytes", core::MAX_SECRET_LEN),
        core::Error::InvalidPoint => "not a valid key (non-canonical Ristretto point)".into(),
        core::Error::IdentityPoint => "not a valid key (identity point)".into(),
        core::Error::MalformedPlaintext => "the delivery decrypts to a block no client produces".into(),
        core::Error::CommitmentMismatch => "the delivery is not the secret that was listed".into(),
        core::Error::WrongKey => "this base key does not give the buyer key registered for this sale".into(),
    }
}

fn io_error(path: &Path, e: &std::io::Error) -> String {
    format!("{}: {e}", path.display())
}

/// Creates `path` for a secret, refusing to overwrite anything, readable by the owner only on Unix.
fn write_private(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| io_error(path, &e))?;
    file.write_all(contents.as_bytes()).map_err(|e| io_error(path, &e))
}

fn read_key(path: &Path) -> Result<Keypair, String> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| io_error(path, &e))?);
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(hex_array(text.trim(), "key file")?);
    Keypair::from_secret_bytes(&bytes).ok_or_else(|| format!("{}: not a valid secret key", path.display()))
}

fn read_block(path: &Path) -> Result<Zeroizing<core::Block>, String> {
    let text = Zeroizing::new(fs::read_to_string(path).map_err(|e| io_error(path, &e))?);
    Ok(Zeroizing::new(hex_array(text.trim(), "block file")?))
}

fn address(text: &str) -> Result<ComponentAddress, String> {
    ComponentAddress::from_str(text.trim()).map_err(|e| format!("{text}: not a component address ({e})"))
}

/// The sale's context: the component address bytes, exactly as the template binds them.
fn context(component: &str) -> Result<Vec<u8>, String> {
    Ok(address(component)?.as_bytes().to_vec())
}

fn hex_array<const N: usize>(text: &str, what: &str) -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    hex::decode_to_slice(text.trim(), &mut out).map_err(|e| format!("{what}: expected {N} hex-encoded bytes ({e})"))?;
    Ok(out)
}

fn hex32(text: &str, what: &str) -> Result<[u8; 32], String> {
    hex_array(text, what)
}

fn print_hex(name: &str, bytes: &[u8]) {
    println!("{name}={}", hex::encode(bytes));
}

fn print_proof(prefix: &str, proof: &Proof) {
    print_hex(&format!("{prefix}c"), &proof.c);
    print_hex(&format!("{prefix}z"), &proof.z);
}
