// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! `crypt`: the offline side of a Crypt sale.
//!
//! Every value a transaction needs (keys, commitment, sealed delivery, proofs) is computed here,
//! printed as `name=hex` lines, and passed to the template through the wallet. Nothing here talks to
//! the network, and no secret is ever taken from the command line: secrets and keys live in files,
//! so they stay out of shell history and process listings.
//!
//! Seller: `keygen` → `commit` → list → `seal` → deliver. Buyer: `keygen` (a base key) → `buy` →
//! `open` → `accept`, or `dispute` if `open` says so.

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
use tari_template_lib_types::ComponentAddress;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "crypt", version, about = "Offline client for Crypt sales on the Tari Ootle")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a secret key file: the seller key, or a buyer base key. Never overwrites a file.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Prints the public key of a key file (the seller key `list` takes).
    Public {
        #[arg(long)]
        key: PathBuf,
    },
    /// Seller: lays the secret out in a salted block, writes the block to `--out` (keep it private
    /// until delivery) and prints the commitment to list.
    Commit {
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
        /// The account the buyer will be paid into if the sale ends in their favour.
        #[arg(long)]
        payout: String,
    },
    /// Seller: seals the block to the buyer's sale key and signs the delivery.
    Seal {
        #[arg(long)]
        seller_key: PathBuf,
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
        component: String,
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
            print_hex("public_key", &key.public());
        }
        Command::Public { key } => print_hex("public_key", &read_key(&key)?.public()),
        Command::Commit { secret_file, out } => {
            let secret = Zeroizing::new(fs::read(&secret_file).map_err(|e| io_error(&secret_file, &e))?);
            let block = Zeroizing::new(core::encode_plaintext(&secret, &mut OsRng).map_err(describe)?);
            write_private(&out, &Zeroizing::new(hex::encode(*block)))?;
            print_hex("commitment", &core::commitment_of(&block));
        }
        Command::Buy {
            base_key,
            component,
            payout,
        } => {
            let ctx = context(&component)?;
            let payout = address(&payout)?;
            let key = read_key(&base_key)?.for_sale(&ctx);
            print_hex("buyer_key", &key.public());
            print_proof(
                "",
                &core::prove_action(&key, &ctx, &core::msg_buy(payout.as_bytes()), &mut OsRng),
            );
        }
        Command::Seal {
            seller_key,
            block,
            component,
            buyer_key,
        } => {
            let ctx = context(&component)?;
            let seller = read_key(&seller_key)?;
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
        Command::Cancel { seller_key, component } => {
            let ctx = context(&component)?;
            let seller = read_key(&seller_key)?;
            print_proof("", &core::prove_action(&seller, &ctx, core::MSG_CANCEL, &mut OsRng));
        }
    }
    Ok(ExitCode::SUCCESS)
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
