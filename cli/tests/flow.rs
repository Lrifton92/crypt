//! A whole sale driven through the `crypt` binary, every output checked with the verifiers the
//! template mirrors. The template side of the same values is covered by the end-to-end suite.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use crypt_core as core;
use tari_template_lib_types::{
    crypto::{PedersenCommitmentBytes, RangeProofBytes, RistrettoPublicKeyBytes, UtxoTag},
    stealth::{
        RevealedOutput, SpendAuthorization, StealthInput, StealthInputsStatement, StealthOutputsStatement,
        StealthTransferStatement, StealthUnspentOutput, UnspentOutput,
    },
    Amount, EncryptedData,
};

const COMPONENT: &str = "component_0101010101010101010101010101010101010101010101010101010101010101";
const SECRET: &[u8] = b"vault combination: 31-04-77";

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("crypt-cli-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, file: &str) -> String {
        self.0.join(file).to_string_lossy().into_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The listing terms every test lists with, as `commit` takes them.
const TERMS: [&str; 12] = [
    "--price",
    "1000",
    "--buyer-bond",
    "200",
    "--seller-bond",
    "300",
    "--listing-window",
    "5",
    "--delivery-window",
    "3",
    "--dispute-window",
    "4",
];

fn with_terms<'a>(args: &[&'a str]) -> Vec<&'a str> {
    [args, &TERMS].concat()
}

fn crypt(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crypt")).args(args).output().unwrap()
}

/// Runs a command that must succeed and returns its `name=value` lines.
fn fields(args: &[&str]) -> HashMap<String, String> {
    let out = crypt(args);
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

fn bytes<const N: usize>(hex_text: &str) -> [u8; N] {
    let mut out = [0u8; N];
    hex::decode_to_slice(hex_text, &mut out).unwrap();
    out
}

fn proof(f: &HashMap<String, String>, prefix: &str) -> core::Proof {
    core::Proof {
        c: bytes(&f[&format!("{prefix}c")]),
        z: bytes(&f[&format!("{prefix}z")]),
    }
}

fn context_of(address: &str) -> Vec<u8> {
    hex::decode(address.trim_start_matches("component_")).unwrap()
}

fn stealth_output(byte: u8) -> StealthUnspentOutput {
    StealthUnspentOutput {
        output: UnspentOutput {
            commitment: PedersenCommitmentBytes::from_bytes(&[byte; 32]).unwrap(),
            sender_public_nonce: RistrettoPublicKeyBytes::from_bytes(&[byte; 32]).unwrap(),
            encrypted_data: EncryptedData::empty(),
            minimum_value_promise: 0,
            viewable_balance_proof: None,
        },
        auth: SpendAuthorization::Key(RistrettoPublicKeyBytes::from_bytes(&[byte; 32]).unwrap()),
        tag: UtxoTag::from(0u32),
    }
}

/// A payout transfer shaped the way the template accepts: `owed` taken from the escrow, two stealth
/// outputs, nothing revealed, no inputs of its own. (The tool only checks shape; proofs are the
/// wallet's and the engine's business.)
fn payout(owed: u64) -> StealthTransferStatement {
    StealthTransferStatement {
        inputs_statement: StealthInputsStatement::new_revealed_only(Amount::from_u64(owed)),
        outputs_statement: StealthOutputsStatement {
            outputs: vec![stealth_output(7), stealth_output(8)],
            revealed_output: None,
            agg_range_proof: RangeProofBytes::empty(),
        },
        balance_proof: None,
        covenant_claims: vec![],
    }
}

fn write_statement(dir: &Dir, name: &str, statement: &StealthTransferStatement) -> String {
    let path = dir.path(name);
    fs::write(&path, hex::encode(tari_bor::encode(statement).unwrap())).unwrap();
    path
}

#[test]
fn a_whole_sale_through_the_cli() {
    let dir = Dir::new("sale");
    let (seller_key, base_key, secret, block) = (
        dir.path("seller.key"),
        dir.path("buyer.key"),
        dir.path("secret.txt"),
        dir.path("block.hex"),
    );
    fs::write(&secret, SECRET).unwrap();
    let ctx = context_of(COMPONENT);

    fields(&["keygen", "--out", &seller_key]);
    fields(&["keygen", "--out", &base_key]);

    let listed = fields(&with_terms(&[
        "commit",
        "--seller-key",
        &seller_key,
        "--secret-file",
        &secret,
        "--out",
        &block,
    ]));
    let commitment = listed["commitment"].clone();
    let listing_key: [u8; 32] = bytes(&listed["seller_key"]);
    assert!(
        core::verify_action(
            &listing_key,
            core::LIST_CONTEXT,
            &core::msg_list(&bytes(&commitment), 1000, 200, 300, 5, 3, 4),
            &proof(&listed, "list_")
        ),
        "commit proves the listing key over the exact terms"
    );

    let bought = fields(&["buy", "--base-key", &base_key, "--component", COMPONENT]);
    let buyer_key: [u8; 32] = bytes(&bought["buyer_key"]);
    assert!(core::verify_action(
        &buyer_key,
        &ctx,
        core::MSG_BUY,
        &proof(&bought, "")
    ));

    let sealed = fields(&[
        "seal",
        "--seller-key",
        &seller_key,
        "--commitment",
        &commitment,
        "--block",
        &block,
        "--component",
        COMPONENT,
        "--buyer-key",
        &bought["buyer_key"],
        "--buy-c",
        &bought["c"],
        "--buy-z",
        &bought["z"],
    ]);
    let ephemeral: [u8; 32] = bytes(&sealed["ephemeral"]);
    let ciphertext: core::Block = bytes(&sealed["ciphertext"]);
    assert!(core::verify_action(
        &ephemeral,
        &ctx,
        core::MSG_EPHEMERAL,
        &proof(&sealed, "ephemeral_")
    ));
    assert!(
        core::verify_action(
            &listing_key,
            &ctx,
            &core::msg_deliver(&ephemeral, &ciphertext),
            &proof(&sealed, "")
        ),
        "signed by the listing key printed at commit"
    );

    let opened = crypt(&[
        "open",
        "--base-key",
        &base_key,
        "--component",
        COMPONENT,
        "--ephemeral",
        &sealed["ephemeral"],
        "--ciphertext",
        &sealed["ciphertext"],
        "--commitment",
        &commitment,
    ]);
    assert!(opened.status.success());
    assert_eq!(opened.stdout, SECRET);

    let accepted = fields(&[
        "accept",
        "--base-key",
        &base_key,
        "--component",
        COMPONENT,
        "--ephemeral",
        &sealed["ephemeral"],
        "--ciphertext",
        &sealed["ciphertext"],
        "--commitment",
        &commitment,
    ]);
    assert!(core::verify_action(
        &buyer_key,
        &ctx,
        &core::msg_accept(&ephemeral),
        &proof(&accepted, "")
    ));

    let disputed = fields(&[
        "dispute",
        "--base-key",
        &base_key,
        "--component",
        COMPONENT,
        "--ephemeral",
        &sealed["ephemeral"],
        "--registered",
        &bought["buyer_key"],
    ]);
    let shared: [u8; 32] = bytes(&disputed["shared"]);
    assert!(core::verify_shared(
        &buyer_key,
        &ephemeral,
        &shared,
        &ctx,
        &proof(&disputed, "")
    ));

    let cancelled = fields(&[
        "cancel",
        "--seller-key",
        &seller_key,
        "--commitment",
        &commitment,
        "--component",
        COMPONENT,
    ]);
    assert!(core::verify_action(
        &listing_key,
        &ctx,
        core::MSG_CANCEL,
        &proof(&cancelled, "")
    ));
}

#[test]
fn every_listing_gets_its_own_seller_key() {
    let dir = Dir::new("listings");
    let (seller_key, secret) = (dir.path("seller.key"), dir.path("secret.txt"));
    fs::write(&secret, SECRET).unwrap();
    let base = fields(&["keygen", "--out", &seller_key])["base_public_key"].clone();
    let first = fields(&with_terms(&[
        "commit",
        "--seller-key",
        &seller_key,
        "--secret-file",
        &secret,
        "--out",
        &dir.path("a.hex"),
    ]));
    let second = fields(&with_terms(&[
        "commit",
        "--seller-key",
        &seller_key,
        "--secret-file",
        &secret,
        "--out",
        &dir.path("b.hex"),
    ]));
    assert_ne!(
        first["seller_key"], second["seller_key"],
        "same seller, same secret, unrelated keys"
    );
    assert_ne!(first["seller_key"], base, "the base key never appears on-chain");
}

#[test]
fn open_says_to_dispute_a_delivery_that_is_not_the_listing() {
    let dir = Dir::new("mismatch");
    let (seller_key, base_key, secret, block, other) = (
        dir.path("seller.key"),
        dir.path("buyer.key"),
        dir.path("secret.txt"),
        dir.path("block.hex"),
        dir.path("other.hex"),
    );
    fs::write(&secret, SECRET).unwrap();
    fields(&["keygen", "--out", &seller_key]);
    fields(&["keygen", "--out", &base_key]);
    let listed = fields(&with_terms(&[
        "commit",
        "--seller-key",
        &seller_key,
        "--secret-file",
        &secret,
        "--out",
        &block,
    ]));
    // The seller seals a different block than the one listed.
    fields(&with_terms(&[
        "commit",
        "--seller-key",
        &seller_key,
        "--secret-file",
        &secret,
        "--out",
        &other,
    ]));
    let bought = fields(&["buy", "--base-key", &base_key, "--component", COMPONENT]);
    let sealed = dishonest_delivery(&seller_key, &listed["commitment"], &other, &bought["buyer_key"]);
    let opened = crypt(&[
        "open",
        "--base-key",
        &base_key,
        "--component",
        COMPONENT,
        "--ephemeral",
        &sealed["ephemeral"],
        "--ciphertext",
        &sealed["ciphertext"],
        "--commitment",
        &listed["commitment"],
    ]);
    assert_eq!(opened.status.code(), Some(2));
    assert!(opened.stdout.is_empty(), "nothing is printed as the secret");
    assert!(String::from_utf8_lossy(&opened.stderr).contains("dispute"));
}

#[test]
fn a_dispute_is_refused_with_a_key_that_is_not_the_registered_one() {
    let dir = Dir::new("wrongkey");
    let (base_key, other_key) = (dir.path("buyer.key"), dir.path("other.key"));
    fields(&["keygen", "--out", &base_key]);
    fields(&["keygen", "--out", &other_key]);
    let bought = fields(&["buy", "--base-key", &base_key, "--component", COMPONENT]);
    let r = fields(&["public", "--key", &other_key])["public_key"].clone();
    let out = crypt(&[
        "dispute",
        "--base-key",
        &other_key,
        "--component",
        COMPONENT,
        "--ephemeral",
        &r,
        "--registered",
        &bought["buyer_key"],
    ]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "no shared point is printed");
}

#[test]
fn payout_signs_only_a_transfer_the_template_would_accept() {
    let dir = Dir::new("payout");
    let (seller_key, base_key, secret) = (dir.path("seller.key"), dir.path("buyer.key"), dir.path("s.txt"));
    fs::write(&secret, SECRET).unwrap();
    fields(&["keygen", "--out", &seller_key]);
    fields(&["keygen", "--out", &base_key]);
    let listed = fields(&with_terms(&[
        "commit",
        "--seller-key",
        &seller_key,
        "--secret-file",
        &secret,
        "--out",
        &dir.path("b.hex"),
    ]));
    let listing_key: [u8; 32] = bytes(&listed["seller_key"]);
    let buyer_key: [u8; 32] = bytes(&fields(&["buy", "--base-key", &base_key, "--component", COMPONENT])["buyer_key"]);
    let ctx = context_of(COMPONENT);

    let good = payout(1_300);
    let file = write_statement(&dir, "good.hex", &good);
    let digest = core::statement_digest(&tari_bor::encode(&good).unwrap());

    let seller = |file: &str, owed: &str| {
        crypt(&[
            "payout",
            "--seller-key",
            &seller_key,
            "--commitment",
            &listed["commitment"],
            "--component",
            COMPONENT,
            "--statement",
            file,
            "--owed",
            owed,
        ])
    };

    let signed = seller(&file, "1300");
    assert!(signed.status.success(), "{}", String::from_utf8_lossy(&signed.stderr));
    let signed: HashMap<String, String> = String::from_utf8(signed.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    assert_eq!(bytes::<64>(&signed["digest"]), digest);
    let message = core::msg_pay(core::MSG_PAY_SELLER, &digest);
    assert!(core::verify_action(&listing_key, &ctx, &message, &proof(&signed, "")));

    let buyer = fields(&[
        "payout",
        "--base-key",
        &base_key,
        "--component",
        COMPONENT,
        "--statement",
        &file,
        "--owed",
        "1300",
    ]);
    let message = core::msg_pay(core::MSG_PAY_BUYER, &digest);
    assert!(
        core::verify_action(&buyer_key, &ctx, &message, &proof(&buyer, "")),
        "signed by the sale key"
    );

    // Everything the template would refuse is refused before signing, with nothing printed.
    let mut revealed = payout(1_300);
    revealed.outputs_statement.revealed_output = Some(RevealedOutput::new(
        Amount::from_u64(100),
        RistrettoPublicKeyBytes::from_bytes(&[9; 32]).unwrap(),
    ));
    let mut with_input = payout(1_300);
    with_input.inputs_statement.inputs.push(StealthInput::new(
        PedersenCommitmentBytes::from_bytes(&[3; 32]).unwrap(),
    ));
    let mut no_outputs = payout(1_300);
    no_outputs.outputs_statement.outputs.clear();
    let cases = [
        (
            write_statement(&dir, "revealed.hex", &revealed),
            "1300",
            "reveals funds",
        ),
        (
            write_statement(&dir, "input.hex", &with_input),
            "1300",
            "spends stealth inputs",
        ),
        (
            write_statement(&dir, "empty.hex", &no_outputs),
            "1300",
            "no stealth outputs",
        ),
        (file.clone(), "1299", "not the 1299 owed"),
    ];
    for (file, owed, reason) in cases {
        let out = seller(&file, owed);
        assert!(!out.status.success(), "{reason}");
        assert!(out.stdout.is_empty(), "{reason}: nothing signed");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(reason),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fs::write(&file, "00ff").unwrap();
    assert!(String::from_utf8_lossy(&seller(&file, "1300").stderr).contains("not a stealth transfer"));
}

#[test]
fn keys_and_blocks_are_never_overwritten() {
    let dir = Dir::new("overwrite");
    let key = dir.path("seller.key");
    let first = crypt(&["keygen", "--out", &key]);
    assert!(String::from_utf8_lossy(&first.stderr).contains("back up"));
    let before = fs::read_to_string(&key).unwrap();
    assert!(!crypt(&["keygen", "--out", &key]).status.success());
    assert_eq!(fs::read_to_string(&key).unwrap(), before);
    assert!(Path::new(&key).exists());
}

#[test]
fn bad_inputs_are_refused_with_a_reason() {
    let dir = Dir::new("bad");
    let key = dir.path("buyer.key");
    fields(&["keygen", "--out", &key]);
    let (zeros_ciphertext, zeros_commitment) = ("00".repeat(core::PLAINTEXT_LEN), "00".repeat(64));
    for (args, reason) in [
        (
            vec!["buy", "--base-key", &key, "--component", "component_zz"],
            "not a component address",
        ),
        (
            vec![
                "accept",
                "--base-key",
                &key,
                "--component",
                COMPONENT,
                "--ephemeral",
                "abcd",
                "--ciphertext",
                &zeros_ciphertext,
                "--commitment",
                &zeros_commitment,
            ],
            "hex-encoded bytes",
        ),
        (vec!["public", "--key", &dir.path("missing.key")], "missing.key"),
    ] {
        let out = crypt(&args);
        assert!(!out.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(reason),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let too_long = dir.path("long.txt");
    fs::write(&too_long, vec![b'x'; core::MAX_SECRET_LEN + 1]).unwrap();
    let out = crypt(&with_terms(&[
        "commit",
        "--seller-key",
        &key,
        "--secret-file",
        &too_long,
        "--out",
        &dir.path("block.hex"),
    ]));
    assert!(String::from_utf8_lossy(&out.stderr).contains("longer than"));
}

/// What a seller who bypasses the CLI's checks can still post: `block` sealed to `buyer_key` and
/// signed by the listing key of `commitment`.
fn dishonest_delivery(seller_key: &str, commitment: &str, block: &str, buyer_key: &str) -> HashMap<String, String> {
    let ctx = context_of(COMPONENT);
    let base = core::Keypair::from_secret_bytes(&bytes(fs::read_to_string(seller_key).unwrap().trim())).unwrap();
    let listing = base.for_listing(&bytes(commitment));
    let block: core::Block = bytes(fs::read_to_string(block).unwrap().trim());
    let sealed = core::seal(&block, &bytes(buyer_key), &ctx, &mut rand_core::OsRng).unwrap();
    let signature = core::prove_action(
        &listing,
        &ctx,
        &core::msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
        &mut rand_core::OsRng,
    );
    HashMap::from([
        ("ephemeral".to_string(), hex::encode(sealed.ephemeral)),
        ("ciphertext".to_string(), hex::encode(sealed.ciphertext)),
        ("c".to_string(), hex::encode(signature.c)),
        ("z".to_string(), hex::encode(signature.z)),
    ])
}

/// A seller with two listings: keys, both blocks, and a buyer who bought the first one.
struct TwoListings {
    _dir: Dir,
    seller_key: String,
    base_key: String,
    listed: HashMap<String, String>,
    block: String,
    other: String,
    bought: HashMap<String, String>,
}

fn two_listings(name: &str) -> TwoListings {
    let dir = Dir::new(name);
    let (seller_key, base_key, secret, block, other) = (
        dir.path("seller.key"),
        dir.path("buyer.key"),
        dir.path("secret.txt"),
        dir.path("block.hex"),
        dir.path("other.hex"),
    );
    fs::write(&secret, SECRET).unwrap();
    fields(&["keygen", "--out", &seller_key]);
    fields(&["keygen", "--out", &base_key]);
    let commit = |out: &str| {
        fields(&with_terms(&[
            "commit",
            "--seller-key",
            &seller_key,
            "--secret-file",
            &secret,
            "--out",
            out,
        ]))
    };
    let listed = commit(&block);
    commit(&other);
    let bought = fields(&["buy", "--base-key", &base_key, "--component", COMPONENT]);
    TwoListings {
        _dir: dir,
        seller_key,
        base_key,
        listed,
        block,
        other,
        bought,
    }
}

fn seal_with(t: &TwoListings, block: &str, buyer_key: &str, buy: &HashMap<String, String>) -> Output {
    crypt(&[
        "seal",
        "--seller-key",
        &t.seller_key,
        "--commitment",
        &t.listed["commitment"],
        "--block",
        block,
        "--component",
        COMPONENT,
        "--buyer-key",
        buyer_key,
        "--buy-c",
        &buy["c"],
        "--buy-z",
        &buy["z"],
    ])
}

#[test]
fn seal_refuses_a_block_that_is_not_the_listing() {
    let t = two_listings("seal-mismatch");
    let out = seal_with(&t, &t.other, &t.bought["buyer_key"], &t.bought);
    assert!(
        !out.status.success(),
        "a delivery that loses the dispute and leaks the other secret"
    );
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not the block of this listing"));
}

#[test]
fn seal_refuses_a_block_no_client_can_decode() {
    // A seller who commits by hand to a block with a non-zero padding byte: the commitment matches, the
    // template's dispute would still rule Fraud, and the buyer never gets a readable secret.
    let t = two_listings("seal-malformed");
    let mut block: core::Block = bytes(fs::read_to_string(&t.block).unwrap().trim());
    block[core::PLAINTEXT_LEN - 1] = 1;
    let malformed = format!("{}.bad", t.block);
    fs::write(&malformed, hex::encode(block)).unwrap();
    let out = crypt(&[
        "seal",
        "--seller-key",
        &t.seller_key,
        "--commitment",
        &hex::encode(core::commitment_of(&block)),
        "--block",
        &malformed,
        "--component",
        COMPONENT,
        "--buyer-key",
        &t.bought["buyer_key"],
        "--buy-c",
        &t.bought["c"],
        "--buy-z",
        &t.bought["z"],
    ]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no client can decode"));
}

#[test]
fn seal_refuses_a_buyer_key_not_bought_on_this_component() {
    let t = two_listings("seal-wrong-buyer");
    let elsewhere = fields(&[
        "buy",
        "--base-key",
        &t.base_key,
        "--component",
        "component_0202020202020202020202020202020202020202020202020202020202020202",
    ]);
    let out = seal_with(&t, &t.block, &elsewhere["buyer_key"], &elsewhere);
    assert!(!out.status.success(), "another sale's buyer could read this secret");
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not the buyer of this sale"));
}

#[test]
fn accept_refuses_a_delivery_that_is_not_the_listing() {
    let t = two_listings("accept-mismatch");
    let sealed = dishonest_delivery(&t.seller_key, &t.listed["commitment"], &t.other, &t.bought["buyer_key"]);
    let out = crypt(&[
        "accept",
        "--base-key",
        &t.base_key,
        "--component",
        COMPONENT,
        "--ephemeral",
        &sealed["ephemeral"],
        "--ciphertext",
        &sealed["ciphertext"],
        "--commitment",
        &t.listed["commitment"],
    ]);
    assert!(!out.status.success(), "accepting pays the seller for the wrong secret");
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("dispute"));
}

#[test]
fn keygen_never_presents_the_base_key_as_an_on_chain_key() {
    let dir = Dir::new("keygen-label");
    let out = crypt(&["keygen", "--out", &dir.path("k.key")]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.lines().any(|l| l.starts_with("public_key=")), "{stdout}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("never use it on-chain"));
}
