//! Real Crypt sales on esmeralda: the template is published once, then each sale is played call by
//! call with the same client code as the CLI (`crypt_core`), and every transaction id is recorded.
//!
//! The demo account holds stealth UTXOs only (a claimed burn is minted as one), and no indexer call
//! lists an account's UTXOs, so this program keeps its own two: one that pays the fees, one that
//! funds bonds and payments. Every transaction is dry-run first, and the state file is updated only
//! with what the network committed.

use std::{collections::BTreeMap, env, fs, num::NonZeroU64, path::PathBuf};

use crypt_core::{self as client, Keypair, rules};
use ootle_rs::{
    Address, TransactionRequest,
    builtin_templates::{
        UnsignedTransactionBuilder,
        component::{IComponent, TransactionBuildable},
    },
    provider::{IndexerProvider, Provider, WalletProvider},
    stealth::{Output, StealthTransfer},
    template_types::{ComponentAddress, UtxoAddress, constants::TARI_TOKEN},
    wallet::OotleWallet,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tari_ootle_transaction::{Epoch, args};
use tari_template_lib_types::{
    Amount, Hash64,
    bytes::Bytes,
    crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes, Scalar32Bytes},
};

/// 1 tTARI in µT.
const TARI: u64 = 1_000_000;
const PRICE: u64 = 10 * TARI;
const BUYER_BOND: u64 = 2 * TARI;
const SELLER_BOND: u64 = 3 * TARI;
/// Windows in epochs: generous, so a sale never races the clock while it is being played.
const WINDOWS: (u64, u64, u64) = (200, 100, 100);
const FEE_POOL: u64 = 100 * TARI;

pub type Prov = IndexerProvider<OotleWallet>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    pub commitment: String,
    pub value: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Run {
    pub component: Option<String>,
    /// Step name → transaction id, in the order played.
    pub txs: Vec<(String, String)>,
    pub outcome: Option<String>,
    /// The stealth outputs paid out to the demo account.
    pub payouts: Vec<Utxo>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub fee: Option<Utxo>,
    pub funds: Option<Utxo>,
    pub template: Option<String>,
    pub template_sha256: Option<String>,
    pub publish_tx: Option<String>,
    pub runs: BTreeMap<String, Run>,
}

fn state_path() -> PathBuf {
    env::var("CRYPT_DEMO_STATE").map_or_else(
        |_| {
            PathBuf::from(format!(
                "{}.state.json",
                env::var("CRYPT_DEMO_KEY").expect("CRYPT_DEMO_KEY")
            ))
        },
        PathBuf::from,
    )
}

impl State {
    pub fn load() -> Self {
        fs::read_to_string(state_path())
            .map_or_else(|_| Self::default(), |s| serde_json::from_str(&s).expect("state file"))
    }

    pub fn save(&self) {
        let tmp = state_path().with_extension("tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self).unwrap()).expect("write state");
        fs::rename(tmp, state_path()).expect("replace state");
    }
}

fn commitment_of_hex(hex: &str) -> PedersenCommitmentBytes {
    PedersenCommitmentBytes::from_bytes(&hex::decode(hex).expect("hex commitment")).expect("32-byte commitment")
}

fn utxo(hex: &str) -> UtxoAddress {
    UtxoAddress::new(TARI_TOKEN, commitment_of_hex(hex).into())
}

fn nz(v: u64) -> NonZeroU64 {
    NonZeroU64::new(v).expect("positive amount")
}

fn point(bytes: [u8; 32]) -> RistrettoPublicKeyBytes {
    RistrettoPublicKeyBytes::from_bytes(&bytes).expect("32 bytes")
}

fn scalar(bytes: [u8; 32]) -> Scalar32Bytes {
    Scalar32Bytes::from_bytes(&bytes).expect("32 bytes")
}

fn me(p: &Prov) -> Address {
    p.default_signer_address().clone()
}

/// What a committed transaction left behind.
pub struct Sent {
    pub tx_id: String,
    pub receipt: tari_ootle_common_types::engine_types::transaction_receipt::TransactionReceipt,
}

/// Sends one transaction: the fee comes out of the fee UTXO (change back to the account), `spend`
/// reveals that exact amount out of the funds UTXO onto the workspace as `"funds"`, then `main`
/// adds the calls. Dry-run first; the state moves only on a full commit.
pub async fn send(
    p: &mut Prov,
    st: &mut State,
    fee_budget: u64,
    spend: Option<u64>,
    main: impl FnOnce(IComponent<'_, Prov>) -> IComponent<'_, Prov>,
) -> Result<Sent, String> {
    let fee = st.fee.clone().ok_or("no fee UTXO: run `split` first")?;
    if fee.value <= fee_budget {
        return Err(format!(
            "the fee UTXO holds {} µT, less than the budget {fee_budget}",
            fee.value
        ));
    }
    let max_epoch = Epoch(p.get_epoch().await.map_err(|e| e.to_string())?.as_u64() + 10);
    let (fee_stmt, mut sigs) = StealthTransfer::new(TARI_TOKEN, &*p)
        .spend_stealth_input(me(p), commitment_of_hex(&fee.commitment))
        .to_revealed_output(fee_budget)
        .to_stealth_output(Output::new(me(p), TARI_TOKEN, nz(fee.value - fee_budget)))
        .prepare()
        .await
        .map_err(|e| format!("fee statement: {e}"))?;
    let new_fee = Utxo {
        commitment: hex::encode(fee_stmt.stealth_outputs()[0].output.commitment.as_bytes()),
        value: fee.value - fee_budget,
    };

    let mut funds_change = None;
    let mut funds_stmt = None;
    let funds = st.funds.clone();
    if let Some(amount) = spend {
        let funds = funds.clone().ok_or("no funds UTXO")?;
        if funds.value <= amount {
            return Err(format!("the funds UTXO holds {} µT, less than {amount}", funds.value));
        }
        let (stmt, s) = StealthTransfer::new(TARI_TOKEN, &*p)
            .spend_stealth_input(me(p), commitment_of_hex(&funds.commitment))
            .to_revealed_output(amount)
            .to_stealth_output(Output::new(me(p), TARI_TOKEN, nz(funds.value - amount)))
            .prepare()
            .await
            .map_err(|e| format!("funds statement: {e}"))?;
        funds_change = Some(Utxo {
            commitment: hex::encode(stmt.stealth_outputs()[0].output.commitment.as_bytes()),
            value: funds.value - amount,
        });
        sigs = sigs.merge(s);
        funds_stmt = Some(stmt);
    }

    let mut builder = IComponent::new(&*p, max_epoch)
        .then(|b| {
            b.with_fee_instructions_builder(|f| {
                f.stealth_transfer(TARI_TOKEN, fee_stmt)
                    .put_last_instruction_output_on_workspace("fees")
                    .pay_fee_from_bucket("fees")
            })
        })
        .then(|b| b.add_input(TARI_TOKEN).add_input(utxo(&fee.commitment)));
    if let (Some(stmt), Some(funds)) = (funds_stmt, &funds) {
        builder = builder.then(|b| {
            b.stealth_transfer(TARI_TOKEN, stmt)
                .put_last_instruction_output_on_workspace("funds")
                .add_input(utxo(&funds.commitment))
        });
    }
    let unsigned = main(builder).prepare().await.map_err(|e| format!("prepare: {e}"))?;

    let authorizer = p.wallet().stealth_authorizer(sigs);
    let dry = p
        .sign_and_send_dry_run_with(&authorizer, unsigned.clone())
        .await
        .map_err(|e| format!("dry run: {e}"))?;
    if !dry.finalize.is_full_accept() {
        return Err(format!("dry run refused: {:?}", dry.finalize.result));
    }
    println!(
        "  dry run ok, fees charged {} of budget {fee_budget}",
        dry.finalize.fee_receipt.total_fees_charged()
    );
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(&authorizer)
        .await
        .map_err(|e| format!("seal: {e}"))?;
    let pending = p.send_transaction(tx).await.map_err(|e| format!("submit: {e}"))?;
    let tx_id = pending.tx_id().to_string();
    println!("  tx {tx_id}");
    let outcome = pending.watch().await.map_err(|e| format!("watch {tx_id}: {e}"))?;
    if outcome.is_only_fee_commit() {
        st.fee = Some(new_fee);
        st.save();
        return Err(format!("{tx_id}: only the fee committed: {outcome}"));
    }
    if !outcome.is_commit() {
        return Err(format!("{tx_id}: {outcome}"));
    }
    st.fee = Some(new_fee);
    if let Some(change) = funds_change {
        st.funds = Some(change);
    }
    st.save();
    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| format!("receipt {tx_id}: {e}"))?;
    Ok(Sent { tx_id, receipt })
}

/// Records the UTXO a claim minted (value: the burn minus the claim's fee, which is not refunded).
pub async fn utxo_from_claim(p: &mut Prov, tx_id: &str, value: u64) {
    let client = p.client_upgrade().expect("indexer client");
    let id = tari_ootle_transaction::TransactionId::from_hex(tx_id).expect("transaction id");
    let receipt = client
        .get_transaction_receipt(id.into_receipt_address())
        .await
        .expect("claim receipt")
        .receipt;
    let utxos: Vec<_> = receipt
        .diff_summary
        .upped
        .iter()
        .filter_map(|u| u.substate_id.as_utxo_address())
        .collect();
    assert_eq!(utxos.len(), 1, "the claim mints exactly one output: {utxos:?}");
    let mut st = State::load();
    assert!(st.funds.is_none() && st.fee.is_none(), "state already holds UTXOs");
    st.funds = Some(Utxo {
        commitment: hex::encode(utxos[0].id().as_bytes()),
        value,
    });
    st.save();
    println!("funds UTXO recorded: {} µT", value);
}

/// Splits the claimed UTXO into a fee UTXO and a funds UTXO, paying the split's own fee from it.
pub async fn split(p: &mut Prov) {
    let mut st = State::load();
    let claimed = st.funds.clone().expect("run utxo-from-claim first");
    assert!(st.fee.is_none(), "already split");
    // The claimed UTXO pays this one fee itself, as the fee UTXO.
    st.fee = Some(claimed.clone());
    st.funds = None;
    let budget = TARI;
    let max_epoch = Epoch(p.get_epoch().await.unwrap().as_u64() + 10);
    let rest = claimed.value - budget - FEE_POOL;
    let (stmt, sigs) = StealthTransfer::new(TARI_TOKEN, &*p)
        .spend_stealth_input(me(p), commitment_of_hex(&claimed.commitment))
        .to_revealed_output(budget)
        .to_stealth_output(Output::new(me(p), TARI_TOKEN, nz(FEE_POOL)))
        .to_stealth_output(Output::new(me(p), TARI_TOKEN, nz(rest)))
        .prepare()
        .await
        .expect("split statement");
    let outs = stmt.stealth_outputs();
    let fee = Utxo {
        commitment: hex::encode(outs[0].output.commitment.as_bytes()),
        value: FEE_POOL,
    };
    let funds = Utxo {
        commitment: hex::encode(outs[1].output.commitment.as_bytes()),
        value: rest,
    };
    let unsigned = IComponent::new(&*p, max_epoch)
        .then(|b| {
            b.with_fee_instructions_builder(|f| {
                f.stealth_transfer(TARI_TOKEN, stmt)
                    .put_last_instruction_output_on_workspace("fees")
                    .pay_fee_from_bucket("fees")
            })
        })
        .then(|b| b.add_input(TARI_TOKEN).add_input(utxo(&claimed.commitment)))
        .prepare()
        .await
        .expect("prepare split");
    let authorizer = p.wallet().stealth_authorizer(sigs);
    let dry = p
        .sign_and_send_dry_run_with(&authorizer, unsigned.clone())
        .await
        .expect("dry run");
    assert!(
        dry.finalize.is_full_accept(),
        "split dry run refused: {:?}",
        dry.finalize.result
    );
    let tx = TransactionRequest::default()
        .with_transaction(unsigned)
        .build(&authorizer)
        .await
        .unwrap();
    let pending = p.send_transaction(tx).await.unwrap();
    println!("split tx {}", pending.tx_id());
    let outcome = pending.watch().await.unwrap();
    assert!(outcome.is_commit(), "split: {outcome}");
    st.fee = Some(fee);
    st.funds = Some(funds);
    st.save();
    println!("fee UTXO {FEE_POOL} µT, funds UTXO {rest} µT");
}

pub async fn publish(p: &mut Prov, wasm_path: &str, budget: u64) {
    let wasm = fs::read(wasm_path).expect("read template wasm");
    let sha = sha256_hex(&wasm);
    println!("publishing {} bytes, sha256 {sha}", wasm.len());
    let mut st = State::load();
    let sent = send(p, &mut st, budget, None, |b| b.then(|t| t.publish_template(wasm)))
        .await
        .unwrap_or_else(|e| panic!("publish: {e}"));
    let template = sent
        .receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|u| u.substate_id.as_template())
        .expect("a published template in the receipt");
    st.template = Some(template.to_string());
    st.template_sha256 = Some(sha);
    st.publish_tx = Some(sent.tx_id);
    st.save();
    println!("template {template}");
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn record(st: &mut State, name: &str, step: &str, tx: &str) {
    st.runs
        .entry(name.into())
        .or_default()
        .txs
        .push((step.into(), tx.into()));
    st.save();
}

fn events(sent: &Sent) {
    for e in sent.receipt.events.iter() {
        println!("    event {} {}", e.topic(), e.payload());
    }
}

/// Plays a whole sale. `honest`: list, buy, deliver, accept, both payouts. Otherwise the seller
/// delivers another secret, the buyer disputes, and the buyer is paid everything.
pub async fn play(p: &mut Prov, name: &str, honest: bool) {
    let mut st = State::load();
    assert!(
        !st.runs.contains_key(name),
        "run {name} already exists in the state file"
    );
    let template: ootle_rs::template_types::TemplateAddress = st
        .template
        .as_deref()
        .expect("publish first")
        .parse::<tari_ootle_common_types::engine_types::published_template::PublishedTemplateAddress>()
        .expect("template address")
        .as_template_address();

    let secret: &[u8] = if honest {
        b"Crypt esmeralda demo: the honest sale's secret is 'pumpkin-lantern-1031'."
    } else {
        b"Crypt esmeralda demo: the real secret the seller never sent."
    };
    let block = client::encode_plaintext(secret, &mut OsRng).unwrap();
    let commitment = client::commitment_of(&block);
    let seller = Keypair::generate(&mut OsRng).for_listing(&commitment);
    let terms = rules::Terms {
        price: PRICE,
        buyer_bond: BUYER_BOND,
        seller_bond: SELLER_BOND,
        listing_window: WINDOWS.0,
        delivery_window: WINDOWS.1,
        dispute_window: WINDOWS.2,
    };
    let fee = TARI;

    // list
    println!("[{name}] list");
    let proof = client::prove_action(
        &seller,
        client::LIST_CONTEXT,
        &terms.list_message(&commitment),
        &mut OsRng,
    );
    let sent = send(p, &mut st, fee, Some(SELLER_BOND), |b| {
        b.call_function(
            template,
            "list",
            args![
                Hash64::from(commitment),
                Amount::from_u64(PRICE),
                Amount::from_u64(BUYER_BOND),
                WINDOWS.0,
                WINDOWS.1,
                WINDOWS.2,
                point(seller.public()),
                scalar(proof.c),
                scalar(proof.z),
                Workspace("funds")
            ],
        )
    })
    .await
    .unwrap_or_else(|e| panic!("list: {e}"));
    let crypt: ComponentAddress = sent
        .receipt
        .diff_summary
        .upped
        .iter()
        .find_map(|u| u.substate_id.as_component_address())
        .expect("the new Crypt component");
    println!("  component {crypt}");
    st.runs.entry(name.into()).or_default().component = Some(crypt.to_string());
    record(&mut st, name, "list", &sent.tx_id);
    let ctx = crypt.as_bytes().to_vec();

    // buy
    println!("[{name}] buy");
    let buyer = Keypair::generate(&mut OsRng).for_sale(&ctx);
    let proof = client::prove_action(&buyer, &ctx, client::MSG_BUY, &mut OsRng);
    let sent = send(p, &mut st, fee, Some(PRICE + BUYER_BOND), |b| {
        b.call_method(
            crypt,
            "buy",
            args![
                point(buyer.public()),
                scalar(proof.c),
                scalar(proof.z),
                Workspace("funds")
            ],
        )
    })
    .await
    .unwrap_or_else(|e| panic!("buy: {e}"));
    events(&sent);
    record(&mut st, name, "buy", &sent.tx_id);

    // deliver
    println!(
        "[{name}] deliver ({})",
        if honest { "the listed secret" } else { "another secret" }
    );
    let delivered = if honest {
        block
    } else {
        client::encode_plaintext(b"lol. nothing. the buyer paid for air.", &mut OsRng).unwrap()
    };
    let sealed = client::seal(&delivered, &buyer.public(), &ctx, &mut OsRng).unwrap();
    let proof = client::prove_action(
        &seller,
        &ctx,
        &client::msg_deliver(&sealed.ephemeral, &sealed.ciphertext),
        &mut OsRng,
    );
    let sent = send(p, &mut st, fee, None, |b| {
        b.call_method(
            crypt,
            "deliver",
            args![
                point(sealed.ephemeral),
                scalar(sealed.ephemeral_proof.c),
                scalar(sealed.ephemeral_proof.z),
                Bytes::from_vec(sealed.ciphertext.to_vec()),
                scalar(proof.c),
                scalar(proof.z)
            ],
        )
    })
    .await
    .unwrap_or_else(|e| panic!("deliver: {e}"));
    events(&sent);
    record(&mut st, name, "deliver", &sent.tx_id);

    // The buyer's client opens it, exactly as the CLI would, and decides.
    let opened = client::open_verified(&buyer, &ctx, &sealed.ephemeral, &sealed.ciphertext, &commitment);
    println!(
        "  buyer opens: {:?}",
        opened.as_ref().map(|s| String::from_utf8_lossy(s).into_owned())
    );
    let outcome = if opened.is_ok() {
        println!("[{name}] accept");
        let proof = client::prove_action(&buyer, &ctx, &client::msg_accept(&sealed.ephemeral), &mut OsRng);
        let sent = send(p, &mut st, fee, None, |b| {
            b.call_method(crypt, "accept", args![scalar(proof.c), scalar(proof.z)])
        })
        .await
        .unwrap_or_else(|e| panic!("accept: {e}"));
        events(&sent);
        record(&mut st, name, "accept", &sent.tx_id);
        rules::Outcome::Accepted
    } else {
        println!("[{name}] dispute");
        let (shared, proof) =
            client::prove_shared(&buyer, &buyer.public(), &ctx, &sealed.ephemeral, &mut OsRng).unwrap();
        let sent = send(p, &mut st, fee, None, |b| {
            b.call_method(crypt, "dispute", args![point(shared), scalar(proof.c), scalar(proof.z)])
        })
        .await
        .unwrap_or_else(|e| panic!("dispute: {e}"));
        events(&sent);
        record(&mut st, name, "dispute", &sent.tx_id);
        rules::Outcome::Fraud
    };
    st.runs.get_mut(name).unwrap().outcome = Some(format!("{outcome:?}"));
    st.save();

    // Payouts: the split the template settled on, the same as the rules port computes.
    let (to_seller, to_buyer) = match outcome {
        rules::Outcome::Accepted => (PRICE + SELLER_BOND, BUYER_BOND),
        _ => (0, PRICE + BUYER_BOND + SELLER_BOND),
    };
    for (owed, method, action, key) in [
        (to_seller, "pay_seller", client::MSG_PAY_SELLER, &seller),
        (to_buyer, "pay_buyer", client::MSG_PAY_BUYER, &buyer),
    ] {
        if owed == 0 {
            continue;
        }
        println!("[{name}] {method} {owed} µT");
        let (stmt, _) = StealthTransfer::new(TARI_TOKEN, &*p)
            .spend_revealed_input(owed)
            .to_stealth_output(Output::new(me(p), TARI_TOKEN, nz(owed)))
            .prepare()
            .await
            .expect("payout statement");
        let digest = client::statement_digest(&tari_bor::encode(&stmt).expect("encode statement"));
        let proof = client::prove_action(key, &ctx, &client::msg_pay(action, &digest), &mut OsRng);
        let paid = Utxo {
            commitment: hex::encode(stmt.stealth_outputs()[0].output.commitment.as_bytes()),
            value: owed,
        };
        let sent = send(p, &mut st, fee, None, |b| {
            b.call_method(crypt, method, args![stmt, scalar(proof.c), scalar(proof.z)])
        })
        .await
        .unwrap_or_else(|e| panic!("{method}: {e}"));
        events(&sent);
        record(&mut st, name, method, &sent.tx_id);
        st.runs.get_mut(name).unwrap().payouts.push(paid);
        st.save();
    }
    println!(
        "[{name}] done: {}",
        serde_json::to_string_pretty(&st.runs[name]).unwrap()
    );
}
