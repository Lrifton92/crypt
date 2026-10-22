// The visitor's Tari wallet (Sapient, or any wallet behind window.tari) and the four transactions of
// a real sale on esmeralda. See https://universe.tari.mw/integrations for the provider API.

export const XTM_RESOURCE = "resource_0101010101010101010101010101010101010101010101010101010101010101";
export const NETWORK = "esmeralda";
const MAX_FEE = "200000";

interface Provider {
  request(args: { method: string; params?: unknown }): Promise<unknown>;
}
declare global {
  interface Window {
    tari?: Provider;
  }
}

export interface ProofHex { c: string; z: string }
export interface ListArgs {
  commitment: string;
  price: number;
  buyer_bond: number;
  seller_bond: number;
  listing_window: number;
  delivery_window: number;
  dispute_window: number;
  seller_key: string;
  proof: ProofHex;
}
export interface BuyArgs { buyer_key: string; proof: ProofHex; payment: number }
export interface DeliverArgs { ephemeral: string; ephemeral_proof: ProofHex; ciphertext: string; proof: ProofHex }

/** A refusal from the wallet: `code` 4001 means the visitor said no. */
export class WalletError extends Error {
  constructor(message: string, readonly code?: number) {
    super(message);
  }
}

// ---------------------------------------------------------------------------------------------
// Arguments: InstructionArg::Literal is the CBOR encoding of the value, as hex.

const hexOf = (bytes: number[]) => bytes.map((b) => b.toString(16).padStart(2, "0")).join("");

function head(major: number, n: bigint): number[] {
  const m = major << 5;
  if (n < 24n) return [m | Number(n)];
  const widths: [number, number][] = [[24, 1], [25, 2], [26, 4], [27, 8]];
  for (const [info, len] of widths) {
    if (n < 1n << BigInt(8 * len)) {
      const out = [m | info];
      for (let i = len - 1; i >= 0; i--) out.push(Number((n >> BigInt(8 * i)) & 0xffn));
      return out;
    }
  }
  throw new RangeError("integer above 64 bits");
}

/** An unsigned integer (u64, or an Amount that fits one). */
export const uint = (n: number | bigint) => ({ Literal: hexOf(head(0, BigInt(n))) });

/** A byte string: Hash64, RistrettoPublicKeyBytes, Scalar32Bytes, Bytes. */
export function bytes(hex: string) {
  if (!/^([0-9a-f]{2})*$/.test(hex)) throw new TypeError("not lowercase hex");
  return { Literal: hexOf(head(2, BigInt(hex.length / 2))) + hex };
}

// The paid amount, as a bucket. Workspace 0 holds the account withdraw the StealthTransfer consumes;
// the revealed bucket it hands on is 1 (checked on esmeralda: id 0 fails "unknown bucket").
const REVEALED = { Workspace: { id: 1, offset: null } };

// ---------------------------------------------------------------------------------------------
// Provider

function provider(): Provider {
  if (!window.tari) throw new WalletError("No Tari wallet found on this page. Install Sapient, then reload.");
  return window.tari;
}

async function call<T>(method: string, params?: unknown): Promise<T> {
  try {
    return (await provider().request(params === undefined ? { method } : { method, params })) as T;
  } catch (e) {
    if (e instanceof WalletError) throw e;
    const err = e as { message?: string; code?: number };
    throw new WalletError(err.message ?? String(e), err.code);
  }
}

export const hasWallet = () => Boolean(window.tari);

export interface Connected { account: string; network: string; publicXtm: bigint; stealthWithdraw: boolean }

let connected = "";

/** Connects (prompts once), and reads what the sale needs: network, capabilities, public XTM. */
export async function connect(): Promise<Connected> {
  const [account] = await call<string[]>("tari_requestAccounts");
  if (!account) throw new WalletError("The wallet returned no account.");
  connected = account;
  const network = await call<string>("tari_getNetwork");
  const caps = await call<{ stealthWithdraw?: boolean }>("tari_getCapabilities");
  const balances = await call<{ resourceAddress: string; amount?: string }[]>("tari_getBalances");
  const xtm = balances.find((b) => b.resourceAddress === XTM_RESOURCE);
  return { account, network, publicXtm: BigInt(xtm?.amount ?? "0"), stealthWithdraw: Boolean(caps.stealthWithdraw) };
}

type Status = "pending" | "approved" | "submitting" | "submitted" | "rejected" | "failed";

/**
 * Opens the wallet's approval popup for `operation`, waits for the visitor's answer, submits and
 * returns the transaction id and its result. A refusal throws a WalletError with code 4001.
 */
async function transact(operation: Record<string, unknown>, onWaiting: (note: string) => void): Promise<{ id: string; result: unknown }> {
  const { requestId } = await call<{ requestId: string }>("tari_createTransactionRequest", operation);
  for (;;) {
    const r = await call<{ status: Status; note?: string; result?: unknown; error?: string }>("tari_getTransactionRequest", { requestId });
    if (r.status === "pending") {
      onWaiting(r.note ?? "");
      await new Promise((ok) => window.setTimeout(ok, 1500));
      continue;
    }
    if (r.status === "rejected") throw new WalletError(r.error ?? "Rejected in the wallet.", 4001);
    if (r.status === "failed") throw new WalletError(r.error ?? "The transaction failed.");
    const result = r.status === "submitted" ? r.result : await call<unknown>("tari_submitTransactionRequest", { requestId });
    const id = (result as { transactionId?: string } | null)?.transactionId;
    if (!id) throw new WalletError("The wallet returned no transaction id.");
    if (/"Reject"\s*:/.test(JSON.stringify(result))) throw new WalletError("The network rejected the transaction.");
    return { id, result };
  }
}

/**
 * Pays `amount` into a bucket that `followUp` consumes, in one transaction. XTM is a stealth
 * resource, so a plain vault withdraw is not valid: the wallet moves it with a StealthTransfer that
 * spends the account's public balance (Sapient's withdrawStealthAndExecute).
 */
const fromBalance = async (amount: number, followUp: unknown[], related: string[] = []) => ({
  kind: "withdrawStealthAndExecute",
  resourceAddress: XTM_RESOURCE,
  amount: String(amount),
  workspaceVarName: "funds",
  followUpInstructions: followUp,
  relatedComponents: [...related, ...(await accountVaults())],
  maxFee: MAX_FEE,
});

/**
 * The connected account's vaults. The wallet SDK (ootle-sdk 0.1.22) withdraws from the account's
 * XTM vault without declaring it as an input, and the network refuses the call ("vault not found");
 * passing the vaults as related components declares them (checked on esmeralda). In the account's
 * state a vault id is the CBOR tag 132 around its 32 bytes.
 */
async function accountVaults(): Promise<string[]> {
  const substate = await call<unknown>("tari_getSubstate", { substateId: connected });
  const found = JSON.stringify(substate).matchAll(/"tag":132,"value":\{"@cbor":"bytes","hex":"([0-9a-f]{64})"/g);
  return [...new Set([...found].map((m) => `vault_${m[1]}`))];
}

const method = (component: string, name: string, args: unknown[]) => ({ CallMethod: { call: { Address: component }, method: name, args } });

/** `list`, with the seller bond paid from the wallet. Returns the new component's address. */
export async function list(template: string, a: ListArgs, onWaiting: (note: string) => void): Promise<{ id: string; component: string }> {
  const args = [
    bytes(a.commitment),
    uint(a.price),
    uint(a.buyer_bond),
    uint(a.listing_window),
    uint(a.delivery_window),
    uint(a.dispute_window),
    bytes(a.seller_key),
    bytes(a.proof.c),
    bytes(a.proof.z),
    REVEALED,
  ];
  // CallFunction takes the template's bare Hash32: the "template_" prefix fails the wallet's seal
  // ("did not match any variant of untagged enum TransactionInput", checked with Sapient 0.6.12).
  const address = template.replace(/^template_/, "");
  const { id, result } = await transact(await fromBalance(a.seller_bond, [{ CallFunction: { address, function: "list", args } }]), onWaiting);
  return { id, component: await newComponent(id, result, template) };
}

/** `buy`, the price and buyer bond paid from the wallet. */
export async function buy(component: string, a: BuyArgs, onWaiting: (note: string) => void): Promise<string> {
  const args = [bytes(a.buyer_key), bytes(a.proof.c), bytes(a.proof.z), REVEALED];
  return (await transact(await fromBalance(a.payment, [method(component, "buy", args)], [component]), onWaiting)).id;
}

export async function deliver(component: string, a: DeliverArgs, onWaiting: (note: string) => void): Promise<string> {
  const args = [bytes(a.ephemeral), bytes(a.ephemeral_proof.c), bytes(a.ephemeral_proof.z), bytes(a.ciphertext), bytes(a.proof.c), bytes(a.proof.z)];
  return (await transact({ kind: "instructions", instructions: [method(component, "deliver", args)], maxFee: MAX_FEE }, onWaiting)).id;
}

export async function accept(component: string, proof: ProofHex, onWaiting: (note: string) => void): Promise<string> {
  const args = [bytes(proof.c), bytes(proof.z)];
  return (await transact({ kind: "instructions", instructions: [method(component, "accept", args)], maxFee: MAX_FEE }, onWaiting)).id;
}

/**
 * The Crypt component `list` created. Every component id the result mentions is a candidate; the
 * one whose substate names our template is it (the visitor's own account names another).
 */
async function newComponent(id: string, submitted: unknown, template: string): Promise<string> {
  const templateHex = template.replace(/^template_/, "");
  let text = JSON.stringify(submitted);
  if (!/component_[0-9a-f]{64}/.test(text)) text = JSON.stringify(await call<unknown>("tari_getTransactionResult", { transactionId: id }));
  for (const candidate of new Set(text.match(/component_[0-9a-f]{64}/g) ?? [])) {
    const substate = await call<unknown>("tari_getSubstate", { substateId: candidate }).catch(() => null);
    if (substate && JSON.stringify(substate).includes(templateHex)) return candidate;
  }
  throw new WalletError(`Listed (transaction ${id}), but the new component was not found in the result.`);
}
