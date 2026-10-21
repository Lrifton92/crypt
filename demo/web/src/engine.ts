// Typed access to the crypt engine (crypt_core + the rules port, compiled to WebAssembly).

import init, { Game, LiveSale } from "../../wasm/pkg/crypt_wasm.js";

export { LiveSale };

export const PRICE = 100;
export const BUYER_BOND = 20;
export const SELLER_BOND = 30;
export const DELIVERY_WINDOW = 3;
export const DISPUTE_WINDOW = 3;
export const MAX_SECRET_BYTES = 286;

export type Outcome = "Accepted" | "Uncontested" | "Undelivered" | "DisputeRejected" | "Fraud" | "Cancelled";

export interface State {
  stage?: "Listed" | "Paid" | "Delivered" | "Settled";
  outcome?: Outcome;
  owed: [number, number];
  escrow: number;
  epoch: number;
  listing_deadline?: number;
  delivery_deadline?: number;
  dispute_deadline?: number;
}
export interface ProofHex { c: string; z: string }
export interface Listed { commitment: string; seller_key: string; secret_bytes: number; state: State }
export interface Bought { buyer_key: string; paid: number; state: State }
export interface Delivered { ephemeral: string; ephemeral_proof: ProofHex; ciphertext: string; state: State }
export interface Opened { secret?: string; verdict: "ok" | "mismatch" | "malformed"; delivered_hash: string; promised_hash: string }
export interface Disputed {
  outcome: Outcome;
  shared: string;
  proof: ProofHex;
  delivered_hash: string;
  promised_hash: string;
  revealed?: string;
  state: State;
}

export async function loadEngine(): Promise<void> {
  await init();
}

/** Thrown by the engine when the template would refuse a step; `message` is readable as is. */
export const errorMessage = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** One sale, played by the real client code and the template's rules. */
export class Sale {
  private game = new Game();
  list = (secret: string): Listed => this.game.list(secret, PRICE, BUYER_BOND, SELLER_BOND);
  buy = (): Bought => this.game.buy();
  deliverHonest = (): Delivered => this.game.deliver_honest();
  deliverFake = (fake: string): Delivered => this.game.deliver_fake(fake);
  open = (): Opened => this.game.buyer_open();
  accept = (): State => this.game.accept();
  dispute = (): Disputed => this.game.dispute();
  advance = (n: number): void => this.game.advance_epochs(n);
  claimUndelivered = (): State => this.game.claim_undelivered();
  claimUncontested = (): State => this.game.claim_uncontested();
  state = (): State => this.game.state();
}
