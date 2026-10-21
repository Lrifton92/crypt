// The real thing: one sale on esmeralda, played by the visitor on both sides, paid privately from
// their own wallet (Sapient). The engine computes each step as the Crypt client does; the wallet
// signs and pays it.

import onchain from "./onchain.json";
import { play } from "./audio";
import { LiveSale } from "./engine";
import { button, h, short } from "./ui";
import * as wallet from "./wallet";

const TEMPLATE = (onchain as { template: { address: string } | null }).template?.address ?? "";
const EXPLORER = "https://explorer.tari.mw";
const SAPIENT = "https://sapient.tari.mw";
const XTM = 1_000_000;
const DEFAULT_SECRET = "The crypt's real key is under the third pumpkin.";

const xtm = (raw: number | bigint) => `${Number(raw) / XTM} XTM`;
const link = (url: string, text: string) => h("a", { href: url, target: "_blank", rel: "noopener" }, text);
const txLink = (id: string) => link(`${EXPLORER}/tx/${id.replace(/^0x/, "")}`, short(id.replace(/^0x/, ""), 10));

/** Builds the screen. `back` returns to the title. */
export function liveScreen(back: () => void): HTMLElement {
  const status = h("p", { class: "live-status", role: "status", "aria-live": "polite" });
  const steps = h("ol", { class: "live-steps" });
  const actions = h("div", { class: "row" });
  const say = (text: string, kind = "") => {
    status.textContent = text;
    status.className = `live-status ${kind}`.trim();
  };

  const screen = h(
    "section",
    { class: "screen live" },
    h("h2", { tabindex: "-1" }, "PLAY IT FOR REAL"),
    h(
      "p",
      { class: "lead" },
      "One real sale on the esmeralda testnet, through your own Tari wallet. You play both sides: you list a secret, buy it, deliver it sealed to your buyer key, open it and accept. The seller bond and the payment come out of your ",
      h("b", {}, "private"),
      " balance: the wallet reveals just the amount into the escrow, your account never pays it in the clear.",
    ),
    h(
      "div",
      { class: "pbox live-terms" },
      h("p", {}, `Price ${xtm(10 * XTM)} · buyer bond ${xtm(2 * XTM)} · seller bond ${xtm(3 * XTM)}: ${xtm(15 * XTM)} of private testnet XTM, plus four small fees.`),
      h(
        "p",
        { class: "warn" },
        "Testnet only. The payouts back to you are stealth transfers built by the Rust SDK, which a browser wallet cannot sign yet: the 15 XTM stay in the settled escrow. Reloading the page mid-sale abandons it.",
      ),
      h("p", {}, "Wallet: ", link(SAPIENT, "Sapient"), " (or any wallet behind ", h("code", {}, "window.tari"), ") on esmeralda. Contract: ", link(`${EXPLORER}/template/${TEMPLATE.replace(/^template_/, "")}`, short(TEMPLATE.replace(/^template_/, ""), 10)), "."),
    ),
    status,
    steps,
    actions,
    h("div", { class: "row" }, button("TITLE", back, "btn-ghost btn-small")),
  );

  const stepRow = (label: string) => {
    const li = h("li", {}, h("b", {}, label), h("span", { class: "live-tx" }, "…"));
    steps.append(li);
    return {
      done: (id: string) => {
        li.classList.add("done");
        li.querySelector(".live-tx")!.replaceChildren(txLink(id));
        play("coin");
      },
      fail: () => li.classList.add("failed"),
    };
  };

  const fail = (e: unknown) => {
    const err = e instanceof wallet.WalletError ? e : new wallet.WalletError(e instanceof Error ? e.message : String(e));
    say(err.code === 4001 ? "Cancelled in the wallet. Nothing more was sent." : err.message, "bad");
    play("curse");
  };

  if (!wallet.hasWallet()) {
    say("No Tari wallet on this page.", "bad");
    actions.append(h("p", {}, "Install ", link(SAPIENT, "the Sapient extension"), ", switch it to esmeralda, then reload this page."));
    return screen;
  }

  const connectBtn = button("CONNECT WALLET", () => void connectFlow(), "btn-big");
  actions.append(connectBtn);

  async function connectFlow(): Promise<void> {
    connectBtn.disabled = true;
    say("Waiting for the wallet…");
    try {
      let c = await wallet.connect();
      if (c.network.toLowerCase() !== wallet.NETWORK) {
        say(`Your wallet is on ${c.network}. Switch it to esmeralda, then connect again.`, "bad");
        connectBtn.disabled = false;
        return;
      }
      if (!c.stealthWithdraw) {
        say("This account cannot spend from a private balance (no view key). Use a seed-derived account.", "bad");
        connectBtn.disabled = false;
        return;
      }
      if (c.privateXtm === null && (await wallet.requestViewAccess())) c = await wallet.connect();
      const balance = c.privateXtm === null ? "private balance hidden" : `${xtm(c.privateXtm)} private`;
      say(`Connected: ${short(c.account.replace(/^component_/, ""), 10)} on esmeralda, ${balance}.`, "good");
      if (c.privateXtm !== null && c.privateXtm < BigInt(15 * XTM)) {
        actions.replaceChildren(h("p", {}, "You need at least 15 XTM in your private balance. Claim testnet XTM from Sapient's home screen, shield it, then connect again."));
        actions.append(button("CONNECT AGAIN", () => void connectFlow()));
        return;
      }
      secretForm();
    } catch (e) {
      fail(e);
      connectBtn.disabled = false;
    }
  }

  function secretForm(): void {
    const input = h("input", { type: "text", maxlength: "200", value: DEFAULT_SECRET, "aria-label": "The secret to sell", class: "live-secret" });
    const start = button("SEAL, LIST AND PLAY", () => void sale(input.value.trim() || DEFAULT_SECRET), "btn-big");
    actions.replaceChildren(h("label", { class: "live-label" }, "Your secret (it stays sealed on-chain):", input), start);
  }

  async function sale(secret: string): Promise<void> {
    actions.replaceChildren();
    steps.replaceChildren();
    let live: LiveSale;
    try {
      live = new LiveSale(secret);
    } catch (e) {
      fail(e);
      secretForm();
      return;
    }
    const waiting = (what: string) => () => say(`${what}: approve it in your wallet.`);
    let component = "";
    let current = stepRow("1 · list, seller bond paid privately");
    try {
      const listed = await wallet.list(TEMPLATE, live.list(), waiting("Listing"));
      component = listed.component;
      current.done(listed.id);
      steps.append(h("li", { class: "done" }, h("b", {}, "Your sale"), link(`${EXPLORER}/substate/${component}`, short(component.replace(/^component_/, ""), 10))));

      current = stepRow("2 · buy, paid privately");
      current.done(await wallet.buy(component, live.buy(component.replace(/^component_/, "")), waiting("Buying")));

      current = stepRow("3 · deliver, sealed to your buyer key");
      current.done(await wallet.deliver(component, live.deliver(), waiting("Delivering")));

      const accepted = live.accept();
      current = stepRow("4 · open, check the seal, accept");
      current.done(await wallet.accept(component, accepted.proof, waiting("Accepting")));

      say("Settled on-chain: Accepted. The template checked every proof.", "good");
      actions.replaceChildren(
        h("div", { class: "pbox live-secret-out" }, h("small", {}, "YOUR BUYER KEY OPENED"), h("p", {}, accepted.secret)),
        button("PLAY AGAIN", () => secretForm()),
      );
      play("justice");
    } catch (e) {
      current.fail();
      fail(e);
      actions.append(button("START OVER", () => secretForm()));
    }
  }

  return screen;
}
