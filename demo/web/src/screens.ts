// Every screen of the demo and the flow of a sale. The player takes one side, a scripted ghost the
// other; every step calls the real engine, and the verdict shows what it computed.

import attacks from "./attacks.json";
import onchain from "./onchain.json";
import { play, soundOn, toggleSound } from "./audio";
import {
  BUYER_BOND,
  DELIVERY_WINDOW,
  DISPUTE_WINDOW,
  MAX_SECRET_BYTES,
  PRICE,
  SELLER_BOND,
  Sale,
  errorMessage,
  type Disputed,
  type Opened,
  type Outcome,
  type State,
} from "./engine";
import { burst, coinsTo, pixelWipe } from "./fx";
import { BUYER, CHEST, COFFIN_LID, COFFIN_OPEN, COIN_FRAMES, GHOST_A, GHOST_B, SELLER, SKULL, sprite, strip } from "./sprites";
import { button, compareSeals, fact, h, short, sleep, typewrite } from "./ui";

type Role = "seller" | "buyer";
type Conduct = "honest" | "cheat";
type Ending = Exclude<Outcome, "Cancelled">;

const REPO = "https://github.com/Lrifton92/crypt";

const ENDINGS: Record<Ending, { name: string; cursed: Role | null; hint: string }> = {
  Accepted: { name: "A FAIR DEAL", cursed: null, hint: "Play honest, on either side." },
  Uncontested: { name: "SILENCE IS CONSENT", cursed: null, hint: "Sell honestly. The ghost may never answer." },
  Fraud: { name: "THE FORGER'S CURSE", cursed: "seller", hint: "Sell a fake, or buy from a ghost who does." },
  DisputeRejected: { name: "THE LIAR'S CURSE", cursed: "buyer", hint: "Buy, read the secret, then lie." },
  Undelivered: { name: "THE VANISHED SELLER", cursed: "seller", hint: "Buy honestly. The ghost may vanish." },
};
const ENDING_ORDER = Object.keys(ENDINGS) as Ending[];

const GHOST_SECRETS = [
  "The witch's gold lies under the third grave from the yew.",
  "Bone vault password: candle-raven-1666",
  "The vampire's real name is Gerald.",
  "North gate, thirteen steps, lift the cracked slab.",
];
const GHOST_FAKES = ["boo. there is no secret.", "this is definitely the secret (it is not)", "lol. nothing. enjoy."];

interface OnchainStep { step: string; tx: string; url: string }
interface OnchainSale { component: string; component_url: string; steps: OnchainStep[] }
interface Onchain {
  template: { address: string; url: string; sha256: string; tx_url: string; commit: string } | null;
  honest?: OnchainSale;
  fraud?: OnchainSale;
  sales: { Accepted?: OnchainStep; Fraud?: OnchainStep };
}
const ONCHAIN = onchain as unknown as Onchain;

const app = () => document.getElementById("app")!;
let run = 0;

function foundEndings(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem("crypt.endings") ?? "[]") as string[]);
  } catch {
    return new Set();
  }
}

function markFound(ending: Ending): boolean {
  const found = foundEndings();
  const isNew = !found.has(ending);
  found.add(ending);
  try {
    localStorage.setItem("crypt.endings", JSON.stringify([...found]));
  } catch {
    // Private mode: the tracker just forgets.
  }
  return isNew;
}

const pick = <T,>(items: T[]) => items[Math.floor(Math.random() * items.length)];

/** The ghost leans toward an ending the player has not seen yet. */
function ghostChoice<T>(options: { value: T; ending: Ending; weight: number }[]): T {
  const found = foundEndings();
  const unseen = options.filter((o) => !found.has(o.ending));
  if (unseen.length) return pick(unseen).value;
  const total = options.reduce((s, o) => s + o.weight, 0);
  let r = Math.random() * total;
  for (const o of options) if ((r -= o.weight) < 0) return o.value;
  return options[0].value;
}

async function mount(screen: HTMLElement): Promise<void> {
  await pixelWipe(() => {
    app().replaceChildren(screen);
    window.scrollTo(0, 0);
    screen.querySelector<HTMLElement>("h1, h2")?.focus({ preventScroll: true });
  });
}

function soundButton(): HTMLButtonElement {
  const b = button(soundOn() ? "SOUND: ON" : "SOUND: OFF", () => {
    b.querySelector("span")!.textContent = toggleSound() ? "SOUND: ON" : "SOUND: OFF";
  }, "btn-small btn-ghost");
  b.setAttribute("aria-pressed", String(soundOn()));
  return b;
}

function endingsBadge(): HTMLElement {
  return h("span", { class: "badge" }, `ENDINGS ${foundEndings().size}/${ENDING_ORDER.length}`);
}

function coin(): HTMLElement {
  return strip(COIN_FRAMES, "coin spin");
}

// ---------------------------------------------------------------------------------------------
// Title

export async function title(): Promise<void> {
  run++;
  const tagline = h("p", { class: "tagline" });
  const screen = h(
    "section",
    { class: "screen title" },
    h("div", { class: "title-top" }, endingsBadge(), soundButton()),
    h(
      "div",
      { class: "title-cast" },
      strip([SELLER], "actor-sprite bob"),
      h("div", { class: "title-coffin" }, sprite(COFFIN_LID, "coffin-sprite glow-green")),
      strip([GHOST_A, GHOST_B], "actor-sprite float ghosty"),
    ),
    h("h1", { class: "logo", "data-text": "CRYPT", tabindex: "-1" }, "CRYPT"),
    tagline,
    h(
      "div",
      { class: "title-actions" },
      button("PLAY", () => void choose(), "btn-big pulse"),
      button("ATTACKS REPELLED", () => void board(), "btn-ghost"),
    ),
    h(
      "p",
      { class: "fineprint" },
      "Played in your browser with the real Crypt client code, compiled to WebAssembly. Every verdict is the contract's own check, run on your sale. ",
      h("a", { href: REPO, target: "_blank", rel: "noopener" }, "Source"),
      " · ",
      h("a", { href: `${REPO}/blob/main/THREAT_MODEL.md`, target: "_blank", rel: "noopener" }, "Threat model"),
    ),
  );
  await mount(screen);
  await typewrite(tagline, "Sell a secret. Nobody judges but the crypt.", 40);
}

// ---------------------------------------------------------------------------------------------
// Choose a side and a conduct

async function choose(): Promise<void> {
  const id = ++run;
  const found = foundEndings();
  const step = h("div", { class: "choose-step" });
  const screen = h(
    "section",
    { class: "screen choose" },
    h("h2", { tabindex: "-1" }, "CHOOSE YOUR SIDE"),
    step,
    h(
      "div",
      { class: "endings pbox" },
      h("h3", {}, `ENDINGS FOUND ${found.size}/${ENDING_ORDER.length}`),
      h(
        "ul",
        {},
        ...ENDING_ORDER.map((e) =>
          h(
            "li",
            { class: found.has(e) ? "got" : "" },
            h("b", {}, found.has(e) ? ENDINGS[e].name : "? ? ?"),
            h("span", {}, ENDINGS[e].hint),
          ),
        ),
      ),
    ),
    h("div", { class: "row" }, button("BACK", () => void title(), "btn-small btn-ghost")),
  );
  const sideCard = (role: Role, art: HTMLElement, text: string) => {
    const b = h("button", { class: "card", type: "button" }, art, h("b", {}, role.toUpperCase()), h("span", {}, text));
    b.addEventListener("click", () => {
      play("click");
      showConduct(role);
    });
    return b;
  };
  const showConduct = (role: Role) => {
    if (id !== run) return;
    const other = role === "seller" ? "buyer" : "seller";
    const cheat =
      role === "seller"
        ? "Deliver a fake and hope nobody checks."
        : "Read the secret, then claim it was a fake.";
    const honest = role === "seller" ? "Deliver exactly what you sealed." : "Pay, open, judge fairly.";
    const card = (conduct: Conduct, label: string, text: string, cls: string) => {
      const b = h("button", { class: `card ${cls}`, type: "button" }, h("b", {}, label), h("span", {}, text));
      b.addEventListener("click", () => {
        play("click");
        void game(role, conduct);
      });
      return b;
    };
    step.replaceChildren(
      h("p", { class: "lead" }, `You are the ${role.toUpperCase()}. A ghost plays the ${other}. How do you play?`),
      h("div", { class: "cards" }, card("honest", "HONEST", honest, "card-honest"), card("cheat", "CHEAT", cheat, "card-cheat")),
    );
    step.querySelector<HTMLElement>(".card")?.focus();
  };
  step.append(
    h("p", { class: "lead" }, "A secret is sold through the crypt. Pick a side:"),
    h(
      "div",
      { class: "cards" },
      sideCard("seller", strip([SELLER], "card-sprite bob"), "Seal a secret, sell it, deliver it."),
      sideCard("buyer", strip([BUYER], "card-sprite bob"), "Buy a sealed secret, open it, judge it."),
    ),
  );
  await mount(screen);
}

// ---------------------------------------------------------------------------------------------
// The table: one sale, step by step

interface Facts {
  commitment?: string;
  sellerKey?: string;
  buyerKey?: string;
  ephemeral?: string;
  ephemeralProof?: { c: string; z: string };
  ciphertext?: string;
  opened?: Opened;
  disputed?: Disputed;
}

function table(role: Role) {
  const ghostRole: Role = role === "seller" ? "buyer" : "seller";
  const hud = {
    epoch: h("b", {}, "100"),
    vault: h("b", {}, "0"),
    stage: h("b", {}, "-"),
  };
  const you = h("figure", { class: "actor you" }, strip([role === "seller" ? SELLER : BUYER], "actor-sprite bob"), h("figcaption", {}, `YOU · ${role.toUpperCase()}`));
  const ghostSprite = strip([GHOST_A, GHOST_B], "actor-sprite float ghosty");
  const ghost = h("figure", { class: "actor ghost" }, ghostSprite, h("figcaption", {}, `GHOST · ${ghostRole.toUpperCase()}`));
  const lid = sprite(COFFIN_LID, "coffin-sprite lid");
  const vault = h(
    "figure",
    { class: "vault" },
    h("div", { class: "coffin" }, sprite(COFFIN_OPEN, "coffin-sprite"), lid),
    h("figcaption", {}, h("span", {}, "CRYPT VAULT"), h("span", { class: "vault-amount" }, coin(), hud.vault)),
  );
  const speaker = h("span", { class: "speaker" });
  const line = h("p", { class: "line", "aria-live": "polite" });
  const actions = h("div", { class: "actions" });
  const log = h("ol", { class: "log" });
  const quit = button("✕", () => void title(), "btn-small btn-ghost btn-quit");
  quit.setAttribute("aria-label", "Quit to title");
  const el = h(
    "section",
    { class: `screen table role-${role}` },
    h(
      "header",
      { class: "hud" },
      h("span", {}, "EPOCH ", hud.epoch),
      h("span", {}, "STAGE ", hud.stage),
      endingsBadge(),
      quit,
    ),
    h("h2", { class: "sr-only", tabindex: "-1" }, `You are the ${role}`),
    h("div", { class: "stage" }, you, vault, ghost),
    h("div", { class: "dialog pbox" }, speaker, line),
    actions,
    h("details", { class: "logbox pbox", open: "" }, h("summary", {}, "QUEST LOG · real calls"), log),
  );

  const update = (state: State) => {
    hud.epoch.textContent = String(state.epoch);
    hud.stage.textContent = (state.stage ?? "-").toUpperCase();
    hud.vault.textContent = String(state.escrow);
    hud.vault.parentElement?.classList.remove("bump");
    void hud.vault.parentElement?.offsetWidth;
    hud.vault.parentElement?.classList.add("bump");
  };
  const say = async (who: "YOU" | "GHOST" | "CRYPT", text: string) => {
    speaker.textContent = who;
    speaker.dataset.who = who.toLowerCase();
    await typewrite(line, text);
  };
  const choice = <T,>(options: { label: string; value: T; variant?: string }[]): Promise<T> =>
    new Promise((resolve) => {
      const buttons = options.map((o) =>
        button(o.label, () => {
          buttons.forEach((b) => (b.disabled = true));
          resolve(o.value);
        }, o.variant ?? ""),
      );
      actions.replaceChildren(...buttons);
      buttons[0]?.focus({ preventScroll: true });
    });
  const clear = () => actions.replaceChildren();
  const record = (call: string, ok: boolean, detail: string) => {
    log.append(h("li", { class: ok ? "ok" : "ko" }, h("b", {}, `${ok ? "✓" : "✗"} ${call}`), h("code", {}, detail)));
    log.scrollTop = log.scrollHeight;
  };
  const actorFor = (r: Role) => (r === role ? you : ghost);
  return { el, update, say, choice, clear, record, actorFor, vault, lid, ghost, ghostSprite };
}

type Table = ReturnType<typeof table>;

async function askSecret(t: Table, sale: Sale): Promise<string> {
  for (;;) {
    const input = h("textarea", { class: "secret-input", rows: "2", maxlength: "400", "aria-label": "Your secret", spellcheck: "false" });
    input.value = "The pumpkin king hides his crown in the well.";
    const counter = h("span", { class: "counter" });
    const error = h("p", { class: "error", role: "alert" });
    const count = () => {
      const n = new TextEncoder().encode(input.value).length;
      counter.textContent = `${n}/${MAX_SECRET_BYTES} BYTES`;
      counter.classList.toggle("over", n > MAX_SECRET_BYTES);
    };
    input.addEventListener("input", count);
    count();
    const submitted = new Promise<string>((resolve) => {
      const go = button("SEAL & LIST", () => resolve(input.value), "btn-big");
      t.el.querySelector(".actions")!.replaceChildren(h("label", { class: "field" }, h("span", {}, "YOUR SECRET"), input, counter), error, go);
      input.focus({ preventScroll: true });
    });
    const secret = await submitted;
    try {
      const listed = sale.list(secret);
      onListed(t, listed.commitment, listed.seller_key, listed.state);
      return secret;
    } catch (e) {
      error.textContent = errorMessage(e);
      t.record("list", false, errorMessage(e));
      await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    }
  }
}

let facts: Facts = {};

function onListed(t: Table, commitment: string, sellerKey: string, state: State): void {
  facts.commitment = commitment;
  facts.sellerKey = sellerKey;
  t.record("list", true, `seal ${short(commitment)} · seller bond ${SELLER_BOND}`);
  t.vault.classList.add("sealed");
  play("seal");
  t.update(state);
}

async function game(role: Role, conduct: Conduct): Promise<void> {
  const id = ++run;
  const alive = () => id === run;
  facts = {};
  const sale = new Sale();
  const t = table(role);
  const seller = t.actorFor("seller");
  const buyer = t.actorFor("buyer");
  await mount(t.el);
  t.update(sale.state());

  // 1. List.
  let secret: string;
  if (role === "seller") {
    await t.say("CRYPT", "Write a secret. The crypt seals it: anyone sees the seal, nobody sees the secret.");
    if (!alive()) return;
    secret = await askSecret(t, sale);
  } else {
    await t.say("GHOST", "Psst. A secret, sealed in the crypt. One hundred coins. Interested?");
    if (!alive()) return;
    secret = pick(GHOST_SECRETS);
    const listed = sale.list(secret);
    onListed(t, listed.commitment, listed.seller_key, listed.state);
  }
  t.clear();
  await coinsTo(seller, t.vault, SELLER_BOND / 3);
  if (!alive()) return;
  play("coin");
  await t.say("CRYPT", `Sealed: ${short(facts.commitment!, 12)}. The seller locked a ${SELLER_BOND}-coin bond.`);
  if (!alive()) return;

  // 2. Buy.
  if (role === "buyer") {
    await t.choice([{ label: `BUY · ${PRICE} + ${BUYER_BOND} BOND`, value: true, variant: "btn-big" }]);
  } else {
    await t.say("GHOST", "Ooooh. I'll take it. Here are my coins, and my bond.");
  }
  if (!alive()) return;
  const bought = sale.buy();
  facts.buyerKey = bought.buyer_key;
  t.clear();
  t.record("buy", true, `paid ${bought.paid} · buyer sale key ${short(bought.buyer_key)}`);
  await coinsTo(buyer, t.vault, bought.paid / 10);
  if (!alive()) return;
  play("coin");
  t.update(bought.state);
  await t.say("CRYPT", `The vault holds ${bought.state.escrow}. Delivery due by epoch ${bought.state.delivery_deadline}.`);
  if (!alive()) return;

  // 3. Deliver (or vanish).
  let ghostSeller: "honest" | "fake" | "vanish" = "honest";
  if (role === "buyer" && conduct === "honest") {
    ghostSeller = ghostChoice<"honest" | "fake" | "vanish">([
      { value: "honest", ending: "Accepted", weight: 2 },
      { value: "fake", ending: "Fraud", weight: 1 },
      { value: "vanish", ending: "Undelivered", weight: 1 },
    ]);
  }
  if (ghostSeller === "vanish") {
    t.ghost.classList.add("vanish");
    await t.say("GHOST", "Hehehe… *the ghost fades into the fog*");
    while (alive() && sale.state().epoch <= (sale.state().delivery_deadline ?? 0)) {
      await sleep(650);
      sale.advance(1);
      play("tick");
      t.update(sale.state());
    }
    if (!alive()) return;
    await t.say("CRYPT", `Epoch ${sale.state().epoch}. The delivery deadline has passed. Anyone may now claim it undelivered.`);
    await t.choice([{ label: "CLAIM UNDELIVERED", value: true, variant: "btn-big" }]);
    if (!alive()) return;
    const state = sale.claimUndelivered();
    t.record("claim_undelivered", true, `epoch ${state.epoch} > deadline ${state.delivery_deadline}`);
    return verdict(role, "Undelivered", sale);
  }

  let delivered;
  if (role === "seller") {
    if (conduct === "honest") {
      await t.say("CRYPT", "The buyer paid. Seal your secret to their key and deliver it.");
      await t.choice([{ label: "DELIVER THE TRUE SECRET", value: true, variant: "btn-big" }]);
      delivered = sale.deliverHonest();
    } else {
      await t.say("CRYPT", "The buyer paid. Deliver something… else?");
      const fake = h("input", { class: "secret-input", "aria-label": "Your fake secret", value: "nothing in here. boo." });
      const go = new Promise<string>((resolve) => {
        t.el.querySelector(".actions")!.replaceChildren(
          h("label", { class: "field" }, h("span", {}, "YOUR FAKE"), fake),
          button("DELIVER A FAKE", () => resolve(fake.value), "btn-big btn-curse"),
        );
      });
      const fakeText = await go;
      try {
        delivered = sale.deliverFake(fakeText);
      } catch (e) {
        await t.say("CRYPT", errorMessage(e));
        delivered = sale.deliverFake(pick(GHOST_FAKES));
      }
    }
  } else {
    await t.say("GHOST", ghostSeller === "fake" ? "Here, your secret. Totally the real one. Hehe." : "Here is your secret, sealed to your key.");
    delivered = ghostSeller === "fake" ? sale.deliverFake(pick(GHOST_FAKES)) : sale.deliverHonest();
  }
  if (!alive()) return;
  t.clear();
  facts.ephemeral = delivered.ephemeral;
  facts.ephemeralProof = delivered.ephemeral_proof;
  facts.ciphertext = delivered.ciphertext;
  t.record("deliver", true, `R ${short(delivered.ephemeral)} · ${delivered.ciphertext.length / 2} encrypted bytes`);
  t.vault.classList.add("delivered");
  burst(t.vault, "ghost", 24);
  t.update(delivered.state);
  await t.say("CRYPT", `Delivered. Only the buyer's key can open it. Dispute window: until epoch ${delivered.state.dispute_deadline}.`);
  if (!alive()) return;

  // 4. Decide.
  if (role === "buyer") {
    await t.choice([{ label: "OPEN IT", value: true, variant: "btn-big" }]);
    if (!alive()) return;
    const opened = sale.open();
    facts.opened = opened;
    t.record("open (your client)", opened.verdict === "ok", `hash ${short(opened.delivered_hash)} vs seal ${short(opened.promised_hash)}`);
    const seals = h("div", { class: "seals pbox" });
    t.el.querySelector(".actions")!.replaceChildren(seals);
    await compareSeals(seals, opened.delivered_hash, opened.promised_hash, 24);
    if (!alive()) return;
    if (opened.verdict === "ok") {
      await t.say("CRYPT", `It reads: “${opened.secret}”. It matches the seal.`);
    } else {
      await t.say("CRYPT", "It does NOT match the seal. Someone is lying.");
    }
    if (!alive()) return;
    const hint = conduct === "cheat" && opened.verdict === "ok" ? "You have the secret now. Claim it was a fake?" : "Accept, or dispute in front of the crypt.";
    await t.say("CRYPT", hint);
    const decision = await t.choice<"accept" | "dispute">(
      conduct === "cheat"
        ? [
            { label: "DISPUTE (LIE)", value: "dispute", variant: "btn-big btn-curse" },
            { label: "ACCEPT", value: "accept" },
          ]
        : [
            { label: "ACCEPT", value: "accept", variant: opened.verdict === "ok" ? "btn-big" : "" },
            { label: "DISPUTE", value: "dispute", variant: opened.verdict === "ok" ? "" : "btn-big btn-curse" },
          ],
    );
    if (!alive()) return;
    if (decision === "accept") {
      sale.accept();
      t.record("accept", true, "signed by the buyer's sale key over R");
      return verdict(role, "Accepted", sale);
    }
    return dispute(role, sale, t);
  }

  // The ghost buyer decides.
  const opened = sale.open();
  facts.opened = opened;
  t.record("open (ghost's client)", opened.verdict === "ok", `hash ${short(opened.delivered_hash)} vs seal ${short(opened.promised_hash)}`);
  if (opened.verdict !== "ok") {
    await t.say("GHOST", "This is NOT what you sealed! To the crypt!");
    return dispute(role, sale, t);
  }
  const silent = ghostChoice<boolean>([
    { value: false, ending: "Accepted", weight: 3 },
    { value: true, ending: "Uncontested", weight: 1 },
  ]);
  if (!silent) {
    await t.say("GHOST", "It matches the seal. A fair deal. I accept.");
    sale.accept();
    t.record("accept", true, "signed by the buyer's sale key over R");
    return verdict(role, "Accepted", sale);
  }
  await t.say("GHOST", "… … … *the ghost reads it and drifts away without a word*");
  while (alive() && sale.state().epoch <= (sale.state().dispute_deadline ?? 0)) {
    await sleep(650);
    sale.advance(1);
    play("tick");
    t.update(sale.state());
  }
  if (!alive()) return;
  await t.say("CRYPT", `Epoch ${sale.state().epoch}. The dispute window is closed. The deal stands.`);
  await t.choice([{ label: "CLAIM YOUR PAY", value: true, variant: "btn-big" }]);
  if (!alive()) return;
  const state = sale.claimUncontested();
  t.record("claim_uncontested", true, `epoch ${state.epoch} > deadline ${state.dispute_deadline}`);
  return verdict(role, "Uncontested", sale);
}

async function dispute(role: Role, sale: Sale, t: Table): Promise<void> {
  const disputed = sale.dispute();
  facts.disputed = disputed;
  t.record("dispute", true, `S ${short(disputed.shared)} · DLEQ c ${short(disputed.proof.c)}`);
  return verdict(role, disputed.outcome as Ending, sale);
}

// ---------------------------------------------------------------------------------------------
// Verdict

function story(role: Role, ending: Ending): string {
  const you = (r: Role) => r === role;
  switch (ending) {
    case "Accepted":
      return "Deal kept. The seller gets the price and their bond back; the buyer gets the secret and their bond back.";
    case "Uncontested":
      return "The buyer never answered. Once the dispute window closed, the deal stood as if accepted.";
    case "Fraud":
      return you("seller")
        ? "The crypt decrypted your delivery and hashed it. It is not what you sealed. The buyer takes everything: the price, their bond and yours."
        : "The ghost sold you a fake. The crypt decrypted it, hashed it, and caught the lie. Everything comes back to you, plus the seller's bond.";
    case "DisputeRejected":
      return you("buyer")
        ? "You lied. The crypt decrypted the delivery: it matches the seal exactly. The seller takes the price and your bond. And the secret is now public for everyone."
        : "The ghost cried fraud. The crypt decrypted your delivery: it matches your seal. You take the price and the liar's bond.";
    case "Undelivered":
      return you("buyer")
        ? "The seller vanished. Past the delivery deadline, the crypt pays you everything back, the seller's bond included."
        : "You never delivered. The crypt paid the buyer everything, your bond included.";
  }
}

async function verdict(role: Role, ending: Ending, sale: Sale): Promise<void> {
  const id = run;
  const alive = () => id === run;
  const state = sale.state();
  const info = ENDINGS[ending];
  const isNew = markFound(ending);
  const cursed = info.cursed;
  const playerCursed = cursed === role;
  const headline = cursed ? (playerCursed ? "YOU ARE CURSED" : "THE GHOST IS CURSED") : "JUSTICE";
  const mood = cursed ? "cursed" : "justice";
  const isDispute = ending === "Fraud" || ending === "DisputeRejected";

  const lid = sprite(COFFIN_LID, "coffin-sprite lid");
  const coffin = h("div", { class: "coffin big" }, sprite(COFFIN_OPEN, "coffin-sprite"), lid);
  const seals = h("div", { class: "seals pbox" });
  const contents = h("p", { class: "contents" });
  const sellerFig = h("figure", { class: "winner seller" }, strip([role === "seller" ? SELLER : GHOST_A], "actor-sprite"), h("figcaption", {}, role === "seller" ? "YOU · SELLER" : "GHOST · SELLER"), h("b", { class: "owed" }, "+0"));
  const buyerFig = h("figure", { class: "winner buyer" }, strip([role === "buyer" ? BUYER : GHOST_A], "actor-sprite"), h("figcaption", {}, role === "buyer" ? "YOU · BUYER" : "GHOST · BUYER"), h("b", { class: "owed" }, "+0"));
  const mark = sprite(cursed ? SKULL : CHEST, `mark ${mood}`);
  const head = h("h1", { class: `headline ${mood}`, "data-text": headline, tabindex: "-1" }, headline);
  // Dispute verdicts carry the DLEQ line; every verdict links the real esmeralda sale it mirrors.
  const dleq = h("p", { class: "dleq" }, isDispute ? "✓ DLEQ proof verified: same check as the contract" : "");
  const real =
    ending === "Fraud"
      ? [ONCHAIN.sales.Fraud, "see this verdict on-chain"]
      : ending === "DisputeRejected"
        ? [ONCHAIN.sales.Fraud, "see a DLEQ proof verified on-chain"]
        : ending === "Accepted" || ending === "Uncontested"
          ? [ONCHAIN.sales.Accepted, "an honest sale, accepted on-chain on esmeralda"]
          : [undefined, ""];
  const [realStep, realLabel] = real as [OnchainStep | undefined, string];
  if (realStep) {
    if (isDispute) dleq.append(" · ");
    else dleq.append("Played for real: ");
    dleq.append(h("a", { href: realStep.url, target: "_blank", rel: "noopener" }, realLabel));
  }

  const checked = h("dl", {});
  const add = (label: string, value: string | undefined, note = "") => value && checked.append(fact(label, value, note));
  add("Promised seal (commitment)", facts.commitment, "SHA-512 of the salted, padded block, set at list");
  add("Seller key", facts.sellerKey, "one key per listing");
  add("Buyer sale key B'", facts.buyerKey, "registered at buy, with a Schnorr proof");
  add("Ephemeral key R", facts.ephemeral, "with a proof the seller knows r");
  if (facts.ephemeralProof) add("Proof of r (c, z)", `${facts.ephemeralProof.c} ${facts.ephemeralProof.z}`);
  if (facts.ciphertext) add("Ciphertext (320 bytes)", `${facts.ciphertext.slice(0, 64)}…`);
  if (facts.disputed) {
    add("Shared point S = b'·R", facts.disputed.shared, "published by the dispute");
    add("DLEQ proof (c, z)", `${facts.disputed.proof.c} ${facts.disputed.proof.z}`, "log_G(B') = log_R(S)");
    add("Hash of what the crypt decrypted", facts.disputed.delivered_hash, facts.disputed.delivered_hash === facts.disputed.promised_hash ? "= the seal" : "≠ the seal");
  } else if (facts.opened) {
    add("Hash of what the buyer opened", facts.opened.delivered_hash, facts.opened.verdict === "ok" ? "= the seal" : "≠ the seal");
  }
  add("Epoch now", String(state.epoch));
  if (state.delivery_deadline !== undefined) add("Delivery deadline", String(state.delivery_deadline), "inclusive");
  if (state.dispute_deadline !== undefined) add("Dispute deadline", String(state.dispute_deadline), "inclusive");
  add("Split (seller / buyer)", `${state.owed[0]} / ${state.owed[1]}`, `escrow ${state.escrow}: nothing created, nothing lost`);
  add("Terms", `price ${PRICE} · buyer bond ${BUYER_BOND} · seller bond ${SELLER_BOND} · windows ${DELIVERY_WINDOW}/${DISPUTE_WINDOW}`);

  const actions = h(
    "div",
    { class: "actions verdict-actions" },
    button("PLAY AGAIN", () => void choose(), "btn-big"),
    button("ATTACKS REPELLED", () => void board(), "btn-ghost"),
    button("TITLE", () => void title(), "btn-ghost btn-small"),
  );
  const screen = h(
    "section",
    { class: `screen verdict mood-${mood}` },
    h("div", { class: "verdict-stage" }, sellerFig, h("div", { class: "verdict-coffin" }, coffin, mark), buyerFig),
    head,
    h("p", { class: "ending-name" }, `ENDING · ${info.name}`, isNew ? h("span", { class: "new" }, " NEW!") : null, ` · ${foundEndings().size}/${ENDING_ORDER.length}`),
    h("p", { class: "story" }, story(role, ending)),
    contents,
    seals,
    dleq.childNodes.length ? dleq : null,
    h("details", { class: "checked pbox" }, h("summary", {}, "WHAT THE CONTRACT CHECKED"), checked),
    actions,
  );
  seals.hidden = true;
  head.classList.add("hidden");
  actions.classList.add("hidden");
  dleq.classList.add("hidden");
  await mount(screen);

  // The coffin opens.
  await sleep(250);
  play("creak");
  coffin.classList.add("open");
  await sleep(900);
  if (!alive()) return;
  const revealed = facts.disputed?.revealed ?? (facts.opened?.verdict === "ok" ? facts.opened.secret : undefined);
  if (ending === "Undelivered") contents.textContent = "Inside: nothing. It was never delivered.";
  else if (revealed !== undefined) contents.textContent = `Inside: “${revealed}”`;
  else contents.textContent = "Inside: bytes that decode to nothing.";
  contents.classList.add("show");

  const hashes = facts.disputed ?? facts.opened;
  if (hashes) {
    seals.hidden = false;
    await compareSeals(seals, hashes.delivered_hash, hashes.promised_hash, 32);
  }
  if (!alive()) return;

  // The verdict.
  head.classList.remove("hidden");
  burst(head, cursed ? "curse" : "justice", 70);
  play(cursed ? "curse" : "justice");
  if (cursed) document.body.classList.add("shake");
  window.setTimeout(() => document.body.classList.remove("shake"), 500);
  dleq.classList.remove("hidden");
  await sleep(500);
  if (!alive()) return;

  // The treasure goes where it is owed.
  const [toSeller, toBuyer] = state.owed;
  const pay = async (fig: HTMLElement, amount: number) => {
    if (!amount) return;
    await coinsTo(coffin, fig, amount / 10);
    play("coin");
    fig.querySelector(".owed")!.textContent = `+${amount}`;
    fig.classList.add("paid");
  };
  await Promise.all([pay(sellerFig, toSeller), pay(buyerFig, toBuyer)]);
  if (cursed) (cursed === "seller" ? sellerFig : buyerFig).classList.add("is-cursed");
  if (!alive()) return;
  actions.classList.remove("hidden");
  actions.querySelector<HTMLElement>("button")?.focus({ preventScroll: true });
}

// ---------------------------------------------------------------------------------------------
// Attacks repelled

interface Attack { attack: string; defence: string; tests: string[] }

async function board(): Promise<void> {
  run++;
  const groups = attacks as { section: string; rows: Attack[] }[];
  const rows = groups.flatMap((g) => g.rows);
  const tested = rows.filter((r) => r.tests.length).length;
  const screen = h(
    "section",
    { class: "screen board" },
    h("h2", { tabindex: "-1" }, "ATTACKS REPELLED"),
    h(
      "p",
      { class: "lead" },
      `${rows.length} attacks from the threat model. ${tested} are played against the real contract in CI on every change; ${rows.length - tested === 1 ? "one holds" : `${rows.length - tested} hold`} by construction. `,
      h(
        "a",
        { href: `${REPO}/actions/workflows/ci.yml`, target: "_blank", rel: "noopener" },
        h("img", { src: `${REPO}/actions/workflows/ci.yml/badge.svg`, alt: "CI status", class: "ci-badge" }),
      ),
    ),
    onchainBoard(),
    ...groups.map((g) =>
      h(
        "div",
        { class: "attack-group pbox" },
        h("h3", {}, g.section.toUpperCase()),
        h(
          "ul",
          {},
          ...g.rows.map((r, i) =>
            h(
              "li",
              { style: `--i:${i}` },
              r.tests.length
                ? h("span", { class: "stamp" }, "REPELLED")
                : h("span", { class: "stamp design" }, "BY DESIGN"),
              h("b", {}, r.attack),
              h("span", {}, r.defence),
              h(
                "small",
                {},
                r.tests.length
                  ? `${r.tests.length} test${r.tests.length === 1 ? "" : "s"}: ${r.tests.join(", ")}`
                  : "Holds by construction; no test plays it.",
              ),
            ),
          ),
        ),
      ),
    ),
    h("div", { class: "row" }, button("PLAY", () => void choose(), "btn-big"), button("TITLE", () => void title(), "btn-ghost btn-small")),
  );
  await mount(screen);
}

/** The two sales played for real on esmeralda, every transaction linked to the explorer. */
function onchainBoard(): HTMLElement | null {
  const t = ONCHAIN.template;
  if (!t || !ONCHAIN.honest || !ONCHAIN.fraud) return null;
  const link = (url: string, text: string) => h("a", { href: url, target: "_blank", rel: "noopener" }, text);
  const sale = (title: string, s: OnchainSale) =>
    h(
      "li",
      {},
      h("b", {}, title),
      h("span", { class: "steps" }, ...s.steps.flatMap((step, i) => [i ? " → " : "", link(step.url, step.step)])),
      h("small", {}, link(s.component_url, s.component)),
    );
  return h(
    "div",
    { class: "attack-group onchain pbox" },
    h("h3", {}, "PLAYED FOR REAL ON ESMERALDA"),
    h(
      "p",
      { class: "onchain-lead" },
      "The same contract, published on the Tari Ootle testnet, with two real sales. Every step links to the ",
      link("https://explorer.tari.mw", "Veil explorer"),
      ".",
    ),
    h(
      "ul",
      {},
      h("li", {}, h("b", {}, "Template"), link(t.url, t.address), h("small", {}, "published from commit ", t.commit, " · wasm sha256 ", t.sha256, " · ", link(t.tx_url, "publish tx"))),
      sale("An honest sale, accepted, both sides paid", ONCHAIN.honest),
      sale("A fake delivery, disputed: the template decrypted it, ruled Fraud, paid the buyer everything", ONCHAIN.fraud),
    ),
  );
}
