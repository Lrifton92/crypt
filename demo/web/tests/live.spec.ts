import { expect, test, type Page } from "@playwright/test";

const COMPONENT = `component_${"c".repeat(64)}`;
const ACCOUNT = `component_${"a".repeat(64)}`;
const VAULT = "d".repeat(64);

// A stand-in for Sapient's window.tari: approves everything and records what the page asked for.
async function fakeWallet(page: Page, opts: { network?: string; publicXtm?: string; reject?: boolean } = {}): Promise<void> {
  await page.addInitScript(
    ({ COMPONENT, ACCOUNT, VAULT, network, publicXtm, reject }) => {
      const ops: unknown[] = [];
      let n = 0;
      (window as unknown as { __ops: unknown[] }).__ops = ops;
      (window as unknown as { tari: unknown }).tari = {
        async request({ method, params }: { method: string; params?: Record<string, unknown> }) {
          switch (method) {
            case "tari_requestAccounts":
              return [ACCOUNT];
            case "tari_getNetwork":
              return network;
            case "tari_getCapabilities":
              return { stealthWithdraw: true };
            case "tari_getBalances":
              return [{ resourceAddress: `resource_${"01".repeat(32)}`, amount: publicXtm, confidentialAmount: "0" }];
            case "tari_createTransactionRequest":
              ops.push(params);
              return { requestId: `r${++n}` };
            case "tari_getTransactionRequest":
              return reject ? { status: "rejected", error: "no" } : { status: "approved", note: "" };
            case "tari_submitTransactionRequest":
              return { transactionId: `${n}`.padStart(64, "0"), result: { upped: [ACCOUNT, COMPONENT] } };
            case "tari_getSubstate":
              if (params?.substateId === COMPONENT) return { template_address: "b7282faa09858bc1ca1257734d5e2739135c7ed29edec8a51d6b86d8225a61bf" };
              // The account's state, as the indexer gives it: its vault is CBOR tag 132.
              return { state: { up: { substate: { Component: { body: { state: [{ "@cbor": "map", entries: [[{ "@cbor": "tag", tag: 131, value: { "@cbor": "bytes", hex: "01".repeat(32) } }, { "@cbor": "tag", tag: 132, value: { "@cbor": "bytes", hex: VAULT } }]] }] } } } } } };
            default:
              throw Object.assign(new Error(`unexpected ${method}`), { code: 4200 });
          }
        },
      };
    },
    { COMPONENT, ACCOUNT, VAULT, network: opts.network ?? "esmeralda", publicXtm: opts.publicXtm ?? "50000000", reject: opts.reject ?? false },
  );
}

async function open(page: Page): Promise<void> {
  await page.goto("./");
  await page.getByRole("button", { name: "ON-CHAIN · SAPIENT" }).click();
  await expect(page.getByRole("heading", { name: "PLAY IT FOR REAL" })).toBeVisible();
}

type Op = { kind: string; amount?: string; relatedComponents?: string[]; followUpInstructions?: Record<string, { args: { Literal?: string }[]; address?: string; function?: string; method?: string }>[]; instructions?: Record<string, { method: string; args: { Literal?: string }[] }>[] };

test("a full sale goes through the wallet, paid from the public balance", async ({ page }) => {
  await fakeWallet(page);
  await open(page);
  await page.getByRole("button", { name: "CONNECT WALLET" }).click();
  await expect(page.locator(".live-status")).toContainText("50 XTM public");
  await page.getByRole("textbox", { name: "The secret to sell" }).fill("the bat flies at midnight");
  await page.getByRole("button", { name: "SEAL, LIST AND PLAY" }).click();
  await expect(page.locator(".live-status")).toContainText("Accepted", { timeout: 60_000 });
  await expect(page.locator(".live-secret-out")).toContainText("the bat flies at midnight");
  await expect(page.locator(".live-steps li.done")).toHaveCount(5);
  await expect(page.locator(".live-steps a").first()).toHaveAttribute("href", /^https:\/\/explorer\.tari\.mw\/tx\/0{63}1$/);

  const ops = (await page.evaluate(() => (window as unknown as { __ops: unknown[] }).__ops)) as Op[];
  expect(ops.map((o) => o.kind)).toEqual(["withdrawStealthAndExecute", "withdrawStealthAndExecute", "instructions", "instructions"]);

  // list: the seller bond, revealed into workspace 1, then the template function; the account's
  // vault declared (the wallet SDK leaves it out).
  expect(ops[0].amount).toBe("3000000");
  expect(ops[0].relatedComponents).toEqual([`vault_${VAULT}`]);
  const list = ops[0].followUpInstructions![0].CallFunction;
  expect(list.address).toBe("template_b7282faa09858bc1ca1257734d5e2739135c7ed29edec8a51d6b86d8225a61bf");
  expect(list.function).toBe("list");
  const la = list.args;
  expect(la).toHaveLength(10);
  // Encodings checked against tari_bor 0.16 (Hash64, Amount, u64, point, scalar).
  expect(la[0].Literal).toMatch(/^5840[0-9a-f]{128}$/);
  expect(la[1].Literal).toBe("1a00989680"); // 10 XTM
  expect(la[2].Literal).toBe("1a001e8480"); // 2 XTM
  expect(la[3].Literal).toBe("18c8"); // 200 epochs
  expect(la[4].Literal).toBe("1864");
  for (const i of [6, 7, 8]) expect(la[i].Literal).toMatch(/^5820[0-9a-f]{64}$/);
  expect(la[9]).toEqual({ Workspace: { id: 1, offset: null } });

  // buy: price + buyer bond, the component and the account's vault registered as related.
  expect(ops[1].amount).toBe("12000000");
  expect(ops[1].relatedComponents).toEqual([COMPONENT, `vault_${VAULT}`]);
  const buy = ops[1].followUpInstructions![0].CallMethod as unknown as { call: { Address: string }; method: string; args: unknown[] };
  expect(buy.call.Address).toBe(COMPONENT);
  expect(buy.method).toBe("buy");
  expect(buy.args).toHaveLength(4);

  // deliver: R, its proof, the 320-byte block (59 01 40), the seller proof. accept: one proof.
  const deliver = ops[2].instructions![0].CallMethod;
  expect(deliver.method).toBe("deliver");
  expect(deliver.args[3].Literal).toMatch(/^590140[0-9a-f]{640}$/);
  expect(ops[3].instructions![0].CallMethod.method).toBe("accept");
});

test("a wallet on another network is told to switch", async ({ page }) => {
  await fakeWallet(page, { network: "igor" });
  await open(page);
  await page.getByRole("button", { name: "CONNECT WALLET" }).click();
  await expect(page.locator(".live-status")).toContainText("Switch it to esmeralda");
});

test("too little public XTM stops before anything is signed", async ({ page }) => {
  await fakeWallet(page, { publicXtm: "1000000" });
  await open(page);
  await page.getByRole("button", { name: "CONNECT WALLET" }).click();
  await expect(page.getByText("about 16 XTM")).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { __ops: unknown[] }).__ops.length)).toBe(0);
});

test("a refusal in the wallet stops the sale quietly", async ({ page }) => {
  await fakeWallet(page, { reject: true });
  await open(page);
  await page.getByRole("button", { name: "CONNECT WALLET" }).click();
  await page.getByRole("button", { name: "SEAL, LIST AND PLAY" }).click();
  await expect(page.locator(".live-status")).toContainText("Cancelled in the wallet");
  expect(await page.evaluate(() => (window as unknown as { __ops: unknown[] }).__ops.length)).toBe(1);
});

test("without a wallet the page points to Sapient", async ({ page }) => {
  await open(page);
  await expect(page.getByRole("link", { name: "the Sapient extension" })).toHaveAttribute("href", "https://sapient.tari.mw");
});
