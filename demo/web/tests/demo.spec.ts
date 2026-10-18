import { expect, test, type Page } from "@playwright/test";

// The ghost always heads for an ending the player has not found yet, so pre-filling the found
// endings decides which way it goes.
async function start(page: Page, found: string[] = []): Promise<void> {
  await page.addInitScript((f) => localStorage.setItem("crypt.endings", JSON.stringify(f)), found);
  await page.goto("./");
  await expect(page.locator(".logo")).toBeVisible();
}

async function press(page: Page, label: string | RegExp): Promise<void> {
  const button = page.getByRole("button", { name: label }).first();
  await expect(button).toBeEnabled({ timeout: 60_000 });
  await button.click();
}

async function pick(page: Page, side: "SELLER" | "BUYER", conduct: "HONEST" | "CHEAT"): Promise<void> {
  await press(page, "PLAY");
  await press(page, side);
  await press(page, conduct);
}

async function noHorizontalScroll(page: Page): Promise<void> {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
}

async function expectVerdict(page: Page, headline: string, ending: string, split: string): Promise<void> {
  await expect(page.locator(".verdict-actions")).not.toHaveClass(/hidden/, { timeout: 60_000 });
  await expect(page.locator(".headline")).toHaveText(headline);
  await expect(page.locator(".ending-name")).toContainText(ending);
  await page.locator(".checked summary").click();
  await expect(page.locator(".checked")).toContainText(split);
  await noHorizontalScroll(page);
}

test("an honest seller gets a fair deal", async ({ page }) => {
  await start(page, ["Uncontested"]);
  await pick(page, "SELLER", "HONEST");
  await noHorizontalScroll(page);
  await press(page, "SEAL & LIST");
  await press(page, "DELIVER THE TRUE SECRET");
  await expectVerdict(page, "JUSTICE", "A FAIR DEAL", "130 / 20");
});

test("a seller who delivers a fake is cursed", async ({ page }) => {
  await start(page);
  await pick(page, "SELLER", "CHEAT");
  await press(page, "SEAL & LIST");
  await press(page, "DELIVER A FAKE");
  await expectVerdict(page, "YOU ARE CURSED", "THE FORGER'S CURSE", "0 / 150");
  await expect(page.locator(".dleq")).toContainText("DLEQ proof verified");
  await expect(page.locator(".dleq a")).toHaveAttribute("href", /^https:\/\/explorer\.tari\.mw\/tx\/[0-9a-f]{64}$/);
  await expect(page.locator(".seals .nib.diff").first()).toBeVisible();
});

test("a buyer who lies about the delivery is cursed", async ({ page }) => {
  await start(page);
  await pick(page, "BUYER", "CHEAT");
  await press(page, /^BUY/);
  await press(page, "OPEN IT");
  await press(page, "DISPUTE (LIE)");
  await expectVerdict(page, "YOU ARE CURSED", "THE LIAR'S CURSE", "150 / 0");
  await expect(page.locator(".contents")).toContainText("Inside:");
});

test("an honest buyer catches a forging ghost", async ({ page }) => {
  await start(page, ["Accepted", "Undelivered"]);
  await pick(page, "BUYER", "HONEST");
  await press(page, /^BUY/);
  await press(page, "OPEN IT");
  // The line that says so is replaced a moment later; the log and the seals keep the evidence.
  await expect(page.locator(".log .ko")).toContainText("open (your client)", { timeout: 60_000 });
  await expect(page.locator(".seals .nib.diff").first()).toBeVisible();
  await press(page, "DISPUTE");
  await expectVerdict(page, "THE GHOST IS CURSED", "THE FORGER'S CURSE", "0 / 150");
});

test("a seller who vanishes pays the buyer everything", async ({ page }) => {
  await start(page, ["Accepted", "Fraud"]);
  await pick(page, "BUYER", "HONEST");
  await press(page, /^BUY/);
  await press(page, "CLAIM UNDELIVERED");
  await expectVerdict(page, "THE GHOST IS CURSED", "THE VANISHED SELLER", "0 / 150");
});

test("a reload in the middle of a sale starts clean on the title", async ({ page }) => {
  await start(page);
  await pick(page, "SELLER", "HONEST");
  await expect(page.locator(".secret-input")).toBeVisible();
  await page.reload();
  await expect(page.locator(".logo")).toBeVisible();
  await expect(page.locator(".table")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "PLAY" })).toBeVisible();
});

test("a game left while the ghost disputes never shows its verdict", async ({ page }) => {
  await start(page);
  await pick(page, "SELLER", "CHEAT");
  await press(page, "SEAL & LIST");
  await press(page, "DELIVER A FAKE");
  await page.getByRole("button", { name: "Quit to title" }).click();
  await expect(page.locator(".logo")).toBeVisible();
  await page.waitForTimeout(9_000);
  await expect(page.locator(".verdict")).toHaveCount(0);
  await expect(page.locator(".logo")).toBeVisible();
});

test("double clicks never bring an older screen back", async ({ page }) => {
  // A double click may count as two clicks: the second lands on whatever appeared under the
  // pointer, so the game may skip a step. What must never happen: an older screen coming back over
  // a newer one, or a game left frozen.
  const oneScreen = async () => {
    await page.waitForTimeout(1_500);
    expect(await page.locator("#app > section").count()).toBe(1);
    return (await page.locator("#app > section").getAttribute("class")) ?? "";
  };
  const visible = (name: string) => page.getByRole("button", { name }).first().isVisible();
  await start(page);
  await page.getByRole("button", { name: "PLAY" }).dblclick();
  expect(await oneScreen()).toContain("choose");
  if (await visible("SELLER")) {
    await page.getByRole("button", { name: "SELLER" }).first().dblclick();
    await oneScreen();
  }
  if (await visible("HONEST")) {
    await page.getByRole("button", { name: "HONEST" }).first().dblclick();
  }
  expect(await oneScreen()).toContain("table");
  // The side is on the table from the start; the secret field only shows after the first line.
  if ((await page.locator(".table.role-seller").count()) === 1) {
    await press(page, "SEAL & LIST");
    await expect(page.getByRole("button", { name: "DELIVER THE TRUE SECRET" })).toBeEnabled({ timeout: 60_000 });
  } else {
    await press(page, /^BUY/);
    await expect(page.getByRole("button", { name: /OPEN IT|CLAIM UNDELIVERED/ })).toBeEnabled({ timeout: 60_000 });
  }
  expect(await oneScreen()).toContain("table");
});

test("a browser that cannot load the engine gets a clear message", async ({ page }) => {
  await page.route("**/*.wasm", (route) => route.abort());
  await page.goto("./");
  await expect(page.locator("#boot")).toContainText("Your browser could not load the crypt engine");
});

test("the attacks board lists the threat model", async ({ page }) => {
  await start(page);
  await press(page, "ATTACKS REPELLED");
  await expect(page.locator(".attack-group").first()).toBeVisible();
  expect(await page.locator(".attack-group li").count()).toBeGreaterThan(30);
  // The two real esmeralda sales: the template, then 6 + 5 transactions, each linked.
  expect(await page.locator(".onchain .steps a").count()).toBe(11);
  await noHorizontalScroll(page);
});

test.describe("with reduced motion", () => {
  test.use({ reducedMotion: "reduce" });

  test("the coffin opens without animating", async ({ page }) => {
    await start(page);
    await pick(page, "SELLER", "CHEAT");
    await press(page, "SEAL & LIST");
    await press(page, "DELIVER A FAKE");
    await expect(page.locator(".verdict-actions")).not.toHaveClass(/hidden/, { timeout: 60_000 });
    const lid = page.locator(".verdict .lid");
    expect(await lid.evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
    expect(await page.locator(".logo, .sprite").first().evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
  });
});
