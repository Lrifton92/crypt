// Small DOM helpers: elements, pixel buttons, the typewriter, the seal comparison.

import { play } from "./audio";
import { reducedMotion } from "./fx";

type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Record<string, string> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") el.className = v;
    else el.setAttribute(k, v);
  }
  for (const c of children) if (c) el.append(c);
  return el;
}

export const sleep = (ms: number) => new Promise<void>((r) => window.setTimeout(r, reducedMotion.matches ? 0 : ms));

export function button(label: string, onClick: () => void, variant = ""): HTMLButtonElement {
  const b = h("button", { class: `btn ${variant}`.trim(), type: "button" }, h("span", {}, label));
  b.addEventListener("click", () => {
    play("click");
    onClick();
  });
  return b;
}

/** Types `text` into `el` one character at a time. */
export async function typewrite(el: HTMLElement, text: string, speed = 22): Promise<void> {
  el.classList.add("typing");
  if (reducedMotion.matches) {
    el.textContent = text;
  } else {
    el.textContent = "";
    for (const ch of Array.from(text)) {
      el.textContent += ch;
      if (ch !== " ") play("type");
      await new Promise((r) => window.setTimeout(r, speed));
    }
  }
  el.classList.remove("typing");
}

export const short = (hex: string, n = 8) => `0x${hex.slice(0, n)}…${hex.slice(-4)}`;

/**
 * Two hashes, revealed nibble by nibble. Equal nibbles light up green, different ones red: the
 * same comparison the template makes byte for byte.
 */
export async function compareSeals(host: HTMLElement, delivered: string, promised: string, nibbles = 32): Promise<boolean> {
  const rows = [
    ["DELIVERED", delivered],
    ["PROMISED SEAL", promised],
  ] as const;
  const cells: HTMLSpanElement[][] = [];
  for (const [label, hex] of rows) {
    const line = h("div", { class: "seal-row" }, h("span", { class: "seal-label" }, label));
    const code = h("code", { class: "seal-hex" });
    const row: HTMLSpanElement[] = [];
    for (let i = 0; i < nibbles; i++) {
      const c = h("span", { class: "nib" }, "·");
      c.dataset.v = hex[i];
      row.push(c);
      code.append(c);
    }
    code.append(h("span", { class: "nib dim" }, "…"));
    line.append(code);
    host.append(line);
    cells.push(row);
  }
  for (let i = 0; i < nibbles; i++) {
    const same = delivered[i] === promised[i];
    for (const row of cells) {
      row[i].textContent = row[i].dataset.v ?? "";
      row[i].classList.add(same ? "same" : "diff");
    }
    if (i % 4 === 0) play("tick");
    await sleep(28);
  }
  return delivered === promised;
}

/** A label/value line for the "What the contract checked" panel. */
export function fact(label: string, value: string, note = ""): HTMLElement {
  return h(
    "div",
    { class: "fact" },
    h("dt", {}, label),
    h("dd", {}, h("code", { title: value }, value), note ? h("small", {}, note) : null),
  );
}
