// Hand-drawn pixel sprites. Each is a grid of palette keys ('.' is transparent), rendered once to a
// tiny canvas and scaled up by CSS with `image-rendering: pixelated`.

export const PALETTE: Record<string, string> = {
  K: "#1a0f2e", // outline
  W: "#f4ecff", // ghost white
  C: "#d9cbef", // bone
  V: "#b48cff", // violet
  D: "#5b3d8f", // cloak
  B: "#2a1b45", // cloak shadow
  N: "#120a1f", // void
  O: "#ff8a1f", // pumpkin
  Y: "#ffd166", // gold
  G: "#5dff7a", // spectre
  R: "#ff3b5c", // curse
  M: "#6b4a2a", // wood dark
  L: "#a0723f", // wood
  S: "#8a7aa8", // stone
};

export type Grid = string[];

const pad = (grid: Grid): Grid => {
  const w = Math.max(...grid.map((r) => r.length));
  return grid.map((r) => r.padEnd(w, "."));
};

export const GHOST_A: Grid = pad([
  ".....KKKK.....",
  "...KKWWWWKK...",
  "..KWWWWWWWWK..",
  ".KWWWWWWWWWWK.",
  ".KWWKKWWKKWWK.",
  "KWWWKGWWKGWWWK",
  "KWWWKKWWKKWWWK",
  "KWWWWWWWWWWWWK",
  "KWWWWWKKWWWWWK",
  "KWWWWWKKWWWWWK",
  "KWWWWWWWWWWWWK",
  "KWWWWWWWWWWWWK",
  "KWKWWKWWKWWKWK",
  ".K.KK.KK.KK.K.",
]);

export const GHOST_B: Grid = pad([
  ".....KKKK.....",
  "...KKWWWWKK...",
  "..KWWWWWWWWK..",
  ".KWWWWWWWWWWK.",
  ".KWWKKWWKKWWK.",
  "KWWWKGWWKGWWWK",
  "KWWWKKWWKKWWWK",
  "KWWWWWWWWWWWWK",
  "KWWWWWWWWWWWWK",
  "KWWWWWKKWWWWWK",
  "KWWWWWWWWWWWWK",
  "KWWWWWWWWWWWWK",
  "KWWKWWKWWKWWWK",
  ".KK.KK.KK.KKK.",
]);

export const SELLER: Grid = pad([
  ".....KKKK.....",
  "....KDDDDK....",
  "...KDDDDDDK...",
  "..KDDBBBBDDK..",
  "..KDBKKKKBDK..",
  "..KDBOKKOBDK..",
  "..KDBKKKKBDK..",
  ".KDDDBBBBDDDK.",
  ".KDDDDDDDDDDK.",
  "KDDDDDDDDDDDDK",
  "KDDKDDDDDDKDDK",
  "KDDKDDKKDDKDDK",
  "KDDKDKOYKDKDDK",
  "KDDDDKYOKDDDDK",
  "KDDDDDKKDDDDDK",
  ".KKKKKKKKKKKK.",
]);

export const BUYER: Grid = pad([
  "......KK......",
  "......KG......",
  "...KKKKKKKK...",
  "..KOOOOOOOOK..",
  ".KOOKOOOOKOOK.",
  ".KOKYKOOKYKOK.",
  ".KOOOOOOOOOOK.",
  ".KOKYKYKYKYOK.",
  "..KOOKOKOKOK..",
  "...KKKKKKKK...",
  "....KVVVVK....",
  "...KVVVVVVK...",
  "..KVVKVVKVVK..",
  "..KVVKVVKVVK..",
  "...KVVVVVVK...",
  "...KK....KK...",
]);

export const COFFIN_LID: Grid = pad([
  "....KKKKKK....",
  "...KMLLLLMK...",
  "..KMLLLLLLMK..",
  ".KMLLLKKLLLMK.",
  "KMLLLLKKLLLLMK",
  "KMLLKKKKKKLLMK",
  "KMLLKKKKKKLLMK",
  "KMLLLLKKLLLLMK",
  ".KMLLLKKLLLMK.",
  ".KMLLLKKLLLMK.",
  ".KMLLLLLLLLMK.",
  "..KMLLLLLLMK..",
  "..KMLLLLLLMK..",
  "...KMLLLLMK...",
  "...KMLLLLMK...",
  "....KKKKKK....",
]);

/** The coffin with its lid off: a void, faintly lit from inside. */
export const COFFIN_OPEN: Grid = pad([
  "....KKKKKK....",
  "...KMNNNNMK...",
  "..KMNNNNNNMK..",
  ".KMNNNNNNNNMK.",
  "KMNNNNGNNNNNMK",
  "KMNNNNNNNNNNMK",
  "KMNNNNNNNGNNMK",
  "KMNNGNNNNNNNMK",
  ".KMNNNNNNNNMK.",
  ".KMNNNNNGNNMK.",
  ".KMNNNNNNNNMK.",
  "..KMNNGNNNMK..",
  "..KMNNNNNNMK..",
  "...KMNNNNMK...",
  "...KMNNNNMK...",
  "....KKKKKK....",
]);

export const COIN_FRAMES: Grid[] = [
  ["..KKKK..", ".KYYYYK.", "KYYOYYYK", "KYOYYYYK", "KYOYYYYK", "KYYOYYYK", ".KYYYYK.", "..KKKK.."],
  ["...KK...", "..KYYK..", "..KYOK..", "..KYOK..", "..KYOK..", "..KYOK..", "..KYYK..", "...KK..."],
  ["...KK...", "...KK...", "...KK...", "...KK...", "...KK...", "...KK...", "...KK...", "...KK..."],
  ["...KK...", "..KYYK..", "..KOYK..", "..KOYK..", "..KOYK..", "..KOYK..", "..KYYK..", "...KK..."],
];

export const SKULL: Grid = pad([
  "..KKKKKK..",
  ".KCCCCCCK.",
  "KCCCCCCCCK",
  "KCKKCCKKCK",
  "KCKRCCKRCK",
  "KCCCKKCCCK",
  ".KCCCCCCK.",
  "..KCKCKCK.",
  "..KCCCCK..",
  "...KKKK...",
]);

export const CHEST: Grid = pad([
  "..KKKKKKKK..",
  ".KMLLLLLLMK.",
  "KMLLYYYYLLMK",
  "KKKKKYYKKKKK",
  "KMLLLKKLLLMK",
  "KMLLLLLLLLMK",
  "KMLLLLLLLLMK",
  "KKKKKKKKKKKK",
]);

export const PUMPKIN: Grid = pad([
  "....G....",
  "..KKKKK..",
  ".KOOOOOK.",
  "KOYOOOYOK",
  "KOOOOOOOK",
  "KOYYYYYOK",
  ".KOOOOOK.",
  "..KKKKK..",
]);

export const BAT_UP: Grid = pad(["K.......K", "KK.....KK", ".KKKKKKK.", "...KRK...", "....K...."]);
export const BAT_DOWN: Grid = pad(["....K....", "...KRK...", ".KKKKKKK.", "KK.....KK", "K.......K"]);

/** Draws a grid at (x, y), one canvas pixel per cell. `tint` replaces every opaque color. */
export function drawGrid(ctx: CanvasRenderingContext2D, grid: Grid, x: number, y: number, tint?: string): void {
  for (let r = 0; r < grid.length; r++) {
    const row = grid[r];
    for (let c = 0; c < row.length; c++) {
      const key = row[c];
      if (key === ".") continue;
      ctx.fillStyle = tint ?? PALETTE[key] ?? "#000";
      ctx.fillRect(x + c, y + r, 1, 1);
    }
  }
}

const cache = new Map<string, string>();

function dataUrl(frames: Grid[]): string {
  const key = frames.map((f) => f.join("/")).join("|");
  let url = cache.get(key);
  if (!url) {
    const w = frames[0][0].length;
    const canvas = document.createElement("canvas");
    canvas.width = w * frames.length;
    canvas.height = frames[0].length;
    const ctx = canvas.getContext("2d")!;
    frames.forEach((f, i) => drawGrid(ctx, f, i * w, 0));
    url = canvas.toDataURL();
    cache.set(key, url);
  }
  return url;
}

/**
 * An element showing `frames` one at a time: the frames sit side by side in a background image and
 * a CSS `steps()` animation walks through them. `--s` (set in CSS) is the size of one sprite pixel.
 */
export function strip(frames: Grid[], className: string, label = ""): HTMLElement {
  const el = document.createElement("div");
  el.className = `sprite ${className}`;
  el.style.backgroundImage = `url(${dataUrl(frames)})`;
  el.style.setProperty("--frames", String(frames.length));
  el.style.setProperty("--w", String(frames[0][0].length));
  el.style.setProperty("--h", String(frames[0].length));
  if (label) {
    el.setAttribute("role", "img");
    el.setAttribute("aria-label", label);
  } else {
    el.setAttribute("aria-hidden", "true");
  }
  return el;
}

/** A single-frame sprite. */
export function sprite(grid: Grid, className: string, label = ""): HTMLElement {
  return strip([grid], className, label);
}
