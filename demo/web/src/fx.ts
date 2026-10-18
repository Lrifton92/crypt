// The demo's only animation loop. Two low-resolution canvases scaled up with crisp pixels: the
// graveyard behind the page (sky, moon, bats, wisps, flickering pumpkins, fog, lightning) and an
// overlay above it (flying coins, sparks, the pixel-dissolve between screens). With reduced motion
// the scene is drawn once and every effect resolves at once.

import { BAT_DOWN, BAT_UP, COIN_FRAMES, PUMPKIN, drawGrid } from "./sprites";

export const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

const H = 180;
const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5].map((v) => (v + 0.5) / 16);
const dither = (x: number, y: number) => BAYER[(y & 3) * 4 + (x & 3)];

interface Star { x: number; y: number; phase: number; speed: number }
interface Bat { x: number; base: number; amp: number; phase: number; speed: number; flap: number }
interface Wisp { x: number; y: number; born: number; life: number; sway: number }
interface Blob { x: number; y: number; w: number; speed: number }
interface Spark { x: number; y: number; vx: number; vy: number; born: number; life: number; colors: string[] }
interface Coin { sx: number; sy: number; tx: number; ty: number; start: number; dur: number; arc: number }

let W = 320;
let scale = 1;
let bg: HTMLCanvasElement;
let fg: HTMLCanvasElement;
let bctx: CanvasRenderingContext2D;
let fctx: CanvasRenderingContext2D;
let sky: HTMLCanvasElement;
let ground: HTMLCanvasElement;
let stars: Star[] = [];
let bats: Bat[] = [];
let blobs: Blob[] = [];
let pumpkins: { x: number; y: number; phase: number }[] = [];
let tombs: number[] = [];
let crypt = { x: 0, y: 0 };
const wisps: Wisp[] = [];
const sparks: Spark[] = [];
const coins: Coin[] = [];
let coinWaiters: { until: number; resolve: () => void }[] = [];
let wipe: { start: number; order: number[]; cols: number; rows: number; swap: () => void; swapped: boolean; resolve: () => void } | null = null;
let nextLightning = 0;
let lightning: { start: number; bolt: [number, number][] } | null = null;
let pointer = 0;
let lastWisp = 0;
let running = false;

const rand = (a: number, b: number) => a + Math.random() * (b - a);
/** Top right, clear of the centred content on wide screens. */
const moonX = () => W - Math.round(Math.min(40, W * 0.16));
const moonR = () => (W < 160 ? 8 : 15);
const moonY = () => (W < 160 ? 14 : 26);
const layer = (w: number, h: number) => {
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  return c;
};

function paintSky(): void {
  sky = layer(W, H);
  const ctx = sky.getContext("2d")!;
  const bands = ["#06030b", "#0b0712", "#110a1e", "#170d2a", "#1f1036", "#2a1442", "#3a1b4f"];
  for (let y = 0; y < H; y++) {
    const t = (y / H) * (bands.length - 1);
    const i = Math.floor(t);
    for (let x = 0; x < W; x++) {
      ctx.fillStyle = bands[Math.min(bands.length - 1, i + (t - i > dither(x, y) ? 1 : 0))];
      ctx.fillRect(x, y, 1, 1);
    }
  }
  // The moon, with a few craters.
  const mx = moonX();
  const my = moonY();
  const r = moonR();
  for (let y = -r; y <= r; y++) {
    for (let x = -r; x <= r; x++) {
      const d = Math.hypot(x, y);
      if (d > r) continue;
      const shade = x * 0.4 + y * 0.3 + d * 0.3;
      ctx.fillStyle = shade > 9 + dither(x, y) * 6 ? "#d8c9a8" : "#f3e9cf";
      ctx.fillRect(mx + x, my + y, 1, 1);
    }
  }
  ctx.fillStyle = "#c9b892";
  const craters = r < 15 ? [[-3, -2, 2], [3, 3, 1]] : [[-6, -4, 4], [5, 6, 3], [7, -8, 2], [-3, 9, 2]];
  for (const [cx, cy, cr] of craters) {
    for (let y = -cr; y <= cr; y++) for (let x = -cr; x <= cr; x++) if (x * x + y * y <= cr * cr) ctx.fillRect(mx + cx + x, my + cy + y, 1, 1);
  }
}

function paintGround(): void {
  const gw = W + 16;
  ground = layer(gw, H);
  const ctx = ground.getContext("2d")!;
  // Far hill, with the crypt on it.
  ctx.fillStyle = "#140b22";
  for (let x = 0; x < gw; x++) {
    const h = H - 52 + Math.round(Math.sin(x / 37) * 6 + Math.sin(x / 13) * 2);
    ctx.fillRect(x, h, 1, H - h);
  }
  crypt = { x: Math.round(gw * 0.3), y: H - 58 };
  ctx.fillStyle = "#24163a";
  ctx.fillRect(crypt.x - 14, crypt.y - 20, 28, 22);
  for (let i = 0; i < 12; i++) ctx.fillRect(crypt.x - 16 + i, crypt.y - 20 - i, 32 - i * 2, 1);
  ctx.fillRect(crypt.x - 1, crypt.y - 38, 2, 8);
  ctx.fillRect(crypt.x - 4, crypt.y - 35, 8, 2);
  ctx.fillStyle = "#0a0612";
  ctx.fillRect(crypt.x - 4, crypt.y - 11, 8, 13);
  ctx.fillStyle = "#33204f";
  for (const dx of [-11, 9]) ctx.fillRect(crypt.x + dx, crypt.y - 18, 2, 20);
  // Near ground.
  ctx.fillStyle = "#0a0614";
  for (let x = 0; x < gw; x++) {
    const h = H - 30 + Math.round(Math.sin(x / 29 + 1) * 4 + Math.sin(x / 7) * 1);
    ctx.fillRect(x, h, 1, H - h);
  }
  // Tombstones and crosses.
  tombs = [];
  for (let x = 12; x < gw - 12; x += Math.round(rand(26, 44))) {
    tombs.push(x);
    const top = H - 30 + Math.round(Math.sin(x / 29 + 1) * 4) - Math.round(rand(10, 16));
    if (Math.random() < 0.3) {
      ctx.fillStyle = "#1a1030";
      ctx.fillRect(x - 1, top - 2, 3, 16);
      ctx.fillRect(x - 4, top + 2, 9, 3);
    } else {
      ctx.fillStyle = "#1a1030";
      ctx.fillRect(x - 5, top + 2, 11, 14);
      ctx.fillRect(x - 4, top + 1, 9, 1);
      ctx.fillRect(x - 3, top, 7, 1);
      ctx.fillStyle = "#2a1b45";
      ctx.fillRect(x - 5, top + 2, 1, 12);
      ctx.fillRect(x - 2, top + 5, 5, 1);
      ctx.fillRect(x - 2, top + 8, 4, 1);
    }
  }
  // A dead tree.
  const tx = Math.round(gw * 0.9);
  ctx.fillStyle = "#07040c";
  ctx.fillRect(tx, H - 70, 3, 44);
  const branch = (x: number, y: number, dx: number, len: number) => {
    for (let i = 0; i < len; i++) ctx.fillRect(x + i * dx, y - Math.round(i * 0.7), 2, 1);
  };
  branch(tx + 2, H - 58, 1, 14);
  branch(tx, H - 64, -1, 12);
  branch(tx + 2, H - 46, 1, 9);
  branch(tx, H - 50, -1, 7);
  pumpkins = tombs
    .filter((_, i) => i % 2 === 1)
    .slice(0, 5)
    .map((x) => ({ x: x + 8, y: H - 30 + Math.round(Math.sin((x + 8) / 29 + 1) * 4) - 6, phase: rand(0, 6) }));
}

function seed(): void {
  stars = Array.from({ length: Math.round(W / 4) }, () => ({ x: rand(0, W) | 0, y: rand(0, H * 0.55) | 0, phase: rand(0, 6), speed: rand(0.6, 2.4) }));
  bats = Array.from({ length: 5 }, () => ({ x: rand(0, W), base: rand(18, 90), amp: rand(4, 14), phase: rand(0, 6), speed: rand(9, 20), flap: rand(90, 160) }));
  blobs = Array.from({ length: 9 }, () => ({ x: rand(-40, W), y: rand(H - 34, H - 6), w: rand(30, 70), speed: rand(2, 6) }));
}

function resize(): void {
  const aspect = window.innerWidth / Math.max(1, window.innerHeight);
  // Square pixels at any aspect: the width follows the screen, the height stays 180.
  W = Math.max(60, Math.min(420, Math.round(H * aspect)));
  scale = window.innerWidth / W;
  for (const c of [bg, fg]) {
    c.width = W;
    c.height = H;
  }
  paintSky();
  paintGround();
  seed();
  if (reducedMotion.matches) draw(performance.now());
}

function glow(ctx: CanvasRenderingContext2D, cx: number, cy: number, r: number, color: string, strength: number): void {
  ctx.fillStyle = color;
  for (let y = -r; y <= r; y++) {
    for (let x = -r; x <= r; x++) {
      const d = Math.hypot(x, y) / r;
      if (d < 1 && (1 - d) * strength > dither(cx + x, cy + y)) ctx.fillRect(cx + x, cy + y, 1, 1);
    }
  }
}

function drawBackground(t: number): void {
  const s = t / 1000;
  bctx.drawImage(sky, 0, 0);
  for (const st of stars) {
    const b = (Math.sin(s * st.speed + st.phase) + 1) / 2;
    bctx.fillStyle = b > 0.8 ? "#f4ecff" : b > 0.4 ? "#8a7aa8" : "#3d2a5c";
    bctx.fillRect(st.x, st.y, 1, 1);
  }
  // Moon halo breathing.
  bctx.globalAlpha = 0.18 + Math.sin(s * 0.8) * 0.05;
  glow(bctx, moonX(), moonY(), moonR() + 11, "#b48cff", 0.55);
  bctx.globalAlpha = 1;
  // Clouds sliding across the moon.
  bctx.fillStyle = "#1a1030";
  for (let i = 0; i < 3; i++) {
    const cx = Math.round(((s * (4 + i * 2) + i * 140) % (W + 120)) - 60);
    const cy = 26 + i * 14;
    for (let r = 0; r < 6; r++) bctx.fillRect(cx - 22 + r * 2 + (r % 2), cy + r, 44 - r * 4 + 8, 1);
  }
  const shift = Math.round(pointer * 4);
  bctx.drawImage(ground, -8 + shift, 0);
  // The crypt's door flickers green.
  bctx.globalAlpha = 0.25 + Math.sin(s * 2.2) * 0.12 + (Math.sin(s * 17) > 0.9 ? 0.15 : 0);
  bctx.fillStyle = "#2f8f4a";
  const door = crypt.x - 8 + shift;
  bctx.fillRect(door - 1, crypt.y - 11, 2, 1);
  bctx.fillRect(door - 2, crypt.y - 10, 4, 1);
  bctx.fillRect(door - 3, crypt.y - 9, 6, 10);
  bctx.globalAlpha = 1;
  // Bats.
  for (const b of bats) {
    b.x -= b.speed / 60;
    if (b.x < -12) {
      b.x = W + rand(10, 80);
      b.base = rand(18, 90);
    }
    const y = Math.round(b.base + Math.sin(s * 2 + b.phase) * b.amp);
    drawGrid(bctx, Math.floor(t / b.flap) % 2 ? BAT_UP : BAT_DOWN, Math.round(b.x), y);
  }
  // Pumpkins and their flickering candlelight.
  for (const p of pumpkins) {
    const flicker = 0.45 + Math.sin(s * 9 + p.phase) * 0.12 + Math.sin(s * 23 + p.phase * 2) * 0.08;
    bctx.globalAlpha = 0.55;
    glow(bctx, p.x + 4 + shift, p.y + 4, 13, "#ff8a1f", flicker);
    bctx.globalAlpha = 1;
    drawGrid(bctx, PUMPKIN, p.x + shift, p.y);
  }
  // Wisps rising from the graves.
  if (t - lastWisp > 260 && tombs.length) {
    lastWisp = t;
    wisps.push({ x: tombs[(Math.random() * tombs.length) | 0] - 8 + rand(-4, 4), y: H - 34, born: t, life: rand(2500, 5000), sway: rand(0, 6) });
  }
  for (let i = wisps.length - 1; i >= 0; i--) {
    const w = wisps[i];
    const age = (t - w.born) / w.life;
    if (age >= 1) {
      wisps.splice(i, 1);
      continue;
    }
    const x = Math.round(w.x + shift + Math.sin(s * 2 + w.sway) * 3);
    const y = Math.round(w.y - age * 60);
    bctx.fillStyle = age < 0.7 ? "#5dff7a" : "#2f8f4a";
    bctx.fillRect(x, y, 1, 1);
    if (age < 0.4) bctx.fillRect(x, y + 1, 1, 1);
  }
  // Fog drifting low.
  bctx.globalAlpha = 0.1;
  bctx.fillStyle = "#c9b8e8";
  for (const b of blobs) {
    b.x += b.speed / 60;
    if (b.x > W + 10) b.x = -b.w - rand(0, 40);
    for (let r = 0; r < 6; r++) {
      const inset = Math.abs(r - 2.5) * 5;
      bctx.fillRect(Math.round(b.x + inset), Math.round(b.y + r), Math.round(b.w - inset * 2), 1);
    }
  }
  bctx.globalAlpha = 1;
  // Lightning, now and then.
  if (!nextLightning) nextLightning = t + rand(6000, 12000);
  if (t > nextLightning) {
    nextLightning = t + rand(11000, 22000);
    const bolt: [number, number][] = [];
    let x = rand(W * 0.1, W * 0.6);
    for (let y = 0; y < H - 50; y += 4) {
      x += rand(-4, 4);
      bolt.push([Math.round(x), y]);
    }
    lightning = { start: t, bolt };
    document.body.classList.add("lightning");
    window.setTimeout(() => document.body.classList.remove("lightning"), 320);
  }
  if (lightning) {
    const age = t - lightning.start;
    if (age > 400) lightning = null;
    else {
      bctx.globalAlpha = age < 80 ? 0.45 : age < 160 ? 0.15 : age < 220 ? 0.3 : 0;
      bctx.fillStyle = "#e9ddff";
      bctx.fillRect(0, 0, W, H);
      bctx.globalAlpha = 1;
      if (age < 260) {
        bctx.fillStyle = "#ffffff";
        for (let i = 1; i < lightning.bolt.length; i++) {
          const [x0, y0] = lightning.bolt[i - 1];
          const [x1] = lightning.bolt[i];
          bctx.fillRect(Math.min(x0, x1), y0, Math.abs(x1 - x0) + 1, 4);
        }
      }
    }
  }
}

function drawOverlay(t: number): void {
  fctx.clearRect(0, 0, W, H);
  for (let i = sparks.length - 1; i >= 0; i--) {
    const p = sparks[i];
    const age = (t - p.born) / p.life;
    if (age >= 1) {
      sparks.splice(i, 1);
      continue;
    }
    p.x += p.vx;
    p.y += p.vy;
    p.vy += 0.03;
    fctx.fillStyle = p.colors[Math.min(p.colors.length - 1, Math.floor(age * p.colors.length))];
    fctx.fillRect(Math.round(p.x), Math.round(p.y), 1, 1);
  }
  for (let i = coins.length - 1; i >= 0; i--) {
    const c = coins[i];
    const k = (t - c.start) / c.dur;
    if (k < 0) continue;
    if (k >= 1) {
      coins.splice(i, 1);
      for (let j = 0; j < 3; j++) sparks.push({ x: c.tx, y: c.ty, vx: rand(-0.6, 0.6), vy: rand(-0.9, -0.2), born: t, life: 350, colors: ["#ffd166", "#ff8a1f"] });
      continue;
    }
    const e = 1 - Math.pow(1 - k, 3);
    const x = c.sx + (c.tx - c.sx) * e;
    const y = c.sy + (c.ty - c.sy) * e - Math.sin(Math.PI * k) * c.arc;
    drawGrid(fctx, COIN_FRAMES[Math.floor(t / 70) % 4], Math.round(x) - 4, Math.round(y) - 4);
  }
  coinWaiters = coinWaiters.filter((w) => (t >= w.until ? (w.resolve(), false) : true));
  if (wipe) {
    const k = (t - wipe.start) / 260;
    const total = wipe.order.length;
    fctx.fillStyle = "#0b0712";
    const shown = k < 1 ? Math.floor(k * total) : k < 2 ? total - Math.floor((k - 1) * total) : 0;
    if (k >= 1 && !wipe.swapped) {
      wipe.swapped = true;
      wipe.swap();
    }
    for (let i = 0; i < shown; i++) {
      const cell = wipe.order[k < 1 ? i : total - 1 - i];
      fctx.fillRect((cell % wipe.cols) * 6, Math.floor(cell / wipe.cols) * 6, 6, 6);
    }
    if (k >= 2) {
      const done = wipe.resolve;
      wipe = null;
      done();
    }
  }
}

function draw(t: number): void {
  drawBackground(t);
  drawOverlay(t);
}

function loop(t: number): void {
  if (!document.hidden) draw(t);
  if (running) requestAnimationFrame(loop);
}

function start(): void {
  if (reducedMotion.matches) {
    running = false;
    draw(performance.now());
  } else if (!running) {
    running = true;
    requestAnimationFrame(loop);
  }
}

export function initFx(): void {
  bg = document.getElementById("bg") as HTMLCanvasElement;
  fg = document.getElementById("fx") as HTMLCanvasElement;
  bctx = bg.getContext("2d")!;
  fctx = fg.getContext("2d")!;
  resize();
  window.addEventListener("resize", resize);
  window.addEventListener("pointermove", (e) => {
    pointer = e.clientX / window.innerWidth - 0.5;
  });
  reducedMotion.addEventListener("change", start);
  start();
}

/** Screen coordinates of an element's centre, in canvas pixels. */
function centre(el: Element): [number, number] {
  const r = el.getBoundingClientRect();
  return [(r.left + r.width / 2) / scale, (r.top + r.height / 2) / (window.innerHeight / H)];
}

/** Coins fly from one element to another; resolves when the last one lands. */
export function coinsTo(from: Element, to: Element, n: number): Promise<void> {
  if (reducedMotion.matches || n <= 0) return Promise.resolve();
  const [sx, sy] = centre(from);
  const [tx, ty] = centre(to);
  const now = performance.now();
  const count = Math.min(n, 14);
  for (let i = 0; i < count; i++) {
    coins.push({ sx: sx + rand(-3, 3), sy: sy + rand(-3, 3), tx: tx + rand(-3, 3), ty: ty + rand(-2, 2), start: now + i * 55, dur: 650, arc: rand(18, 34) });
  }
  return new Promise((resolve) => coinWaiters.push({ until: now + (count - 1) * 55 + 700, resolve }));
}

const SPARK_COLORS = {
  curse: ["#ffffff", "#ff3b5c", "#a01f3a", "#3a0a18"],
  justice: ["#ffffff", "#ffd166", "#ff8a1f", "#6b4a2a"],
  ghost: ["#ffffff", "#5dff7a", "#2f8f4a", "#123d20"],
};

/** A burst of sparks out of an element. */
export function burst(el: Element, kind: keyof typeof SPARK_COLORS, n = 48): void {
  if (reducedMotion.matches) return;
  const [x, y] = centre(el);
  const now = performance.now();
  for (let i = 0; i < n; i++) {
    const a = rand(0, Math.PI * 2);
    const v = rand(0.3, 1.6);
    sparks.push({ x, y, vx: Math.cos(a) * v, vy: Math.sin(a) * v - 0.6, born: now, life: rand(600, 1300), colors: SPARK_COLORS[kind] });
  }
}

/** The screen dissolves into pixels, `swap` runs behind them, and the new screen dissolves in. */
export function pixelWipe(swap: () => void): Promise<void> {
  if (reducedMotion.matches || wipe) {
    swap();
    return Promise.resolve();
  }
  const cols = Math.ceil(W / 6);
  const rows = Math.ceil(H / 6);
  const order = Array.from({ length: cols * rows }, (_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = (Math.random() * (i + 1)) | 0;
    [order[i], order[j]] = [order[j], order[i]];
  }
  return new Promise((resolve) => {
    wipe = { start: performance.now(), order, cols, rows, swap, swapped: false, resolve };
  });
}
