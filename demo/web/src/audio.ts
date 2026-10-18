// 8-bit blips made on the fly with WebAudio. Off until the player turns sound on.

let ctx: AudioContext | null = null;
let on = false;

export const soundOn = () => on;

export function toggleSound(): boolean {
  on = !on;
  if (on && !ctx) ctx = new AudioContext();
  return on;
}

function tone(freq: number, start: number, dur: number, type: OscillatorType = "square", gain = 0.06): void {
  if (!ctx) return;
  const osc = ctx.createOscillator();
  const amp = ctx.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(freq, ctx.currentTime + start);
  amp.gain.setValueAtTime(gain, ctx.currentTime + start);
  amp.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + start + dur);
  osc.connect(amp).connect(ctx.destination);
  osc.start(ctx.currentTime + start);
  osc.stop(ctx.currentTime + start + dur + 0.02);
}

const SOUNDS = {
  click: () => tone(660, 0, 0.05),
  type: () => tone(320 + Math.random() * 80, 0, 0.02, "square", 0.025),
  coin: () => {
    tone(988, 0, 0.06);
    tone(1319, 0.06, 0.12);
  },
  seal: () => [392, 523, 659].forEach((f, i) => tone(f, i * 0.07, 0.1, "triangle", 0.08)),
  creak: () => tone(110, 0, 0.5, "sawtooth", 0.04),
  curse: () => [440, 330, 247, 165].forEach((f, i) => tone(f, i * 0.12, 0.22, "sawtooth", 0.06)),
  justice: () => [523, 659, 784, 1047].forEach((f, i) => tone(f, i * 0.1, 0.18, "square", 0.05)),
  tick: () => tone(220, 0, 0.04, "triangle", 0.05),
};

export function play(name: keyof typeof SOUNDS): void {
  if (on && ctx) SOUNDS[name]();
}
