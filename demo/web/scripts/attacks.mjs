// Builds src/attacks.json from the threat model's attack tables, so the board can never list an
// attack the repository does not document and test.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = new URL("../../../", import.meta.url);
const md = readFileSync(new URL("THREAT_MODEL.md", root), "utf8");
const plain = (cell) => cell.replace(/`([^`]*)`/g, "$1").replace(/\*([^*]*)\*/g, "$1").trim();

const groups = [];
let section = null;
let columns = null;
for (const line of md.split(/\r?\n/)) {
  const heading = line.match(/^##\s+(.*)/);
  if (heading) {
    section = heading[1].trim();
    columns = null;
    continue;
  }
  if (!line.startsWith("|")) {
    columns = line.trim() === "" ? columns : null;
    continue;
  }
  const cells = line.split("|").slice(1, -1).map((c) => c.trim());
  if (cells.every((c) => /^-+$/.test(c))) continue;
  if (!columns) {
    columns = cells.map((c) => c.toLowerCase());
    continue;
  }
  const at = (name) => cells[columns.indexOf(name)] ?? "";
  if (!columns.includes("attack")) continue;
  const tests = [...at("test").matchAll(/`([a-z0-9_]+)`/g)].map((m) => m[1]);
  let group = groups.find((g) => g.section === section);
  if (!group) groups.push((group = { section, rows: [] }));
  group.rows.push({ attack: plain(at("attack")), defence: plain(at("defence")), tests });
}

const out = fileURLToPath(new URL("../src/attacks.json", import.meta.url));
writeFileSync(out, JSON.stringify(groups, null, 2) + "\n");
console.log(`attacks.json: ${groups.reduce((s, g) => s + g.rows.length, 0)} attacks in ${groups.length} sections`);
