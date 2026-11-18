#!/usr/bin/env node
/* Regenerates the generated parts of index.html and sw.js from the files on disk:
 *   - <script> tags for js/eng/*.js and js/views/<layer>/*.js (layer order below)
 *   - the service-worker PRECACHE list and a content-hash VERSION
 * Run after adding/removing/renaming a module:   node tools/sync.js
 * CI runs `node tools/sync.js --check` and fails if anything is out of date. */
"use strict";
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const ROOT = path.resolve(__dirname, "..");
const LAYERS = ["yumi", "yoroi", "naginata", "kemuridama"];
const check = process.argv.includes("--check");

const rel = (p) => path.relative(ROOT, p).split(path.sep).join("/");
const list = (dir, ext) => fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(ext)).sort().map((f) => path.join(dir, f)) : [];

const engines = list(path.join(ROOT, "js/eng"), ".js").map(rel);
const views = LAYERS.flatMap((l) => list(path.join(ROOT, "js/views", l), ".js").map(rel))
  .concat(list(path.join(ROOT, "js/views"), ".js").map(rel));            // shared view helpers, if any
const tag = (src) => `<script src="${src}"></script>`;

let html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const block = (name, srcs) => `<!--${name}-->\n${srcs.map(tag).join("\n")}${srcs.length ? "\n" : ""}<!--/${name}-->`;
const swap = (s, name, srcs) => {
  const re = new RegExp(`<!--${name}-->[\\s\\S]*?<!--/${name}-->|<!--${name}-->`);
  if (!re.test(s)) throw new Error(`index.html is missing the <!--${name}--> marker`);
  return s.replace(re, block(name, srcs));
};
html = swap(html, "ENGINES", engines);
html = swap(html, "VIEWS", views);
const styles = list(path.join(ROOT, "css"), ".css").map(rel).filter((f) => f !== "css/app.css");
html = (() => {
  const re = /<!--STYLES-->[\s\S]*?<!--\/STYLES-->|<!--STYLES-->/;
  if (!re.test(html)) throw new Error("index.html is missing the <!--STYLES--> marker");
  return html.replace(re, `<!--STYLES-->\n${styles.map((f) => `<link rel="stylesheet" href="${f}">`).join("\n")}${styles.length ? "\n" : ""}<!--/STYLES-->`);
})();

const statics = ["./", "index.html", "manifest.webmanifest", "css/app.css", "js/core.js", "js/shell.js",
  "assets/icon.svg", "assets/icon-192.png", "assets/icon-512.png", "assets/icon-maskable-512.png", "assets/apple-touch-icon.png", "assets/favicon-32.png"]
  .concat(fs.existsSync(path.join(ROOT, "data")) ? list(path.join(ROOT, "data"), ".json").map(rel) : []);
const precache = statics.concat(styles, engines, views);
const h = crypto.createHash("sha256");
for (const f of precache) if (f !== "./" && f !== "index.html") h.update(f + "\0" + fs.readFileSync(path.join(ROOT, f)));
h.update(html);
const version = h.digest("hex").slice(0, 12);

let sw = fs.readFileSync(path.join(ROOT, "sw.js"), "utf8");
sw = sw.replace(/const VERSION = "wkz-[^"]*";/, `const VERSION = "wkz-${version}";`)
  .replace(/const PRECACHE = \[[\s\S]*?\];/, `const PRECACHE = [/*PRECACHE*/\n${precache.map((f) => `  ${JSON.stringify(f)},`).join("\n")}\n];`);

const files = [["index.html", html], ["sw.js", sw]];
let stale = [];
for (const [f, txt] of files) {
  const cur = fs.readFileSync(path.join(ROOT, f), "utf8");
  if (cur !== txt) { stale.push(f); if (!check) fs.writeFileSync(path.join(ROOT, f), txt); }
}
if (check && stale.length) { console.error(`out of date: ${stale.join(", ")} — run: node tools/sync.js`); process.exit(1); }
console.log(`${check ? "ok" : "synced"}: ${engines.length} engine(s), ${views.length} view file(s), cache ${version}${stale.length && !check ? " (updated " + stale.join(", ") + ")" : ""}`);
