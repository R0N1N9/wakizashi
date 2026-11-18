#!/usr/bin/env node
/* Zero-dependency test runner. Loads js/core.js and every js/eng/*.js into one sandbox (as a
 * browser would, minus the DOM), then runs tests/*.test.js. Each test file gets globals:
 *   test(name, fn)   — fn may be async
 *   assert           — node:assert/strict
 *   W                — the loaded Wakizashi namespace
 *   fixture(name)    — read tests/fixtures/<name> as a string (or Buffer with {bin:true})
 * Run:  node tests/run.js            (all)      node tests/run.js ioc   (files matching "ioc") */
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm"), assert = require("assert/strict");
const ROOT = path.resolve(__dirname, "..");

function sandbox() {
  const store = new Map();
  const ctx = {
    console, setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask, structuredClone,
    TextEncoder, TextDecoder, URL, URLSearchParams, Blob, crypto: globalThis.crypto, atob, btoa, Buffer,
    CompressionStream: globalThis.CompressionStream, DecompressionStream: globalThis.DecompressionStream, Response: globalThis.Response,
    fetch: async () => { throw new Error("network disabled in tests"); },
    localStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k),
      key: (i) => [...store.keys()][i] ?? null, get length() { return store.size; } },
  };
  ctx.globalThis = ctx; ctx.window = undefined; ctx.self = ctx;
  return vm.createContext(ctx);
}

const ctx = sandbox();
const load = (f) => vm.runInContext(fs.readFileSync(f, "utf8"), ctx, { filename: path.relative(ROOT, f) });
load(path.join(ROOT, "js/core.js"));
const engDir = path.join(ROOT, "js/eng");
for (const f of (fs.existsSync(engDir) ? fs.readdirSync(engDir) : []).filter((x) => x.endsWith(".js")).sort()) load(path.join(engDir, f));

const filt = process.argv[2];
const files = fs.readdirSync(__dirname).filter((f) => f.endsWith(".test.js") && (!filt || f.includes(filt))).sort();
const tests = [];
ctx.test = (name, fn) => tests.push({ name, fn, file: null });
ctx.assert = assert;
ctx.fixture = (name, opts = {}) => fs.readFileSync(path.join(__dirname, "fixtures", name), opts.bin ? undefined : "utf8");
for (const f of files) {
  const before = tests.length;
  // each test file gets its own scope so top-level consts in different files can't collide
  vm.runInContext("(function () {" + fs.readFileSync(path.join(__dirname, f), "utf8") + "\n})();", ctx, { filename: "tests/" + f });
  for (let i = before; i < tests.length; i++) tests[i].file = f;
}

(async () => {
  let pass = 0, fail = 0;
  for (const t of tests) {
    try { await t.fn(); pass++; process.stdout.write(`  ok  ${t.file} › ${t.name}\n`); }
    catch (e) { fail++; process.stdout.write(`  FAIL ${t.file} › ${t.name}\n       ${String(e && e.stack || e).split("\n").slice(0, 4).join("\n       ")}\n`); }
  }
  console.log(`\n${pass} passed, ${fail} failed (${files.length} file(s))`);
  process.exit(fail ? 1 : 0);
})();
