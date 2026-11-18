#!/usr/bin/env node
// End-to-end smoke test: every layer home, every tool and Settings, at desktop and phone sizes.
// Fails on console errors, uncaught page errors, failed requests, a tool's error callout, or
// horizontal page overflow. Not part of `node tests/run.js` (that stays zero-dependency).
//
//   node tests/e2e/smoke.js                 # needs `playwright` resolvable (preinstalled or npx playwright install chromium)
//   SHOTS=dir node tests/e2e/smoke.js       # also save a screenshot of every screen
//   ONLY=yoroi node tests/e2e/smoke.js      # restrict to routes containing a substring
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const ROOT = path.resolve(__dirname, "../..");
const VIEWPORTS = [
  { name: "desktop", width: 1360, height: 900 },
  { name: "phone", width: 390, height: 844, isMobile: true, hasTouch: true, deviceScaleFactor: 1 },
];
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png",
  ".json": "application/json", ".webmanifest": "application/manifest+json", ".txt": "text/plain" };
const SHOTS = process.env.SHOTS, ONLY = process.env.ONLY;

function serve() {
  const srv = http.createServer((req, res) => {
    let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
    if (p.endsWith("/")) p += "index.html";
    const f = path.join(ROOT, path.normalize(p));
    if (!f.startsWith(ROOT + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404); return res.end("not found"); }
    res.writeHead(200, { "content-type": MIME[path.extname(f)] || "application/octet-stream", "cache-control": "no-store" });
    fs.createReadStream(f).pipe(res);
  });
  return new Promise((ok) => srv.listen(0, "127.0.0.1", () => ok(srv)));
}

async function main() {
  const srv = await serve();
  const base = `http://127.0.0.1:${srv.address().port}/`;
  if (SHOTS) fs.mkdirSync(SHOTS, { recursive: true });
  const browser = await chromium.launch();
  const failures = [];
  let screens = 0;
  try {
    for (const vp of VIEWPORTS) {
      const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, isMobile: !!vp.isMobile,
        hasTouch: !!vp.hasTouch, deviceScaleFactor: vp.deviceScaleFactor || 1, serviceWorkers: "block" });
      const page = await ctx.newPage();
      let errs = [];
      page.on("console", (m) => { if (m.type() === "error") errs.push("console: " + m.text()); });
      page.on("pageerror", (e) => errs.push("pageerror: " + (e.stack || e.message)));
      page.on("requestfailed", (r) => { if (r.url().startsWith(base)) errs.push("requestfailed: " + r.url()); });
      page.on("response", (r) => { if (r.url().startsWith(base) && r.status() >= 400) errs.push(`http ${r.status()}: ${r.url()}`); });

      await page.goto(base, { waitUntil: "load" });
      await page.waitForFunction(() => window.W && W.layers && W.layers.length && document.querySelector("#view").children.length);
      const routes = await page.evaluate(() => {
        const out = [];
        for (const L of W.layers) { out.push({ hash: `#/${L.id}`, layer: L.id }); for (const T of W.toolsOf(L.id)) out.push({ hash: `#/${L.id}/${T.id}`, layer: L.id, tool: T.id }); }
        out.push({ hash: "#/settings" });
        return out;
      });
      if (routes.length < 10) failures.push(`[${vp.name}] only ${routes.length} routes registered`);

      let gateSeen = false;
      for (const r of routes) {
        if (ONLY && !r.hash.includes(ONLY)) continue;
        errs = [];
        await page.evaluate((h) => { location.hash = h; }, r.hash);
        await page.waitForFunction((h) => location.hash === h && document.querySelector("#view").children.length, r.hash);
        await page.waitForTimeout(150);
        // Naginata: every tool must sit behind the rules-of-engagement gate until acknowledged.
        if (r.layer === "naginata" && r.tool) {
          const gated = await page.$("#roe-go");
          if (!gateSeen) {
            if (!gated) failures.push(`[${vp.name}] ${r.hash}: Naginata tool rendered without the RoE gate`);
            else {
              if (!(await page.$eval("#roe-go", (b) => b.disabled))) failures.push(`[${vp.name}] ${r.hash}: RoE button enabled before acknowledging`);
              await page.check("#roe-c");
              await page.click("#roe-go");
              await page.waitForTimeout(150);
            }
            gateSeen = true;
          } else if (gated) failures.push(`[${vp.name}] ${r.hash}: RoE gate shown again after acknowledging`);
        }
        const state = await page.evaluate(() => {
          const d = document.documentElement;
          const wide = [...document.querySelectorAll("body *")].filter((n) => { const b = n.getBoundingClientRect(); return b.width && b.right > d.clientWidth + 1; })
            .slice(0, 3).map((n) => n.tagName.toLowerCase() + (n.id ? "#" + n.id : "") + (n.className && typeof n.className === "string" ? "." + n.className.split(" ").join(".") : ""));
          const bad = [...document.querySelectorAll("#tool .callout.bad")].map((n) => n.textContent).find((t) => /hit an error/.test(t));
          return { overflow: d.scrollWidth - d.clientWidth, wide, toolError: bad || null, title: document.title };
        });
        const tag = `[${vp.name}] ${r.hash}`;
        if (state.overflow > 0) failures.push(`${tag}: horizontal overflow ${state.overflow}px (${state.wide.join(", ") || "?"})`);
        if (state.toolError) failures.push(`${tag}: ${state.toolError.trim()}`);
        for (const e of errs) failures.push(`${tag}: ${e}`);
        if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${vp.name}_${(r.hash.slice(2) || "home").replace(/\//g, "_")}.png`), fullPage: true });
        screens++;
      }
      if (!ONLY && !gateSeen) failures.push(`[${vp.name}] no Naginata tool visited`);
      await ctx.close();
    }
  } finally {
    await browser.close();
    srv.close();
  }
  if (failures.length) {
    console.error(`e2e smoke: ${failures.length} problem(s) across ${screens} screen(s)\n  ` + failures.join("\n  "));
    process.exit(1);
  }
  console.log(`e2e smoke: ${screens} screen(s) ok (${VIEWPORTS.map((v) => `${v.width}×${v.height}`).join(", ")})`);
}

main().catch((e) => { console.error(e); process.exit(1); });
