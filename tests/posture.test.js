// Browser posture scoring (pure) — fixture facts objects for a hardened and an exposed browser.
(() => {
"use strict";
const PO = W.eng.posture;
const facts = (name) => JSON.parse(fixture(name));

test("UA parsing", () => {
  const c = PO.parseUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36");
  assert.deepEqual([c.name, c.major, c.engine, c.os], ["Chrome", 142, "blink", "Windows"]);
  const f = PO.parseUA("Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0");
  assert.deepEqual([f.name, f.major, f.engine, f.os], ["Firefox", 145, "gecko", "Linux"]);
  const s = PO.parseUA("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1");
  assert.deepEqual([s.name, s.major, s.os, s.osVersion, s.mobile], ["Safari", 26, "iOS", "18.6", true]);
  const e = PO.parseUA("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Edg/141.0", { platform: "Windows", platformVersion: "15.0.0", brands: [] });
  assert.deepEqual([e.name, e.major, e.platformVersion], ["Edge", 141, "15.0.0"]);
  const br = PO.parseUA("Mozilla/5.0 (X11; Linux x86_64) Chrome/142.0 Safari/537.36", { brands: [{ brand: "Brave", version: "142" }], platform: "Linux" });
  assert.equal(br.name, "Brave");
});

test("expected browser majors move with the release train", () => {
  assert.equal(PO.expectedMajor("Chrome", Date.UTC(2025, 9, 28)), 142);
  assert.equal(PO.expectedMajor("Chrome", Date.UTC(2025, 10, 25)), 143);
  assert.equal(PO.expectedMajor("Firefox", "2026-11-18T00:00:00Z"), 158);
  assert.equal(PO.expectedMajor("Opera", Date.now()), null);          // Opera/Samsung numbering differs from Chromium
  assert.equal(PO.expectedMajor("Safari", "2026-11-18T00:00:00Z"), 27);
  assert.equal(PO.expectedMajor("Safari", "2026-03-01T00:00:00Z"), 26);
  assert.equal(PO.expectedMajor("Safari", "2024-10-01T00:00:00Z"), 18);
  assert.equal(PO.expectedMajor("Lynx", Date.now()), null);
});

test("hardened facts score high", () => {
  const r = PO.evaluate(facts("yoroi-b-posture-hardened.json"));
  assert.ok(r.score >= 90, `${r.score} ${JSON.stringify(r.fixes.map((f) => f.id))}`);
  assert.equal(r.posture, "HARDENED");
  assert.equal(r.counts.fail, 0);
  for (const c of r.checks) assert.ok(["pass", "warn", "fail", "info"].includes(c.status) && typeof c.weight === "number" && c.title);
});

test("exposed facts score low with prioritised fixes", () => {
  const r = PO.evaluate(facts("yoroi-b-posture-exposed.json"));
  assert.ok(r.score < 55, String(r.score));
  assert.equal(r.posture, "AT RISK");
  const byId = Object.fromEntries(r.checks.map((c) => [c.id, c]));
  assert.equal(byId["secure-context"].status, "fail");
  assert.equal(byId["browser-current"].status, "fail");
  assert.equal(byId["os-support"].status, "fail");            // Windows 10 via client hints
  assert.equal(byId["webrtc"].status, "fail");
  assert.equal(byId["perm-camera"].status, "warn");
  assert.equal(byId["third-party-cookies"].status, "warn");
  assert.equal(byId["fingerprint"].status, "fail");
  // fixes: failures first, then by weight
  assert.equal(r.fixes[0].status, "fail");
  assert.equal(r.fixes[0].id, "browser-current");
  assert.ok(r.fixes.every((f) => f.fix));
  const ws = r.fixes.map((f) => [f.status, f.weight]);
  for (let i = 1; i < ws.length; i++) assert.ok(ws[i - 1][0] === "fail" && ws[i][0] === "warn" || ws[i - 1][0] === ws[i][0] && ws[i - 1][1] >= ws[i][1], JSON.stringify(ws));
  // checks are sorted fail → warn → pass → info
  const rank = { fail: 0, warn: 1, pass: 2, info: 3 };
  for (let i = 1; i < r.checks.length; i++) assert.ok(rank[r.checks[i - 1].status] <= rank[r.checks[i].status]);
});

test("score maths: warn = half weight, info ignored, empty facts don't crash", () => {
  const r = PO.evaluate({});
  assert.ok(r.score >= 0 && r.score <= 100);
  const scored = r.checks.filter((c) => c.status !== "info" && c.weight > 0);
  const tot = scored.reduce((a, c) => a + c.weight, 0);
  const earned = scored.reduce((a, c) => a + (c.status === "pass" ? c.weight : c.status === "warn" ? c.weight / 2 : 0), 0);
  assert.equal(r.score, Math.round(earned * 100 / tot));
});

test("ICE candidate classification", () => {
  assert.equal(PO.classifyCandidates(["candidate:1 1 udp 2122260223 4f6a-uuid.local 54321 typ host generation 0"]).leak, "mdns");
  const p = PO.classifyCandidates(["candidate:1 1 udp 2122260223 192.168.1.23 54321 typ host"]);
  assert.deepEqual([p.leak, p.ips], ["private", ["192.168.1.23"]]);
  assert.equal(PO.classifyCandidates(["candidate:1 1 udp 2122260223 8.8.4.4 54321 typ host"]).leak, "public");
  assert.equal(PO.classifyCandidates([]).leak, "none");
});
})();
