// Kemuridama · mirror — fingerprint scoring heuristic + Katana stylometry/contamination ports.
const M = () => W.eng.mirror;
const BASE = { ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", languages: ["en-US"],
  timezone: "America/New_York", tzOffset: -300, screen: { w: 1920, h: 1080, availW: 1920, availH: 1040, depth: 24 }, dpr: 1, cores: 8, memory: 8, platform: "Win32",
  cookies: true, localStorage: true, indexedDB: true, dnt: false, gpc: false, touchPoints: 0, mobile: false, canvasHash: "ab12cd34ef56ab12", webglVendor: "Google Inc. (NVIDIA)",
  webglRenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11)", audio: true, sampleRate: 48000, audioChannels: 2, fonts: ["Arial", "Calibri", "Segoe UI"], fontsTested: 30, webrtc: true,
  media: { audioinput: 1, videoinput: 1, audiooutput: 1 }, colorScheme: "dark", pdfViewer: true };
test("score: every signal rated, totals consistent, explanation present", () => {
  const r = M().score(BASE);
  assert.ok(r.signals.length >= 15);
  for (const s of r.signals) { assert.ok(["low", "medium", "high"].includes(s.rating)); assert.ok(s.why); }
  assert.equal(r.bits, +r.signals.reduce((n, s) => n + s.bits, 0).toFixed(1));
  assert.equal(r.effectiveBits, +(r.bits * 0.7).toFixed(1));
  assert.match(r.note, /correlation discount/);
  assert.ok(r.tips.length >= 3);
});
test("rarer configurations score higher", () => {
  const common = M().score(BASE);
  const rare = M().score(Object.assign({}, BASE, { ua: BASE.ua.replace("Windows NT 10.0; Win64; x64", "X11; Linux x86_64"), languages: ["fi-FI", "sv-SE", "en-GB"],
    timezone: "Pacific/Chatham", screen: { w: 2133, h: 1200, availW: 2133, availH: 1100, depth: 30 }, dpr: 1.75, cores: 12, fonts: Array.from({ length: 14 }, (_, i) => "F" + i), dnt: true, gpc: true }));
  assert.ok(rare.effectiveBits > common.effectiveBits + 10, `${rare.effectiveBits} vs ${common.effectiveBits}`);
  assert.ok(rare.unique);
  const noise = M().score(Object.assign({}, BASE, { canvasNoise: true }));
  assert.ok(noise.signals.find((s) => s.id === "canvas").bits < 2);
});
test("stylometry: same text family ranks above unrelated", () => {
  const a = "I think that the plan is good, but we should wait until the morning. It is not that I don't trust them; it's that I have seen this before, and it was not pretty.";
  const b = "I think that the idea is fine, but we should hold off until the evening. It is not that I don't like it; it's that I have tried this before, and it was not easy.";
  const c = "Colour samples arrived!!! Fab. Organise lift to centre tomorrow 9am GMT :) cheers";
  const r = M().stylometry([{ label: "A", text: a }, { label: "B", text: b }, { label: "C", text: c }]);
  assert.equal(r.pairs[0].a + r.pairs[0].b, "AB");
  assert.ok(r.pairs[0].similarity > r.pairs[2].similarity);
  assert.ok(r.pairs.every((p) => p.low_confidence));
  const tells = r.tells[2].hits.map((h) => h.tell);
  for (const t of ["British/Commonwealth spelling", "time zone / locale mention", "emoji / emoticon habit"]) assert.ok(tells.includes(t), t);
  assert.throws(() => M().stylometry([{ text: "only one" }]));
});
test("contamination: shared handle/email local-part raises burn risk", () => {
  const r = M().contamination([{ name: "Ghost", handles: ["nightowl"], emails: ["nightowl@example.com"] }, { name: "Shade", handles: ["NightOwl", "lurker"], emails: ["x@example.org"], notes: "cover" }, { name: "Clean", handles: ["solo"], notes: "ok" }]);
  assert.equal(r.collisions.length, 1); assert.deepEqual(r.collisions[0].shared_by, ["Ghost", "Shade"]);
  assert.equal(r.risks[0].persona, "Ghost"); assert.equal(r.risks[0].score, 60); assert.equal(r.risks[0].level, "critical");
  assert.equal(r.risks.find((x) => x.persona === "Clean").score, 0);
});
