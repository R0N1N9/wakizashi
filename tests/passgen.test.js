// Kemuridama · passgen — generator correctness and zxcvbn-lite estimates.
const P = () => W.eng.passgen;
test("password: length, classes, unbiased pool, entropy bits", () => {
  for (let i = 0; i < 50; i++) {
    const r = P().password({ length: 16 });
    assert.equal(r.value.length, 16);
    assert.ok(/[a-z]/.test(r.value) && /[A-Z]/.test(r.value) && /\d/.test(r.value) && /[^A-Za-z0-9]/.test(r.value), r.value);
  }
  const r = P().password({ length: 20, symbols: false, ambiguous: false });
  assert.ok(!/[Il1O0o]/.test(r.value) && /^[A-Za-z0-9]+$/.test(r.value));
  assert.equal(P().password({ length: 10, upper: false, digits: false, symbols: false }).bits, +(10 * Math.log2(26)).toFixed(1));
  assert.throws(() => P().password({ lower: false, upper: false, digits: false, symbols: false }));
});
test("randInt is uniform-ish (chi-square sanity)", () => {
  const n = 6, c = new Array(n).fill(0); for (let i = 0; i < 6000; i++) c[P().randInt(n)]++;
  const chi = c.reduce((s, x) => s + (x - 1000) ** 2 / 1000, 0); assert.ok(chi < 30, String(chi));
});
test("passphrase: words from the list, bits = n·log2(N)", () => {
  const r = P().passphrase({ words: 6, sep: " " });
  const ws = r.value.split(" "); assert.equal(ws.length, 6);
  for (const w of ws) assert.ok(W.eng.words.set.has(w), w);
  assert.equal(r.bits, +(6 * Math.log2(W.eng.words.size)).toFixed(1));
  assert.ok(W.eng.words.size >= 2000);
  const c = P().passphrase({ words: 4, caps: true, number: true });
  assert.match(c.value, /^([A-Z][a-z]+\d?-){3}[A-Z][a-z]+\d?$/); assert.match(c.value, /\d/);
});
test("estimate: common passwords, l33t, keyboard, sequences, repeats, dates", () => {
  const e = (p, u) => P().estimate(p, u);
  assert.equal(e("password").score, 0); assert.equal(e("password").sequence[0].dict, "common passwords");
  const l = e("P@ssw0rd"); assert.ok(l.sequence[0].l33t && l.score <= 1);
  assert.equal(e("zxcvbnm,./").sequence[0].pattern, "keyboard");
  assert.equal(e("abcdefgh").sequence[0].pattern, "sequence");
  assert.equal(e("aaaaaaaaaa").sequence[0].pattern, "repeat");
  assert.equal(e("12/05/1990").sequence[0].pattern, "date");
  const j = e("jane1987", ["Jane"]); assert.deepEqual(j.sequence.map((m) => m.pattern), ["dictionary", "year"]); assert.match(j.warning, /your own/);
  assert.ok(e("drowssap").sequence[0].reversed);
});
test("estimate: strong inputs score high; monotone in length", () => {
  assert.equal(P().estimate("Xk9#mQ2!vL7p").score, 4);
  assert.ok(P().estimate("lantern-otter-harbor-quill-ember").score >= 4);
  assert.ok(P().estimate("kittenlantern").guesses > P().estimate("kitten").guesses);
  const r = P().estimate("tide-lantern-otter-9");
  for (const k of ["online_throttled", "online", "offline_slow", "offline_fast"]) assert.ok(r.crack[k].text);
  assert.equal(P().estimate("").score, 0);
  assert.equal(P().duration(0.2), "instant"); assert.equal(P().duration(90), "2 minutes"); assert.equal(P().duration(1e12), "centuries");
});
