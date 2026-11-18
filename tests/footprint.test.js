// Kemuridama · footprint — self-OSINT link builder + dossier posture score.
const F = () => W.eng.footprint;
test("classify identifiers", () => {
  assert.equal(F().classify("jane@example.org"), "email"); assert.equal(F().classify("+44 20 7946 0123"), "phone");
  assert.equal(F().classify("@jane_doe"), "username"); assert.equal(F().classify("Jane Example"), "name"); assert.equal(F().classify("example.org"), "domain");
});
test("username → ~40+ profile URLs, all https and encoded", () => {
  const r = F().links("@ja ne?", "username");
  const prof = r.groups.find((g) => g.id === "profiles").items;
  assert.ok(prof.length >= 40);
  for (const it of r.groups.flatMap((g) => g.items)) assert.match(it.url, /^https:\/\//);
  assert.ok(prof.find((p) => p.label === "GitHub").url.endsWith("/ja%20ne%3F"));
  assert.ok(r.groups.some((g) => g.id === "brokers"));
});
test("email → HIBP link, gravatar md5, domain links for custom domains only", () => {
  const r = F().links("Jane@Example.org");
  const breach = r.groups.find((g) => g.id === "breach").items;
  assert.equal(breach[0].url, "https://haveibeenpwned.com/account/Jane%40Example.org");
  assert.ok(breach.find((b) => /Gravatar/.test(b.label)).url.endsWith(W.hash.md5("jane@example.org")));
  assert.ok(r.groups.some((g) => g.id === "domain"));
  assert.ok(!F().links("someone@gmail.com").groups.some((g) => g.id === "domain"));
});
test("dossier score matches dossier.py semantics", () => {
  assert.equal(F().QUESTIONS.length, 22);
  const none = F().score({}); assert.equal(none.score, 0); assert.equal(none.grade, "F"); assert.equal(none.gaps.length, 22);
  const all = {}; for (const q of F().QUESTIONS) all[q.id] = true;
  const full = F().score(all); assert.equal(full.score, 100); assert.equal(full.grade, "A"); assert.equal(full.answered, 22);
  const some = F().score({ dev_fde: true, acc_mfa: true, acc_pwmgr: false });
  const max = F().QUESTIONS.reduce((n, q) => n + q.weight, 0);
  assert.equal(some.score, Math.round(100 * 20 / max)); assert.equal(some.answered, 3);
  assert.equal(some.priorities[0].id, "acc_pwmgr"); // heaviest remaining gap (9)
});
