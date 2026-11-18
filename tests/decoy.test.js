// Kemuridama · decoy — seeded personas (reproducible, fiction phone ranges) + canary/honeytoken port.
const D = () => W.eng.decoy;
test("same seed → same persona; different seed → different", () => {
  const a = D().persona({ seed: "amber-falcon-1234", country: "us", today: "2026-11-18" }), b = D().persona({ seed: "amber-falcon-1234", country: "us", today: "2026-11-18" });
  const strip = (p) => Object.assign({}, p, { password: null });
  assert.deepEqual(strip(a), strip(b));
  assert.notEqual(a.password, b.password); // password never derives from the seed
  const c = D().persona({ seed: "amber-falcon-1235", country: "us", today: "2026-11-18" });
  assert.notDeepEqual([c.name.full, c.birthdate, c.address.street], [a.name.full, a.birthdate, a.address.street]);
  assert.ok(a.fictitious); assert.match(a.note, /Fictitious/);
});
test("rng is deterministic across runs (fixed vector)", () => {
  const r = D().rng("wakizashi"); const v = [r.next(), r.next(), r.next()].map((x) => x.toFixed(6));
  const r2 = D().rng("wakizashi"); assert.deepEqual([r2.next(), r2.next(), r2.next()].map((x) => x.toFixed(6)), v);
  assert.ok(v.every((x) => +x >= 0 && +x < 1));
});
test("phone numbers stay inside regulator-reserved fiction ranges", () => {
  for (let i = 0; i < 40; i++) {
    const seed = "s" + i;
    assert.match(D().persona({ seed, country: "us" }).phone.number, /^\+1 \(\d{3}\) 555-01\d\d$/);
    assert.match(D().persona({ seed, country: "ca" }).phone.number, /^\+1 \(\d{3}\) 555-01\d\d$/);
    assert.match(D().persona({ seed, country: "uk" }).phone.number, /^\+44 (7700 900\d{3}|20 7946 0\d{3}|1[1-9]\d 49[68] 0\d{3})$/);
    assert.match(D().persona({ seed, country: "au" }).phone.number, /^\+61 (491 570 \d{3}|[2378] (5550|7010) \d{4})$/);
    assert.match(D().persona({ seed, country: "fr" }).phone.number, /^\+33 (1 99 00|6 39 98) \d\d \d\d$/);
    assert.equal(D().persona({ seed, country: "es" }).phone.number, null);
  }
});
test("persona fields: age range, address format, handles, alias from base email", () => {
  for (let i = 0; i < 20; i++) {
    const p = D().persona({ seed: "x" + i, country: "de", minAge: 30, maxAge: 40, sex: "f", baseEmail: "me@example.net", today: "2026-06-01" });
    assert.ok(p.age >= 29 && p.age <= 40, String(p.age)); assert.equal(p.sex, "f");
    assert.match(p.address.lines[1], /^\d{5} /);
    assert.ok(p.handles.length >= 4 && p.handles.every((h) => /^[a-z0-9._]+$/.test(h)), p.handles.join());
    assert.match(p.emails[0].value, /^me\+[a-z]+\d\d@example\.net$/);
    assert.equal(p.answers.length, 6);
  }
  assert.equal(D().COUNTRIES.length, 9);
});
test("canary/honeytoken port (decoy.py): web bug, creds, alias, canary docx", async () => {
  const wb = D().webbug("https://hooks.example.org/", "newsletter");
  assert.match(wb.url, /^https:\/\/hooks\.example\.org\/c\/[a-z2-7]{16}\.png$/); assert.ok(wb.snippets.html_img.includes(wb.url));
  assert.match(D().honeycred("aws").token.aws_access_key_id, /^AKIA[A-Z0-9]{16}$/);
  assert.match(D().honeycred("github").token.token, /^ghp_[A-Za-z0-9]{36}$/);
  assert.match(D().alias("joe@example.com", "Shop-X").plus, /^joe\+shopx[a-z2-7]{4}@example\.com$/);
  assert.ok(D().alias("nope", "x").error);
  const d = await D().canaryDocx("cb.example", "q3-salaries");
  assert.equal(d.filename, "q3-salaries.docx");
  const files = await W.eng.kpack.unzip(d.data);
  assert.deepEqual(files.map((f) => f.name), ["[Content_Types].xml", "_rels/.rels", "word/document.xml"]);
  assert.ok(W.utf8(files[2].data).includes(`INCLUDEPICTURE "${d.url}"`));
});
