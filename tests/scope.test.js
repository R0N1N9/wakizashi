// Scope engine: entry parsing, wildcard domains, v4/v6 containment, out-of-scope overrides.
{
const SC = W.eng.scope;
const SCOPE = fixture("naginata-scope.txt").split("\n---\n");
const scope = { in: SCOPE[0], out: SCOPE[1] };

test("scope: parse entries", () => {
  const { entries, invalid } = SC.parseList(SCOPE[0]);
  const forms = entries.map((e) => e.form);
  assert.ok(forms.includes("cidr") && forms.includes("range") && forms.includes("wildcard") && forms.includes("domain") && forms.includes("ip"));
  assert.equal(invalid.length, 1);
  assert.match(invalid[0].error, /wildcard/);
  const r = SC.parseEntry("198.51.100.10-20");
  assert.equal(r.size, 11n);
  assert.equal(r.label, "198.51.100.10 – 198.51.100.20");
  assert.equal(SC.parseEntry("https://User@App.Example.com:8443/login?x=1").domain, "app.example.com");
  assert.equal(SC.parseEntry("api[.]example[.]com").domain, "api.example.com");
  assert.equal(SC.parseEntry("10.0.0.0/8  # corp").note, "corp");
  assert.equal(SC.parseEntry("[2001:db8::1]:443").label, "2001:db8::1");
  assert.equal(SC.parseList("a.example.com, b.example.com; 10.0.0.1").entries.length, 3);
});

test("scope: wildcard domain matching", () => {
  const w = SC.parseEntry("*.example.com"), d = SC.parseEntry(".corp.test"), x = SC.parseEntry("example.com");
  assert.ok(SC.domainMatch(w, "a.example.com"));
  assert.ok(SC.domainMatch(w, "a.b.example.com"));
  assert.ok(!SC.domainMatch(w, "example.com"));
  assert.ok(!SC.domainMatch(w, "badexample.com"));
  assert.ok(SC.domainMatch(d, "corp.test") && SC.domainMatch(d, "x.corp.test"));
  assert.ok(SC.domainMatch(x, "EXAMPLE.com.") && !SC.domainMatch(x, "www.example.com"));
});

test("scope: in-scope checks (v4, v6, domains, URLs)", () => {
  const ok = ["10.20.30.40", "10.20.0.0/16", "198.51.100.15", "2001:db8:1::abcd", "2001:db8:1:ff::/64", "www.example.com", "https://shop.example.com/cart", "example.com", "*.dev.example.com"];
  for (const t of ok) assert.equal(SC.check(t, scope).verdict, "in", t + " → " + SC.check(t, scope).reason);
});

test("scope: out-of-scope overrides in-scope", () => {
  const out = ["10.10.10.10", "10.10.10.0/28", "vpn.example.com", "payments.example.com", "a.b.payments.example.com", "2001:db8:1:dead::1"];
  for (const t of out) assert.equal(SC.check(t, scope).verdict, "out", t + " → " + SC.check(t, scope).reason);
  const r = SC.check("vpn.example.com", scope);
  assert.ok(r.inMatches.length && r.outMatches.length);    // matched both — exclusion wins
  assert.match(r.reason, /excluded/);
});

test("scope: partial, unlisted, unresolved, invalid", () => {
  assert.equal(SC.check("10.10.0.0/16", scope).verdict, "partial");           // contains the excluded /24
  assert.equal(SC.check("198.51.100.0/24", scope).verdict, "partial");        // range only covers .10-.20
  assert.equal(SC.check("8.8.8.8", scope).verdict, "unlisted");
  assert.equal(SC.check("evil.test", scope).verdict, "unlisted");
  assert.equal(SC.check("*.example.com", scope).verdict, "partial");          // wildcard target hits exclusions
  assert.equal(SC.check("app.example.org", { in: "203.0.113.0/24" }).verdict, "unresolved");
  assert.equal(SC.check("not a host!", scope).verdict, "invalid");
  // union coverage: two adjacent /25s cover a /24
  assert.equal(SC.check("192.0.2.0/24", { in: "192.0.2.0/25\n192.0.2.128/25" }).verdict, "in");
  // v4 entries never match v6 targets
  assert.equal(SC.check("::ffff:10.0.0.1", { in: "10.0.0.0/8" }).verdict, "unlisted");
  const many = SC.checkMany("10.20.0.1\nvpn.example.com", scope);
  assert.deepEqual(many.map((m) => m.verdict), ["in", "out"]);
});

test("scope: summarise", () => {
  const s = SC.summarise("10.0.0.0/24\n10.0.1.1-10\n2001:db8::/64\n*.example.com\nexample.com");
  assert.equal(s.v4, 266n); assert.equal(s.v6, 1n << 64n); assert.equal(s.wildcards, 1); assert.equal(s.domains, 1);
});
}
