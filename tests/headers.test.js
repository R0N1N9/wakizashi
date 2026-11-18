// Security-header review: parsing, CSP evaluation, HSTS, framing, CORS, disclosure, cookies, grading.
{
const HD = W.eng.headers;
const ids = (r) => r.findings.map((f) => f.id);
const sevOf = (r, id) => (r.findings.find((f) => f.id === id) || {}).sev;

test("headers: parse picks the last response block, keeps repeated headers", () => {
  const p = HD.parse(fixture("naginata-headers-weak.txt"));
  assert.equal(p.blocks, 2);
  assert.equal(p.status, "HTTP/1.1 200 OK");
  assert.equal(p.headers["set-cookie"].length, 4);
  assert.ok(!p.headers.location);
  const v = HD.parse("< HTTP/1.1 200 OK\n< X-A: 1\n<   continued\n");     // curl -v + folding
  assert.equal(v.headers["x-a"][0], "1 continued");
});

test("headers: CSP parser", () => {
  const c = HD.parseCSP("default-src 'self'; script-src 'self' https://a.example; script-src 'none';;");
  assert.deepEqual(c.order, ["default-src", "script-src"]);
  assert.deepEqual(c.directives["script-src"], ["'self'", "https://a.example"]);
  assert.deepEqual(c.dupes, ["script-src"]);
});

test("headers: strong configuration grades A", () => {
  const r = HD.analyse(fixture("naginata-headers-strong.txt"));
  assert.equal(r.grade, "A", JSON.stringify(r.findings.filter((f) => !["ok", "info"].includes(f.sev))));
  assert.ok(ids(r).includes("csp-strict") && ids(r).includes("hsts-ok") && ids(r).includes("csp-tt"));
  assert.ok(!r.findings.some((f) => ["high", "medium", "critical"].includes(f.sev)));
  assert.equal(r.cookies[0].issues[0].sev, "ok");
});

test("headers: weak configuration grades F with specific findings", () => {
  const r = HD.analyse(fixture("naginata-headers-weak.txt"));
  assert.equal(r.grade, "F");
  const want = ["csp-unsafe-inline", "csp-unsafe-eval", "csp-wild-script", "csp-subdomain-script", "csp-http-script", "csp-dupe", "csp-deprecated", "csp-object", "csp-base",
    "hsts-short", "hsts-sub", "xfo-allowfrom", "rp-unsafe", "pp-legacy", "xxp", "cors-wild-cred", "disc-server", "disc-x-powered-by", "disc-x-aspnet-version",
    "cookie-secure", "cookie-httponly", "cookie-samesite", "cookie-samesite-none", "cookie-host-prefix", "cookie-lifetime", "cache"];
  for (const id of want) assert.ok(ids(r).includes(id), "missing " + id);
  assert.equal(sevOf(r, "csp-unsafe-inline"), "high");
  assert.equal(sevOf(r, "cors-wild-cred"), "high");
  const sess = r.cookies.find((c) => c.name === "PHPSESSID");
  assert.equal(sess.issues.find((i) => i.id === "secure").sev, "high");       // session-looking cookie
  assert.equal(sess.issues.find((i) => i.id === "httponly").sev, "medium");
  assert.match(r.findings.find((f) => f.id === "disc-server").title, /Apache\/2\.4\.49/);
  assert.ok(r.findings[0].sev === "high");                                     // sorted by severity
  assert.ok(r.findings.every((f) => f.fix || f.sev === "ok" || f.sev === "info"));
});

test("headers: missing everything", () => {
  const r = HD.analyse("HTTP/1.1 200 OK\nContent-Type: text/html\n");
  for (const id of ["csp-missing", "hsts-missing", "xfo-missing", "xcto-missing", "rp-missing", "pp-missing", "coop-missing"]) assert.ok(ids(r).includes(id), id);
  assert.ok(["D", "F"].includes(r.grade));
  const http = HD.analyse("Content-Type: text/html\n", { https: false });
  assert.ok(ids(http).includes("http") && !ids(http).includes("hsts-missing"));
  assert.ok(HD.analyse("").empty);
});

test("headers: framing, referrer, CORS and report-only details", () => {
  // frame-ancestors present → no XFO finding needed
  let r = HD.analyse("Content-Security-Policy: default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'");
  assert.ok(!ids(r).includes("xfo-missing"));
  // last valid referrer value wins
  r = HD.analyse("Referrer-Policy: unsafe-url, strict-origin-when-cross-origin");
  assert.equal(sevOf(r, "rp-ok"), "ok");
  r = HD.analyse("Access-Control-Allow-Origin: null");
  assert.equal(sevOf(r, "cors-null"), "high");
  r = HD.analyse("Access-Control-Allow-Origin: https://app.example.com\nAccess-Control-Allow-Credentials: true");
  assert.ok(ids(r).includes("cors-cred") && ids(r).includes("cors-vary"));
  r = HD.analyse("Content-Security-Policy-Report-Only: script-src 'unsafe-inline'");
  assert.ok(ids(r).includes("csp-missing") && ids(r).includes("csp-ro"));
  assert.equal(r.findings.find((f) => f.id === "csp-unsafe-inline").sev, "info");   // report-only never enforces
  // nonce present → unsafe-inline is only a fallback
  r = HD.analyse("Content-Security-Policy: script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'");
  assert.ok(ids(r).includes("csp-unsafe-inline-fallback") && !ids(r).includes("csp-unsafe-inline"));
  assert.match(HD.toMarkdown(r), /Grade [A-F]/);
});
}
