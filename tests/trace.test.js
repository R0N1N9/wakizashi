// Kemuridama · trace — tracker stripping, redirect unwrapping, punycode + homographs, HTML beacons.
const T = () => W.eng.trace;
test("strips utm_*, fbclid, gclid, mc_eid, igshid; keeps real params + order", () => {
  const r = T().cleanUrl("https://shop.example/item?id=42&utm_source=news&utm_medium=email&fbclid=IwAR0&color=red&gclid=Cj0&mc_eid=abc&igshid=x");
  assert.equal(r.clean, "https://shop.example/item?id=42&color=red");
  assert.deepEqual(r.removed.map((x) => x.param), ["utm_source", "utm_medium", "fbclid", "gclid", "mc_eid", "igshid"]);
  assert.equal(T().cleanUrl("https://example.com/?q=hello&page=2").clean, "https://example.com/?q=hello&page=2");
});
test("host-scoped params (si on YouTube/Spotify, Amazon ref + slug)", () => {
  assert.equal(T().cleanUrl("https://youtu.be/dQw4w9WgXcQ?si=AbC123&t=42").clean, "https://youtu.be/dQw4w9WgXcQ?t=42");
  assert.equal(T().cleanUrl("https://open.spotify.com/track/xyz?si=123").clean, "https://open.spotify.com/track/xyz");
  assert.equal(T().cleanUrl("https://www.amazon.com/Some-Product/dp/B08N5WRWNW/ref=sr_1_1?keywords=x&qid=1&th=1").clean, "https://www.amazon.com/dp/B08N5WRWNW?th=1");
  assert.equal(T().cleanUrl("https://example.com/?si=keep").clean, "https://example.com/?si=keep"); // not a tracker elsewhere
});
test("unwraps Google, Facebook, Outlook Safe Links, LinkedIn, Slack, Proofpoint (nested)", () => {
  const cases = {
    "https://www.google.com/url?sa=t&q=https%3A%2F%2Fexample.com%2Fp%3Futm_source%3Dx%26id%3D5&ved=1": "https://example.com/p?id=5",
    "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2F%3Ffbclid%3DIw&h=AT": "https://example.org/",
    "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.net%2Fa&data=05": "https://example.net/a",
    "https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fexample.io%2F&urlhash=x": "https://example.io/",
    "https://slack-redir.net/link?url=https%3A%2F%2Fexample.dev%2Fdocs": "https://example.dev/docs",
    "https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_path-3Fa-3D1&d=DwMF": "https://example.com/path?a=1",
    "https://urldefense.com/v3/__https://example.com/x__;!!abc": "https://example.com/x",
  };
  for (const [i, o] of Object.entries(cases)) assert.equal(T().cleanUrl(i).clean, o, i);
  const nested = "https://www.google.com/url?q=" + encodeURIComponent("https://l.facebook.com/l.php?u=" + encodeURIComponent("https://final.example/?utm_campaign=z"));
  const r = T().cleanUrl(nested);
  assert.equal(r.clean, "https://final.example/"); assert.deepEqual(r.unwrapped.map((u) => u.via), ["Google redirect", "Facebook link shim"]);
});
test("shorteners flagged as unresolvable offline", () => {
  const r = T().cleanUrl("https://t.co/AbC123");
  assert.ok(r.shortener); assert.equal(r.flags[0].level, "high"); assert.match(r.flags[0].text, /can't be expanded offline/);
});
test("punycode RFC 3492 + homograph warning", () => {
  assert.equal(T().punyDecode("bcher-kva"), "bücher");
  assert.equal(T().punyEncode("bücher"), "bcher-kva");
  assert.equal(T().punyEncode("münchen"), "mnchen-3ya");
  assert.equal(T().toUnicodeHost("xn--80ak6aa92e.com"), "аррӏе.com");
  const r = T().cleanUrl("https://xn--pple-43d.com/login");
  assert.equal(r.hostUnicode, "аpple.com");
  assert.ok(r.flags.some((f) => f.level === "high" && /looks like apple\.com/.test(f.text)));
  assert.ok(T().cleanUrl("https://xn--bcher-kva.example/").flags.some((f) => f.level === "info"));
});
test("text mode: rewrites every link in place; HTML mode: beacons + links", () => {
  const a = T().analyze("read https://example.com/a?utm_source=x&b=1, then www.example.org/?gclid=9.");
  assert.equal(a.cleanedText, "read https://example.com/a?b=1, then www.example.org/.");
  const h = T().analyze('<div><img src="https://x.list-manage.com/track/open.php?u=1" width="1" height="1"><img src="https://cdn.example/logo.png" width="120">'
    + '<img src="https://mail.example/o/abc" style="display:none"><a href="https://site.example/?utm_campaign=x&p=2">x</a></div>');
  assert.equal(h.mode, "html"); assert.equal(h.remoteImages, 3);
  assert.deepEqual(h.beacons.map((b) => b.tracker), ["Mailchimp", "likely open-tracking pixel"]);
  assert.deepEqual(h.sanitized, ["https://site.example/?p=2"]);
});
test("credential-prefix, raw IP and http flags", () => {
  const f = T().cleanUrl("http://paypal.com@203.0.113.9/login").flags.map((x) => x.text).join(" | ");
  assert.match(f, /real host is 203\.0\.113\.9/); assert.match(f, /Raw IP/); assert.match(f, /Plain http/);
});
