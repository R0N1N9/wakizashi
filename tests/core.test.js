// Core runtime: hashing, encodings, indicator typing, store, cases.
test("md5 known vectors", () => {
  assert.equal(W.hash.md5(""), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(W.hash.md5("abc"), "900150983cd24fb0d6963f7d28e17f72");
  assert.equal(W.hash.md5("The quick brown fox jumps over the lazy dog"), "9e107d9d372bb6826bd81d3542a419d6");
  assert.equal(W.hash.md5("a".repeat(1000)), "cabe45dcc9ae5b66ba86600cca6b8ba8");
});
test("sha via WebCrypto + hash.all", async () => {
  assert.equal(await W.hash.sha("SHA-256", "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const h = await W.hash.all("abc");
  assert.equal(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
  assert.equal(h.md5, "900150983cd24fb0d6963f7d28e17f72");
});
test("refang / defang", () => {
  assert.equal(W.refang("hxxps://evil[.]example[.]com/x"), "https://evil.example.com/x");
  assert.equal(W.refang("bad(at)mail[dot]com"), "bad@mail.com");
  assert.equal(W.defang("http://a.b"), "hxxp://a[.]b");
});
test("detectType", () => {
  const cases = { "8.8.8.8": "ipv4", "10.0.0.0/8": "cidr", "https://x.io/a": "url", "a@b.co": "email", "evil.example.com": "domain",
    "d41d8cd98f00b204e9800998ecf8427e": "md5", "CVE-2024-3400": "cve", "T1059.001": "attack", "AS13335": "asn", "2001:db8::1": "ipv6", "@handle": "username" };
  for (const [v, t] of Object.entries(cases)) assert.equal(W.detectType(v), t, v);
  assert.equal(W.detectType("not an indicator"), null);
});
test("entropy + hex/b64 round trips", () => {
  assert.equal(W.entropy(new Uint8Array(64)), 0);
  assert.ok(W.entropy(Uint8Array.from({ length: 256 }, (_, i) => i)) > 7.99);
  assert.equal(W.utf8(W.fromB64(W.b64("héllo ✓"))), "héllo ✓");
  assert.equal(W.hex(W.fromHex("deadBEEF")), "deadbeef");
});
test("store + cases", () => {
  W.store.set("x", { a: 1 }); assert.deepEqual(W.store.get("x"), { a: 1 });
  const id = W.Case.create("Op Test");
  assert.equal(W.Case.active().id, id);
  assert.equal(W.Case.add([{ value: "evil[.]com" }, { value: "evil.com" }, { value: "1.2.3.4", verdict: "malicious" }], true), 2);
  const c = W.Case.active();
  assert.equal(c.items.length, 2);
  assert.ok(c.items.some((x) => x.value === "evil.com" && x.type === "domain"));
});
