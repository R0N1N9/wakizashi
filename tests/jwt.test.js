// JWT inspector: decode, claims, weakness analysis, WebCrypto verification (HS/RS/PS/ES, JWK, PEM, cert).
{
const J = W.eng.jwt;
const FX = JSON.parse(fixture("naginata-jwt.json"));
// jwt.io's canonical HS256 example (secret "your-256-bit-secret")
const JWTIO = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const b64u = (o) => W.b64(typeof o === "string" || o instanceof Uint8Array ? o : JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const mk = (h, p, sig = "") => `${b64u(h)}.${b64u(p)}.${sig}`;
const ids = (f) => f.map((x) => x.id);
const pem = (label, der) => `-----BEGIN ${label}-----\n${W.b64(der).match(/.{1,64}/g).join("\n")}\n-----END ${label}-----`;

test("jwt: decode + claims", () => {
  const d = J.decode("Bearer " + JWTIO);
  assert.deepEqual(d.header, { alg: "HS256", typ: "JWT" });
  assert.equal(d.payload.name, "John Doe");
  const c = J.claims(d.payload, 1516239022 + 3600);
  const iat = c.find((x) => x.name === "iat");
  assert.equal(iat.iso, "2018-01-18T01:30:22Z");
  assert.equal(iat.rel, "60m ago");
  assert.throws(() => J.decode("abc.def"), /3 dot-separated/);
  assert.throws(() => J.decode("e30.!!!.x"), /base64url/);
  assert.throws(() => J.decode("bm90IGpzb24.e30."), /header is not JSON/);
  const jwe = J.decode(b64u({ alg: "RSA1_5", enc: "A128GCM" }) + ".a.b.c.d");
  assert.ok(jwe.jwe);
  assert.ok(ids(J.analyse(jwe)).includes("jwe-rsa15"));
});

test("jwt: weakness analysis", () => {
  const now = 1700000000;
  const none = J.analyse(J.decode(mk({ alg: "none" }, { sub: "x" })), { now });
  assert.equal(none.find((f) => f.id === "alg-none").sev, "critical");
  assert.ok(ids(none).includes("exp-missing") && ids(none).includes("aud-missing") && ids(none).includes("iss-missing"));
  const nasty = J.analyse(J.decode(mk({ alg: "RS256", jku: "https://keys.example/jwks.json", x5u: "https://x/c.pem", jwk: { kty: "RSA" }, kid: "../../dev/null" },
    { iss: "a", aud: "b", iat: now, exp: now + 90 * 86400, password: "hunter2", email: "a@b.c", nested: { api_key: "k" } }, "c2ln")), { now });
  for (const id of ["hdr-jku", "hdr-x5u", "hdr-jwk", "hdr-kid-meta", "lifetime-long", "claims-sensitive", "claims-pii"]) assert.ok(ids(nasty).includes(id), id);
  assert.match(nasty.find((f) => f.id === "claims-sensitive").title, /password, nested\.api_key/);
  assert.equal(nasty.find((f) => f.id === "lifetime-long").sev, "medium");
  const stripped = J.analyse(J.decode(mk({ alg: "HS256" }, { exp: now - 10, iat: now - 100 })), { now });
  assert.ok(ids(stripped).includes("sig-empty") && ids(stripped).includes("exp-past") && ids(stripped).includes("alg-hmac"));
  const good = J.analyse(J.decode(FX.es256.token), { now: 1767226000 });
  assert.ok(ids(good).includes("alg-asym") && ids(good).includes("lifetime-ok"));
  assert.ok(!good.some((f) => ["critical", "high", "medium"].includes(f.sev)), JSON.stringify(good));
});

test("jwt: verify HS256 (jwt.io vector)", async () => {
  const r = await J.verify(JWTIO, "your-256-bit-secret");
  assert.equal(r.ok, true);
  assert.equal((await J.verify(JWTIO, "wrong-secret")).ok, false);
  const b64 = await J.verify(JWTIO, W.b64("your-256-bit-secret"), { secretEncoding: "base64" });
  assert.equal(b64.ok, true);
  const jwk = await J.verify(JWTIO, JSON.stringify({ kty: "oct", k: b64u("your-256-bit-secret") }));
  assert.equal(jwk.ok, true);
  assert.ok((await J.verify(JWTIO, "short")).notes.some((n) => /only 5 bytes/.test(n)));
  await assert.rejects(J.verify(mk({ alg: "none" }, {}), "x"), /unsigned/);
  await assert.rejects(J.verify(JWTIO, FX.es256.cert), /shared secret/);
});

test("jwt: verify ES256 with an X.509 certificate and RS256 with a PKCS#1 key (openssl fixtures)", async () => {
  const e = await J.verify(FX.es256.token, FX.es256.cert);
  assert.equal(e.ok, true); assert.equal(e.keyType, "EC"); assert.equal(e.keyFormat, "CERTIFICATE");
  const r = await J.verify(FX.rs256.token, FX.rs256.pkcs1);
  assert.equal(r.ok, true); assert.equal(r.keyType, "RSA");
  const tampered = FX.rs256.token.replace(/\.([^.]+)\./, (m, p) => "." + b64u(JSON.stringify(Object.assign(JSON.parse(W.utf8(W.fromB64(p))), { role: "admin" }))) + ".");
  assert.equal((await J.verify(tampered, FX.rs256.pkcs1)).ok, false);
  await assert.rejects(J.verify(FX.rs256.token, FX.es256.cert), /needs an RSA key/);
  await assert.rejects(J.verify(FX.rs256.token, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"), /private key/);
});

test("jwt: verify RS256 / PS384 / ES384 with generated keys as JWK, JWKS and SPKI PEM", async () => {
  const S = crypto.subtle;
  const cases = [
    ["RS256", { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, { name: "RSASSA-PKCS1-v1_5" }],
    ["PS384", { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-384" }, { name: "RSA-PSS", saltLength: 48 }],
    ["ES384", { name: "ECDSA", namedCurve: "P-384" }, { name: "ECDSA", hash: "SHA-384" }],
  ];
  for (const [alg, gen, sp] of cases) {
    const kp = await S.generateKey(gen, true, ["sign", "verify"]);
    const h = b64u({ alg, kid: "k2" }), p = b64u({ sub: "s", exp: 2000000000 });
    const sig = new Uint8Array(await S.sign(sp, kp.privateKey, W.bytes(h + "." + p)));
    const tok = `${h}.${p}.${b64u(sig)}`;
    const jwk = await S.exportKey("jwk", kp.publicKey);
    const spki = new Uint8Array(await S.exportKey("spki", kp.publicKey));
    assert.equal((await J.verify(tok, JSON.stringify(jwk))).ok, true, alg + " jwk");
    assert.equal((await J.verify(tok, pem("PUBLIC KEY", spki))).ok, true, alg + " pem");
    const jwks = await J.verify(tok, JSON.stringify({ keys: [Object.assign({ kid: "k1" }, jwk, { kid: "k1", n: jwk.n, x: jwk.x }), Object.assign({}, jwk, { kid: "k2" })] }));
    assert.equal(jwks.ok, true, alg + " jwks");
    assert.ok(jwks.notes.some((n) => /kid=k2/.test(n)));
  }
});
}
