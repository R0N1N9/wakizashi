// Kemuridama · cipher — AES-256-GCM container round trips, tamper detection, Katana OTP/Shamir interop.
const C = () => W.eng.cipher;

test("passphrase text round trip (PBKDF2 600k) + armor format", async () => {
  const arm = await C().encryptText("meet at the north gate ✓", { passphrase: "tide-lantern-otter-9" });
  assert.ok(arm.startsWith("-----BEGIN WAKIZASHI MESSAGE-----\n") && arm.endsWith("-----END WAKIZASHI MESSAGE-----"));
  assert.ok(arm.split("\n").every((l) => l.length <= 64 || l.startsWith("-----")));
  const info = C().inspect(C().dearmor(arm));
  assert.equal(info.mode, "passphrase"); assert.equal(info.iterations, 600000); assert.equal(info.version, 1);
  const r = await C().decryptText(arm, { passphrase: "tide-lantern-otter-9" });
  assert.equal(r.text, "meet at the north gate ✓");
});
test("wrong passphrase fails cleanly", async () => {
  const arm = await C().encryptText("x", { passphrase: "right", iterations: 100000 });
  await assert.rejects(() => C().decryptText(arm, { passphrase: "wrong" }), /Decryption failed/);
});
test("fresh salt + IV every time", async () => {
  const a = await C().encrypt(W.bytes("same"), { passphrase: "p", iterations: 100000 });
  const b = await C().encrypt(W.bytes("same"), { passphrase: "p", iterations: 100000 });
  assert.notEqual(W.hex(a.subarray(12, 40)), W.hex(b.subarray(12, 40)));
});
test("tamper detection: ciphertext, tag and header (AAD) bytes", async () => {
  const key = C().genKey();
  const ct = await C().encrypt(W.bytes("attack at dawn"), { key });
  for (const pos of [C().HDR + 2, ct.length - 1, 6, 9, 20, 30]) {
    const t = ct.slice(); t[pos] ^= 0x01;
    await assert.rejects(() => C().decrypt(t, { key }), pos === 6 ? /./ : /Decryption failed|Unknown|Implausible|key/, "pos " + pos);
  }
  const ok = await C().decrypt(ct, { key });
  assert.equal(W.utf8(ok.data), "attack at dawn");
});
test("generated key round trip + key format checks", async () => {
  const key = C().genKey();
  assert.match(key, /^wkzk1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(C().parseKey(key).length, 32);
  assert.throws(() => C().parseKey("wkzk1.short"));
  const ct = await C().encrypt(W.bytes("k"), { key });
  assert.equal(C().inspect(ct).mode, "key");
  await assert.rejects(() => C().decrypt(ct, { key: C().genKey() }), /Decryption failed/);
  await assert.rejects(() => C().decrypt(ct, { passphrase: "x" }), /generated key/);
});
test("binary file envelope keeps name/type, data byte-exact", async () => {
  const data = Uint8Array.from({ length: 70000 }, (_, i) => (i * 7919) & 255);
  const ct = await C().encrypt(data, { passphrase: "file-pass", iterations: 100000, name: "plans.pdf", type: "application/pdf" });
  assert.equal(C().inspect(ct).file, true);
  const r = await C().decrypt(ct, { passphrase: "file-pass" });
  assert.equal(r.name, "plans.pdf"); assert.equal(r.type, "application/pdf");
  assert.equal(r.data.length, data.length);
  assert.equal(W.hash.md5(r.data), W.hash.md5(data));
});
test("refuses garbage, weak iteration counts", async () => {
  assert.throws(() => C().inspect(W.bytes("hello world, definitely not a container at all..")));
  await assert.rejects(() => C().encrypt(W.bytes("x"), { passphrase: "p", iterations: 1000 }), /Iterations/);
  await assert.rejects(() => C().encrypt(W.bytes("x"), {}), /passphrase/);
  assert.throws(() => C().dearmor("!!! not base64 !!!"));
});
test("OTP: decrypts a ciphertext produced by Katana shinobi/cipher.py", () => {
  const pad = "+HJay+czLjGLpHzIqoasx/rT19W3CAXYF6DxOnMIog4=";
  assert.equal(C().otp("lRc/v8dSWhH/zBnoxOnes5LzsLTDbQ==", pad, "decrypt").result, "meet at the north gate");
  assert.equal(C().otp("meet at the north gate", pad).result, "lRc/v8dSWhH/zBnoxOnes5LzsLTDbQ==");
  assert.throws(() => C().otp("too long for this pad".repeat(3), pad), /Pad too short/);
});
test("Shamir: combines shares produced by Katana (any 3 of 5)", () => {
  const sh = ["AGXIFAH5Y5LZWOYK5FKI32AEEAX4IAXE6IZ6L4PN6PV74AXQKN6Z4", "AL2EPTSR2QN7ROHMF7IB75EW3GGQLW53NGYUYLFPFJXTZ2MV6F6GC",
    "AM42UPG6OYXRPI4OVH3OC6NSTPB3LLJ25H5YTLRWXD2K5DSFICOWY", "AQIKIHVUTXJVBD3AW22KKOEO6V42MJXHLSMTHSBIEKPHK5LXNG662", "AXOUT3B3H7T37FACGCJFXNNKW43RMUDG3TJ7MSVRWAC6OEVH3BOOA"];
  assert.equal(C().shamirCombine([sh[0], sh[3], sh[4]]), "correct horse battery staple ✓");
  assert.equal(C().shamirCombine([sh[2], sh[1], sh[0]]), "correct horse battery staple ✓");
  assert.notEqual(C().shamirCombine([sh[0], sh[1]]), "correct horse battery staple ✓"); // below threshold
});
test("Shamir: own split → combine, base32 matches RFC 4648", () => {
  assert.equal(C().b32(W.bytes("foobar")), "MZXW6YTBOI");
  assert.equal(W.utf8(C().unb32("MZXW6YTBOI")), "foobar");
  const shares = C().shamirSplit("vault pin 4417", 4, 2);
  assert.equal(shares.length, 4);
  assert.equal(C().shamirCombine([shares[3], shares[1]]), "vault pin 4417");
  assert.throws(() => C().shamirSplit("x", 2, 3));
  assert.throws(() => C().shamirCombine([shares[0], shares[0]]), /Duplicate/);
});
