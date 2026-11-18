// Kemuridama · stego — KS1 LSB payloads, byte-compatible with Katana shinobi/cipher.py.
const ST = () => W.eng.stego;
const fx = (n) => new Uint8Array(fixture("kemuridama/" + n, { bin: true }));
test("extracts messages embedded by Katana (with and without password)", async () => {
  assert.equal((await ST().extract(fx("katana-stego-pw.png"), "otter")).message, "rendezvous 0300 — pier 7");
  assert.equal((await ST().extract(fx("katana-stego.png"))).message, "no password here");
  const wrong = await ST().extract(fx("katana-stego-pw.png"), "heron");
  assert.notEqual(wrong.message, "rendezvous 0300 — pier 7");
});
test("embed → extract round trip; pixels change only in the LSB", async () => {
  const cover = fx("cover.png");
  const e = await ST().embed(cover, "meet at dawn ✓", "pw");
  assert.equal(e.used, 7 + W.bytes("meet at dawn ✓").length);
  const back = await ST().extract(e.png, "pw"); assert.equal(back.message, "meet at dawn ✓");
  const a = (await ST().decode(cover)).pixels, b = (await ST().decode(e.png)).pixels;
  assert.equal(a.length, b.length);
  for (let i = 0; i < a.length; i++) assert.ok((a[i] ^ b[i]) <= 1);
});
test("capacity limit, bad header, detector", async () => {
  const cover = fx("cover.png"), img = await ST().decode(cover);
  await assert.rejects(() => ST().embed(cover, "x".repeat(ST().capacity(img) + 1)), /too large/);
  await ST().embed(cover, "x".repeat(ST().capacity(img)));
  await assert.rejects(() => ST().extract(cover), /No hidden message/);
  assert.equal((await ST().detect(fx("katana-stego.png"))).ks1_header, true);
  assert.equal((await ST().detect(cover)).ks1_header, false);
});
test("binary payloads (e.g. a CIPHER container) survive", async () => {
  const ct = await W.eng.cipher.encrypt(W.bytes("inner secret"), { passphrase: "p", iterations: 100000 });
  const e = await ST().embed(fx("cover.png"), ct);
  const r = await ST().extract(e.png);
  assert.equal(r.message, null);
  assert.equal(W.utf8((await W.eng.cipher.decrypt(r.bytes, { passphrase: "p" })).data), "inner secret");
});
