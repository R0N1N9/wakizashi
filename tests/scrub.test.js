// Kemuridama · scrub — metadata inspection and lossless stripping over real byte fixtures
// (built by tests/fixtures/kemuridama/make.py with Pillow; all values fictitious).
const S = () => W.eng.scrub;
const fx = (n) => new Uint8Array(fixture("kemuridama/" + n, { bin: true }));
const fields = (r) => r.leaks.map((l) => l.field);
const has = (b, s) => W.latin1(b).includes(s);

test("JPEG: EXIF GPS → decimal lat/lon, camera, serial, owner, time", async () => {
  const r = await S().scan(fx("gps.jpg"), "gps.jpg");
  assert.equal(r.type, "jpeg");
  assert.deepEqual([r.gps.lat, r.gps.lon], [48.8584, 2.2945]);
  assert.equal(r.gps.alt, 35.5);
  assert.equal(r.meta.Make, "FictionCam");
  assert.equal(r.meta.Model, "FC-100 Mk II");
  assert.equal(r.meta.BodySerialNumber, "SN-0042-TEST");
  assert.equal(r.meta.Artist, "Jane Example");
  assert.equal(r.meta.DateTimeOriginal, "2024:05:01 12:34:56");
  assert.ok(r.risks[0].text.startsWith("GPS location present!"));
  assert.equal(r.level, "high");
});
test("JPEG: XMP, comment and trailing data are found", async () => {
  const r = await S().scan(fx("gps.jpg"), "gps.jpg");
  assert.equal(r.meta["dc:creator"], "Jane Example");
  assert.equal(r.meta["photoshop:City"], "Paris");
  assert.ok(fields(r).includes("JPEG comment"));
  assert.ok(fields(r).includes("Data after end of image"));
});
test("JPEG strip: lossless, only Orientation survives, scan data byte-identical", async () => {
  const src = fx("gps.jpg");
  const out = await S().strip(src, "gps.jpg");
  assert.equal(out.name, "gps.clean.jpg");
  assert.ok(out.data.length < src.length);
  for (const s of ["Jane Example", "SN-0042", "FictionCam", "balcony", "xmpmeta", "TRAILER"]) assert.ok(!has(out.data, s), s);
  const again = await S().scan(out.data, "x.jpg");
  assert.equal(again.gps, null);
  assert.equal(again.meta.Orientation, "6");
  assert.equal(again.leaks.filter((l) => l.severity !== "info").length, 0);
  // the entropy-coded scan (SOS → EOI) is copied verbatim
  const sos = (b) => { for (let i = 2; i < b.length - 1; i++) if (b[i] === 0xff && b[i + 1] === 0xda) return i; return -1; };
  const eoi = (b) => { for (let i = b.length - 2; i > 0; i--) if (b[i] === 0xff && b[i + 1] === 0xd9) return i; return -1; };
  assert.equal(W.hex(out.data.subarray(sos(out.data), eoi(out.data) + 2)), W.hex(src.subarray(sos(src), eoi(src) + 2)));
  assert.equal(out.data[out.data.length - 1], 0xd9);
});
test("JPEG strip: keepOrientation=false drops every APP1", async () => {
  const out = await S().strip(fx("gps.jpg"), "gps.jpg", { keepOrientation: false });
  assert.ok(!has(out.data, "Exif\0\0"));
});
test("JPEG without metadata is reported clean and unchanged", async () => {
  const src = fx("plain.jpg"); const r = await S().scan(src, "plain.jpg");
  assert.equal(r.summary, "No identifying metadata found — clean.");
  assert.equal(W.hex(r.clean), W.hex(src));
});
test("PNG: tEXt / zTXt / iTXt (deflated) / eXIf / tIME parsed and dropped", async () => {
  const src = fx("meta.png"); const r = await S().scan(src, "meta.png");
  assert.equal(r.meta.Author, "Jane Example");
  assert.equal(r.meta.Comment, "compressed note");           // zTXt → zlib inflate
  assert.equal(r.meta.Description, "café ünïcode");           // iTXt UTF-8
  assert.ok(fields(r).includes("PNG parameters (AI generation settings)")); // compressed iTXt
  assert.ok(fields(r).includes("PNG last-modified (tIME)"));
  assert.equal(r.gps.lat, 48.8584);
  const again = await S().scan(r.clean, "x.png");
  assert.equal(again.leaks.length, 0);
  const types = W.eng.kpack.pngChunks(r.clean).map((c) => c.type);
  assert.deepEqual(types.filter((t) => !/IDAT/.test(t)), ["IHDR", "IEND"]);
  // IDAT bytes untouched
  const idat = (b) => W.eng.kpack.pngChunks(b).filter((c) => c.type === "IDAT").map((c) => W.hex(c.data)).join("");
  assert.equal(idat(r.clean), idat(src));
});
test("WebP: EXIF + XMP chunks removed, VP8X flags and RIFF size fixed", async () => {
  const r = await S().scan(fx("meta.webp"), "meta.webp");
  assert.equal(r.gps.lon, 2.2945);
  assert.equal(r.meta["dc:creator"], "Jane Example");
  const c = r.clean, k = W.eng.kpack;
  assert.equal(k.u32le(c, 4), c.length - 8);
  assert.ok(!has(c, "EXIF") && !has(c, "XMP "));
  const vp8x = W.latin1(c).indexOf("VP8X");
  if (vp8x > 0) assert.equal(c[vp8x + 8] & 0x0c, 0);
  assert.equal((await S().scan(c, "x.webp")).leaks.length, 0);
});
test("GIF: comment extension removed with proper block walking", async () => {
  const r = await S().scan(fx("meta.gif"), "meta.gif");
  assert.equal(r.leaks[0].value, "secret gif comment");
  assert.ok(!has(r.clean, "secret"));
  assert.equal(r.clean[r.clean.length - 1], 0x3b);
});
test("PDF: Info dict (escaped + UTF-16 hex strings) + XMP; blanked in place", async () => {
  const src = fx("meta.pdf"); const r = await S().scan(src, "meta.pdf");
  assert.equal(r.meta.Author, "Jane (J) Example");
  assert.equal(r.meta.Title, "Top Secret");
  assert.equal(r.meta.CreationDate, "2024-05-01 12:34:56 +02:00");
  assert.equal(r.meta["dc:creator"], "Jane Example");
  assert.equal(r.clean.length, src.length);                    // same length → xref offsets still valid
  const t = W.latin1(r.clean);
  assert.ok(!t.includes("Jane") && !t.includes("FictionPDF"));
  const startxref = +t.match(/startxref\s+(\d+)/)[1];
  assert.equal(t.slice(startxref, startxref + 4), "xref");
  assert.equal((await S().scan(r.clean, "x.pdf")).leaks.length, 0);
});
test("DOCX: core/app props, revision + comment authors, embedded photo GPS, thumbnail", async () => {
  const r = await S().scan(fx("meta.docx"), "meta.docx");
  assert.equal(r.type, "ooxml");
  assert.equal(r.meta.creator, "Jane Example");
  assert.equal(r.meta.lastModifiedBy, "John Sample");
  assert.equal(r.meta.Company, "Example Corp");
  const authors = r.leaks.filter((l) => l.field === "Comment / revision author").map((l) => l.value).sort();
  assert.deepEqual(authors, ["Jane Example", "John Sample"]);
  assert.ok(r.gps, "GPS from word/media/image1.jpeg");
  assert.ok(fields(r).includes("Document thumbnail"));
});
test("DOCX strip: re-zipped archive is valid and free of names", async () => {
  const r = await S().scan(fx("meta.docx"), "meta.docx");
  const files = await W.eng.kpack.unzip(r.clean);
  const names = files.map((f) => f.name);
  assert.ok(!names.includes("docProps/thumbnail.jpeg"));
  assert.ok(names.includes("word/document.xml"));
  for (const f of files) {
    const s = W.latin1(f.data);
    assert.ok(!s.includes("Jane Example") && !s.includes("John Sample") && !s.includes("Example Corp"), f.name);
    assert.ok(!s.includes("thumbnail.jpeg") || f.name === "[Content_Types].xml", f.name);
  }
  const again = await S().scan(r.clean, "x.docx");
  assert.equal(again.leaks.filter((l) => l.severity === "high").length, 0);
  assert.equal(again.gps, null);
});
test("MP3: ID3v2 frames + ID3v1 trailer removed, audio kept", async () => {
  const src = fx("meta.mp3"); const r = await S().scan(src, "meta.mp3");
  assert.equal(r.meta.Artist, "Jane Example");
  assert.equal(r.clean[0], 0xff); assert.equal(r.clean[1], 0xfb);
  const tag = 10 + ((src[6] << 21) | (src[7] << 14) | (src[8] << 7) | src[9]);
  assert.equal(r.clean.length, src.length - tag - 128);
  assert.equal(W.hex(r.clean), W.hex(src.subarray(tag, src.length - 128)));
  assert.ok(!has(r.clean, "Jane"));
});
test("unknown + kind detection", async () => {
  assert.equal(S().kindOf(W.bytes("hello"), "a.txt"), "unknown");
  const r = await S().scan(W.bytes("hello"), "a.txt");
  assert.equal(r.canStrip, false);
  await assert.rejects(() => S().strip(W.bytes("hello"), "a.txt"));
  assert.equal(S().cleanName("holiday.photo.jpg"), "holiday.photo.clean.jpg");
});
test("kpack: CRC-32 + zip round trip", async () => {
  const k = W.eng.kpack;
  assert.equal(k.crc32(W.bytes("123456789")).toString(16), "cbf43926");
  const z = await k.zip([{ name: "a.txt", data: W.bytes("hello hello hello hello") }, { name: "dir/b.bin", data: Uint8Array.of(1, 2, 3), method: 0 }]);
  const files = await k.unzip(z);
  assert.equal(W.utf8(files[0].data), "hello hello hello hello");
  assert.deepEqual(Array.from(files[1].data), [1, 2, 3]);
  assert.equal(files[0].method, 8);
});
