/* STEGO — hide a short message in a PNG's least-significant bits. Port of Katana shinobi/cipher.py (embed /
 * extract / detect) and byte-compatible with it: the payload "KS1" + u32BE length + message is written MSB-first,
 * one bit per decoded pixel byte (all channels, alpha included), and the optional password is Katana's
 * SHA-256 counter-mode keystream XOR. A PNG made here opens in Katana and vice versa.
 * For real secrecy, encrypt with CIPHER first (Wakizashi stores the AES container as the message; the view
 * recognises it on extract). LSB hiding is a privacy demo: it does not survive re-compression or resizing.
 *
 *   decode(png) → {w,h,bpp,color,pixels}     encode(img) → png bytes (filter 0, zlib)
 *   embed(png|img, message, password?) → {png, capacity, used, encrypted}
 *   extract(png|img, password?) → {message|null, bytes(Uint8Array), length, encrypted}
 *   detect(png|img) → chi-square / LSB-balance heuristic
 */
(function (W) {
  "use strict";
  const MAGIC = [0x4b, 0x53, 0x31]; // "KS1"
  const K = () => W.eng.kpack;

  async function decode(buf) {
    const b = W.bytes(buf), k = K();
    const chunks = k.pngChunks(b);
    const ihdr = chunks.find((c) => c.type === "IHDR");
    if (!ihdr) throw new Error("PNG missing header");
    const d = ihdr.data, w = k.u32be(d, 0), h = k.u32be(d, 4), depth = d[8], color = d[9], interlace = d[12];
    if (depth !== 8 || interlace !== 0 || ![0, 2, 4, 6].includes(color)) throw new Error("Only 8-bit, non-interlaced grayscale/RGB/RGBA PNGs can be used directly");
    const bpp = { 0: 1, 2: 3, 4: 2, 6: 4 }[color], stride = w * bpp;
    if (w * h > 40e6) throw new Error("Image too large");
    const raw = await k.inflate(k.concat(chunks.filter((c) => c.type === "IDAT").map((c) => c.data)));
    const px = new Uint8Array(stride * h);
    let pos = 0, prev = new Uint8Array(stride);
    for (let y = 0; y < h; y++) {
      const ft = raw[pos++], line = raw.slice(pos, pos + stride); pos += stride;
      for (let x = 0; x < stride; x++) {
        const a = x >= bpp ? line[x - bpp] : 0, up = prev[x], c = x >= bpp ? prev[x - bpp] : 0;
        if (ft === 1) line[x] = (line[x] + a) & 255;
        else if (ft === 2) line[x] = (line[x] + up) & 255;
        else if (ft === 3) line[x] = (line[x] + ((a + up) >> 1)) & 255;
        else if (ft === 4) { const p = a + up - c, pa = Math.abs(p - a), pb = Math.abs(p - up), pc = Math.abs(p - c); line[x] = (line[x] + (pa <= pb && pa <= pc ? a : pb <= pc ? up : c)) & 255; }
      }
      px.set(line, y * stride); prev = line;
    }
    return { w, h, bpp, color, pixels: px };
  }
  async function encode(img) {
    const k = K(), stride = img.w * img.bpp, raw = new Uint8Array((stride + 1) * img.h);
    for (let y = 0; y < img.h; y++) { raw[y * (stride + 1)] = 0; raw.set(img.pixels.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1); }
    const ihdr = new Uint8Array(13); ihdr.set(k.w32be(img.w), 0); ihdr.set(k.w32be(img.h), 4); ihdr[8] = 8; ihdr[9] = img.color;
    return k.concat([k.PNG_SIG, k.pngChunk("IHDR", ihdr), k.pngChunk("IDAT", await k.deflate(raw)), k.pngChunk("IEND", new Uint8Array(0))]);
  }
  /** Katana keystream: SHA-256(password ‖ u64BE counter) blocks. */
  async function keystream(password, n) {
    const seed = W.bytes(password), out = new Uint8Array(n); let ctr = 0, f = 0;
    while (f < n) {
      const blk = new Uint8Array(seed.length + 8); blk.set(seed);
      new DataView(blk.buffer).setUint32(seed.length + 4, ctr >>> 0); new DataView(blk.buffer).setUint32(seed.length, Math.floor(ctr / 4294967296));
      const d = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", blk));
      out.set(d.subarray(0, Math.min(32, n - f)), f); f += 32; ctr++;
    }
    return out;
  }
  const toImg = async (x) => (x && x.pixels ? x : decode(x));
  const capacity = (img) => Math.max(0, Math.floor(img.pixels.length / 8) - 7);

  async function embed(src, message, password = "") {
    const img = await toImg(src), pix = img.pixels.slice();
    let msg = W.bytes(message);
    if (password) { const ks = await keystream(password, msg.length); msg = msg.map((v, i) => v ^ ks[i]); }
    const payload = new Uint8Array(7 + msg.length);
    payload.set(MAGIC, 0); payload.set(K().w32be(msg.length), 3); payload.set(msg, 7);
    if (payload.length * 8 > pix.length) throw new Error(`Message too large: needs ${payload.length * 8} bytes of cover, image holds ${pix.length} (capacity ${capacity(img)} bytes)`);
    let bi = 0;
    for (const byte of payload) for (let s = 7; s >= 0; s--) { pix[bi] = (pix[bi] & 0xfe) | ((byte >> s) & 1); bi++; }
    const out = Object.assign({}, img, { pixels: pix });
    return { png: await encode(out), image: out, capacity: capacity(img), used: payload.length, encrypted: !!password };
  }
  function readBytes(pix, n, off) {
    const out = new Uint8Array(n);
    for (let b = 0; b < n; b++) { let v = 0; for (let s = 0; s < 8; s++) v = (v << 1) | (pix[off++] & 1); out[b] = v; }
    return out;
  }
  async function extract(src, password = "") {
    const img = await toImg(src), pix = img.pixels;
    if (pix.length < 56) throw new Error("Image too small to hold a message");
    const head = readBytes(pix, 7, 0);
    if (!MAGIC.every((x, i) => head[i] === x)) throw new Error("No hidden message found (bad header). Wrong image, or it was never embedded by Wakizashi/Katana.");
    const length = K().u32be(head, 3);
    if (56 + length * 8 > pix.length) throw new Error("Corrupt/length overflow — not a valid payload");
    let body = readBytes(pix, length, 56);
    if (password) { const ks = await keystream(password, length); body = body.map((v, i) => v ^ ks[i]); }
    let message = null;
    try { message = new TextDecoder("utf-8", { fatal: true }).decode(body); } catch { /* binary */ }
    return { message, bytes: body, length, encrypted: !!password };
  }
  async function detect(src) {
    const img = await toImg(src), pix = img.pixels, n = pix.length, c = new Uint32Array(256);
    let ones = 0; for (const v of pix) { ones += v & 1; c[v]++; }
    const ratio = n ? ones / n : 0;
    let chi = 0; for (let k2 = 0; k2 < 128; k2++) { const a = c[2 * k2], b = c[2 * k2 + 1]; if (a + b) { const e = (a + b) / 2; chi += (a - e) ** 2 / e + (b - e) ** 2 / e; } }
    let header = false; try { header = MAGIC.every((x, i) => readBytes(pix, 3, 0)[i] === x); } catch { /* ignore */ }
    const suspicious = header || (ratio > 0.47 && ratio < 0.53 && chi < 2000);
    return { bytes: n, lsb_ones_ratio: +ratio.toFixed(4), chi_square: +chi.toFixed(1), capacity_bytes: capacity(img), ks1_header: header,
      verdict: header ? "KS1 payload header present" : suspicious ? "likely LSB-modified" : "no strong LSB signal",
      note: "Heuristic only. A clean photo scores ratio≠0.5 / high chi; near-0.5 ratio with low chi suggests hidden data." };
  }
  /** RGBA pixels from a canvas → an image record usable by embed/extract. */
  const fromRGBA = (w, h, rgba) => ({ w, h, bpp: 4, color: 6, pixels: W.bytes(rgba).slice() });

  W.eng.stego = { decode, encode, embed, extract, detect, keystream, capacity, fromRGBA };
})(typeof window !== "undefined" ? window.W : globalThis.W);
