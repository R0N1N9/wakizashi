/* CIPHER — AES-256-GCM encryption for text and files, plus Katana-compatible one-time pad and Shamir sharing.
 *
 * Wakizashi container ("WKZC", v1) — everything before the ciphertext is authenticated as AES-GCM AAD:
 *   0  "WKZC"            magic
 *   4  0x01              version
 *   5  mode              0x01 = passphrase (PBKDF2-HMAC-SHA256)   0x02 = raw 256-bit key
 *   6  flags             bit0 = plaintext starts with a file envelope (u16 len + JSON {name,type})
 *   7  0x00              reserved
 *   8  iterations u32BE  PBKDF2 iterations (0 for raw-key mode)
 *  12  salt[16]          PBKDF2 salt (random; unused in raw-key mode)
 *  28  iv[12]            AES-GCM nonce (random per message)
 *  40  ciphertext ‖ 16-byte GCM tag
 * Armored text = the same bytes, base64 in 64-col lines between BEGIN/END WAKIZASHI MESSAGE markers.
 * Keys look like "wkzk1.<base64url 32 bytes>".
 *
 * Katana's shinobi/cipher.py has no AES (it does stego, OTP and Shamir), so the AES container is Wakizashi's
 * own. The OTP (base64 pad, XOR, base64 ciphertext) and Shamir (GF(256) poly 0x11d, base32 shares with the
 * x-coordinate as the first byte) functions below are byte-for-byte interoperable with Katana and Karambit.
 */
(function (W) {
  "use strict";
  const MAGIC = [0x57, 0x4b, 0x5a, 0x43], HDR = 40, DEFAULT_ITER = 600000, MIN_ITER = 100000, MAX_ITER = 10000000;
  const BEGIN = "-----BEGIN WAKIZASHI MESSAGE-----", END = "-----END WAKIZASHI MESSAGE-----";
  const subtle = () => { const s = globalThis.crypto && globalThis.crypto.subtle; if (!s) throw new Error("WebCrypto unavailable — open Wakizashi over https or localhost"); return s; };
  const rand = (n) => { const b = new Uint8Array(n); globalThis.crypto.getRandomValues(b); return b; };
  const b64url = (b) => W.b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  async function deriveKey(pass, salt, iterations) {
    const base = await subtle().importKey("raw", W.bytes(String(pass).normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
    return subtle().deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  const importRaw = (raw) => subtle().importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

  /** "wkzk1.xxxx" ↔ 32 raw bytes */
  function genKey() { return "wkzk1." + b64url(rand(32)); }
  function parseKey(s) {
    const m = String(s || "").trim().match(/^wkzk1\.([A-Za-z0-9_-]{43})$/);
    if (!m) throw new Error("Not a Wakizashi key (expected wkzk1. followed by 43 base64url characters)");
    const raw = W.fromB64(m[1]); if (raw.length !== 32) throw new Error("Key must be 256 bits");
    return raw;
  }

  function header(mode, flags, iterations, salt, iv) {
    const h = new Uint8Array(HDR);
    h.set(MAGIC, 0); h[4] = 1; h[5] = mode; h[6] = flags; h[7] = 0;
    h[8] = (iterations >>> 24) & 255; h[9] = (iterations >>> 16) & 255; h[10] = (iterations >>> 8) & 255; h[11] = iterations & 255;
    h.set(salt, 12); h.set(iv, 28);
    return h;
  }
  /** Parse the header without decrypting. */
  function inspect(buf) {
    const b = W.bytes(buf);
    if (b.length < HDR + 16 || !MAGIC.every((x, i) => b[i] === x)) throw new Error("Not a Wakizashi encrypted message/file");
    if (b[4] !== 1) throw new Error(`Unsupported container version ${b[4]}`);
    const iterations = ((b[8] << 24) | (b[9] << 16) | (b[10] << 8) | b[11]) >>> 0;
    const mode = b[5] === 1 ? "passphrase" : b[5] === 2 ? "key" : null;
    if (!mode) throw new Error("Unknown key mode");
    return { version: b[4], mode, file: !!(b[6] & 1), iterations, salt: b.subarray(12, 28), iv: b.subarray(28, 40), size: b.length - HDR - 16 };
  }

  /** encrypt(data, {passphrase | key, iterations?, name?, type?}) → Uint8Array container */
  async function encrypt(data, opts = {}) {
    let body = W.bytes(data), flags = 0;
    if (opts.name != null) {
      const meta = W.bytes(JSON.stringify({ name: String(opts.name), type: opts.type || "" }));
      const env = new Uint8Array(2 + meta.length + body.length);
      env[0] = meta.length >> 8; env[1] = meta.length & 255; env.set(meta, 2); env.set(body, 2 + meta.length);
      body = env; flags |= 1;
    }
    const salt = rand(16), iv = rand(12);
    let key, mode, iterations = 0;
    if (opts.key) { key = await importRaw(typeof opts.key === "string" ? parseKey(opts.key) : W.bytes(opts.key)); mode = 2; }
    else {
      if (!opts.passphrase) throw new Error("Enter a passphrase or generate a key");
      iterations = opts.iterations || DEFAULT_ITER;
      if (iterations < MIN_ITER || iterations > MAX_ITER) throw new Error(`Iterations must be between ${MIN_ITER} and ${MAX_ITER}`);
      key = await deriveKey(opts.passphrase, salt, iterations); mode = 1;
    }
    const h = header(mode, flags, iterations, salt, iv);
    const ct = new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv, additionalData: h, tagLength: 128 }, key, body));
    const out = new Uint8Array(HDR + ct.length); out.set(h, 0); out.set(ct, HDR);
    return out;
  }

  /** decrypt(container, {passphrase | key}) → {data, name, type, mode, iterations} */
  async function decrypt(buf, opts = {}) {
    const b = W.bytes(buf), info = inspect(b);
    let key;
    if (info.mode === "key") {
      if (!opts.key) throw new Error("This was encrypted with a generated key — paste the wkzk1. key");
      key = await importRaw(typeof opts.key === "string" ? parseKey(opts.key) : W.bytes(opts.key));
    } else {
      if (!opts.passphrase) throw new Error("This was encrypted with a passphrase — enter it");
      if (info.iterations < 1000 || info.iterations > MAX_ITER) throw new Error("Implausible PBKDF2 iteration count — refusing");
      key = await deriveKey(opts.passphrase, info.salt.slice(), info.iterations);
    }
    let pt;
    try { pt = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: info.iv.slice(), additionalData: b.subarray(0, HDR), tagLength: 128 }, key, b.subarray(HDR))); }
    catch { throw new Error("Decryption failed — wrong passphrase/key, or the data was modified"); }
    const res = { mode: info.mode, iterations: info.iterations, name: null, type: null, data: pt };
    if (info.file) {
      const n = (pt[0] << 8) | pt[1];
      try { const meta = JSON.parse(W.utf8(pt.subarray(2, 2 + n))); res.name = meta.name || null; res.type = meta.type || null; } catch { /* ignore */ }
      res.data = pt.subarray(2 + n);
    }
    return res;
  }

  function armor(buf) {
    const s = W.b64(buf).replace(/(.{64})/g, "$1\n").trim();
    return `${BEGIN}\n${s}\n${END}`;
  }
  function dearmor(text) {
    const t = String(text || "");
    const i = t.indexOf(BEGIN), j = t.indexOf(END);
    const body = i >= 0 && j > i ? t.slice(i + BEGIN.length, j) : t;
    const clean = body.replace(/^[A-Za-z-]+:.*$/gm, "").replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/=_-]+$/.test(clean)) throw new Error("Not an armored Wakizashi message");
    return W.fromB64(clean);
  }
  const isArmored = (t) => String(t || "").includes(BEGIN);
  async function encryptText(text, opts) { return armor(await encrypt(W.bytes(text), opts)); }
  async function decryptText(text, opts) { const r = await decrypt(dearmor(text), opts); return Object.assign(r, { text: W.utf8(r.data) }); }

  // ------------------------------------------------------------------ one-time pad (Katana-compatible)
  function otpPad(n) { return W.b64(rand(n)); }
  function otp(text, padB64, mode = "encrypt") {
    let pad; try { pad = W.fromB64(String(padB64).trim()); } catch { throw new Error("Pad must be base64"); }
    const data = mode === "encrypt" ? W.bytes(text) : W.fromB64(String(text).trim());
    if (pad.length < data.length) throw new Error(`Pad too short: need ${data.length} bytes, pad has ${pad.length} (a one-time pad must be at least as long as the message)`);
    const x = data.map((v, i) => v ^ pad[i]);
    return mode === "encrypt" ? { result: W.b64(x), bytes: data.length } : { result: W.utf8(x), bytes: data.length };
  }

  // ------------------------------------------------------------------ Shamir over GF(256) (Katana-compatible)
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () { let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; } for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]; })();
  const gmul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
  const gdiv = (a, b) => { if (!b) throw new Error("division by zero"); return a ? EXP[(LOG[a] - LOG[b] + 255) % 255] : 0; };
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function b32(bytes) { let s = "", buf = 0, bits = 0; for (const v of bytes) { buf = (buf << 8) | v; bits += 8; while (bits >= 5) { bits -= 5; s += B32[(buf >>> bits) & 31]; } buf &= 0xff; } if (bits) s += B32[(buf << (5 - bits)) & 31]; return s; }
  function unb32(s) { const out = []; let buf = 0, bits = 0; for (const c of String(s).toUpperCase().replace(/=+$/, "")) { const i = B32.indexOf(c); if (i < 0) { if (/\s/.test(c)) continue; throw new Error("Shares must be base32"); } buf = (buf << 5) | i; bits += 5; if (bits >= 8) { bits -= 8; out.push((buf >>> bits) & 255); } buf &= 0xff; } return Uint8Array.from(out); }
  function shamirSplit(secret, n, k) {
    n = +n; k = +k;
    if (!(k >= 2 && k <= n && n <= 255)) throw new Error("Need 2 <= threshold <= shares <= 255");
    const sec = W.bytes(secret), shares = Array.from({ length: n }, (_, i) => [i + 1]);
    for (const byte of sec) {
      const coeffs = [byte, ...rand(k - 1)];
      for (let si = 0; si < n; si++) {
        const x = si + 1; let y = 0, xp = 1;
        for (const c of coeffs) { y ^= gmul(c, xp); xp = gmul(xp, x); }
        shares[si].push(y);
      }
    }
    return shares.map((s) => b32(s));
  }
  function shamirCombine(list) {
    const pts = list.map((s) => String(s).trim()).filter(Boolean).map((s) => { const b = unb32(s); return [b[0], b.subarray(1)]; });
    if (pts.length < 2) throw new Error("Paste at least two shares");
    if (new Set(pts.map((p) => p[0])).size < pts.length) throw new Error("Duplicate share indices");
    const len = pts[0][1].length;
    if (pts.some((p) => p[1].length !== len)) throw new Error("Shares have different lengths — they don't belong together");
    const out = new Uint8Array(len);
    for (let pos = 0; pos < len; pos++) {
      let acc = 0;
      for (let i = 0; i < pts.length; i++) {
        let num = 1, den = 1;
        for (let j = 0; j < pts.length; j++) if (i !== j) { num = gmul(num, pts[j][0]); den = gmul(den, pts[i][0] ^ pts[j][0]); }
        acc ^= gmul(pts[i][1][pos], gdiv(num, den));
      }
      out[pos] = acc;
    }
    return W.utf8(out);
  }

  W.eng.cipher = { encrypt, decrypt, encryptText, decryptText, armor, dearmor, isArmored, inspect, genKey, parseKey,
    otpPad, otp, shamirSplit, shamirCombine, b32, unb32, DEFAULT_ITER, MIN_ITER, HDR, BEGIN, END };
})(typeof window !== "undefined" ? window.W : globalThis.W);
