/* CyberChef-style transform chain. Each op: (Uint8Array, arg) → Uint8Array | Promise<Uint8Array>. Pure. */
(function (W) {
  "use strict";
  const B = (s) => W.bytes(s), S = (b) => W.utf8(b);
  async function stream(b, ctor, fmt) {
    if (typeof ctor === "undefined") throw new Error(`${fmt} needs a modern browser (Compression Streams)`);
    const out = await new Response(new Blob([b]).stream().pipeThrough(new ctor(fmt))).arrayBuffer();
    return new Uint8Array(out);
  }
  const rot = (s, n) => s.replace(/[a-z]/gi, (c) => { const a = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - a + n) % 26 + 26) % 26 + a); });
  const keyBytes = (k) => (/^(0x)?[0-9a-f]+$/i.test(k || "") && (k.replace(/^0x/i, "").length % 2 === 0) ? W.fromHex(k.replace(/^0x/i, "")) : B(k || ""));

  const OPS = {
    from_b64: { name: "From Base64", fn: (b) => W.fromB64(S(b)) },
    to_b64: { name: "To Base64", fn: (b) => B(W.b64(b)) },
    from_hex: { name: "From Hex", fn: (b) => W.fromHex(S(b)) },
    to_hex: { name: "To Hex", fn: (b) => B(W.hex(b)) },
    url_decode: { name: "URL Decode", fn: (b) => B(decodeURIComponent(S(b).replace(/\+/g, " "))) },
    url_encode: { name: "URL Encode", fn: (b) => B(encodeURIComponent(S(b))) },
    html_unescape: { name: "HTML Unescape", fn: (b) => B(W.eng.workbench.stripHtml(S(b).replace(/</g, "&lt;"))) },
    from_charcode: { name: "From Charcode (decimal list)", fn: (b) => B(String.fromCharCode(...(S(b).match(/\d+/g) || []).map(Number))) },
    from_binary: { name: "From Binary", fn: (b) => Uint8Array.from((S(b).match(/[01]{8}/g) || []).map((x) => parseInt(x, 2))) },
    unicode_unescape: { name: "Unescape \\u / \\x", fn: (b) => B(S(b).replace(/\\u\{?([0-9a-f]{4,6})\}?/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))) },
    rot13: { name: "ROT13", fn: (b) => B(rot(S(b), 13)) },
    rotn: { name: "ROT-N", arg: "13", fn: (b, a) => B(rot(S(b), parseInt(a, 10) || 0)) },
    xor: { name: "XOR (key: text or hex)", arg: "key", fn: (b, a) => { const k = keyBytes(a); if (!k.length) throw new Error("XOR needs a key"); return b.map((x, i) => x ^ k[i % k.length]); } },
    reverse: { name: "Reverse", fn: (b) => B([...S(b)].reverse().join("")) },
    upper: { name: "Uppercase", fn: (b) => B(S(b).toUpperCase()) },
    lower: { name: "Lowercase", fn: (b) => B(S(b).toLowerCase()) },
    gunzip: { name: "Gunzip", fn: (b) => stream(b, typeof DecompressionStream !== "undefined" ? DecompressionStream : undefined, "gzip") },
    gzip: { name: "Gzip", fn: (b) => stream(b, typeof CompressionStream !== "undefined" ? CompressionStream : undefined, "gzip") },
    inflate_raw: { name: "Raw Inflate", fn: (b) => stream(b, typeof DecompressionStream !== "undefined" ? DecompressionStream : undefined, "deflate-raw") },
    inflate: { name: "Zlib Inflate", fn: (b) => stream(b, typeof DecompressionStream !== "undefined" ? DecompressionStream : undefined, "deflate") },
    refang: { name: "Refang", fn: (b) => B(W.eng.ioc.refang(S(b))) },
    defang: { name: "Defang", fn: (b) => B(S(b).split(/\r?\n/).map((l) => W.eng.ioc.defang(l)).join("\n")) },
    json_pretty: { name: "JSON Beautify", fn: (b) => B(JSON.stringify(JSON.parse(S(b)), null, 2)) },
    json_min: { name: "JSON Minify", fn: (b) => B(JSON.stringify(JSON.parse(S(b)))) },
    strip_ws: { name: "Remove whitespace", fn: (b) => B(S(b).replace(/\s+/g, "")) },
    strings: { name: "Strings (≥ 6)", fn: (b) => B(W.eng.yaragen.strings(b, 6, 20000).join("\n")) },
    extract_iocs: { name: "Extract IOCs", fn: (b) => B(Object.entries(W.eng.ioc.extract(S(b))).map(([k, v]) => `# ${k}\n${v.join("\n")}`).join("\n\n")) },
    ps_decode: { name: "PowerShell -enc decode", fn: (b) => { const raw = W.fromB64(S(b).replace(/^.*?-e(nc(odedcommand)?)?\s+/i, "").trim()); return B(new TextDecoder("utf-16le").decode(raw)); } },
    md5: { name: "MD5", fn: (b) => B(W.hash.md5(b)) },
    sha1: { name: "SHA-1", fn: async (b) => B(await W.hash.sha("SHA-1", b)) },
    sha256: { name: "SHA-256", fn: async (b) => B(await W.hash.sha("SHA-256", b)) },
    entropy: { name: "Entropy", fn: (b) => B(`${W.entropy(b).toFixed(4)} bits/byte over ${b.length} bytes`) },
  };

  /** run(input, [{op, arg}]) → {output: Uint8Array, steps:[{op, ok, error?, bytes}]} — stops at first error. */
  async function run(input, chain) {
    let b = W.bytes(input); const steps = [];
    for (const { op, arg } of chain || []) {
      const o = OPS[op]; if (!o) { steps.push({ op, ok: false, error: "unknown op" }); break; }
      try { b = W.bytes(await o.fn(b, arg)); steps.push({ op, ok: true, bytes: b.length }); }
      catch (e) { steps.push({ op, ok: false, error: e.message || String(e) }); break; }
    }
    return { output: b, steps };
  }
  /** Is this mostly printable text? */
  const printable = (b) => { b = W.bytes(b); if (!b.length) return true; let n = 0; const m = Math.min(b.length, 4096); for (let i = 0; i < m; i++) { const c = b[i]; if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 0xc2) n++; } return n / m > 0.9; };
  /** Hex dump of the first n bytes. */
  function hexdump(b, n = 2048) {
    b = W.bytes(b).subarray(0, n); const L = [];
    for (let o = 0; o < b.length; o += 16) {
      const row = b.subarray(o, o + 16);
      L.push(o.toString(16).padStart(8, "0") + "  " + Array.from(row, (x) => x.toString(16).padStart(2, "0")).join(" ").padEnd(47) + "  " + Array.from(row, (x) => (x >= 32 && x < 127 ? String.fromCharCode(x) : ".")).join(""));
    }
    return L.join("\n");
  }
  /** Guess what an input is and suggest a first op. */
  function suggest(text) {
    const t = String(text || "").trim();
    if (/-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{8,}/i.test(t)) return "ps_decode";
    if (/^[0-9a-f\s]+$/i.test(t) && t.replace(/\s/g, "").length % 2 === 0 && t.length >= 8) return "from_hex";
    if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(t.replace(/\s/g, "")) && t.length >= 12) return "from_b64";
    if (/%[0-9a-f]{2}/i.test(t)) return "url_decode";
    if (/h[xX]{2}ps?|\[\.\]/.test(t)) return "refang";
    if (/^[\[{]/.test(t)) return "json_pretty";
    return null;
  }
  W.eng.transforms = { OPS, run, printable, hexdump, suggest };
})(typeof window !== "undefined" ? window.W : globalThis.W);
