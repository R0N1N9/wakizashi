/* Regex builder from an example string, ranked best-first (port of katana/cti/regexgen.py). */
(function (W) {
  "use strict";
  const META = /([.^$*+?()[\]{}|\\/\-])/g;
  const esc = (s) => s.replace(META, "\\$1");
  function runs(text, digit, ws) {
    let o = "", i = 0;
    while (i < text.length) {
      const c = text[i];
      if (/\d/.test(c)) { let j = i; while (j < text.length && /\d/.test(text[j])) j++; o += digit(j - i); i = j; }
      else if (c === " " || c === "\t") { let j = i; while (j < text.length && (text[j] === " " || text[j] === "\t")) j++; o += ws; i = j; }
      else { o += esc(c); i++; }
    }
    return o;
  }
  const smart = (t) => runs(t, (k) => (k === 1 ? "\\d" : `\\d{${k}}`), "\\s+");
  const loose = (t) => runs(t, () => "\\d+", "\\s+");
  const keyword = (t) => { const toks = t.match(/[A-Za-z0-9_.\-]{4,}/g); return toks ? "\\b" + esc(toks.reduce((a, b) => (b.length > a.length ? b : a))) + "\\b" : null; };
  const TYPE_RX = {
    ipv4: ["\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b", "any IPv4 address"],
    domain: ["\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,24}\\b", "any domain"],
    email: ["\\b[A-Za-z0-9._%+\\-]+@(?:[A-Za-z0-9-]+\\.)+[A-Za-z]{2,24}\\b", "any email address"],
    url: ["\\bhttps?://[^\\s\"'<>]+", "any http/https URL"],
    cve: ["\\bCVE-\\d{4}-\\d{4,7}\\b", "any CVE id"],
  };
  const HASH_LEN = { 32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512" };
  const yara = (rx, nocase) => "/" + rx.replace(/(?<!\\)\//g, "\\/") + "/" + (nocase ? " nocase" : "");

  function generate(text) {
    text = String(text || "").replace(/[\r\n]+$/, "");
    if (!text.trim()) throw new Error("enter a string to build a regex for");
    text = text.slice(0, 1024);
    const opts = [], seen = new Set();
    const add = (rx, label, desc, fp, nocase = false) => {
      if (!rx || seen.has(rx + nocase)) return;
      let ok; try { ok = new RegExp(rx, nocase ? "i" : "").test(text); } catch { return; }
      seen.add(rx + nocase);
      opts.push({ regex: rx, label, desc, fp, yara: yara(rx, nocase), nocase, matches: ok });
    };
    if (/^[0-9a-fA-F]+$/.test(text) && HASH_LEN[text.length]) {
      add(esc(text), "Exact hash", `Matches only this exact ${HASH_LEN[text.length]}. Zero false positives.`, "none");
      add(`\\b[0-9a-fA-F]{${text.length}}\\b`, `${HASH_LEN[text.length]} class`, `Any ${HASH_LEN[text.length]} (hex of this length) — the usual way to hunt hashes.`, "medium", true);
      return { input: text, options: opts };
    }
    add(smart(text), "Recommended", "Exact structure with fixed-length digit runs and flexible whitespace — concise and very low false-positive.", "low");
    add(esc(text), "Exact literal", "Matches only this exact string. Zero false positives, no flexibility.", "none");
    const t = W.detectType(text);
    if (TYPE_RX[t]) add(TYPE_RX[t][0], t.toUpperCase() + " pattern", `Canonical regex for ${TYPE_RX[t][1]} — matches the whole class, not just this value.`, "medium");
    add(smart(text), "Case-insensitive", "The recommended pattern with the YARA nocase modifier — catches case variants.", "low", true);
    add(loose(text), "Loose", "Digit runs generalised to \\d+ — higher recall, more false positives.", "medium");
    add(keyword(text), "Keyword anchor", "Matches the most distinctive token anywhere (word-bounded) — handy for broad hunting.", "high");
    return { input: text, options: opts };
  }
  /** Test a regex against lines of text → {ok, error, hits:[{line, n, match}]} */
  function test(rx, text, flags = "") {
    let re; try { re = new RegExp(rx, flags.replace(/g/g, "")); } catch (e) { return { ok: false, error: e.message, hits: [] }; }
    const hits = [];
    String(text || "").split(/\r?\n/).forEach((line, n) => { const m = re.exec(line); if (m) hits.push({ line, n: n + 1, match: m[0], index: m.index }); });
    return { ok: true, hits };
  }
  W.eng.regexgen = { generate, test, escape: esc };
})(typeof window !== "undefined" ? window.W : globalThis.W);
