/* PHISH — triage of a user-reported email (port of Katana defense/phish.py + ti/osint.analyze_headers
 * + a slice of ti/triage for attachments). Pure: give it the raw message source, get a verdict.
 *
 *   W.eng.phish.analyze(raw) → {
 *     headers: {summary, auth, hops[{from,by,ip,date,delay_s,raw}], flags[{level,text}], origin_ip, iocs},
 *     urls[{url, text, host, flags}], attachments[{name, type, size, flags, hashes, detected, iocs, yara}],
 *     forms[], lures[], score, verdict, subject, from, body_preview, redflags[{level, text, src}],
 *     iocs{url, domain, ipv4, ipv6, email, sha256}, blockable[] }
 *   levels are "high" | "med" | "low" (as in Katana); verdict "malicious" | "suspicious" | "likely benign".
 * Nothing is fetched; links are never visited.
 */
(function (W) {
  "use strict";

  const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly", "buff.ly", "rb.gy",
    "shorturl.at", "tiny.cc", "s.id", "t.ly", "lnkd.in", "qrco.de", "bit.do", "urlz.fr", "v.gd"]);
  const ABUSED_HOSTS = ["workers.dev", "pages.dev", "r2.dev", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "herokuapp.com",
    "firebaseapp.com", "web.app", "glitch.me", "repl.co", "netlify.app", "vercel.app", "github.io",
    "blob.core.windows.net", "web.core.windows.net", "storage.googleapis.com", "ipfs.io", "dweb.link",
    "sharepoint.com", "1drv.ms", "dropboxusercontent.com", "docs.google.com", "forms.gle", "sites.google.com",
    "wixsite.com", "weebly.com", "000webhostapp.com", "notion.site", "canva.site", "framer.website",
    "surge.sh", "onrender.com", "fly.dev", "amplifyapp.com", "azurewebsites.net", "typeform.com"];
  const SUS_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "cam",
    "icu", "buzz", "monster", "sbs", "cfd", "quest", "lol", "beauty", "hair", "skin", "bond", "cyou", "live", "shop"]);
  const BRANDS = { microsoft: "microsoft.com", office365: "office.com", outlook: "outlook.com", paypal: "paypal.com",
    apple: "apple.com", icloud: "icloud.com", amazon: "amazon.com", netflix: "netflix.com",
    docusign: "docusign.net", dhl: "dhl.com", fedex: "fedex.com", ups: "ups.com", google: "google.com",
    facebook: "facebook.com", instagram: "instagram.com", linkedin: "linkedin.com", dropbox: "dropbox.com",
    adobe: "adobe.com", wellsfargo: "wellsfargo.com", chase: "chase.com", bankofamerica: "bankofamerica.com",
    coinbase: "coinbase.com", binance: "binance.com", metamask: "metamask.io", usps: "usps.com",
    irs: "irs.gov", okta: "okta.com", zoom: "zoom.us", steam: "steampowered.com", github: "github.com" };
  const BRAND_DOMAINS = new Set(Object.values(BRANDS));
  const FREEMAIL = new Set(["gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "aol.com", "icloud.com", "gmx.com",
    "gmx.de", "mail.com", "proton.me", "protonmail.com", "yandex.ru", "yandex.com", "mail.ru", "zoho.com", "qq.com", "163.com", "web.de"]);
  const MULTI_SUFFIX = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.nz", "com.br", "com.mx",
    "co.in", "co.za", "com.sg", "com.tr", "com.cn", "com.hk", "co.kr", "com.ar", "com.co"]);
  const RISKY_EXT = /\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|lnk|iso|img|vhd|vhdx|msi|jar|cpl|dll|html?|shtml|svg|one|xll|docm|xlsm|pptm|zip|rar|7z|gz|ace|r\d\d)$/i;
  const RISKY_HIGH = /\.(exe|scr|js|vbs|hta|ps1|lnk|iso|img|one|xll|html?|svg)$/i;
  const URGENCY = /(urgent|immediately|within 24 hours|account (will be )?(suspended|locked|closed|deactivated)|verify your (account|identity)|unusual (sign-?in|activity)|password (expires|expired)|confirm your|invoice attached|payment (failed|declined)|wire transfer|gift ?cards?|act now|final notice|security alert|mailbox (is )?full|shared a (file|document) with you)/gi;
  const RE_URL = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
  const FILE_EXT = new Set(("exe dll sys bat cmd ps1 psm1 vbs vbe js jse hta lnk scr msi jar py sh elf bin dat tmp log txt ini cfg conf json xml yml yaml csv " +
    "doc docx docm xls xlsx xlsm ppt pptx pdf rtf png jpg jpeg gif bmp svg ico htm html php asp aspx jsp css zip rar 7z gz tar iso img apk dex so o c h " +
    "cpp go rs java class md db sqlite bak old mov mp4 mp3 wav tgz").split(" "));

  // ------------------------------------------------------------------ small helpers
  function regDomain(host) {
    host = String(host || "").toLowerCase().replace(/^\.+|\.+$/g, "");
    const p = host.split(".");
    if (p.length >= 3 && MULTI_SUFFIX.has(p.slice(-2).join("."))) return p.slice(-3).join(".");
    return p.slice(-2).join(".");
  }
  function lev(a, b) {
    if (Math.abs(a.length - b.length) > 2) return 9;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)));
      prev = cur;
    }
    return prev[b.length];
  }
  const isPublicIp = (ip) => { const B = W.eng.block; return B && B.isPublicIp ? B.isPublicIp(ip) : !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.|::1$|f[cd]|fe[89ab])/i.test(ip); };
  const uniq = (a) => [...new Set(a)];

  const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®", hellip: "…", mdash: "—", ndash: "–", rsquo: "’", lsquo: "‘",
    rdquo: "”", ldquo: "“", bull: "•", middot: "·", zwnj: "", zwj: "", shy: "", euro: "€", trade: "™" };
  const unent = (s) => String(s).replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]*);?/gi, (m, e) => {
    if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m; } catch { return m; } }
    const v = ENT[e.toLowerCase()]; return v != null ? v : m;
  });

  // sync SHA-1 / SHA-256 (analyze() must stay synchronous; WebCrypto is async-only)
  function sha(bytes, alg) {
    const b = W.bytes(bytes), n = b.length, words = new Uint32Array((((n + 8) >>> 6) + 1) * 16);
    for (let i = 0; i < n; i++) words[i >> 2] |= b[i] << (24 - (i % 4) * 8);
    words[n >> 2] |= 0x80 << (24 - (n % 4) * 8);
    words[words.length - 1] = (n * 8) >>> 0; words[words.length - 2] = Math.floor(n / 0x20000000);
    const rotr = (x, k) => (x >>> k) | (x << (32 - k)), rotl = (x, k) => (x << k) | (x >>> (32 - k));
    const w = new Uint32Array(alg === 1 ? 80 : 64);
    if (alg === 1) {
      let h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
      for (let o = 0; o < words.length; o += 16) {
        for (let i = 0; i < 80; i++) w[i] = i < 16 ? words[o + i] : rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        let [a, bb, c, d, e] = h;
        for (let i = 0; i < 80; i++) {
          const f = i < 20 ? (bb & c) | (~bb & d) : i < 40 ? bb ^ c ^ d : i < 60 ? (bb & c) | (bb & d) | (c & d) : bb ^ c ^ d;
          const k = i < 20 ? 0x5a827999 : i < 40 ? 0x6ed9eba1 : i < 60 ? 0x8f1bbcdc : 0xca62c1d6;
          const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0; e = d; d = c; c = rotl(bb, 30) >>> 0; bb = a; a = t;
        }
        h = [h[0] + a, h[1] + bb, h[2] + c, h[3] + d, h[4] + e].map((x) => x >>> 0);
      }
      return h.map((x) => x.toString(16).padStart(8, "0")).join("");
    }
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    let h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for (let o = 0; o < words.length; o += 16) {
      for (let i = 0; i < 64; i++) {
        if (i < 16) w[i] = words[o + i];
        else { const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0; }
      }
      let [a, bb, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g), t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), mj = (a & bb) ^ (a & c) ^ (bb & c), t2 = (S0 + mj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = bb; bb = a; a = (t1 + t2) >>> 0;
      }
      h = [h[0] + a, h[1] + bb, h[2] + c, h[3] + d, h[4] + e, h[5] + f, h[6] + g, h[7] + hh].map((x) => x >>> 0);
    }
    return h.map((x) => x.toString(16).padStart(8, "0")).join("");
  }

  // ------------------------------------------------------------------ RFC 822 / MIME
  function decodeCharset(bytes, cs) {
    cs = String(cs || "utf-8").trim().toLowerCase().replace(/^"|"$/g, "");
    if (cs === "us-ascii" || cs === "ascii") cs = "utf-8";
    try { return new TextDecoder(cs, { fatal: false }).decode(bytes); } catch { try { return new TextDecoder("utf-8").decode(bytes); } catch { return W.latin1(bytes); } }
  }
  const strBytes = (s) => { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 255; return o; };
  function qpDecode(s, header) {
    if (header) s = s.replace(/_/g, " ");
    s = s.replace(/=\r?\n/g, "");
    const out = [];
    const b = W.bytes(s);           // keep non-ASCII text as UTF-8
    for (let i = 0; i < b.length; i++) {
      if (b[i] === 61 && i + 2 < b.length && /^[0-9a-f]{2}$/i.test(String.fromCharCode(b[i + 1], b[i + 2]))) { out.push(parseInt(String.fromCharCode(b[i + 1], b[i + 2]), 16)); i += 2; }
      else out.push(b[i]);
    }
    return Uint8Array.from(out);
  }
  function b64Decode(s) { try { return W.fromB64(String(s).replace(/[^A-Za-z0-9+/=_-]/g, "").replace(/=+$/, "")); } catch { return new Uint8Array(0); } }
  /** RFC 2047 encoded words. */
  function decodeWords(v) {
    return String(v || "").replace(/(=\?[^?\s]+\?[bBqQ]\?[^?\s]*\?=)(\s+(?==\?))?/g, "$1").replace(/=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=/g, (m, cs, enc, txt) => {
      const bytes = enc.toUpperCase() === "B" ? b64Decode(txt) : qpDecode(txt, true);
      return decodeCharset(bytes, cs.split("*")[0]);
    });
  }
  /** "text/html; charset=utf-8; name*=utf-8''a%20b" → {value, params} (RFC 2231 aware). */
  function parseParams(v) {
    const s = String(v || "");
    const parts = [];
    let cur = "", q = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '"' && s[i - 1] !== "\\") q = !q;
      if (c === ";" && !q) { parts.push(cur); cur = ""; } else cur += c;
    }
    parts.push(cur);
    const params = {}, cont = {};
    for (const p of parts.slice(1)) {
      const m = /^\s*([^=\s]+)\s*=\s*(.*?)\s*$/.exec(p);
      if (!m) continue;
      let k = m[1].toLowerCase(), val = m[2];
      if (val.startsWith('"') && val.endsWith('"') && val.length >= 2) val = val.slice(1, -1).replace(/\\(.)/g, "$1");
      const c = /^(.*?)\*(\d+)?(\*)?$/.exec(k);
      if (c) { (cont[c[1]] = cont[c[1]] || []).push({ n: +(c[2] || 0), val, enc: !!c[3] || (!c[2] && k.endsWith("*")) }); continue; }
      params[k] = decodeWords(val);
    }
    for (const [k, segs] of Object.entries(cont)) {
      segs.sort((a, b) => a.n - b.n);
      let cs = "utf-8", acc = [];
      segs.forEach((sg, i) => {
        let t = sg.val;
        if (sg.enc) {
          if (i === 0) { const m = /^([^']*)'[^']*'(.*)$/.exec(t); if (m) { cs = m[1] || "utf-8"; t = m[2]; } }
          const bytes = []; for (let j = 0; j < t.length; j++) { if (t[j] === "%" && /^[0-9a-f]{2}$/i.test(t.substr(j + 1, 2))) { bytes.push(parseInt(t.substr(j + 1, 2), 16)); j += 2; } else bytes.push(...W.bytes(t[j])); }
          acc.push(decodeCharset(Uint8Array.from(bytes), cs));
        } else acc.push(t);
      });
      params[k] = acc.join("");
    }
    return { value: parts[0].trim().toLowerCase(), params };
  }
  /** Split header block / body. Lines that don't look like headers end the header block (pasted body-only text works). */
  function splitMessage(raw) {
    const lines = raw.split("\n");
    const hdr = [];
    let i = 0;
    for (; i < lines.length; i++) {
      const ln = lines[i];
      if (/^\s*$/.test(ln)) { i++; break; }
      if (i === 0 && /^From \S/.test(ln)) continue;                 // mbox separator line
      if (/^[!-9;-~]+:/.test(ln)) hdr.push(ln);
      else if (/^[ \t]/.test(ln) && hdr.length) hdr[hdr.length - 1] += "\n" + ln;
      else break;
    }
    const headers = hdr.map((h) => { const k = h.indexOf(":"); return { name: h.slice(0, k).trim(), value: h.slice(k + 1).replace(/\n[ \t]+/g, " ").trim() }; });
    return { headers, body: lines.slice(i).join("\n"), headerText: hdr.join("\n") };
  }
  const hget = (H, k) => { k = k.toLowerCase(); const h = H.find((x) => x.name.toLowerCase() === k); return h ? h.value : ""; };
  const hall = (H, k) => { k = k.toLowerCase(); return H.filter((x) => x.name.toLowerCase() === k).map((x) => x.value); };

  /** Walk MIME parts → leaf parts [{headers, ctype, params, disp, filename, bytes(), text()}]. */
  function walk(headers, body, depth, out) {
    out = out || [];
    if (depth > 12 || out.length > 200) return out;
    const ct = parseParams(hget(headers, "Content-Type") || "text/plain");
    const ctype = ct.value || "text/plain";
    if (ctype.startsWith("multipart/") && ct.params.boundary) {
      const bnd = "--" + ct.params.boundary;
      const segs = [];
      let cur = null;
      for (const ln of body.split("\n")) {
        const t = ln.replace(/\s+$/, "");
        if (t === bnd + "--") { if (cur) segs.push(cur); cur = null; break; }
        if (t === bnd) { if (cur) segs.push(cur); cur = []; continue; }
        if (cur) cur.push(ln);
      }
      if (cur) segs.push(cur);
      for (const s of segs) { const m = splitMessage(s.join("\n")); walk(m.headers, m.body, depth + 1, out); }
      return out;
    }
    if (ctype === "message/rfc822") { const m = splitMessage(body.replace(/^\n+/, "")); walk(m.headers, m.body, depth + 1, out); return out; }
    const cte = (hget(headers, "Content-Transfer-Encoding") || "").toLowerCase().trim();
    const disp = parseParams(hget(headers, "Content-Disposition"));
    const filename = disp.params.filename || ct.params.name || null;
    let cache;
    const bytes = () => cache || (cache = cte === "base64" ? b64Decode(body) : cte === "quoted-printable" ? qpDecode(body) : W.bytes(body));
    const text = () => (cte === "base64" || cte === "quoted-printable") ? decodeCharset(bytes(), ct.params.charset) : body;
    out.push({ headers, ctype, params: ct.params, disp: disp.value, filename, bytes, text });
    return out;
  }

  function parseAddr(v) {
    v = String(v || "").trim();
    const m = /^(.*)<([^<>]*)>\s*$/.exec(v);
    if (m) return { name: m[1].trim().replace(/^"|"$/g, "").replace(/\\(.)/g, "$1").trim(), addr: m[2].trim() };
    const c = /^([^\s()]+@[^\s()]+)\s*(?:\((.*)\))?$/.exec(v);
    if (c) return { name: (c[2] || "").trim(), addr: c[1] };
    return { name: "", addr: /@/.test(v) ? v : "" };
  }
  const domainOf = (v) => { const a = parseAddr(v).addr; return a.includes("@") ? a.split("@").pop().toLowerCase().replace(/[>\s]+$/, "") : ""; };

  // ------------------------------------------------------------------ IOC extraction (headers)
  function extractIocs(text) {
    text = W.refang(text);
    const url = uniq((text.match(/\b(?:https?|ftp):\/\/[^\s<>"'`\])}|\\^]+/gi) || []).map((u) => u.replace(/[.,;:!?'"]+$/, "")));
    const email = uniq((text.match(/\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b/gi) || []).map((e) => e.toLowerCase()));
    const ipv4 = uniq((text.match(/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g) || []).filter(isPublicIp));
    const ipv6 = uniq((text.match(/(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])/g) || [])
      .filter((c) => (c.match(/:/g) || []).length >= 2 && c.length >= 3 && !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(c) && !/^[\d:]+$/.test(c) && (!W.eng.block || W.eng.block._parseV6(c)))
      .filter(isPublicIp));
    const dom = [];
    for (const m of text.matchAll(/(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24}))(?![\w-])/gi)) {
      const d = m[1].toLowerCase().replace(/\.+$/, "");
      if (!FILE_EXT.has(d.split(".").pop()) && !/^[\d.]+$/.test(d)) dom.push(d);
    }
    const domain = uniq(dom.concat(email.map((e) => e.split("@")[1]).sort()));
    return { ipv4, ipv6, domain, url, email };
  }

  // ------------------------------------------------------------------ headers (osint.analyze_headers)
  const AUTH = /\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)/gi;
  function parseDate(s) {
    const t = Date.parse(String(s || "").replace(/\([^)]*\)/g, " ").replace(/\s+/g, " ").trim());
    return isNaN(t) ? null : t;
  }
  function analyzeHeaders(H, headerText) {
    const g = (k) => decodeWords(hget(H, k)).trim();
    const hops = [];
    for (let r of hall(H, "Received")) {
      r = r.split(/\s+/).join(" ");
      const datePart = r.includes(";") ? r.slice(r.lastIndexOf(";") + 1).trim() : "";
      const dt = datePart ? parseDate(datePart) : null;
      const fm = /from\s+(\S+)(?:\s+\(([^)]*)\))?/i.exec(r);
      const by = /\bby\s+(\S+)/i.exec(r);
      const ips = [];
      // the connecting IP usually sits in the "(rdns [ip])" comment; the HELO literal may be private/forged
      for (const m of ((fm && fm[2] ? fm[2] + " " : "") + (fm ? fm[0] : "")).matchAll(/\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{6,})\]?/gi)) {
        const i = m[1];
        if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(i) || (i.match(/:/g) || []).length >= 2) ips.push(i.replace(/^ipv6:/i, ""));
      }
      const uips = uniq(ips);
      hops.push({ from: fm ? fm[1] : null, by: by ? by[1] : null, ip: uips.find(isPublicIp) || uips[0] || null, ips: uips, date: dt != null ? new Date(dt).toISOString().replace(/\.000Z$/, "Z") : datePart || null, _dt: dt, raw: r });
    }
    hops.reverse();      // chronological: origin first
    let prev = null;
    for (const h of hops) { const dt = h._dt; delete h._dt; h.delay_s = dt != null && prev != null ? Math.round((dt - prev) / 1000) : null; if (dt != null) prev = dt; }

    const authTxt = hall(H, "Authentication-Results").concat(hall(H, "ARC-Authentication-Results")).join(" ");
    const auth = {};
    for (const m of authTxt.matchAll(AUTH)) { const k = m[1].toLowerCase(); if (!(k in auth)) auth[k] = m[2].toLowerCase(); }
    const rspf = g("Received-SPF");
    if (rspf && !("spf" in auth)) auth.spf = rspf.split(/\s+/)[0].toLowerCase();

    const frm = g("From"), rp = g("Return-Path"), rt = g("Reply-To");
    const fd = domainOf(frm), rpd = domainOf(rp), rtd = domainOf(rt);
    const flags = [];
    const F = (level, text) => flags.push({ level, text });
    for (const k of ["spf", "dkim", "dmarc"]) {
      if (["fail", "softfail", "permerror", "temperror"].includes(auth[k])) F(k === "dmarc" || auth[k] === "fail" ? "high" : "med", `${k.toUpperCase()} ${auth[k]}`);
      else if (!(k in auth)) F("low", `No ${k.toUpperCase()} result recorded`);
    }
    if (fd && rpd && fd !== rpd && !rpd.endsWith("." + fd) && !fd.endsWith("." + rpd)) F("med", `From domain (${fd}) differs from Return-Path (${rpd})`);
    if (rtd && fd && rtd !== fd) F("high", `Reply-To domain (${rtd}) differs from From (${fd}) - classic BEC pattern`);
    const { name: disp, addr } = parseAddr(frm);
    const em = /[\w.+-]+@[\w.-]+/.exec(disp || "");
    if (em && em[0].toLowerCase() !== addr.toLowerCase()) F("high", `Display name contains a different address (${em[0]})`);
    // display-name brand impersonation + lookalike sender domains (Wakizashi additions)
    if (fd) {
      const dn = (disp || "").toLowerCase().replace(/[^a-z0-9]/g, "");
      const fr = regDomain(fd);
      for (const [brand, real] of Object.entries(BRANDS)) {
        if (brand.length < 4 || !dn.includes(brand)) continue;
        if (fr === real || fd.endsWith("." + real) || fr.split(".")[0] === brand) break;
        F(FREEMAIL.has(fr) ? "high" : "med", `Display name impersonates '${brand}' but the sender domain is ${fr}${FREEMAIL.has(fr) ? " (free-mail)" : ""}`);
        break;
      }
      if (fd.includes("xn--")) F("high", `Sender domain ${fd} is punycode (IDN) - possible homoglyph`);
      const lab = fr.split(".")[0];
      for (const real of BRAND_DOMAINS) {
        if (fr === real) break;
        if ([lab].concat(lab.split("-")).some((x) => x.length >= 5 && lev(x, real.split(".")[0]) === 1)) { F("high", `Sender domain ${fr} is a lookalike of ${real}`); break; }
      }
    }
    const mid = g("Message-ID"), midd = (/@([^>\s]+)>?\s*$/.exec(mid) || [])[1];
    if (midd && fd && regDomain(midd) !== regDomain(fd)) F("low", `Message-ID domain (${midd.toLowerCase()}) differs from From (${fd})`);
    if (hops.some((h) => h.delay_s != null && h.delay_s < -300)) F("med", "Received timestamps go backwards (forged or skewed hop)");
    const xip = g("X-Originating-IP") || g("X-Sender-IP");
    const origin = hops.map((h) => h.ip).find((ip) => ip && isPublicIp(ip)) || null;
    return {
      summary: { From: frm, To: g("To"), Subject: g("Subject"), Date: g("Date"), "Return-Path": rp, "Reply-To": rt, "Message-ID": mid,
        "X-Mailer": g("X-Mailer") || g("User-Agent"), "X-Originating-IP": xip },
      auth, hops, flags, origin_ip: xip ? xip.replace(/^\[|\]$/g, "") : origin, iocs: extractIocs(headerText),
    };
  }

  // ------------------------------------------------------------------ URLs
  function urlFlags(u, text) {
    const flags = [];
    const F = (l, t) => flags.push([l, t]);
    let p;
    try { p = new URL(u); } catch { return [["high", "malformed URL"]]; }
    const host = p.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (!host) return flags;
    const rd = regDomain(host), tld = host.split(".").pop();
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":")) F("high", "URL uses a raw IP address");
    if (host.includes("xn--")) F("high", "punycode (IDN) hostname - possible homoglyph");
    if (p.username || p.password || /^[a-z]+:\/\/[^/?#]*@/i.test(u)) F("high", "'@' in authority - real host is after the @");
    if (p.protocol === "http:") F("low", "not HTTPS");
    if (SHORTENERS.has(host) || SHORTENERS.has(rd)) F("med", "URL shortener hides the destination");
    if (SUS_TLDS.has(tld)) F("med", `high-abuse TLD .${tld}`);
    if (ABUSED_HOSTS.some((h) => host === h || host.endsWith("." + h))) F("med", `free hosting / file-share often abused for phishing (${rd})`);
    if ((host.match(/\./g) || []).length >= 4) F("low", "deeply nested subdomains");
    if (u.length > 180) F("low", "very long URL");
    const label = rd.split(".")[0];
    for (const [brand, real] of Object.entries(BRANDS)) {
      if (rd === real || rd.endsWith("." + real)) break;
      if (host.replace(/-/g, "").includes(brand) && rd !== real) { F("high", `mentions '${brand}' but domain is ${rd}`); break; }
      if ([label].concat(label.split("-")).some((x) => x.length >= 5 && lev(x, real.split(".")[0]) === 1)) { F("high", `lookalike of ${real}`); break; }
    }
    for (const k of ["url", "redirect", "redirect_uri", "next", "u", "target", "dest", "continue", "goto", "r"]) {
      const v = p.searchParams.get(k);
      if (v == null) continue;
      let dv = v; try { dv = decodeURIComponent(v); } catch { /* keep */ }
      if (/^https?:/i.test(dv)) { let h = "?"; try { h = new URL(dv).hostname; } catch { /* ignore */ } F("med", `open-redirect style parameter '${k}' → ${h}`); break; }
    }
    if (/(login|signin|sign-in|verify|account|secure|update|password|wallet|unlock|auth)/i.test(p.pathname + host) && !BRAND_DOMAINS.has(rd)) F("low", "credential-harvest keywords in URL");
    if (text) {
      const t = text.trim().toLowerCase();
      const m = /([a-z0-9-]+\.)+[a-z]{2,}/.exec(t);
      if (m && /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}/.test(t)) {
        const shown = regDomain(m[0]);
        if (shown !== rd) F("high", `link text shows ${shown} but goes to ${rd}`);
      }
    }
    return flags;
  }

  // ------------------------------------------------------------------ HTML (links, forms, text) without a DOM
  function parseHtml(html) {
    const links = [], forms = [], text = [];
    let cur = null, skip = null;
    const TOK = /<!--[\s\S]*?(?:-->|$)|<(\/?)([a-zA-Z][\w:-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>|<![^>]*>|[^<]+|</g;
    const attrs = (s) => { const o = {}; for (const m of s.matchAll(/([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?/g)) { const k = m[1].toLowerCase(); if (!(k in o)) o[k] = unent(m[2] ?? m[3] ?? m[4] ?? ""); } return o; };
    for (const m of String(html).matchAll(TOK)) {
      const tok = m[0];
      if (m[2]) {
        const tag = m[2].toLowerCase(), close = !!m[1];
        if (skip) { if (close && tag === skip) skip = null; continue; }
        if (close) { if (tag === "a" && cur) { links.push(cur); cur = null; } continue; }
        const a = attrs(m[3] || "");
        if (tag === "a" && a.href) { if (cur) links.push(cur); cur = [a.href, ""]; }
        else if (tag === "form") forms.push(a.action || "");
        else if (["img", "iframe", "script", "embed"].includes(tag) && /^http/i.test(a.src || "")) links.push([a.src, `<${tag}>`]);
        else if (tag === "meta" && /refresh/i.test(a["http-equiv"] || "")) { const u = /url\s*=\s*['"]?([^'"\s>]+)/i.exec(a.content || ""); if (u) links.push([u[1], "<meta refresh>"]); }
        if (tag === "script" || tag === "style") skip = tag;
        if (/^(br|p|div|tr|li|h\d|td)$/.test(tag)) text.push(" ");
        continue;
      }
      if (tok.startsWith("<!") || (tok.startsWith("<") && tok.length === 1)) continue;
      if (skip) continue;
      const d = unent(tok);
      if (cur) cur[1] += d;
      text.push(d);
    }
    if (cur) links.push(cur);
    return { links, forms, text: text.join(" ") };
  }

  // ------------------------------------------------------------------ attachments (triage-lite)
  const MAGIC = [[[0x4d, 0x5a], "PE / DOS executable"], [[0x7f, 0x45, 0x4c, 0x46], "ELF executable"], [[0x25, 0x50, 0x44, 0x46], "PDF document"],
    [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], "OLE2 (legacy Office / MSI)"], [[0x50, 0x4b, 0x03, 0x04], "ZIP container"],
    [[0x1f, 0x8b], "GZIP"], [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], "7-Zip"], [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], "RAR"],
    [[0x89, 0x50, 0x4e, 0x47], "PNG image"], [[0xff, 0xd8, 0xff], "JPEG image"], [[0x47, 0x49, 0x46, 0x38], "GIF image"],
    [[0x7b, 0x5c, 0x72, 0x74, 0x66], "RTF document"], [[0x4c, 0, 0, 0, 1, 0x14, 2, 0], "Windows shortcut (LNK)"], [[0x4d, 0x53, 0x43, 0x46], "Microsoft CAB"],
    [[0x23, 0x21], "Script (shebang)"], [[0x3c, 0x3f, 0x78, 0x6d, 0x6c], "XML"]];
  const PACKED = /^(ZIP|GZIP|7-Zip|RAR|PNG|JPEG|GIF|PDF|Office|Microsoft CAB)/;
  const RISKY_INNER = /\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|lnk|iso|img|vhdx?|msi|jar|cpl|dll|one|xll)$/i;

  function triage(data, name) {
    const head = data.subarray(0, 16);
    let type = (MAGIC.find(([m]) => m.every((b, i) => head[i] === b)) || [])[1] || null;
    const lat = W.latin1(data.subarray(0, 4 * 1024 * 1024));
    const low = lat.slice(0, 200000).toLowerCase();
    if (!type) {
      if (data.length > 0x8006 && W.latin1(data.subarray(0x8001, 0x8006)) === "CD001") type = "ISO 9660 disk image";
      else if (/^\s*(<!doctype html|<html|<head|<body|<script|<form|<meta|<div)/i.test(low)) type = "HTML";
      else if (/^\s*<svg|^\s*<\?xml[^>]*>\s*<svg/i.test(low)) type = "SVG image";
      else { const u = W.utf8(data.subarray(0, 4096)); type = u.includes("�") ? "Unknown binary" : "Text / script"; }
    }
    if (type === "XML" && /<svg/i.test(low.slice(0, 2000))) type = "SVG image";
    const flags = [];
    const F = (level, text) => flags.push({ level, text });
    const ent = W.entropy(data);
    if (ent > 7.5 && !PACKED.test(type)) F("med", "Very high overall entropy: compressed, packed or encrypted");
    const ext = name && name.includes(".") ? name.toLowerCase().split(".").pop() : "";
    if (type.startsWith("PE") && ["pdf", "doc", "docx", "jpg", "png", "txt", "xls", "xlsx", "rtf", "csv"].includes(ext)) F("high", `Executable masquerading as .${ext}`);
    else if (type.startsWith("PE")) F("high", "Windows executable attached");
    if (type === "ZIP container") {
      const names = [];
      let enc = false;
      for (let i = 0; i + 30 < data.length && names.length < 500;) {
        if (data[i] === 0x50 && data[i + 1] === 0x4b && data[i + 2] === 3 && data[i + 3] === 4) {
          const fl = data[i + 6] | (data[i + 7] << 8), nl = data[i + 26] | (data[i + 27] << 8), xl = data[i + 28] | (data[i + 29] << 8);
          if (fl & 1) enc = true;
          names.push(W.utf8(data.subarray(i + 30, i + 30 + nl)));
          const csize = (data[i + 18] | (data[i + 19] << 8) | (data[i + 20] << 16) | (data[i + 21] << 24)) >>> 0;
          i += 30 + nl + xl + ((fl & 8) || !csize ? 0 : csize);
          if ((fl & 8) || !csize) i++;
        } else i++;
      }
      if (names.includes("[Content_Types].xml")) type = names.some((n) => n.startsWith("word/")) ? "Office Open XML (Word)" : names.some((n) => n.startsWith("xl/")) ? "Office Open XML (Excel)" : names.some((n) => n.startsWith("ppt/")) ? "Office Open XML (PowerPoint)" : "Office Open XML";
      if (names.some((n) => /vbaProject\.bin$/i.test(n))) F("high", "Office document contains VBA macros");
      if (names.some((n) => /oleObject\d*\.bin$/i.test(n))) F("med", "Office document embeds OLE objects");
      const bad = names.filter((n) => RISKY_INNER.test(n));
      if (bad.length) F("high", `Archive contains executable/script: ${bad.slice(0, 3).join(", ")}${bad.length > 3 ? " …" : ""}`);
      if (enc) F("high", "Password-protected archive (hides content from mail filters)");
    }
    if (type.startsWith("OLE2") && (lat.includes("_VBA_PROJECT") || (lat.includes("VBA") && lat.includes("Attribute VB_")))) F("high", "VBA macro streams present");
    if (type === "PDF document") {
      if (/\/(JavaScript|JS)\b/.test(lat)) F("high", "PDF contains JavaScript");
      if (/\/Launch\b/.test(lat)) F("high", "PDF has a Launch action");
      if (/\/OpenAction\b|\/AA\b/.test(lat) && /\/(JavaScript|JS|URI|Launch)\b/.test(lat)) F("med", "PDF runs an action when opened");
      if (/\/EmbeddedFile\b/.test(lat)) F("med", "PDF embeds files");
    }
    if (type === "HTML" || type === "SVG image" || /^(html?|svg|shtml)$/.test(ext)) {
      if (/<form\b|type\s*=\s*["']?password/i.test(low)) F("high", "HTML/SVG attachment with a form or password field (credential phishing page)");
      if (/<script\b/i.test(low) && (/atob\s*\(|fromcharcode|unescape\s*\(|eval\s*\(|window\.location|location\.href|\.click\(\)|new blob/i.test(low))) F("high", "Attachment with obfuscated/redirecting script (HTML smuggling)");
      else if (/<script\b/i.test(low) && type === "SVG image") F("high", "SVG image with embedded script");
    }
    if (type === "Windows shortcut (LNK)") F("high", "Windows shortcut attachment");
    if (type.startsWith("ISO")) F("high", "Disk image attachment (bypasses Mark-of-the-Web)");
    // YARA (lazy: the yara engine is optional)
    const yara = [];
    try {
      const Y = W.eng.yara;
      if (Y && Y.builtin) for (const h of Y.scan(Y.builtin(), data)) {
        if (h.error) continue;
        const sev = Y.severity(h);
        yara.push({ rule: h.rule, severity: sev, description: (h.meta && h.meta.description) || "" });
        if (sev !== "info") F(sev === "critical" || sev === "high" ? "high" : sev === "medium" ? "med" : "low", `YARA ${h.rule}: ${(h.meta && h.meta.description) || "match"}`);
      }
    } catch { /* yara unavailable */ }
    const strs = (lat.match(/[\x20-\x7e]{6,}/g) || []).join("\n");
    const urls = uniq((strs.match(/\bhttps?:\/\/[^\s<>"'`\])}|\\^]+/gi) || []).map((u) => u.replace(/[.,;:!?'"]+$/, ""))).slice(0, 200);
    return { type, entropy: Math.round(ent * 1000) / 1000, flags, yara, iocs: urls.length ? { url: urls } : {} };
  }

  // ------------------------------------------------------------------ analyze
  function analyze(raw) {
    raw = String(raw == null ? "" : raw).replace(/\r\n?/g, "\n").replace(/^\s+/, "");
    const msg = splitMessage(raw);
    const hdr = analyzeHeaders(msg.headers, msg.headerText);
    const parts = walk(msg.headers, msg.body, 0);
    let links = [], forms = [];
    const texts = [], atts = [];
    for (const part of parts) {
      const fname = part.filename ? String(part.filename) : null;
      if (fname || part.disp === "attachment" || !part.ctype.startsWith("text/")) {
        const data = part.bytes();
        const t = data.length ? triage(data.subarray(0, 20000000), fname || "attachment") : null;
        const fl = [];
        if (fname && RISKY_EXT.test(fname)) fl.push({ level: RISKY_HIGH.test(fname) ? "high" : "med", text: `risky attachment type ${fname.split(".").pop()}` });
        if (fname && /\.\w{2,4}\.\w{2,4}$/.test(fname)) fl.push({ level: "high", text: "double extension" });
        if (fname && /[‮‭‏]/.test(fname)) fl.push({ level: "high", text: "right-to-left override in filename (extension spoofing)" });
        if (t) fl.push(...t.flags);
        atts.push({ name: fname || "(unnamed)", type: part.ctype, size: data.length, flags: fl,
          hashes: data.length ? { md5: W.hash.md5(data), sha1: sha(data, 1), sha256: sha(data, 256) } : {},
          detected: t ? t.type : null, entropy: t ? t.entropy : 0, yara: t ? t.yara : [], iocs: t ? t.iocs : {} });
        continue;
      }
      const body = part.text();
      if (part.ctype === "text/html") {
        const p = parseHtml(body);
        links = links.concat(p.links.map(([h, t]) => [unent(h), t]));
        forms = forms.concat(p.forms);
        texts.push(p.text);
        // bare URLs in the HTML text that aren't the visible text of a link (that text is often a decoy like https://www.paypal.com)
        const shown = p.links.map(([, t]) => t || "").join(" ");
        for (const u of p.text.match(RE_URL) || []) if (!shown.includes(u)) links.push([u, null]);
      } else if (part.ctype.startsWith("text/")) {
        texts.push(body);
        for (const u of body.match(RE_URL) || []) links.push([u, null]);
      }
    }
    const seen = new Set(), urls = [];
    for (let [u, t] of links) {
      u = String(u).trim();
      if (!/^https?:\/\//i.test(u) || seen.has(u)) continue;
      seen.add(u);
      const fl = urlFlags(u, t && !t.startsWith("<") ? t : null);
      let host = null; try { host = new URL(u).hostname.replace(/^\[|\]$/g, ""); } catch { /* malformed */ }
      urls.push({ url: u, text: (t || "").trim().replace(/\s+/g, " ").slice(0, 120), host, flags: fl.map(([level, text]) => ({ level, text })) });
    }
    const bodyTxt = texts.join(" ");
    const lures = uniq(((bodyTxt + " " + (hdr.summary.Subject || "")).match(URGENCY) || []).map((x) => x.toLowerCase())).sort();
    const pts = { high: 3, med: 2, low: 1 };
    let score = hdr.flags.filter((f) => f.level !== "low").reduce((a, f) => a + (pts[f.level] || 0), 0);
    score += urls.reduce((a, u) => a + u.flags.reduce((b, f) => b + (pts[f.level] || 0), 0), 0);
    score += atts.reduce((a, x) => a + x.flags.reduce((b, f) => b + (pts[f.level] || 0), 0), 0);
    score += Math.min(lures.length, 3) * 2;
    if (forms.length) score += 3;
    const verdict = score >= 12 ? "malicious" : score >= 5 ? "suspicious" : "likely benign";

    const order = { high: 0, med: 1, low: 2 };
    const redflags = [
      ...hdr.flags.map((f) => ({ level: f.level, text: f.text, src: "HDR" })),
      ...urls.flatMap((u) => u.flags.map((f) => ({ level: f.level, text: `${f.text} — ${u.host || u.url}`, src: "URL" }))),
      ...atts.flatMap((a) => a.flags.map((f) => ({ level: f.level, text: `${a.name}: ${f.text}`, src: "ATT" }))),
      ...lures.map((x) => ({ level: "med", text: `pressure language: "${x}"`, src: "LURE" })),
      ...forms.map((f) => ({ level: "high", text: `embedded HTML form → ${f || "(self)"}`, src: "FORM" })),
    ].sort((a, b) => order[a.level] - order[b.level]);

    const hosts = uniq(urls.map((u) => u.host).filter(Boolean));
    const iocs = {
      url: urls.map((u) => u.url),
      domain: hosts.filter((h) => !/^[\d.]+$/.test(h) && !h.includes(":")),
      ipv4: uniq([hdr.origin_ip, ...hdr.iocs.ipv4, ...hosts.filter((h) => /^[\d.]+$/.test(h))].filter((x) => x && /^[\d.]+$/.test(x) && isPublicIp(x))),
      ipv6: uniq(hdr.iocs.ipv6 || []),
      email: uniq([parseAddr(hdr.summary.From).addr, parseAddr(hdr.summary["Reply-To"]).addr, parseAddr(hdr.summary["Return-Path"]).addr].filter((x) => x && x.includes("@")).map((x) => x.toLowerCase())),
      sha256: atts.map((a) => a.hashes.sha256).filter(Boolean),
    };
    // never suggest blocking the brands being impersonated (or their subdomains)
    const legit = (v) => { let h = v; try { if (/^https?:/i.test(v)) h = new URL(v).hostname; } catch { /* keep */ } return BRAND_DOMAINS.has(regDomain(h)); };
    const blockable = uniq([...iocs.domain, ...iocs.url, ...iocs.ipv4, ...iocs.sha256]).filter((v) => !legit(v));
    return {
      headers: hdr, urls, attachments: atts, forms, lures, score, verdict, redflags, iocs, blockable,
      subject: hdr.summary.Subject || null, from: hdr.summary.From || null,
      body_preview: bodyTxt.replace(/\s+/g, " ").trim().slice(0, 1200),
      parts: parts.length,
    };
  }

  W.eng.phish = { analyze, urlFlags, regDomain, lev, parseHtml, decodeWords, parseParams, parseAddr, sha256: (b) => sha(b, 256), sha1: (b) => sha(b, 1), BRANDS };
})(typeof window !== "undefined" ? window.W : globalThis.W);
