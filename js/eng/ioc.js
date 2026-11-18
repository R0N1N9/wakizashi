/* IOC extraction + host-artifact extraction (port of katana/cti/ioc.py + artifacts.py). Pure. */
(function (W) {
  "use strict";

  const FILE_EXT = new Set(("exe dll sys bat cmd ps1 psm1 vbs vbe js jse hta lnk scr msi jar py sh elf bin dat tmp log txt ini cfg conf json xml yml yaml csv " +
    "doc docx docm xls xlsx xlsm ppt pptx pdf rtf png jpg jpeg gif bmp svg ico htm html php asp aspx jsp css zip rar 7z gz tar iso img apk dex so o c h cpp go rs " +
    "java class md db sqlite bak old mov mp4 mp3 wav tgz pdb lib obj msc cab cpl wsf xll one vhd vhdx ova dmg pkg deb rpm").split(" "));

  const REFANG = [
    [/h(?:xx|XX|\*\*)p(s?)(?=\[?:)/gi, "http$1"],
    [/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}/gi, "."],
    [/\[\s*:\s*\/\/\s*\]/g, "://"],
    [/\[\s*:\s*\]/g, ":"],
    [/\[\s*\/\s*\]/g, "/"],
    [/\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)/gi, "@"],
    [/\s+\[dot\]\s+|\s+\(dot\)\s+/gi, "."],
  ];
  const refang = (t) => REFANG.reduce((s, [rx, rep]) => s.replace(rx, rep), String(t || ""));
  const defang = (v) => String(v).replace(/^http/i, "hxxp").replace("://", "[://]").replace(/@/g, "[@]").replace(/\./g, "[.]");

  const RX = {
    url: /\b(?:https?|ftp|sftp):\/\/[^\s<>"'`\])}|\\^]+/gi,
    ipv4: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g,
    ipv6: /(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])/g,
    domain: /(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24}))(?![\w-])/gi,
    email: /\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b/gi,
    md5: /(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])/gi,
    sha1: /(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])/gi,
    sha256: /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/gi,
    sha512: /(?<![0-9a-f])[0-9a-f]{128}(?![0-9a-f])/gi,
    cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
    attack: /\b(?:T|TA)\d{4}(?:\.\d{3})?\b/g,
    asn: /\bAS\d{1,10}\b/gi,
    btc: /\b(?:bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
    eth: /\b0x[a-fA-F0-9]{40}\b/g,
    xmr: /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g,
    filepath: /\b[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]*/g,
    registry: /\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[^\s"'<>]+/g,
    mac: /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi,
  };
  const ORDER = ["url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256", "sha512", "cve", "attack", "asn", "btc", "eth", "xmr", "mac", "filepath", "registry"];
  const LABEL = { url: "URLs", domain: "Domains", ipv4: "IPv4", ipv6: "IPv6", email: "Emails", md5: "MD5", sha1: "SHA-1", sha256: "SHA-256", sha512: "SHA-512",
    cve: "CVEs", attack: "ATT&CK IDs", asn: "ASNs", btc: "Bitcoin", eth: "Ethereum", xmr: "Monero", mac: "MAC addresses", filepath: "Windows paths", registry: "Registry keys" };
  /** Map extractor kinds to the indicator types used by cases / STIX. */
  const CASE_TYPE = { url: "url", domain: "domain", ipv4: "ipv4", ipv6: "ipv6", email: "email", md5: "md5", sha1: "sha1", sha256: "sha256", sha512: "sha512",
    cve: "cve", attack: "attack", asn: "asn", btc: "btc", eth: "eth", xmr: "xmr", mac: "mac", filepath: "file", registry: "registry" };

  const uniq = (a) => [...new Set(a)];
  const all = (rx, s) => Array.from(s.matchAll(new RegExp(rx.source, rx.flags)), (m) => m[1] !== undefined && rx === RX.domain ? m[1] : m[0]);

  function ipv4Private(ip) {
    const p = ip.split(".").map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || p[0] >= 224 ||
      (p[0] === 192 && p[1] === 0 && (p[2] === 0 || p[2] === 2)) || (p[0] === 198 && (p[1] === 18 || p[1] === 19)) ||
      (p[0] === 198 && p[1] === 51 && p[2] === 100) || (p[0] === 203 && p[1] === 0 && p[2] === 113);
  }
  /** Parse an IPv6 literal into 8 hextets, or null. */
  function v6parse(s) {
    if (!/^[0-9a-f:.]+$/i.test(s) || (s.match(/::/g) || []).length > 1) return null;
    let [head, tail] = s.includes("::") ? s.split("::") : [s, null];
    const h = head ? head.split(":") : [], t = tail ? tail.split(":") : [];
    if (tail === null && h.length !== 8) return null;
    const fill = 8 - h.length - t.length; if (fill < 0 || (tail !== null && fill < 1)) return null;
    const parts = [...h, ...Array(tail === null ? 0 : fill).fill("0"), ...t];
    if (parts.length !== 8 || parts.some((x) => !/^[0-9a-f]{1,4}$/i.test(x))) return null;
    return parts.map((x) => parseInt(x, 16));
  }
  function v6norm(parts) {   // RFC 5952 compression
    const hx = parts.map((x) => x.toString(16));
    let best = [-1, 0], cur = [-1, 0];
    hx.forEach((x, i) => { if (x === "0") { if (cur[0] < 0) cur = [i, 0]; cur[1]++; if (cur[1] > best[1]) best = cur.slice(); } else cur = [-1, 0]; });
    if (best[1] < 2) return hx.join(":");
    return hx.slice(0, best[0]).join(":") + "::" + hx.slice(best[0] + best[1]).join(":");
  }
  const v6private = (p) => (p[0] & 0xfe00) === 0xfc00 || (p[0] & 0xffc0) === 0xfe80 || (p[0] & 0xff00) === 0xff00 || p.every((x, i) => i < 7 ? x === 0 : x <= 1) || (p[0] === 0x2001 && p[1] === 0xdb8);
  const isDomain = (d) => { const tld = d.split(".").pop(); return !FILE_EXT.has(tld) && !/^[\d.]+$/.test(d) && d.length <= 253; };

  /** extract(text, {includePrivate=true, refang=true}) → {kind: [values]} (only non-empty kinds) */
  function extract(text, opts = {}) {
    const inclPriv = opts.includePrivate !== false;
    let t = String(text || "").slice(0, 5_000_000);
    if (opts.refang !== false) t = refang(t);
    const out = {};
    out.url = uniq(all(RX.url, t).map((u) => u.replace(/[.,;:!?'"]+$/, "")));
    out.email = uniq(all(RX.email, t).map((e) => e.toLowerCase()));
    for (const h of ["sha512", "sha256", "sha1", "md5"]) out[h] = uniq(all(RX[h], t).map((x) => x.toLowerCase()));
    out.cve = uniq(all(RX.cve, t).map((x) => x.toUpperCase()));
    out.attack = uniq(all(RX.attack, t));
    out.asn = uniq(all(RX.asn, t).map((x) => x.toUpperCase()));
    out.btc = uniq(all(RX.btc, t)); out.eth = uniq(all(RX.eth, t)); out.xmr = uniq(all(RX.xmr, t));
    out.mac = uniq(all(RX.mac, t).map((x) => x.toLowerCase()));
    out.filepath = uniq(all(RX.filepath, t).map((x) => x.replace(/[.,;]+$/, "")));
    out.registry = uniq(all(RX.registry, t).map((x) => x.replace(/[.,;]+$/, "")));
    out.ipv4 = uniq(all(RX.ipv4, t).filter((ip) => inclPriv || !ipv4Private(ip)));
    const v6 = [];
    for (const c of all(RX.ipv6, t)) {
      if ((c.match(/:/g) || []).length < 2 || c.length < 3 || /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(c)) continue;
      const p = v6parse(c); if (!p) continue;
      if (inclPriv || !v6private(p)) v6.push(v6norm(p));
    }
    out.ipv6 = uniq(v6);
    const emailDomains = out.email.map((e) => e.split("@")[1]).sort();
    out.domain = uniq(all(RX.domain, t).map((d) => d.toLowerCase().replace(/\.$/, "")).filter(isDomain).concat(emailDomains));
    const res = {};
    for (const k of ORDER) if (out[k] && out[k].length) res[k] = out[k];
    return res;
  }

  /** Flatten extract() output into case items. */
  const toItems = (iocs, extra = {}) => Object.entries(iocs).flatMap(([k, vs]) => vs.map((value) => Object.assign({ value, type: CASE_TYPE[k] || k }, extra)));
  const count = (iocs) => Object.values(iocs).reduce((n, v) => n + v.length, 0);

  // ------------------------------------------------------------------ host artifacts
  const SPECS = [
    ["pdb", /\b[a-z]:\\(?:[^\\\r\n"<>|?*]{1,80}\\){0,12}[^\\\r\n"<>|?*]{1,80}\.pdb\b/gi],
    ["pdb", /(?<![\w/])\/(?:[^/\r\n"<>|]{1,80}\/){1,12}[^/\r\n"<>|]{1,80}\.pdb\b/g],
    ["mutex", /\b(?:Global|Local|Session\\{1,2}\d+)\\{1,2}[\w.$#@{}\-]{3,80}/gi],
    ["pipe", /\\{1,2}\.\\{1,2}pipe\\{1,2}[\w.$#@\-]{1,80}/gi],
    ["registry", /\b(?:HKLM|HKCU|HKU|HKCR|HKEY_[A-Z_]{2,30})(?:\\{1,2}[\w .$\-]{1,64}){2,12}/gi],
    ["service", /\bCurrentControlSet\\{1,2}Services\\{1,2}[\w.$\-]{1,64}/gi],
    ["guid", /\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?/g],
    ["useragent", /(?:User-Agent:\s*)?Mozilla\/\d\.\d \([^)\r\n]{0,120}\)[^\r\n"']{0,160}/g],
    ["btc", /\b(?:bc1[0-9ac-hj-np-z]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g],
    ["eth", /\b0x[a-fA-F0-9]{40}\b/g],
    ["xmr", /\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g],
    ["onion", /\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b/g],
    ["panel", /\bhttps?:\/\/[^\s"'<>]+?\/[^\s"'<>]*?(?:gate|panel|admin|login|config|command|task|bot|upload|c2)[^\s"'<>]*/gi],
  ];
  const A_ORDER = ["pdb", "mutex", "pipe", "registry", "service", "guid", "useragent", "btc", "eth", "xmr", "onion", "panel", "username"];
  const A_META = {
    pdb: ["PDB build paths", "high", "Compiler debug path — leaks the author's username, project name and build layout. Rarely changed."],
    mutex: ["Mutexes / sync objects", "high", "Named synchronization object (CreateMutex/Event). Attacker-chosen and stable across a family."],
    pipe: ["Named pipes", "high", "Named pipe — a local C2 / IPC channel name. Very distinctive."],
    registry: ["Registry keys", "medium", "Registry path. Run / RunOnce keys indicate persistence."],
    service: ["Service names", "high", "Windows service registration — often how the implant persists."],
    guid: ["GUIDs", "medium", "GUID — may be a mutex, COM CLSID or a campaign identifier."],
    useragent: ["User-Agent strings", "medium", "HTTP User-Agent — hard-coded UAs are a reliable network signature."],
    btc: ["Bitcoin wallets", "high", "BTC address — ransom / payment pivot."], eth: ["Ethereum wallets", "medium", "ETH address."],
    xmr: ["Monero wallets", "high", "XMR address — common in ransomware notes."], onion: ["Tor .onion addresses", "high", "Hidden-service address — a C2 or leak site."],
    panel: ["C2 / panel URLs", "medium", "URL whose path looks like a controller panel or gate."],
    username: ["Build-machine usernames", "medium", "Developer/build username lifted from a path — a possible actor handle."],
  };
  const HUNTABLE = new Set(["pdb", "mutex", "pipe", "registry", "service", "guid", "useragent", "onion", "panel"]);
  const clean = (v) => v.trim().replace(/^[\s.,;:'"<>]+|[\s.,;:'"<>]+$/g, "");

  function artifacts(text) {
    const t = String(text || "").slice(0, 2_000_000);
    const b = {};
    for (const [kind, rx] of SPECS) {
      const seen = (b[kind] = b[kind] || []); const have = new Set(seen.map((x) => x.toLowerCase()));
      for (const m of t.matchAll(rx)) {
        const v = clean(m[0]); if (v.length < 4 || have.has(v.toLowerCase())) continue;
        have.add(v.toLowerCase()); seen.push(v); if (seen.length >= 150) break;
      }
    }
    const users = (b.username = []); const uh = new Set();
    for (const m of t.matchAll(/[a-z]:\\users\\([^\\\r\n"<>|]{1,40})\\/gi)) {
      const u = clean(m[1]); if (u && !uh.has(u.toLowerCase()) && !["public", "default", "all users"].includes(u.toLowerCase())) { uh.add(u.toLowerCase()); users.push(u); }
    }
    const groups = A_ORDER.filter((k) => (b[k] || []).length).map((kind) => ({ kind, label: A_META[kind][0], confidence: A_META[kind][1], note: A_META[kind][2], items: b[kind], huntable: HUNTABLE.has(kind) }));
    return { groups, total: groups.reduce((n, g) => n + g.items.length, 0), kinds: groups.length };
  }

  W.eng.ioc = { extract, refang, defang, artifacts, toItems, count, ORDER, LABEL, CASE_TYPE, ipv4Private, v6parse, v6norm, isDomain };
})(typeof window !== "undefined" ? window.W : globalThis.W);
