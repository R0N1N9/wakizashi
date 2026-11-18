/* YARA rule builder (port of katana/cti/yaragen.py). Validation/testing use W.eng.yara (YARA-lite) when present. */
(function (W) {
  "use strict";
  const NAME_RE = /[^A-Za-z0-9_]/g;
  const INTEREST = /(http|https|ftp):\/\/|\\\\|cmd\.exe|powershell|rundll32|CreateProcess|VirtualAlloc|WScript|schtasks|reg add|-enc|FromBase64|Invoke-|\.dll|\.ps1|\.vbs|User-Agent|Authorization|BEGIN |mimikatz|\/bin\/sh|\/bin\/bash|chmod|wget |curl |nc -|socat/i;

  const ruleName = (n) => { let s = String(n || "").trim().replace(NAME_RE, "_") || "generated_rule"; if (/^\d/.test(s)) s = "r_" + s; return s.slice(0, 80); };
  const escText = (s) => String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t");
  const MODS = ["ascii", "wide", "nocase", "fullword", "xor", "base64"];
  const mods = (m) => { const a = (m || []).filter((x) => MODS.includes(x)); return a.length ? " " + a.join(" ") : ""; };

  function renderString(sid, st) {
    sid = sid.startsWith("$") ? sid.replace(/[^$\w]/g, "_") : "$" + String(sid || "s").replace(NAME_RE, "_");
    const kind = st.type || "text", val = String(st.value || "");
    if (kind === "hex") {
      const hx = val.replace(/[^0-9A-Fa-f? [\]\-]/g, "").trim();
      if (!hx) throw new Error(`${sid}: empty/invalid hex`);
      return `${sid} = { ${hx} }`;
    }
    if (kind === "regex") {
      const body = val.trim();
      if (body.startsWith("/") && body.lastIndexOf("/") > 0) return `${sid} = ${body}${mods(st.modifiers)}`;
      return `${sid} = /${body.replace(/(?<!\\)\//g, "\\/")}/${mods(st.modifiers)}`;
    }
    return `${sid} = "${escText(val)}"${mods(st.modifiers)}`;
  }

  /** spec: {name, tags[], meta{}, strings:[{id,type:text|hex|regex,value,modifiers[]}], condition?, condition_mode:any|all|n, n, filesize_kb, mz} */
  function build(spec) {
    spec = spec || {};
    const name = ruleName(spec.name);
    const tags = (spec.tags || []).map((t) => String(t).replace(NAME_RE, "")).filter(Boolean).join(" ");
    const meta = Object.assign({}, spec.meta || {});
    if (!meta.date) meta.date = new Date().toISOString().slice(0, 10);
    if (!meta.generator) meta.generator = "Wakizashi";
    const L = [`rule ${name}${tags ? " : " + tags : ""}`, "{"];
    const metaRows = Object.entries(meta).filter(([, v]) => v != null && v !== "");
    if (metaRows.length) { L.push("    meta:"); for (const [k, v] of metaRows) L.push(`        ${String(k).replace(NAME_RE, "_")} = "${escText(v)}"`); }
    const sids = [];
    const strs = (spec.strings || []).filter((s) => String(s.value || "").trim());
    if (strs.length) {
      L.push("    strings:");
      strs.forEach((st, i) => { const r = renderString(st.id || `$s${i + 1}`, st); L.push("        " + r); sids.push(r.split(" =")[0].trim()); });
    }
    let cond = spec.condition;
    if (!cond) {
      const mode = spec.condition_mode || "any";
      if (!sids.length) cond = "filesize < 10MB";
      else if (mode === "all") cond = "all of them";
      else if (mode === "n") cond = `${Math.max(1, Math.min(+spec.n || 2, sids.length))} of them`;
      else cond = "any of them";
      const extra = [];
      if (spec.filesize_kb) extra.push(`filesize < ${parseInt(spec.filesize_kb, 10)}KB`);
      if (spec.mz) extra.push("uint16(0) == 0x5A4D");
      if (extra.length) cond = sids.length ? `(${cond}) and ${extra.join(" and ")}` : extra.join(" and ");
    }
    L.push("    condition:", "        " + cond, "}");
    return L.join("\n");
  }

  function validate(text) {
    const y = W.eng.yara;
    if (!y) return { valid: true, rules: [], errors: [], engine: false };
    const { rules, errors } = y.compile(text || "");
    return { valid: rules.length > 0 && !errors.some((e) => !/^import/.test(e)), rules: rules.map((r) => ({ name: r.name, tags: r.tags, meta: r.meta })), errors, engine: true };
  }
  function generate(spec) { const rule = build(spec); const v = validate(rule); return { rule, valid: v.valid, errors: v.errors, rules: v.rules, spec }; }

  /** Printable ASCII and UTF-16LE strings (like `strings`). */
  function strings(bytes, minLen = 6, limit = 8000) {
    const b = W.bytes(bytes), out = [];
    let cur = "";
    for (let i = 0; i < b.length && out.length < limit; i++) {
      const c = b[i];
      if (c >= 0x20 && c <= 0x7e) cur += String.fromCharCode(c); else { if (cur.length >= minLen) out.push(cur); cur = ""; }
    }
    if (cur.length >= minLen) out.push(cur);
    cur = "";
    for (let i = 0; i + 1 < b.length && out.length < limit * 2; i += 2) {
      const c = b[i], z = b[i + 1];
      if (z === 0 && c >= 0x20 && c <= 0x7e) cur += String.fromCharCode(c); else { if (cur.length >= minLen) out.push(cur); cur = ""; }
    }
    if (cur.length >= minLen) out.push(cur);
    return out;
  }

  async function fromSample(bytes, name = "sample") {
    const data = W.bytes(bytes); if (!data.length) throw new Error("empty sample");
    const hashes = await W.hash.all(data);
    const cands = [], seen = new Set();
    for (const s of strings(data, 6, 8000)) {
      const m = INTEREST.exec(s); if (!m) continue;
      const frag = s.length > 80 ? s.slice(Math.max(0, m.index - 16), m.index + 48).trim() : s.trim();
      if (frag.length >= 6 && frag.length <= 80 && !seen.has(frag)) { seen.add(frag); cands.push(frag); }
      if (cands.length >= 12) break;
    }
    if (cands.length < 6) {
      for (const s of [...new Set(strings(data, 8, 4000).map((x) => x.trim()))].sort((a, b) => b.length - a.length)) {
        if (s.length >= 8 && s.length <= 80 && !seen.has(s)) { seen.add(s); cands.push(s); }
        if (cands.length >= 10) break;
      }
    }
    const type = W.eng.triage ? W.eng.triage.magic(data) : "unknown";
    const spec = { name: ruleName(String(name).replace(/\.[^.]+$/, "")) + "_sample", tags: ["generated", "sample"],
      meta: { description: `Auto-generated from sample ${name}`, sha256: hashes.sha256, filetype: type, author: "Wakizashi" },
      strings: cands.map((v, i) => ({ id: `$s${i + 1}`, type: "text", value: v, modifiers: ["ascii", "wide"] })),
      condition_mode: "n", n: Math.max(2, Math.min(4, cands.length)), filesize_kb: Math.max(16, Math.floor(data.length / 1024) * 2 || 16), mz: data[0] === 0x4d && data[1] === 0x5a };
    return Object.assign(generate(spec), { hashes, filetype: type, size: data.length, candidates: cands, entropy: W.entropy(data) });
  }

  function fromIocs(text) {
    const iocs = W.eng.ioc.extract(text || "", { includePrivate: false });
    const strings = []; let n = 1;
    for (const k of ["url", "domain", "ipv4", "email"]) for (const v of (iocs[k] || []).slice(0, 15)) strings.push({ id: `$n${n++}`, type: "text", value: v, modifiers: ["ascii", "wide", "nocase"] });
    const hashes = ["sha256", "sha1", "md5"].flatMap((h) => iocs[h] || []);
    const meta = { description: "Generated from IOC set", author: "Wakizashi" };
    if (hashes.length) meta.hashes = hashes.slice(0, 8).join(", ");
    const spec = { name: "ioc_set_" + new Date().toISOString().slice(0, 10).replace(/-/g, ""), tags: ["generated", "ioc"], meta, strings, condition_mode: "any" };
    return Object.assign(generate(spec), { ioc_counts: Object.fromEntries(Object.entries(iocs).map(([k, v]) => [k, v.length])), network_iocs: strings.length, hashes: hashes.slice(0, 16) });
  }

  /** Rule from a list of literal strings (host artifacts, etc.). */
  function fromStrings(values, name, meta) {
    const vals = [...new Set((values || []).map((v) => String(v).trim()).filter(Boolean))].slice(0, 60);
    if (!vals.length) throw new Error("no strings to build a rule from");
    return generate({ name: name || "wakizashi_strings", tags: ["wakizashi"], meta: Object.assign({ author: "Wakizashi" }, meta || {}),
      strings: vals.map((v, i) => ({ id: `$s${i + 1}`, type: "text", value: v, modifiers: ["ascii", "wide"] })), condition_mode: "any" });
  }

  const TEMPLATES = [
    { name: "Suspicious PowerShell", spec: { name: "suspicious_powershell", tags: ["generated"], meta: { description: "Encoded / download-cradle PowerShell" },
      strings: [{ id: "$a", type: "text", value: "-EncodedCommand", modifiers: ["nocase", "wide", "ascii"] }, { id: "$b", type: "text", value: "FromBase64String", modifiers: ["nocase", "wide", "ascii"] },
        { id: "$c", type: "text", value: "Net.WebClient", modifiers: ["nocase", "wide", "ascii"] }], condition_mode: "n", n: 2 } },
    { name: "Generic webshell", spec: { name: "generic_webshell", tags: ["generated"], meta: { description: "Common PHP webshell sinks" },
      strings: [{ id: "$a", type: "text", value: "eval(", modifiers: ["nocase"] }, { id: "$b", type: "text", value: "base64_decode", modifiers: ["nocase"] },
        { id: "$c", type: "regex", value: "\\$_(GET|POST|REQUEST)\\[", modifiers: ["nocase"] }], condition_mode: "all" } },
    { name: "PE with suspicious imports", spec: { name: "pe_injection_imports", tags: ["generated", "pe"], meta: { description: "PE importing process-injection APIs" },
      strings: [{ id: "$a", type: "text", value: "VirtualAllocEx" }, { id: "$b", type: "text", value: "WriteProcessMemory" }, { id: "$c", type: "text", value: "CreateRemoteThread" }],
      condition_mode: "all", mz: true } },
  ];

  W.eng.yaragen = { build, generate, validate, fromSample, fromIocs, fromStrings, strings, ruleName, TEMPLATES };
})(typeof window !== "undefined" ? window.W : globalThis.W);
