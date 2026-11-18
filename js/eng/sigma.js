/* Yoroi Sigma engine — W.eng.sigma. Port of Katana's defense/sigma.py: a practical subset of Sigma.
 *
 * Supported
 *   - YAML: block maps/lists, lists of maps, flow lists [a, b] and maps {a: b}, quoted scalars, | and > block
 *     scalars, comments, multiple documents (---).
 *   - Detection items: maps (AND of fields), lists of maps (OR), keyword lists (match anywhere).
 *   - Modifiers: contains, startswith, endswith, all, re (+ i/m/s), cidr, base64, base64offset, windash, exists,
 *     gt/gte/lt/lte, cased.
 *   - Conditions: and / or / not, parentheses, "1 of sel*", "any of", "all of sel*", "1 of them", "all of them".
 * Not supported: aggregations ("| count() by …"), correlation rules, placeholders (%var%).
 *
 *   compile(text)        → {rules, errors}
 *   run(rules, events)   → [{rule, name, severity, attack, title, detail, events, count, entities, sigma:true}]
 *   fieldValue(ev, name) → the value a rule's field name resolves to on a normalised event
 *   BUILTIN              → bundled rule text (multi-document YAML)
 */
(function (W) {
  "use strict";
  const L = () => W.eng.logs;
  const obj = () => Object.create(null);
  const isMap = (x) => x != null && typeof x === "object" && !Array.isArray(x);
  const reEsc = (s) => String(s).replace(/[.*+?^${}()|[\]\\/-]/g, "\\$&");

  // ------------------------------------------------------------------ mini YAML
  class YamlError extends Error {}

  function unescapeDq(s) {
    return s.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (all, c) => {
      if (c[0] === "x" || c[0] === "u" || c[0] === "U") { try { return String.fromCodePoint(parseInt(c.slice(1), 16)); } catch { return all; } }
      return { n: "\n", t: "\t", r: "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'", a: "\x07", b: "\b", f: "\f", v: "\v", "/": "/", " ": " " }[c] ?? all;
    });
  }
  function splitFlow(s) {
    const parts = []; let buf = "", q = null, depth = 0;
    for (const ch of s) {
      if (q) { buf += ch; if (ch === q) q = null; }
      else if (ch === "'" || ch === '"') { q = ch; buf += ch; }
      else if (ch === "[" || ch === "{") { depth++; buf += ch; }
      else if (ch === "]" || ch === "}") { depth--; buf += ch; }
      else if (ch === "," && depth === 0) { parts.push(buf.trim()); buf = ""; }
      else buf += ch;
    }
    if (buf.trim()) parts.push(buf.trim());
    return parts;
  }
  function scalar(s) {
    s = s.trim();
    if (!s) return null;
    if (s[0] === "'" && s.endsWith("'") && s.length >= 2) return s.slice(1, -1).replace(/''/g, "'");
    if (s[0] === '"' && s.endsWith('"') && s.length >= 2) return s.includes("\\") ? unescapeDq(s.slice(1, -1)) : s.slice(1, -1);
    if (s.startsWith("[") && s.endsWith("]")) { const inner = s.slice(1, -1).trim(); return inner ? splitFlow(inner).map(scalar) : []; }
    if (s.startsWith("{") && s.endsWith("}")) {
      const out = obj();
      for (const part of splitFlow(s.slice(1, -1))) {
        const i = part.indexOf(":");
        if (i >= 0) out[String(scalar(part.slice(0, i)))] = scalar(part.slice(i + 1));
      }
      return out;
    }
    const low = s.toLowerCase();
    if (low === "null" || low === "~") return null;
    if (low === "true" || low === "yes") return true;
    if (low === "false" || low === "no") return false;
    if (/^-?\d+$/.test(s)) return parseInt(s, 10);
    if (/^-?\d+\.\d+$/.test(s)) return parseFloat(s);
    return s;
  }
  function stripComment(line) {
    let q = null;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (q) { if (ch === q) q = null; }
      else if (ch === "'" || ch === '"') q = ch;
      else if (ch === "#" && (i === 0 || line[i - 1] === " " || line[i - 1] === "\t")) return line.slice(0, i).replace(/\s+$/, "");
    }
    return line.replace(/\s+$/, "");
  }
  const RE_KEY = /^((?:'[^']*'|"[^"]*"|[^:'"]+?)):(?:\s+(.*)|\s*)$/;
  const indentOf = (ln) => ln.length - ln.replace(/^ +/, "").length;

  function yamlLoad(text) {
    return String(text).replace(/\r\n?/g, "\n").split(/^---[ \t]*$/m).filter((d) => d.trim()).map(parseBlock);
  }

  function parseBlock(text) {
    const raw = text.replace(/\t/g, "    ").split("\n");
    const lines = [];        // [indent, content, rawIndex]
    raw.forEach((ln, i) => { const s = stripComment(ln); if (s.trim()) lines.push([indentOf(ln), s.trim(), i]); });
    let pos = 0;

    function blockScalar(startIdx, style, parentIndent) {
      const buf = []; let j = startIdx + 1, ind = null;
      while (j < raw.length) {
        const ln = raw[j];
        if (ln.trim() === "") { buf.push(""); j++; continue; }
        const cur = indentOf(ln);
        if (cur <= parentIndent) break;
        if (ind == null) ind = cur;
        buf.push(ln.slice(ind)); j++;
      }
      while (pos < lines.length && lines[pos][2] < j) pos++;
      const txt = buf.join("\n").replace(/\n+$/, "");
      return style === "|" ? txt : txt.replace(/([^\n])\n(?!\n)/g, "$1 ");
    }
    function parse() {
      if (pos >= lines.length) return null;
      const [ind, content] = lines[pos];
      return content.startsWith("- ") || content === "-" ? parseList(ind) : parseMap(ind);
    }
    function valueAfter(rest, ind, lineno) {
      if (["|", ">", "|-", ">-", "|+", ">+"].includes(rest)) return blockScalar(lineno, rest[0], ind);
      if (rest == null || rest === "") {
        if (pos < lines.length && (lines[pos][0] > ind || (lines[pos][0] === ind && lines[pos][1].startsWith("-")))) return parse();
        return null;
      }
      return scalar(rest);
    }
    function parseMap(ind) {
      const m = obj();
      while (pos < lines.length) {
        const [cind, content, lineno] = lines[pos];
        if (cind < ind || content.startsWith("- ")) break;
        if (cind > ind) throw new YamlError(`unexpected indentation at line ${lineno + 1}`);
        const mk = RE_KEY.exec(content);
        if (!mk) throw new YamlError(`expected 'key: value' at line ${lineno + 1}: ${content.slice(0, 60)}`);
        pos++;
        m[String(scalar(mk[1]))] = valueAfter(mk[2], ind, lineno);
      }
      return m;
    }
    function parseList(ind) {
      const lst = [];
      while (pos < lines.length) {
        const [cind, content, lineno] = lines[pos];
        if (cind !== ind || !(content.startsWith("- ") || content === "-")) {
          if (cind > ind) throw new YamlError(`bad list indentation at line ${lineno + 1}`);
          break;
        }
        const item = content.slice(1).trim();
        pos++;
        if (!item) { lst.push(pos < lines.length && lines[pos][0] > ind ? parse() : null); continue; }
        const mk = "'\"[{".includes(item[0]) ? null : RE_KEY.exec(item);
        if (mk) {   // list of maps: first key inline, the rest indented to the key column
          const subInd = ind + (content.length - content.slice(1).replace(/^\s+/, "").length);
          const d = obj();
          d[String(scalar(mk[1]))] = valueAfter(mk[2], subInd, lineno);
          if (pos < lines.length && lines[pos][0] === subInd && !lines[pos][1].startsWith("- ")) Object.assign(d, parseMap(subInd));
          lst.push(d);
        } else lst.push(scalar(item));
      }
      return lst;
    }
    const res = lines.length ? parse() : obj();
    if (pos < lines.length) throw new YamlError(`could not parse line ${lines[pos][2] + 1}: ${lines[pos][1].slice(0, 60)}`);
    return res;
  }

  // ------------------------------------------------------------------ field mapping
  // Sigma field name → candidates in normalised events
  const ALIASES = {
    commandline: ["CommandLine", "process.command_line", "ProcessCommandLine", "ScriptBlockText"],
    image: ["Image", "NewProcessName", "process.executable"],
    parentimage: ["ParentImage", "ParentProcessName", "process.parent.executable"],
    parentcommandline: ["ParentCommandLine", "process.parent.command_line"],
    user: ["User", "SubjectUserName", "TargetUserName", "user.name"],
    eventid: ["EventID", "event.code", "winlog.event_id", "Id"],
    sourceip: ["IpAddress", "SourceIp", "SourceAddress", "source.ip", "c-ip"],
    "c-ip": ["c-ip", "IpAddress"],
    "c-uri": ["cs-uri"], "cs-uri-query": ["cs-uri"], "cs-uri-stem": ["cs-uri"], "c-uri-query": ["cs-uri"],
    "c-useragent": ["cs-user-agent"], "cs-useragent": ["cs-user-agent"], "cs-user-agent": ["cs-user-agent"],
    "sc-status": ["sc-status"], "cs-method": ["cs-method"],
    destinationhostname: ["DestinationHostname", "QueryName", "destination.domain"],
    queryname: ["QueryName", "dns.question.name"],
    targetfilename: ["TargetFilename", "file.path"],
    targetobject: ["TargetObject", "registry.path"],
  };

  function fieldValue(ev, name) {
    const get = L().get, low = String(name).toLowerCase(), f = ev.fields || {};
    if (low === "eventid" && ev.eid != null) return ev.eid;
    if (low === "eventname" && ev.fmt === "cloudtrail") return ev.eid;
    if (["ipaddress", "sourceip", "src_ip", "c-ip", "sourceipaddress"].includes(low) && ev.ip) {
      const v = get(f, name);
      return v != null ? v : ev.ip;
    }
    let v = get(f, name);
    if (v == null && ALIASES[low]) v = get(f, ...ALIASES[low]);
    if (v == null && ["user", "username", "targetusername"].includes(low) && ev.user) v = ev.user;
    if (v == null && (low === "message" || low === "msg")) v = ev.msg;
    // normalised-event attributes (Wakizashi extension: lets rules say `action: auth_fail` or `host: web01`)
    if (v == null && ["action", "host", "src", "fmt", "ip"].includes(low) && ev[low] != null) v = ev[low];
    return v;
  }

  // ------------------------------------------------------------------ value matching
  const pyStr = (v) => (typeof v === "string" ? v : v === true ? "True" : v === false ? "False" : v == null ? "None" : typeof v === "object" ? JSON.stringify(v) : String(v));

  const ANY = { w: "*" }, ONE = { w: "?" };
  function tokRe(toks, cased) {
    const dot = cased ? "." : "[\\s\\S]";
    const src = toks.map((t) => (t === ANY ? dot + "*" : t === ONE ? dot : reEsc(t))).join("");
    return new RegExp("^" + src + "$", cased ? "" : "i");
  }
  function wildToRe(pat, cased) {
    let out = "";
    for (let i = 0; i < pat.length; i++) {
      const c = pat[i];
      if (c === "\\" && i + 1 < pat.length && "*?\\".includes(pat[i + 1])) { out += reEsc(pat[i + 1]); i++; continue; }
      out += c === "*" ? "[\\s\\S]*" : c === "?" ? (cased ? "." : "[\\s\\S]") : reEsc(c);
    }
    if (cased) out = out.replace(/\[\\s\\S\]\*/g, ".*");
    return new RegExp("^" + out + "$", cased ? "" : "i");
  }

  function b64Variants(s, offset) {
    const b = W.bytes(String(s));
    if (!offset) return [W.b64(b)];
    const starts = [0, 2, 3], ends = [null, -3, -2];
    const out = [];
    for (let i = 0; i < 3; i++) {
      const pre = new Uint8Array(i + b.length); pre.fill(32, 0, i); pre.set(b, i);
      const enc = W.b64(pre), end = ends[(b.length + i) % 3];
      out.push(enc.slice(starts[i], end == null ? undefined : end));
    }
    return out;
  }

  /** Python-flavoured regex → JS RegExp (inline (?i)/(?s)/(?m) flags, \A \Z, (?P<n>…)). */
  function pyRegex(src, flags) {
    let s = String(src), f = new Set(flags);
    const m = /^\(\?([aiLmsux]+)\)/.exec(s);
    if (m) { for (const c of m[1]) if ("ims".includes(c)) f.add(c); s = s.slice(m[0].length); }
    s = s.replace(/\(\?P<([A-Za-z_]\w*)>/g, "(?<$1>").replace(/\(\?P=([A-Za-z_]\w*)\)/g, "\\k<$1>").replace(/\\A/g, "^").replace(/\\Z/g, "$");
    return new RegExp(s, [...f].join(""));
  }

  function compileMatcher(field, mods, values) {
    mods = mods.map((x) => x.toLowerCase());
    values = Array.isArray(values) ? values : [values];
    const all = mods.includes("all"), cased = mods.includes("cased");
    const tests = [];
    for (const v of values) tests.push(...compileValue(v, mods, cased));
    const one = (test, val) => {
      const [kind, t] = test;
      if (kind === "exists") return (val != null) === t;
      if (kind === "null") return val == null || val === "";
      if (val == null) return false;
      if (kind === "num") {
        const x = typeof val === "number" ? val : typeof val === "string" && val.trim() !== "" ? Number(val) : NaN;
        if (Number.isNaN(x)) return false;
        const [op, n] = t;
        return op === "gt" ? x > n : op === "gte" ? x >= n : op === "lt" ? x < n : x <= n;
      }
      if (kind === "cidr") return L().inCidr(String(val).replace(/^\[|\]$/g, ""), t);
      const sval = pyStr(val);
      if (kind === "re") return t.test(sval);
      if (kind === "eq") return (cased ? sval : sval.toLowerCase()) === t;
      return t.test(sval);
    };
    return (ev) => {
      const val = fieldValue(ev, field);
      const vals = Array.isArray(val) ? val : [val];
      const res = tests.map((t) => vals.some((v) => one(t, v)));
      return all ? res.every(Boolean) : res.some(Boolean);
    };
  }

  function compileValue(v, m, cased) {
    if (m.includes("exists")) return [["exists", !!v && v !== "false"]];
    if (v == null) return [["null", null]];
    if (["gt", "gte", "lt", "lte"].some((x) => m.includes(x))) {
      const op = ["gte", "lte", "gt", "lt"].find((x) => m.includes(x));
      const n = Number(v);
      if (typeof v === "boolean" || String(v).trim() === "" || Number.isNaN(n)) throw new Error(`could not convert '${pyStr(v)}' to a number`);
      return [["num", [op, n]]];
    }
    if (m.includes("cidr")) return [["cidr", L().parseCidr(String(v))]];
    if (m.includes("re")) return [["re", pyRegex(pyStr(v), (m.includes("i") ? "i" : "") + (m.includes("s") ? "s" : "") + (m.includes("m") ? "m" : ""))]];
    let vals = [pyStr(v)];
    if (m.includes("windash")) vals = [...new Set(vals.flatMap((s) => [s, s.replace(/-/g, "/"), s.replace(/-/g, "–"), s.replace(/-/g, "—"), s.replace(/-/g, "―")]))].sort();
    if (m.includes("base64") || m.includes("base64offset")) {
      const off = m.includes("base64offset");
      vals = vals.flatMap((s) => b64Variants(s, off));
      if (off) m = m.concat(["contains"]);
    }
    const out = [];
    for (const s of vals) {
      // Sigma escaping: \* \? \\ are literals, a lone backslash is a literal backslash, * and ? are wildcards.
      const toks = [];
      for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c === "\\" && i + 1 < s.length && "*?\\".includes(s[i + 1])) { toks.push(s[++i]); continue; }
        toks.push(c === "*" ? ANY : c === "?" ? ONE : c);
      }
      if (m.includes("contains")) { toks.unshift(ANY); toks.push(ANY); }
      else if (m.includes("startswith")) toks.push(ANY);
      else if (m.includes("endswith")) toks.unshift(ANY);
      if (!toks.some((t) => t === ANY || t === ONE)) { const plain = toks.join(""); out.push(["eq", cased ? plain : plain.toLowerCase()]); }
      else out.push(["wild", tokRe(toks, cased)]);
    }
    return out;
  }

  function keywords(values) {
    const vals = values.map((v) => pyStr(v).toLowerCase());
    const rx = vals.map((v) => (v.includes("*") || v.includes("?") ? wildToRe("*" + v + "*") : null));
    return (ev) => {
      const f = ev.fields || {};
      const hay = ((ev.msg || "") + " " + Object.keys(f).map((k) => pyStr(f[k])).join(" ")).toLowerCase();
      return vals.some((v, i) => (rx[i] ? rx[i].test(hay) : hay.includes(v)));
    };
  }

  function compileItem(node) {
    if (Array.isArray(node)) {
      if (node.every((x) => !(x && typeof x === "object"))) return keywords(node);
      const subs = node.map(compileItem);
      return (ev) => subs.some((s) => s(ev));
    }
    if (isMap(node)) {
      const ms = [];
      for (const key of Object.keys(node)) {
        const val = node[key];
        const parts = String(key).split("|");
        const field = parts[0], mods = parts.slice(1);
        if (!field) { ms.push(keywords(Array.isArray(val) ? val : [val])); continue; }
        ms.push(compileMatcher(field, mods, val));
      }
      return (ev) => ms.every((m) => m(ev));
    }
    if (typeof node === "string") return keywords([node]);
    throw new Error("unsupported detection item");
  }

  // ------------------------------------------------------------------ conditions
  const TOK = /\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|\bany of\b|[A-Za-z0-9_*.-]+)/iy;
  const globRe = (pat) => new RegExp("^" + String(pat).replace(/[.+^${}()|\\/-]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");

  function compileCondition(cond, items) {
    if (cond.includes("|")) throw new Error("aggregation conditions (| count() …) are not supported");
    cond = cond.trim();
    const toks = [];
    let pos = 0;
    while (pos < cond.length) {
      TOK.lastIndex = pos;
      const m = TOK.exec(cond);
      if (!m) throw new Error(`bad condition near: ${cond.slice(pos, pos + 20)}`);
      toks.push(m[1]);
      pos = TOK.lastIndex;
      while (pos < cond.length && /\s/.test(cond[pos])) pos++;
    }
    let i = 0;
    const has = (k) => Object.prototype.hasOwnProperty.call(items, k);
    const peek = () => (i < toks.length ? toks[i].toLowerCase() : null);
    const take = () => toks[i++];
    const names = (pat) => {
      if (pat == null) throw new Error("unexpected end of condition");
      if (pat.toLowerCase() === "them") return Object.keys(items).filter((k) => !k.startsWith("_"));
      const re = globRe(pat), got = Object.keys(items).filter((k) => re.test(k));
      if (!got.length) throw new Error(`condition references unknown item '${pat}'`);
      return got;
    };
    function atom() {
      const t = peek();
      if (t == null) throw new Error("unexpected end of condition");
      if (t === "(") {
        take(); const e = expr();
        if (peek() !== ")") throw new Error("missing ')'");
        take(); return e;
      }
      if (t === "not") { take(); const a = atom(); return (ev) => !a(ev); }
      if (t === "1 of" || t === "any of" || t === "all of") {
        take();
        const grp = names(take()).map((n) => items[n]);
        return t === "all of" ? (ev) => grp.every((g) => g(ev)) : (ev) => grp.some((g) => g(ev));
      }
      const name = take();
      if (!has(name)) throw new Error(`condition references unknown item '${name}'`);
      return items[name];
    }
    function conj() {
      let left = atom();
      while (peek() === "and") { take(); const a = left, b = atom(); left = (ev) => a(ev) && b(ev); }
      return left;
    }
    function expr() {
      let left = conj();
      while (peek() === "or") { take(); const a = left, b = conj(); left = (ev) => a(ev) || b(ev); }
      return left;
    }
    const fn = expr();
    if (i !== toks.length) throw new Error(`unexpected token '${toks[i]}' in condition`);
    return fn;
  }

  // ------------------------------------------------------------------ rules
  const LOGSOURCE_FMT = {
    windows: ["windows", "json", "csv"], linux: ["syslog", "text", "json"], aws: ["cloudtrail"],
    webserver: ["web", "json"], proxy: ["web", "json"],
  };
  const LEVELS = ["informational", "low", "medium", "high", "critical"];

  function makeRule(doc, text) {
    if (!isMap(doc)) throw new Error("rule is not a mapping");
    const title = String(doc.title || "untitled");
    let level = String(doc.level || "medium").toLowerCase();
    if (!LEVELS.includes(level)) level = "medium";
    const tg = doc.tags || [];
    const tags = Array.isArray(tg) ? tg.map(pyStr) : [pyStr(tg)];
    const attack = [...new Set(tags.filter((t) => /^attack\.t\d{4}(\.\d{3})?$/i.test(t)).map((t) => t.split(".").slice(1).join(".").toUpperCase()))].sort();
    const logsource = isMap(doc.logsource) ? doc.logsource : {};
    const det = doc.detection;
    if (!isMap(det) || !("condition" in det)) throw new Error("rule needs detection: with a condition");
    let cond = det.condition;
    if (Array.isArray(cond)) cond = cond.map((c) => `(${pyStr(c)})`).join(" or ");
    const items = obj();
    for (const k of Object.keys(det)) if (k !== "condition" && k !== "timeframe") items[k] = compileItem(det[k]);
    const match = compileCondition(pyStr(cond), items);
    let fmts = null;
    for (const k of ["product", "category", "service"]) {
      const v = String(logsource[k] == null ? "" : logsource[k]).toLowerCase();
      if (LOGSOURCE_FMT[v]) { fmts = new Set(LOGSOURCE_FMT[v]); break; }
    }
    const rule = {
      id: String(doc.id || title), title, level, tags, attack, logsource, doc, text: text || "", fmts, match,
      applies: (ev) => fmts == null || fmts.has(ev.fmt),
      meta: () => ({ id: rule.id, title, level, attack, tags, logsource, description: doc.description || "", falsepositives: doc.falsepositives || [] }),
    };
    return rule;
  }

  /** Parse one or more Sigma rules (YAML documents) → {rules, errors}. */
  function compile(text) {
    const rules = [], errors = [];
    let docs;
    try { docs = yamlLoad(text || ""); } catch (e) { return { rules: [], errors: [e.message] }; }
    docs.forEach((d, n) => {
      try { rules.push(makeRule(d, text)); }
      catch (e) {
        const title = isMap(d) ? d.title : null;
        errors.push(`rule ${n + 1}${title ? " (" + title + ")" : ""}: ${e.message}`);
      }
    });
    return { rules, errors };
  }

  function run(rules, events) {
    const out = [];
    for (const r of rules || []) {
      const hits = [];
      for (const e of events || []) if (r.applies(e) && r.match(e)) hits.push(e.i);
      if (hits.length) out.push({ rule: r.id, name: r.title, severity: r.level === "informational" ? "info" : r.level, attack: r.attack,
        title: `Sigma: ${r.title}`, detail: String(r.doc.description || "").slice(0, 400), events: hits.slice(0, 300), count: hits.length, entities: {}, sigma: true });
    }
    return out;
  }

  // ------------------------------------------------------------------ bundled rules (written for Yoroi)
  const D = "${";
  const BUILTIN = String.raw`
title: Suspicious PowerShell download cradle
id: yoroi-sig-0001
status: stable
description: PowerShell fetching and executing remote content in one command line.
tags: [attack.execution, attack.t1059.001, attack.t1105]
logsource: {product: windows, category: process_creation}
detection:
    selection_img:
        Image|endswith: ['\powershell.exe', '\pwsh.exe']
    selection_cmd:
        CommandLine|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
    exec:
        CommandLine|contains: ['IEX', 'Invoke-Expression', '| iex', '|iex']
    condition: selection_img and selection_cmd and exec
falsepositives: [Admin scripts that bootstrap tooling]
level: high
---
title: Windows Security log cleared
id: yoroi-sig-0002
description: The Security event log was cleared (event 1102).
tags: [attack.defense_evasion, attack.t1070.001]
logsource: {product: windows, service: security}
detection:
    selection:
        EventID: 1102
    condition: selection
level: high
---
title: Shadow copy deletion
id: yoroi-sig-0003
description: Volume shadow copies deleted via vssadmin, wmic or PowerShell - common ransomware step.
tags: [attack.impact, attack.t1490]
logsource: {product: windows, category: process_creation}
detection:
    vss:
        CommandLine|contains|all: ['vssadmin', 'delete', 'shadows']
    wmic:
        CommandLine|contains|all: ['shadowcopy', 'delete']
    ps:
        CommandLine|contains|all: ['Win32_ShadowCopy', 'Delete']
    condition: vss or wmic or ps
level: critical
---
title: New service installed from user-writable path
id: yoroi-sig-0004
description: A service (7045) whose binary lives in Temp, Users\Public or ProgramData, or launches a script host.
tags: [attack.persistence, attack.t1543.003]
logsource: {product: windows, service: system}
detection:
    selection:
        EventID: 7045
    sus:
        ImagePath|contains: ['\Temp\', '\Users\Public\', '\ProgramData\', 'powershell', 'cmd.exe /c', 'mshta', 'rundll32']
    condition: selection and sus
level: high
---
title: SSH logon as root
id: yoroi-sig-0005
description: Successful SSH logon directly as root.
tags: [attack.initial_access, attack.t1078.003]
logsource: {product: linux, service: sshd}
detection:
    keywords:
        - 'Accepted password for root'
        - 'Accepted publickey for root'
    condition: keywords
level: medium
---
title: Reverse shell one-liner
id: yoroi-sig-0006
description: Common Linux reverse shell patterns in command lines or logs.
tags: [attack.execution, attack.t1059.004]
logsource: {product: linux}
detection:
    keywords:
        - '/dev/tcp/'
        - 'nc -e /bin/sh'
        - 'ncat -e /bin/bash'
        - 'socat exec:'
        - 'pty.spawn("/bin/sh")'
        - "pty.spawn('/bin/bash')"
    condition: keywords
level: high
---
title: Log4Shell exploitation attempt
id: yoroi-sig-0007
description: JNDI lookup strings in web requests (CVE-2021-44228).
tags: [attack.initial_access, attack.t1190]
logsource: {category: webserver}
detection:
    keywords:
        - '${D}jndi:'
        - '%24%7Bjndi'
        - '${D}${D}lower:j}ndi'
        - '${D}${D}::-j}'
    condition: keywords
level: critical
---
title: LSASS dump via comsvcs MiniDump
id: yoroi-sig-0008
description: rundll32 calling comsvcs.dll MiniDump to dump LSASS memory.
tags: [attack.credential_access, attack.t1003.001]
logsource: {product: windows, category: process_creation}
detection:
    selection:
        CommandLine|contains: 'comsvcs'
        CommandLine|contains|all: ['rundll32']
    dump:
        CommandLine|contains: ['MiniDump', '#24', '#+24']
    condition: selection and dump
level: critical
---
title: AWS CloudTrail logging disabled
id: yoroi-sig-0009
description: StopLogging / DeleteTrail called.
tags: [attack.defense_evasion, attack.t1562.008]
logsource: {product: aws, service: cloudtrail}
detection:
    selection:
        eventSource: cloudtrail.amazonaws.com
        eventName: [StopLogging, DeleteTrail]
    condition: selection
level: high
---
title: Remote access tool executed
id: yoroi-sig-0010
description: Execution of common remote-management tools frequently abused for hands-on-keyboard access.
tags: [attack.command_and_control, attack.t1219]
logsource: {product: windows, category: process_creation}
detection:
    selection:
        Image|endswith:
            - '\AnyDesk.exe'
            - '\TeamViewer.exe'
            - '\ScreenConnect.ClientService.exe'
            - '\rustdesk.exe'
            - '\AteraAgent.exe'
            - '\ngrok.exe'
            - '\plink.exe'
    condition: selection
falsepositives: [Sanctioned IT remote support]
level: medium
---
title: Certutil used to download a file
id: yoroi-sig-0011
description: certutil.exe with -urlcache or -split and a URL - a classic living-off-the-land download.
tags: [attack.command_and_control, attack.t1105]
logsource: {product: windows, category: process_creation}
detection:
    img:
        Image|endswith: '\certutil.exe'
    flags:
        CommandLine|contains|windash: ['-urlcache', '-split', '-verifyctl']
    url:
        CommandLine|contains: ['http://', 'https://']
    condition: img and flags and url
level: high
---
title: Offensive web scanner user agent
id: yoroi-sig-0012
description: Requests from well-known vulnerability scanners and injection tools.
tags: [attack.reconnaissance, attack.t1595.002]
logsource: {category: webserver}
detection:
    ua:
        cs-user-agent|contains: ['sqlmap', 'nikto', 'nuclei', 'wpscan', 'masscan', 'zgrab', 'gobuster', 'feroxbuster', 'acunetix']
    condition: ua
falsepositives: [Your own authorised scans]
level: medium
`;

  let _builtin = null;
  function builtinRules() {
    if (_builtin) return _builtin;
    const { rules, errors } = compile(BUILTIN);
    if (errors.length) throw new Error("bundled Sigma rules failed to compile: " + errors.join("; "));
    return (_builtin = rules);
  }

  W.eng.sigma = { compile, run, fieldValue, yamlLoad, builtinRules, BUILTIN: BUILTIN.trim(), ALIASES, LOGSOURCE_FMT };
})(typeof window !== "undefined" ? window.W : globalThis.W);
