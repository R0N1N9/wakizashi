/* YARA-lite — a pure-JS subset of the YARA rule language (port of Katana's defense/yaralite.py).
 *
 *   W.eng.yara.compile(text)        → {rules, errors}
 *   W.eng.yara.scan(rules, bytes)   → [{rule, tags, meta, strings:[{id, count, first, preview}]}] | [{rule, error}]
 *   W.eng.yara.BUILTIN              bundled rule text
 *   W.eng.yara.builtin()            compiled bundled rules (cached)
 *
 * Supported
 *   [private|global] rule NAME [: tags] { meta: … strings: … condition: … }
 *   text strings "…" with nocase, wide, ascii, fullword, private, xor / xor(N) / xor(A-B), base64, base64wide
 *   hex strings  { 4D 5A ?? 9? ?A ~00 [2-4] [-] ( 6A | 6B ) }
 *   regex        /…/is  (matched against a latin-1 view of the bytes; wide regex is ascii-only)
 *   condition    and / or / not, ( ), $a, #a, @a, @a[i], $a at N, $a in (X..Y), any/all/none/N of them,
 *                any/all/none/N of ($a*, $b), filesize (KB/MB), [u]int8/16/32[be](off), comparisons,
 *                + - * \ %, true/false, references to rules defined earlier in the same text (private rules!).
 *   global rules gate every other rule (a failing global rule → no matches).
 * Modules (import "pe" …), entrypoint, for-loops and !len are reported as unsupported.
 * Everything works on bytes; nothing is evaluated as code.
 */
(function (W) {
  "use strict";

  const MAX_HITS = 10000;     // per string pattern, like yaralite
  let ruleSeq = 0;

  // ------------------------------------------------------------------ helpers
  const hx = (b) => "\\x" + (b & 255).toString(16).padStart(2, "0");
  const isAlpha = (b) => (b >= 65 && b <= 90) || (b >= 97 && b <= 122);
  /** bytes → regex source matching exactly those bytes in a latin-1 string (optionally ASCII case-insensitive). */
  function bytesRe(bytes, nocase) {
    let s = "";
    for (const b of bytes) {
      if (nocase && isAlpha(b)) s += "[" + String.fromCharCode(b | 0x20) + String.fromCharCode(b & ~0x20) + "]";
      else if ((b >= 48 && b <= 57) || isAlpha(b)) s += String.fromCharCode(b);
      else s += hx(b);
    }
    return s;
  }
  const utf8 = (s) => W.bytes(String(s));

  /** YARA/yaralite string escapes: \n \t \r \\ \" \0 \xHH; anything else = the next char. Input is text, output UTF-8 bytes. */
  function unescape(s) {
    const b = utf8(s), out = [];
    for (let i = 0; i < b.length; i++) {
      const c = b[i];
      if (c === 0x5c && i + 1 < b.length) {
        const n = String.fromCharCode(b[i + 1]);
        if (n === "x" && i + 3 < b.length) {
          const h = String.fromCharCode(b[i + 2], b[i + 3]);
          if (!/^[0-9a-fA-F]{2}$/.test(h)) throw new Error(`bad \\x escape '\\x${h}'`);
          out.push(parseInt(h, 16)); i += 3; continue;
        }
        out.push({ n: 10, t: 9, r: 13, "\\": 92, '"': 34, "0": 0 }[n] ?? b[i + 1]); i++; continue;
      }
      out.push(c);
    }
    return Uint8Array.from(out);
  }

  /** Mirrors Python's bytes.decode("latin-1").encode("unicode_escape") for previews. */
  function preview(bytes) {
    let s = "";
    for (const b of bytes) {
      if (b === 92) s += "\\\\";
      else if (b === 10) s += "\\n"; else if (b === 13) s += "\\r"; else if (b === 9) s += "\\t";
      else if (b >= 32 && b < 127) s += String.fromCharCode(b);
      else s += hx(b);
    }
    return s.slice(0, 120);
  }

  /** Python-compatible base64 of a latin-1/bytes array. */
  const b64 = (bytes) => W.b64(bytes);

  // ------------------------------------------------------------------ matchers
  // A matcher has find(ctx) → sorted offsets (non-overlapping per pattern, like Python's finditer).
  function reMatcher(src, flags) {
    const re = new RegExp(src, "g" + (flags || ""));
    return {
      kind: "re", src,
      find(ctx) {
        const s = ctx.str(), o = [];
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(s))) {
          o.push(m.index);
          if (m[0].length === 0) re.lastIndex++;
          if (o.length > MAX_HITS) break;
        }
        return o;
      },
    };
  }
  /** Single-byte XOR search over every key in [lo, hi] — one pass instead of 256 regexes. */
  function xorMatcher(lit, lo, hi, fullword) {
    return {
      kind: "xor",
      find(ctx) {
        const d = ctx.data, n = lit.length, o = [];
        if (!n) return o;
        let i = 0;
        while (i + n <= d.length) {
          const k = d[i] ^ lit[0];
          let ok = k >= lo && k <= hi;
          for (let j = 1; ok && j < n; j++) if ((d[i + j] ^ lit[j]) !== k) ok = false;
          if (ok && fullword) {
            const isW = (x) => (x >= 48 && x <= 57) || isAlpha(x);
            if ((i > 0 && isW(d[i - 1] ^ k)) || (i + n < d.length && isW(d[i + n] ^ k))) ok = false;
          }
          if (ok) { o.push(i); if (o.length > MAX_HITS) break; i += n; } else i++;
        }
        return o;
      },
    };
  }

  function wideOf(bytes) { const o = new Uint8Array(bytes.length * 2); bytes.forEach((c, i) => (o[i * 2] = c)); return o; }

  function parseXorRange(arg) {
    if (!arg) return [0, 255];
    const inner = arg.slice(1, -1).trim();
    const num = (t) => { t = t.trim(); const v = /^0x[0-9a-f]+$/i.test(t) ? parseInt(t, 16) : /^\d+$/.test(t) ? +t : NaN; if (!(v >= 0 && v <= 255)) throw new Error(`bad xor range '${arg}'`); return v; };
    const m = inner.split("-");
    if (m.length === 1) { const v = num(m[0]); return [v, v]; }
    if (m.length === 2) { const a = num(m[0]), b = num(m[1]); if (a > b) throw new Error(`bad xor range '${arg}'`); return [a, b]; }
    throw new Error(`bad xor range '${arg}'`);
  }

  /** Text string → matchers (port of _text_patterns). */
  function textMatchers(lit, mods) {
    const nocase = mods.has("nocase"), fullword = mods.has("fullword");
    if (mods.has("base64") || mods.has("base64wide")) {
      // same three-alignment trick yaralite uses
      const starts = [0, 2, 3], ends = [null, -3, -2], out = [];
      for (let i = 0; i < 3; i++) {
        const pad = new Uint8Array(i + lit.length); pad.fill(32, 0, i); pad.set(lit, i);
        const full = b64(pad);
        const e = ends[(lit.length + i) % 3];
        const enc = full.slice(starts[i], e == null ? undefined : full.length + e);
        if (!enc) continue;
        const eb = utf8(enc);
        if (mods.has("base64")) out.push(eb);
        if (mods.has("base64wide")) out.push(wideOf(eb));
      }
      return out.filter((v) => v.length).map((v) => reMatcher(bytesRe(v, false), "s"));
    }
    const variants = [];
    if (mods.has("ascii") || !mods.has("wide")) variants.push(lit);
    if (mods.has("wide")) variants.push(wideOf(lit));
    if (mods.has("xor")) {
      const [lo, hi] = parseXorRange(mods.get("xor"));
      return variants.map((v) => xorMatcher(v, lo, hi, fullword));
    }
    return variants.map((v) => {
      let p = bytesRe(v, nocase);
      if (fullword) p = "(?<![A-Za-z0-9])" + p + "(?![A-Za-z0-9])";
      return reMatcher(p, "s");
    });
  }

  /** Hex string body → regex source (port of _hex_to_regex, with strict leftovers check). */
  function hexToRegex(body) {
    body = body.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, "");
    const TOK = /[0-9A-Fa-f?]{2}|\[\s*\d*\s*(?:-\s*\d*\s*)?\]|[()|~]/g;
    const left = body.replace(TOK, "").replace(/\s+/g, "");
    if (left) throw new Error(`bad hex string near '${left.slice(0, 12)}'`);
    const toks = body.match(TOK) || [];
    let rx = "", depth = 0, bytes = 0;
    for (let i = 0; i < toks.length; i++) {
      let t = toks[i];
      if (t === "~") {
        const t2 = toks[++i];
        if (!t2 || !/^[0-9A-Fa-f]{2}$/.test(t2)) throw new Error("bad ~ (not) in hex string");
        rx += "[^" + hx(parseInt(t2, 16)) + "]"; bytes++;
      } else if (t[0] === "[") {
        const inner = t.slice(1, -1).replace(/\s+/g, "");
        if (inner.includes("-")) {
          const [lo, hi] = inner.split("-");
          if (hi && lo && +lo > +hi) throw new Error(`bad jump [${inner}]`);
          rx += "[\\s\\S]{" + (lo || "0") + "," + (hi || "") + "}";
        } else {
          if (!inner) throw new Error("empty jump []");
          rx += "[\\s\\S]{" + inner + "}";
        }
      } else if (t === "(") { rx += "(?:"; depth++; }
      else if (t === ")") { rx += ")"; depth--; if (depth < 0) throw new Error("unbalanced ) in hex string"); }
      else if (t === "|") rx += "|";
      else if (t === "??") { rx += "[\\s\\S]"; bytes++; }
      else if (t.includes("?")) {
        if (t[0] === "?") {
          const lo = parseInt(t[1], 16); let c = "";
          for (let h = 0; h < 16; h++) c += hx(h * 16 + lo);
          rx += "[" + c + "]";
        } else {
          const hi = parseInt(t[0], 16);
          rx += "[" + hx(hi * 16) + "-" + hx(hi * 16 + 15) + "]";
        }
        bytes++;
      } else { rx += hx(parseInt(t, 16)); bytes++; }
    }
    if (depth) throw new Error("unbalanced ( in hex string");
    if (!rx || !bytes) throw new Error("empty hex string");
    return rx;
  }

  // ------------------------------------------------------------------ source scanner
  /** Returns {masked, struct}: masked = comments blanked; struct = also blanks string/regex/hex contents
   *  (so braces, keywords and 'rule' inside literals can't confuse the structural parse). Same length as input. */
  function scanSource(text) {
    const n = text.length;
    const m = text.split(""), s = text.split("");
    const blank = (arr, a, b) => { for (let k = a; k < b; k++) if (arr[k] !== "\n") arr[k] = " "; };
    const fill = (a, b) => { for (let k = a; k < b; k++) if (s[k] !== "\n") s[k] = "_"; };
    let i = 0, prev = "";            // prev = last significant char outside literals
    while (i < n) {
      const c = text[i], d = text[i + 1];
      if (c === "/" && d === "/") { let j = text.indexOf("\n", i); if (j < 0) j = n; blank(m, i, j); blank(s, i, j); i = j; continue; }
      if (c === "/" && d === "*") { let j = text.indexOf("*/", i + 2); j = j < 0 ? n : j + 2; blank(m, i, j); blank(s, i, j); i = j; continue; }
      if (c === '"') {
        let j = i + 1; while (j < n && text[j] !== '"' && text[j] !== "\n") j += text[j] === "\\" ? 2 : 1;
        fill(i + 1, Math.min(j, n)); i = j + 1; prev = '"'; continue;
      }
      if (c === "/" && prev === "=") {           // regex literal:  $r = /…/
        let j = i + 1; while (j < n && text[j] !== "/" && text[j] !== "\n") j += text[j] === "\\" ? 2 : 1;
        fill(i + 1, Math.min(j, n)); i = j + 1; prev = "/"; continue;
      }
      if (c === "{" && prev === "=") {           // hex string:  $h = { … }  (may hold comments)
        let j = i + 1;
        while (j < n && text[j] !== "}") {
          if (text[j] === "/" && text[j + 1] === "/") { let e = text.indexOf("\n", j); if (e < 0) e = n; blank(m, j, e); j = e; continue; }
          if (text[j] === "/" && text[j + 1] === "*") { let e = text.indexOf("*/", j + 2); e = e < 0 ? n : e + 2; blank(m, j, e); j = e; continue; }
          j++;
        }
        fill(i + 1, Math.min(j, n)); i = j + 1; prev = "}"; continue;
      }
      if (!/\s/.test(c)) prev = c;
      i++;
    }
    return { masked: m.join(""), struct: s.join("") };
  }

  function blockEnd(struct, start) {
    let depth = 0;
    for (let i = start; i < struct.length; i++) {
      if (struct[i] === "{") depth++;
      else if (struct[i] === "}") { depth--; if (depth === 0) return i; }
    }
    return -1;
  }

  // ------------------------------------------------------------------ condition lexer + parser
  const TOKEN = /(\s+)|("(?:\\.|[^"\\])*")|(0x[0-9a-fA-F]+)|(\d+(?:KB|MB)?)|([$#@!][A-Za-z0-9_]*\*?)|([A-Za-z_][A-Za-z0-9_.]*)|(\.\.|==|!=|<=|>=|<<|>>|[<>(){}[\]:,=+\-*\\|&^~%])/y;
  const KIND = [null, "ws", "str", "hex", "num", "var", "id", "op"];
  function lex(src, rname) {
    const toks = []; TOKEN.lastIndex = 0; let i = 0;
    while (i < src.length) {
      TOKEN.lastIndex = i;
      const m = TOKEN.exec(src);
      if (!m) throw new Error(`rule ${rname}: unsupported characters in condition near '${src.slice(i, i + 12)}'`);
      const g = m.findIndex((x, k) => k > 0 && x !== undefined);
      if (KIND[g] !== "ws") toks.push([KIND[g], m[0]]);
      i = TOKEN.lastIndex;
    }
    return toks;
  }

  function offsets(ctx, rule, name) {
    const key = rule.uid + "\0" + name;
    let o = ctx.cache.get(key);
    if (!o) {
      const all = [];
      for (const p of (rule.strings.get(name) || {}).matchers || []) { for (const x of p.find(ctx)) all.push(x); if (all.length > MAX_HITS) break; }
      o = [...new Set(all)].sort((a, b) => a - b);
      ctx.cache.set(key, o);
    }
    return o;
  }

  function evalRule(rule, ctx) {
    const k = "\0rule\0" + rule.uid;
    if (ctx.cache.has(k)) return ctx.cache.get(k);
    ctx.cache.set(k, false);                            // guard against accidental recursion
    const v = !!rule.cond(ctx);
    ctx.cache.set(k, v);
    return v;
  }

  class CondParser {
    constructor(src, rule, known) {
      this.rule = rule; this.known = known; this.i = 0;
      this.toks = lex(src, rule.name);
      if (!this.toks.length) throw new Error(`rule ${rule.name}: empty condition`);
    }
    err(msg) { return new Error(`rule ${this.rule.name}: ${msg}`); }
    peek(k = 0) { return this.toks[this.i + k] || [null, null]; }
    take(val) { const t = this.peek(); if (val != null && t[1] !== val) throw this.err(`expected '${val}' got '${t[1] == null ? "end of condition" : t[1]}'`); this.i++; return t; }
    parse() { const e = this.or_(); if (this.i !== this.toks.length) throw this.err(`unexpected '${this.peek()[1]}' in condition`); return e; }
    or_() { let l = this.and_(); while (this.peek()[1] === "or") { this.take(); const a = l, b = this.and_(); l = (c) => a(c) || b(c); } return l; }
    and_() { let l = this.not_(); while (this.peek()[1] === "and") { this.take(); const a = l, b = this.not_(); l = (c) => a(c) && b(c); } return l; }
    not_() { if (this.peek()[1] === "not") { this.take(); const a = this.not_(); return (c) => !a(c); } return this.cmp(); }
    cmp() {
      const l = this.add(), op = this.peek()[1];
      const F = { "==": (a, b) => a === b, "!=": (a, b) => a !== b, "<": (a, b) => a < b, ">": (a, b) => a > b, "<=": (a, b) => a <= b, ">=": (a, b) => a >= b };
      if (F[op]) { this.take(); const r = this.add(), f = F[op]; return (c) => f(l(c), r(c)); }
      return l;
    }
    add() {
      let l = this.mul();
      while (["+", "-"].includes(this.peek()[1])) { const op = this.take()[1], a = l, b = this.mul(); l = op === "+" ? (c) => a(c) + b(c) : (c) => a(c) - b(c); }
      return l;
    }
    mul() {
      let l = this.unary();
      while (["*", "\\", "%"].includes(this.peek()[1])) {
        const op = this.take()[1], a = l, b = this.unary();
        l = op === "*" ? (c) => a(c) * b(c) : op === "\\" ? (c) => { const y = b(c); return y ? Math.trunc(a(c) / y) : 0; } : (c) => { const y = b(c); return y ? a(c) % y : 0; };
      }
      return l;
    }
    set() {
      const names = [...this.rule.strings.keys()];
      if (this.peek()[1] === "them") { this.take(); return names; }
      this.take("(");
      const out = [];
      for (;;) {
        const [k, v] = this.take();
        if (k !== "var" || v[0] !== "$") throw this.err("bad string set");
        if (v.endsWith("*")) { const pre = v.slice(0, -1); const hit = names.filter((n) => n.startsWith(pre)); if (!hit.length) throw this.err(`no strings match ${v}`); out.push(...hit); }
        else out.push(v);
        if (this.peek()[1] === ",") { this.take(); continue; }
        this.take(")");
        return out;
      }
    }
    unary() {
      const [k, v] = this.peek(), rule = this.rule;
      if (v === "(") { this.take(); const e = this.or_(); this.take(")"); return e; }
      if (v === "-") { this.take(); const a = this.unary(); return (c) => -a(c); }
      if ((k === "id" && ["any", "all", "none"].includes(v)) || (k === "num" && this.peek(1)[1] === "of")) {
        this.take(); this.take("of");
        const names = this.set();
        for (const n of names) if (!rule.strings.has(n)) throw this.err(`undefined string ${n}`);
        const has = (c, n) => offsets(c, rule, n).length > 0;
        if (v === "all") return (c) => names.every((n) => has(c, n));
        if (v === "any") return (c) => names.some((n) => has(c, n));
        if (v === "none") return (c) => !names.some((n) => has(c, n));
        const need = parseInt(v, 10);
        return (c) => names.filter((n) => has(c, n)).length >= need;
      }
      if (k === "num") { this.take(); const n = /KB$/.test(v) ? parseInt(v, 10) * 1024 : /MB$/.test(v) ? parseInt(v, 10) * 1048576 : parseInt(v, 10); return () => n; }
      if (k === "hex") { this.take(); const n = parseInt(v, 16); return () => n; }
      if (k === "str") { this.take(); const s = W.latin1(unescape(v.slice(1, -1))); return () => s; }
      if (k === "var") {
        this.take();
        if (v.endsWith("*")) throw this.err(`wildcard ${v} only allowed in 'of' sets`);
        const name = "$" + v.slice(1);
        if ("#@!".includes(v[0]) && name === "$") throw this.err("anonymous count/offset not supported");
        if (!rule.strings.has(name)) throw this.err(`undefined string ${name}`);
        if (v[0] === "#") {
          if (this.peek()[1] === "in") throw this.err("#x in (range) not supported");
          return (c) => offsets(c, rule, name).length;
        }
        if (v[0] === "@") {
          let idx = () => 1;
          if (this.peek()[1] === "[") { this.take(); idx = this.add(); this.take("]"); }
          return (c) => { const o = offsets(c, rule, name), i = idx(c); return i >= 1 && o.length >= i ? o[i - 1] : -1; };
        }
        if (v[0] === "!") throw this.err("match length (!) not supported");
        if (this.peek()[1] === "at") { this.take(); const pos = this.add(); return (c) => offsets(c, rule, name).includes(pos(c)); }
        if (this.peek()[1] === "in") {
          this.take(); this.take("("); const lo = this.add(); this.take(".."); const hi = this.add(); this.take(")");
          return (c) => { const a = lo(c), b = hi(c); return offsets(c, rule, name).some((o) => o >= a && o <= b); };
        }
        return (c) => offsets(c, rule, name).length > 0;
      }
      if (k === "id") {
        this.take();
        if (v === "true") return () => true;
        if (v === "false") return () => false;
        if (v === "filesize") return (c) => c.data.length;
        const m = /^(u?)int(8|16|32)(be)?$/.exec(v);
        if (m) {
          const size = +m[2] / 8, signed = !m[1], be = !!m[3];
          this.take("("); const off = this.add(); this.take(")");
          return (c) => {
            const o = off(c), d = c.data;
            if (!(o >= 0) || o + size > d.length) return -1;
            let n = 0;
            for (let j = 0; j < size; j++) n = n * 256 + d[be ? o + j : o + size - 1 - j];
            if (signed && n >= 2 ** (size * 8 - 1)) n -= 2 ** (size * 8);
            return n;
          };
        }
        if (v === "for") throw this.err("for-loops are not supported in YARA-lite");
        if (v === "entrypoint" || v.includes(".")) throw this.err(`'${v}' needs a YARA module (not supported in YARA-lite)`);
        if (this.known.has(v)) { const ref = this.known.get(v); return (c) => evalRule(ref, c); }
        throw this.err(`unknown identifier '${v}' (rules must be defined before they are referenced)`);
      }
      throw this.err(`unexpected token '${v == null ? "end of condition" : v}'`);
    }
  }

  // ------------------------------------------------------------------ rule
  const MODS = /[ \t]*(nocase|wide|ascii|fullword|private|xor|base64wide|base64)(\([^)]*\))?/y;
  function readMods(s, i) {
    const mods = new Map();
    for (;;) {
      MODS.lastIndex = i;
      const m = MODS.exec(s);
      if (!m) return [mods, i];
      // require a word boundary after the modifier
      if (/[A-Za-z0-9_]/.test(s[MODS.lastIndex] || "")) return [mods, i];
      mods.set(m[1], m[2] || ""); i = MODS.lastIndex;
    }
  }

  function parseStrings(rule, s) {
    let i = 0, anon = 0;
    const DEF = /\s*(\$[A-Za-z0-9_]*)\s*=\s*/y;
    while (i < s.length) {
      if (!s.slice(i).trim()) break;
      DEF.lastIndex = i;
      const m = DEF.exec(s);
      if (!m) throw new Error(`rule ${rule.name}: cannot parse strings near '${s.slice(i, i + 30).trim()}'`);
      let name = m[1];
      if (name === "$") name = `$_anon${++anon}`;
      if (rule.strings.has(name)) throw new Error(`rule ${rule.name}: duplicate string ${name}`);
      i = DEF.lastIndex;
      const c = s[i];
      let matchers, mods, kind;
      if (c === '"') {
        const mm = /"((?:\\.|[^"\\\n])*)"/y; mm.lastIndex = i;
        const r = mm.exec(s);
        if (!r) throw new Error(`rule ${rule.name}: unterminated string ${name}`);
        const lit = unescape(r[1]); i = mm.lastIndex;
        if (!lit.length) throw new Error(`rule ${rule.name}: empty string ${name}`);
        [mods, i] = readMods(s, i);
        matchers = textMatchers(lit, mods); kind = "text";
      } else if (c === "{") {
        const j = s.indexOf("}", i);
        if (j < 0) throw new Error(`rule ${rule.name}: unterminated hex string ${name}`);
        let src;
        try { src = hexToRegex(s.slice(i + 1, j)); } catch (e) { throw new Error(`rule ${rule.name}: ${name}: ${e.message}`); }
        i = j + 1;
        [mods, i] = readMods(s, i);
        matchers = [reMatcher(src, "s")]; kind = "hex";
      } else if (c === "/") {
        let j = i + 1;
        while (j < s.length && s[j] !== "/" && s[j] !== "\n") j += s[j] === "\\" ? 2 : 1;
        if (s[j] !== "/") throw new Error(`rule ${rule.name}: unterminated regex ${name}`);
        const src = s.slice(i + 1, j); i = j + 1;
        const fl = /^[is]*/.exec(s.slice(i))[0]; i += fl.length;
        [mods, i] = readMods(s, i);
        let flags = fl.includes("s") ? "s" : "";
        if (fl.includes("i") || mods.has("nocase")) flags += "i";
        // YARA regexes are byte-oriented; \/ is an escaped delimiter.
        const jsSrc = src.replace(/\\\//g, "/");
        let re;
        try { re = reMatcher(jsSrc, flags); } catch (e) { throw new Error(`rule ${rule.name}: bad regex ${name}: ${e.message}`); }
        matchers = [re]; kind = "regex";
        if (mods.has("fullword")) matchers = [reMatcher("(?<![A-Za-z0-9])(?:" + jsSrc + ")(?![A-Za-z0-9])", flags)];
      } else {
        throw new Error(`rule ${rule.name}: bad string definition for ${name}`);
      }
      rule.strings.set(name, { kind, mods: [...mods.keys()], matchers, private: mods.has("private") });
    }
  }

  function makeRule(name, tags, body, bodyStruct, flags, known, src) {
    const rule = { uid: ++ruleSeq, name, tags, private: flags.includes("private"), global: flags.includes("global"), meta: {}, strings: new Map(), cond: null, condSrc: "", src };
    // literal contents are blanked in bodyStruct, so a bare keyword + ':' can only be a section marker
    const SECT = /(^|[^A-Za-z0-9_$#@!.])(meta|strings|condition)\s*:/g;
    const marks = [];
    let m;
    while ((m = SECT.exec(bodyStruct))) marks.push({ k: m[2], at: m.index + m[1].length, end: SECT.lastIndex });
    const parts = {};
    marks.forEach((x, i) => {
      if (parts[x.k] != null) throw new Error(`rule ${name}: duplicate ${x.k} section`);
      parts[x.k] = body.slice(x.end, i + 1 < marks.length ? marks[i + 1].at : body.length);
    });
    const lead = body.slice(0, marks.length ? marks[0].at : body.length).trim();
    if (lead) throw new Error(`rule ${name}: unexpected '${lead.slice(0, 30)}' before first section`);
    if (parts.condition == null) throw new Error(`rule ${name}: missing condition`);
    for (const ln of (parts.meta || "").split("\n")) {
      const mm = /^\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*$/.exec(ln);
      if (!mm) continue;
      let v = mm[2];
      if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) { try { v = W.utf8(unescape(v.slice(1, -1))); } catch { v = v.slice(1, -1); } }
      rule.meta[mm[1]] = v;
    }
    parseStrings(rule, parts.strings || "");
    rule.condSrc = parts.condition.trim();
    rule.cond = new CondParser(rule.condSrc, rule, known).parse();
    return rule;
  }

  // ------------------------------------------------------------------ public API
  const RULE_RE = /(?:^|\s)((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*([A-Za-z0-9_\s]+?))?\s*\{/g;

  function compile(text) {
    text = String(text == null ? "" : text).replace(/\r\n?/g, "\n");
    const rules = [], errors = [], known = new Map();
    const { masked, struct } = scanSource(text);
    if (/^\s*import\s+"/m.test(masked)) errors.push("import statements ignored: YARA modules (pe, elf, math, hash…) are not supported");
    if (/^\s*include\s+"/m.test(masked)) errors.push("include statements ignored: paste the included rules instead");
    const st = struct.replace(/^(\s*)(import|include)(\s+)"[^"\n]*"/gm, (all) => " ".repeat(all.length));
    RULE_RE.lastIndex = 0;
    let m;
    while ((m = RULE_RE.exec(st))) {
      const start = RULE_RE.lastIndex - 1, name = m[2];
      const end = blockEnd(st, start);
      if (end < 0) { errors.push(`rule ${name}: missing closing brace`); break; }
      const ruleStart = m.index + m[0].search(/(?:private|global|rule)/);
      try {
        if (known.has(name)) throw new Error(`rule ${name}: duplicate rule name`);
        const r = makeRule(name, (m[3] || "").trim().split(/\s+/).filter(Boolean), masked.slice(start + 1, end), st.slice(start + 1, end),
          (m[1] || "").trim().split(/\s+/), known, text.slice(ruleStart, end + 1));
        rules.push(r); known.set(name, r);
      } catch (e) {
        const msg = String(e && e.message || e);
        errors.push(msg.startsWith("rule ") ? msg : `rule ${name}: ${msg}`);
      }
      RULE_RE.lastIndex = end + 1;
    }
    if (!rules.length && !errors.length) errors.push("no rules found");
    return { rules, errors };
  }

  function scan(rules, data) {
    const bytes = W.bytes(data);
    let s = null;
    const ctx = { data: bytes, cache: new Map(), str: () => (s == null ? (s = W.latin1(bytes)) : s) };
    const hits = [];
    rules = rules || [];
    for (const g of rules.filter((r) => r.global)) {
      try { if (!evalRule(g, ctx)) return []; } catch (e) { hits.push({ rule: g.name, error: `${e.name || "Error"}: ${e.message}` }); }
    }
    for (const r of rules) {
      if (r.private) continue;
      let ok;
      try { ok = evalRule(r, ctx); } catch (e) { hits.push({ rule: r.name, error: `${e.name || "Error"}: ${e.message}` }); continue; }
      if (!ok) continue;
      const strs = [];
      for (const [n, def] of r.strings) {
        if (def.private) continue;
        const o = offsets(ctx, r, n);
        if (o.length) strs.push({ id: n, count: o.length, first: o[0], preview: preview(bytes.subarray(o[0], o[0] + 48)) });
      }
      hits.push({ rule: r.name, tags: r.tags, meta: r.meta, strings: strs });
    }
    return hits;
  }

  /** Quick validation summary (for editors). */
  function validate(text) {
    const { rules, errors } = compile(text);
    return { ok: !errors.length && rules.length > 0, rules: rules.map((r) => ({ name: r.name, tags: r.tags, private: r.private, global: r.global, meta: r.meta, strings: r.strings.size })), errors };
  }

  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  const severity = (hit) => { const s = String((hit && hit.meta && hit.meta.severity) || "medium").toLowerCase(); return SEV_ORDER.includes(s) ? s : s === "informational" ? "info" : s === "med" ? "medium" : "medium"; };

  const BUILTIN = String.raw`
rule Aegis_Suspicious_PowerShell_Script
{
    meta:
        description = "PowerShell script with download-and-execute or AMSI bypass traits"
        severity = "high"
    strings:
        $a1 = "DownloadString" nocase
        $a2 = "Net.WebClient" nocase
        $a3 = "Invoke-WebRequest" nocase
        $x1 = "IEX" fullword
        $x2 = "Invoke-Expression" nocase
        $x3 = "FromBase64String" nocase
        $b1 = "AmsiUtils" nocase
        $b2 = "amsiInitFailed" nocase
    condition:
        (1 of ($a*) and 1 of ($x*)) or any of ($b*)
}

rule Aegis_Webshell_Generic
{
    meta:
        description = "Server-side script that executes request parameters"
        severity = "critical"
    strings:
        $php1 = /(eval|assert|system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $php2 = /base64_decode\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $asp1 = /eval\s*\(\s*Request(\.Item)?\s*[\[(]/ nocase
        $asp2 = "Process.Start" nocase
        $asp3 = "Request.Form" nocase
        $jsp1 = /Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter/ nocase
    condition:
        filesize < 2MB and (any of ($php*) or $asp1 or ($asp2 and $asp3) or $jsp1)
}

rule Aegis_Ransom_Note_Traits
{
    meta:
        description = "Text that reads like a ransom note"
        severity = "high"
    strings:
        $s1 = "your files have been encrypted" nocase
        $s2 = "decrypt" nocase
        $s3 = "bitcoin" nocase
        $s4 = ".onion" nocase
        $s5 = "private key" nocase
        $s6 = "do not rename" nocase
    condition:
        filesize < 512KB and $s1 or 4 of them
}

rule Aegis_Shadow_Copy_Deletion
{
    meta:
        description = "Binary or script that deletes shadow copies / disables recovery"
        severity = "critical"
    strings:
        $v1 = "vssadmin delete shadows" nocase ascii wide
        $v2 = "shadowcopy delete" nocase ascii wide
        $v3 = "recoveryenabled no" nocase ascii wide
        $v4 = "wbadmin delete catalog" nocase ascii wide
    condition:
        any of them
}

rule Aegis_PE_In_Non_Executable
{
    meta:
        description = "MZ/PE header found at the start of the file (check the extension)"
        severity = "info"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Aegis_Reverse_Shell_Script
{
    meta:
        description = "Shell / Python / PowerShell reverse shell snippets"
        severity = "high"
    strings:
        $b1 = "/dev/tcp/" ascii
        $b2 = "bash -i" ascii
        $p1 = "pty.spawn" ascii
        $p2 = "socket.socket" ascii
        $w1 = "System.Net.Sockets.TCPClient" nocase ascii wide
        $w2 = "GetStream()" nocase ascii wide
    condition:
        ($b1 and $b2) or ($p1 and $p2) or ($w1 and $w2)
}

rule Aegis_Credential_Theft_Tool_Strings
{
    meta:
        description = "Strings from common credential theft tooling"
        severity = "critical"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase ascii wide
        $m2 = "gentilkiwi" nocase ascii wide
        $m3 = "lsadump::" nocase ascii wide
        $r1 = "kerberoast" nocase ascii wide
        $l1 = "LaZagne" ascii wide
    condition:
        any of them
}

rule Wkz_Encoded_PowerShell_Command
{
    meta:
        description = "PowerShell launched with a long -EncodedCommand payload"
        severity = "high"
    strings:
        $e = /powershell(\.exe)?["']?\s+[^\n]{0,80}-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $w = "-encodedcommand" nocase wide
    condition:
        $e or $w
}

rule Wkz_WSH_JScript_Dropper
{
    meta:
        description = "Windows Script Host JScript/VBScript that runs commands or writes binaries"
        severity = "high"
    strings:
        $ax = "ActiveXObject" nocase
        $co = "CreateObject" nocase
        $sh = "WScript.Shell" nocase
        $st = "ADODB.Stream" nocase
        $xh = "MSXML2.XMLHTTP" nocase
        $run = ".Run(" nocase
        $sav = ".SaveToFile" nocase
    condition:
        filesize < 5MB and ($ax or $co) and $sh and ($run or ($st and $sav) or $xh)
}

rule Wkz_LNK_Launches_Interpreter
{
    meta:
        description = "Windows shortcut (LNK) that launches a script interpreter"
        severity = "high"
    strings:
        $p = "powershell" nocase wide ascii
        $c = "cmd.exe" nocase wide ascii
        $m = "mshta" nocase wide ascii
        $w = "wscript" nocase wide ascii
        $r = "rundll32" nocase wide ascii
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401 and any of them
}

rule Wkz_Cryptominer_Traits
{
    meta:
        description = "Cryptocurrency miner configuration or binary strings"
        severity = "medium"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $x1 = "xmrig" nocase fullword
        $x2 = "cryptonight" nocase
        $x3 = "--donate-level" nocase
        $x4 = "randomx" nocase fullword
    condition:
        any of ($s*) or 2 of ($x*)
}

rule Wkz_EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless, used to test scanners)"
        severity = "info"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e at 0 and filesize < 256
}
`;

  let builtinCache = null;
  function builtin() {
    if (!builtinCache) {
      const r = compile(BUILTIN);
      if (r.errors.length) throw new Error("bundled YARA rules failed to compile: " + r.errors.join("; "));
      builtinCache = r.rules;
    }
    return builtinCache;
  }

  W.eng.yara = { compile, scan, validate, builtin, BUILTIN, severity, SEV_ORDER, _hexToRegex: hexToRegex, _unescape: unescape };
})(typeof window !== "undefined" ? window.W : globalThis.W);
