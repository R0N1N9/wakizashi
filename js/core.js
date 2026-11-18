/* Wakizashi 脇差 — core runtime.
 *
 * Everything hangs off one global, `W`. Load order (index.html): core.js → js/eng/*.js → js/views/**.js → shell.js.
 *
 *   W.layer(id, def)            register a layer  {name, kanji, role, accent, mark}
 *   W.tool(layer, id, def)      register a tool   {name, desc, icon, order, render(el, arg)}
 *   W.go(layer, tool?, arg?)    navigate (arg is handed to the tool's render, not put in the URL)
 *   W.eng.*                     pure engines — no DOM access at load time, unit-testable in Node
 *   W.ui.*, W.toast, W.modal    UI helpers (DOM only touched when called)
 *   W.store, W.Case             persistence (localStorage, namespaced "wkz:")
 *   W.hash.*                    md5 (sync) + sha1/256/384/512 via WebCrypto (async)
 *
 * Nothing leaves the device: no telemetry, no CDNs. Network calls happen only when the user
 * presses a button that says it fetches something.
 */
(function (root) {
  "use strict";
  const W = (root.W = root.W || {});
  W.VERSION = "1.0.0";
  W.eng = W.eng || {};
  W.layers = W.layers || [];
  W.tools = W.tools || {};

  // ------------------------------------------------------------------ registry
  W.layer = (id, def) => {
    const l = Object.assign({ id, tools: [] }, def);
    const i = W.layers.findIndex((x) => x.id === id);
    if (i >= 0) W.layers[i] = Object.assign(W.layers[i], l); else W.layers.push(l);
    W.tools[id] = W.tools[id] || {};
    return l;
  };
  W.tool = (layer, id, def) => {
    W.tools[layer] = W.tools[layer] || {};
    W.tools[layer][id] = Object.assign({ id, layer, order: 50, desc: "" }, def);
  };
  W.toolsOf = (layer) => Object.values(W.tools[layer] || {}).sort((a, b) => (a.order - b.order) || a.name.localeCompare(b.name));
  W.getLayer = (id) => W.layers.find((l) => l.id === id);

  // ------------------------------------------------------------------ text helpers
  W.esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  W.refang = (s) => String(s == null ? "" : s)
    .replace(/h[xX]{2}p(s?):\/\//g, "http$1://").replace(/\bhxxp/gi, "http").replace(/\[(\.|dot)\]|\((\.|dot)\)|\{(\.|dot)\}/gi, ".")
    .replace(/\[(@|at)\]|\((@|at)\)/gi, "@").replace(/\[:\]/g, ":").replace(/\[\/\]/g, "/").replace(/\s+\.\s+/g, ".");
  W.defang = (s) => String(s == null ? "" : s).replace(/^http/i, "hxxp").replace(/\./g, "[.]").replace(/@/g, "[@]");
  W.uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  W.nowIso = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
  W.clamp = (n, a, b) => Math.max(a, Math.min(b, n));
  W.uniq = (arr) => [...new Set(arr)];

  const RE = {
    ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
    ipv6: /^(?=.*:)[0-9a-f:.]{2,45}$/i,
    cidr: /^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
    url: /^(?:https?|ftp):\/\/\S+$/i,
    email: /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i,
    md5: /^[a-f0-9]{32}$/i, sha1: /^[a-f0-9]{40}$/i, sha256: /^[a-f0-9]{64}$/i, sha512: /^[a-f0-9]{128}$/i,
    cve: /^CVE-\d{4}-\d{4,7}$/i, attack: /^T\d{4}(?:\.\d{3})?$/, asn: /^AS\d{1,10}$/i,
    domain: /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})$/i,
    username: /^@[A-Za-z0-9_.-]{2,40}$/,
  };
  W.RE = RE;
  /** Best-effort indicator type: ipv4 ipv6 cidr url email md5 sha1 sha256 sha512 cve attack asn domain username | null */
  W.detectType = (v) => {
    v = W.refang(String(v || "").trim());
    if (!v) return null;
    for (const t of ["cidr", "ipv4", "url", "email", "md5", "sha1", "sha256", "sha512", "cve", "attack", "asn", "username"]) if (RE[t].test(v)) return t;
    if (RE.ipv6.test(v) && (v.match(/:/g) || []).length >= 2) return "ipv6";
    if (RE.domain.test(v)) return "domain";
    return null;
  };

  // ------------------------------------------------------------------ formatting
  W.fmt = {
    bytes(n) { n = +n || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + " " + u[i]; },
    num(n) { return (+n || 0).toLocaleString("en-US"); },
    ago(iso) {
      const t = Date.parse(iso); if (!t) return "—";
      const s = Math.round((Date.now() - t) / 1000);
      if (s < 60) return s + "s ago"; if (s < 3600) return Math.round(s / 60) + "m ago"; if (s < 86400) return Math.round(s / 3600) + "h ago";
      return Math.round(s / 86400) + "d ago";
    },
    ts(iso) { const d = new Date(iso); return isNaN(d) ? String(iso || "—") : d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z"); },
  };

  // ------------------------------------------------------------------ bytes / encodings
  const enc = new TextEncoder(), dec = new TextDecoder("utf-8", { fatal: false });
  // realm-safe (buffers from workers/iframes/WebCrypto fail `instanceof` checks)
  const tag = (x) => Object.prototype.toString.call(x);
  W.bytes = (x) => x instanceof Uint8Array ? x
    : (tag(x) === "[object ArrayBuffer]" || tag(x) === "[object SharedArrayBuffer]") ? new Uint8Array(x)
    : ArrayBuffer.isView(x) ? new Uint8Array(x.buffer, x.byteOffset, x.byteLength)
    : enc.encode(String(x == null ? "" : x));
  W.utf8 = (b) => dec.decode(W.bytes(b));
  W.latin1 = (b) => { b = W.bytes(b); let s = ""; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return s; };
  W.hex = (b) => Array.from(W.bytes(b), (x) => x.toString(16).padStart(2, "0")).join("");
  W.fromHex = (h) => { h = String(h).replace(/[^0-9a-f]/gi, ""); const o = new Uint8Array(h.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };
  W.b64 = (b) => { const s = W.latin1(b); return typeof btoa === "function" ? btoa(s) : Buffer.from(s, "latin1").toString("base64"); };
  W.fromB64 = (s) => {
    s = String(s).replace(/[\s]/g, "").replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
    const bin = typeof atob === "function" ? atob(s) : Buffer.from(s, "base64").toString("latin1");
    const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o;
  };
  /** Shannon entropy in bits/byte (0–8). */
  W.entropy = (b) => {
    b = W.bytes(b); if (!b.length) return 0;
    const f = new Uint32Array(256); for (const x of b) f[x]++;
    let e = 0; for (const c of f) if (c) { const p = c / b.length; e -= p * Math.log2(p); }
    return e;
  };

  // ------------------------------------------------------------------ hashing
  // MD5 (RFC 1321) — WebCrypto has no MD5, but threat intel lives on it.
  function md5(input) {
    const b = W.bytes(input), n = b.length;
    const words = new Uint32Array((((n + 8) >>> 6) + 1) * 16);
    for (let i = 0; i < n; i++) words[i >> 2] |= b[i] << ((i % 4) * 8);
    words[n >> 2] |= 0x80 << ((n % 4) * 8);
    words[words.length - 2] = (n * 8) >>> 0; words[words.length - 1] = Math.floor(n / 0x20000000);
    const K = new Uint32Array(64), S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    for (let o = 0; o < words.length; o += 16) {
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
        else { F = C ^ (B | ~D); g = (7 * i) % 16; }
        F = (F + A + K[i] + words[o + g]) >>> 0;
        A = D; D = C; C = B;
        const s = S[(i >> 4) * 4 + (i % 4)];
        B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    return [a0, b0, c0, d0].map((x) => [0, 8, 16, 24].map((s) => ((x >>> s) & 255).toString(16).padStart(2, "0")).join("")).join("");
  }
  const subtle = () => (root.crypto && root.crypto.subtle) || null;
  W.hash = {
    md5,
    async sha(alg, data) {
      const s = subtle(); if (!s) throw new Error("WebCrypto unavailable — open Wakizashi over https or localhost");
      return W.hex(await s.digest(alg.toUpperCase().replace(/^SHA(\d)/, "SHA-$1"), W.bytes(data)));
    },
    async all(data) {
      const b = W.bytes(data);
      const [sha1, sha256, sha512] = await Promise.all([W.hash.sha("SHA-1", b), W.hash.sha("SHA-256", b), W.hash.sha("SHA-512", b)]);
      return { md5: md5(b), sha1, sha256, sha512 };
    },
  };
  W.randomBytes = (n) => { const b = new Uint8Array(n); root.crypto.getRandomValues(b); return b; };

  // ------------------------------------------------------------------ persistence
  const NS = "wkz:";
  let mem = {};
  const ls = () => { try { return root.localStorage || null; } catch { return null; } };
  W.store = {
    get(k, def) {
      try { const s = ls(); const v = s ? s.getItem(NS + k) : mem[k]; return v == null ? def : JSON.parse(v); } catch { return def; }
    },
    set(k, v) {
      const j = JSON.stringify(v);
      try { const s = ls(); if (s) s.setItem(NS + k, j); else mem[k] = j; return true; }
      catch (e) { W.toast && W.toast("Storage full or blocked — " + e.message, 1); mem[k] = j; return false; }
    },
    del(k) { try { const s = ls(); if (s) s.removeItem(NS + k); delete mem[k]; } catch { /* ignore */ } },
    keys() { const s = ls(); if (!s) return Object.keys(mem); const o = []; for (let i = 0; i < s.length; i++) { const k = s.key(i); if (k && k.startsWith(NS)) o.push(k.slice(NS.length)); } return o; },
    dump() { const o = {}; for (const k of W.store.keys()) o[k] = W.store.get(k); return o; },
    load(obj) { for (const [k, v] of Object.entries(obj || {})) W.store.set(k, v); },
    clear() { for (const k of W.store.keys()) W.store.del(k); },
  };

  // ------------------------------------------------------------------ cases (shared across layers)
  W.Case = {
    _ws() {
      let ws = W.store.get("cases");
      if (!ws || !Array.isArray(ws.cases) || !ws.cases.length) ws = { cases: [{ id: "general", name: "General", items: [], notes: "", created: W.nowIso() }], active: "general" };
      return ws;
    },
    get ws() { return this._ws(); },
    active() { const ws = this._ws(); return ws.cases.find((c) => c.id === ws.active) || ws.cases[0]; },
    save(ws) { W.store.set("cases", ws); W.emit && W.emit("case"); },
    /** Mutate the workspace: W.Case.update((ws, active) => { ... }) */
    update(fn) { const ws = this._ws(); const act = ws.cases.find((c) => c.id === ws.active) || ws.cases[0]; fn(ws, act); this.save(ws); return act; },
    create(name, opts = {}) {
      const id = "c" + W.uid();
      this.update((ws) => { ws.cases.push({ id, name: String(name || "Case").slice(0, 120), items: [], notes: opts.notes || "", tags: opts.tags || [], created: W.nowIso() }); ws.active = id; });
      return id;
    },
    activate(id) { this.update((ws) => { if (ws.cases.some((c) => c.id === id)) ws.active = id; }); },
    /** Add indicators [{value, type?, verdict?, tags?, note?}] to the active case. Returns how many were new. */
    add(items, quiet) {
      let n = 0, name = "";
      this.update((ws, c) => {
        name = c.name;
        for (const it of items || []) {
          const v = W.refang(String((it && it.value) != null ? it.value : it).trim()); if (!v) continue;
          const ex = c.items.find((x) => x.value === v);
          if (ex) { if (it.verdict) ex.verdict = it.verdict; if (it.tags) ex.tags = W.uniq([...(ex.tags || []), ...it.tags]); continue; }
          c.items.unshift({ value: v, type: it.type || W.detectType(v) || "other", verdict: it.verdict || null, tags: it.tags || [], note: it.note || "", added: W.nowIso() });
          n++;
        }
      });
      if (!quiet && W.toast) W.toast(`${n} added to case “${name}”`);
      return n;
    },
  };

  // ------------------------------------------------------------------ tiny event bus
  const subs = {};
  W.on = (ev, fn) => { (subs[ev] = subs[ev] || []).push(fn); return () => { subs[ev] = subs[ev].filter((f) => f !== fn); }; };
  W.emit = (ev, data) => { for (const f of subs[ev] || []) { try { f(data); } catch (e) { console.error(e); } } };

  // ------------------------------------------------------------------ DOM helpers (only touch the DOM when called)
  W.$ = (sel, el) => (el || root.document).querySelector(sel);
  W.$$ = (sel, el) => Array.from((el || root.document).querySelectorAll(sel));
  W.icon = (paths, cls) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"${cls ? ` class="${cls}"` : ""}>${paths}</svg>`;
  W.I = {   // shared icon paths (24x24, stroke)
    back: '<path d="M15 18l-6-6 6-6"/>', copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    dl: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>', up: '<path d="M12 21V9M7 14l5-5 5 5M4 3h16"/>', plus: '<path d="M12 5v14M5 12h14"/>',
    x: '<path d="M6 6l12 12M18 6 6 18"/>', gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    case: '<path d="M3 7h18v13H3zM8 7V4h8v3M3 12h18"/>', file: '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4"/>', search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-5-5"/>',
    install: '<path d="M12 3v12M7 10l5 5 5-5"/><rect x="3" y="17" width="18" height="4" rx="1"/>', link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    check: '<path d="M5 12l4 4L19 6"/>', warn: '<path d="M12 3 2 21h20z"/><path d="M12 10v4M12 17.5v.5"/>', play: '<path d="M7 4l13 8-13 8z"/>',
    trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>', refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
  };
  const DROP_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5M4 21h16"/></svg>';

  W.ui = {
    /** View header: W.ui.head("Extract", "IOC extraction", "subtitle") → "EXTRACT | IOC extraction". */
    head(code, title, sub) {
      return `<div class="vhead"><h1>${code ? `<span class="vcode">${W.esc(code)}</span>${title ? '<span class="vbar"></span>' : ""}` : ""}${title ? `<span>${W.esc(title)}</span>` : ""}</h1>${sub ? `<p>${sub}</p>` : ""}</div>`;
    },
    panel: (title, inner, cls) => `<section class="panel ${cls || ""}">${title ? `<h2>${W.esc(title)}</h2>` : ""}${inner}</section>`,
    empty: (title, msg) => `<div class="empty"><b>${W.esc(title || "NOTHING YET")}</b>${msg ? W.esc(msg) : ""}</div>`,
    loader: (t) => `<span class="loader">${W.esc(t || "WORKING")}<i>_</i></span>`,
    badge: (text, kind, fill) => `<span class="badge ${kind || ""} ${fill ? "fill" : ""}">${W.esc(text)}</span>`,
    sev: (level, fill) => W.ui.badge(level || "info", ({ critical: "critical", high: "high", medium: "medium", low: "low", info: "info", ok: "ok", good: "ok" })[level] || "", fill),
    chip: (v, attrs) => `<span class="chip"${attrs || ""}>${W.esc(v)}</span>`,
    kv: (rows) => `<dl class="kv">${rows.filter((r) => r && r[1] != null && r[1] !== "").map(([k, v, raw]) => `<dt>${W.esc(k)}</dt><dd>${raw ? v : W.esc(v)}</dd>`).join("")}</dl>`,
    /** table(["Col", ...], rows[][], {raw: true}) — cells are escaped unless raw. */
    table(cols, rows, opts = {}) {
      return `<div class="tablewrap"${opts.max ? ` style="max-height:${opts.max}px"` : ""}><table class="tbl"><thead><tr>${cols.map((c) => `<th>${W.esc(c)}</th>`).join("")}</tr></thead><tbody>${
        rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td${opts.mono ? ' class="mono"' : ""}>${opts.raw ? (c == null ? "" : c) : W.esc(c)}</td>`).join("")}</tr>`).join("")
          : `<tr><td colspan="${cols.length}">${W.ui.empty("NONE")}</td></tr>`}</tbody></table></div>`;
    },
    stat: (n, label, acc) => `<div class="panel stat"><div class="n ${acc ? "acc" : ""}">${W.esc(n)}</div><div class="l">${W.esc(label)}</div></div>`,
    bars(pairs) { const max = Math.max(1, ...pairs.map((p) => p[1])); return `<div class="bars">${pairs.map(([k, n]) => `<div class="b"><span title="${W.esc(k)}">${W.esc(k)}</span><i style="width:${(100 * n / max).toFixed(1)}%"></i><span class="mono">${n}</span></div>`).join("")}</div>`; },
    btn: (label, attrs, cls) => `<button type="button" class="btn ${cls || ""}" ${attrs || ""}>${label}</button>`,
    /** Segmented control: seg("id", [["a","A"],...], "a") */
    seg: (id, opts, cur) => `<div class="seg" id="${id}">${opts.map(([v, l]) => `<button type="button" data-v="${W.esc(v)}" class="${v === cur ? "on" : ""}">${W.esc(l)}</button>`).join("")}</div>`,
    drop: (id, text, accept) => `<label class="drop" id="${id}">${DROP_SVG}<span>${W.esc(text || "Drop a file or tap to choose")}</span><span class="tiny faint">Stays on this device — never uploaded.</span><input type="file"${accept ? ` accept="${accept}"` : ""}></label>`,
  };

  /** Wire a seg control; returns getter. */
  W.seg = (el, onChange) => {
    const box = typeof el === "string" ? W.$("#" + el) : el;
    box.addEventListener("click", (e) => { const b = e.target.closest("button[data-v]"); if (!b) return; W.$$("button", box).forEach((x) => x.classList.toggle("on", x === b)); onChange && onChange(b.dataset.v); });
    return () => (W.$("button.on", box) || {}).dataset?.v;
  };
  /** Wire tabs inside el: buttons [data-tab]; calls onTab(name). */
  W.tabs = (box, onTab) => {
    box.addEventListener("click", (e) => { const b = e.target.closest("button[data-tab]"); if (!b) return; W.$$("button[data-tab]", box).forEach((x) => x.classList.toggle("on", x === b)); onTab(b.dataset.tab); });
  };

  W.toast = (msg, err) => {
    const box = root.document && W.$("#toast"); if (!box) { (err ? console.error : console.log)("[toast]", msg); return; }
    const t = root.document.createElement("div"); t.className = "toast" + (err ? " err" : ""); t.setAttribute("role", err ? "alert" : "status"); t.textContent = msg;
    box.appendChild(t); setTimeout(() => t.remove(), err ? 5200 : 2800);
  };
  W.modal = (html, opts = {}) => {
    const m = W.$("#modal"), body = W.$("#modal-body");
    body.innerHTML = (opts.title ? `<h2>${W.esc(opts.title)}</h2>` : "") + html; m.hidden = false;
    W.$("#modal-x").focus();
    return body;
  };
  W.closeModal = () => { const m = W.$("#modal"); if (m) m.hidden = true; };

  W.copy = async (text, label) => {
    try { await root.navigator.clipboard.writeText(String(text)); }
    catch {
      const ta = root.document.createElement("textarea"); ta.value = String(text); ta.style.position = "fixed"; ta.style.opacity = "0";
      root.document.body.appendChild(ta); ta.select(); try { root.document.execCommand("copy"); } catch { /* ignore */ } ta.remove();
    }
    W.toast(label || "Copied");
  };
  W.download = (name, data, type) => {
    const blob = data instanceof Blob ? data : new Blob([data instanceof Uint8Array ? data : String(data)], { type: type || "text/plain;charset=utf-8" });
    const a = root.document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name;
    root.document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
  };
  /** Read a File/Blob as "text" | "buffer" (Uint8Array) | "dataurl". */
  W.readFile = (file, as = "text") => new Promise((res, rej) => {
    const r = new FileReader();
    r.onerror = () => rej(r.error || new Error("could not read file"));
    r.onload = () => res(as === "buffer" ? new Uint8Array(r.result) : r.result);
    if (as === "buffer") r.readAsArrayBuffer(file); else if (as === "dataurl") r.readAsDataURL(file); else r.readAsText(file);
  });
  /** Make a .drop label (from W.ui.drop) accept drag/drop + click. onFile(file) per file. */
  W.dropZone = (el, onFile, opts = {}) => {
    el = typeof el === "string" ? W.$("#" + el) : el;
    const inp = el.querySelector("input[type=file]"); if (opts.multiple) inp.multiple = true;
    const take = (files) => { for (const f of Array.from(files || []).slice(0, opts.multiple ? 50 : 1)) onFile(f); };
    inp.addEventListener("change", () => { take(inp.files); inp.value = ""; });
    ["dragenter", "dragover"].forEach((ev) => el.addEventListener(ev, (e) => { e.preventDefault(); el.classList.add("over"); }));
    ["dragleave", "drop"].forEach((ev) => el.addEventListener(ev, (e) => { e.preventDefault(); el.classList.remove("over"); }));
    el.addEventListener("drop", (e) => take(e.dataTransfer && e.dataTransfer.files));
  };
  /** Wrap an async click handler: disables the button and shows errors as toasts. */
  W.act = (btn, fn) => {
    if (typeof btn === "string") btn = W.$(btn);
    if (!btn) return;
    btn.addEventListener("click", async (e) => {
      if (btn.disabled) return; btn.disabled = true;
      try { await fn(e); } catch (err) { console.error(err); W.toast(err.message || String(err), 1); } finally { btn.disabled = false; }
    });
  };
  /** Debounce. */
  W.debounce = (fn, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

  /** Rules-of-engagement gate (Naginata). Resolves true once acknowledged (persisted). */
  W.roeOk = () => !!W.store.get("roe.ack");
  W.roeGate = (el, then) => {
    if (W.roeOk()) return then();
    el.innerHTML = `<div class="gate">${W.ui.panel("Rules of engagement", `
      <p>Naginata's tools support <b>authorised</b> security testing: recon planning, header and token analysis, scoring and reporting.
      Only use them against systems you own or have <b>written permission</b> to test. Wakizashi never sends traffic on its own — it only builds, decodes and analyses what you give it.</p>
      <label class="check"><input type="checkbox" id="roe-c"> I'm authorised to test the systems I'll work on, and I accept responsibility for how I use these tools.</label>
      <div class="spacer"></div><button class="btn pri" id="roe-go" disabled>Enter Naginata</button>`)}</div>`;
    W.$("#roe-c").onchange = (e) => (W.$("#roe-go").disabled = !e.target.checked);
    W.$("#roe-go").onclick = () => { W.store.set("roe.ack", W.nowIso()); then(); };
  };
})(typeof window !== "undefined" ? window : globalThis);
