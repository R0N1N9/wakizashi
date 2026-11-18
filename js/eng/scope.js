/* Scope engine — engagement scope entries and "is this target in scope?".
 *   parseEntry("10.0.0.0/8" | "10.0.0.1-50" | "2001:db8::/32" | "*.example.com" | "https://app.example.com/x")
 *   parseList(text)  → {entries, invalid}
 *   check(target, {in: text|entries, out: text|entries}) → {verdict, inMatches, outMatches, reason, target}
 * Rule: out-of-scope entries always override in-scope ones. A bare domain matches only itself;
 * "*.example.com" matches any subdomain (not the apex); ".example.com" matches the apex and every subdomain.
 * Uses W.eng.subnet (loaded after this file) lazily for address math. */
(function (W) {
  "use strict";
  const S = () => W.eng.subnet;
  const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

  /** Strip scheme, credentials, path, port; refang; lowercase. Leaves CIDRs/ranges alone. */
  function normHost(s) {
    s = W.refang(String(s == null ? "" : s).trim()).replace(/\s+#.*$/, "");
    const um = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(s);
    if (um) s = um[1].replace(/^[^@]*@/, "");
    if (/^\[[0-9a-f:.]+\](:\d+)?$/i.test(s)) return s.replace(/^\[|\](:\d+)?$/g, "").toLowerCase();
    if (/^[^:]+:\d{1,5}$/.test(s)) s = s.replace(/:\d+$/, "");          // host:port (not IPv6)
    else if (!um && /^[^/\s]+\/[^\d]/.test(s)) s = s.split("/")[0];      // host/path (not CIDR)
    return s.replace(/\.$/, "").toLowerCase();
  }

  /** One scope line → {kind:"net"|"domain"|"invalid", raw, label, ...}. "# comment" text after the entry is kept as note. */
  function parseEntry(line) {
    const raw = String(line == null ? "" : line).trim();
    const note = (/\s+#\s*(.*)$/.exec(raw) || [])[1] || "";
    const body = raw.replace(/\s+#.*$/, "").trim();
    if (!body) return null;
    const sn = S();
    const range = sn.parseRange(body);
    if (range) return { kind: "net", raw, note, v: range.v, start: range.start, end: range.end, size: range.end - range.start + 1n, label: `${sn.formatIP(range.v, range.start)} – ${sn.formatIP(range.v, range.end)}`, form: "range" };
    const c = sn.parseCidr(body);
    if (c) {
      const isAddr = !body.includes("/");
      return { kind: "net", raw, note, v: c.v, start: c.start, end: c.end, size: c.size, label: isAddr ? sn.formatIP(c.v, c.addr) : sn.cidrStr(c.v, c.net, c.bits), form: isAddr ? "ip" : "cidr", hostBits: c.hostBits };
    }
    let h = normHost(body);
    if (sn.parseIP(h)) { const p = sn.parseIP(h); return { kind: "net", raw, note, v: p.v, start: p.n, end: p.n, size: 1n, label: sn.formatIP(p.v, p.n), form: "ip" }; }
    let wildcard = null;
    if (h.startsWith("*.")) { wildcard = "sub"; h = h.slice(2); }
    else if (h.startsWith(".")) { wildcard = "apex+sub"; h = h.slice(1); }
    if (h.includes("*")) return { kind: "invalid", raw, note, error: "wildcards are only supported as a leading *." };
    if (!HOST_RE.test(h) || /^\d+(\.\d+)*$/.test(h)) return { kind: "invalid", raw, note, error: "not an IP, CIDR, range or hostname" };
    return { kind: "domain", raw, note, domain: h, wildcard, label: (wildcard === "sub" ? "*." : wildcard ? "." : "") + h, form: wildcard ? "wildcard" : "domain" };
  }

  /** Text (one entry per line or comma/space-separated) → {entries, invalid}. */
  function parseList(text) {
    if (Array.isArray(text) && text.length && typeof text[0] === "object") return { entries: text.filter((e) => e && e.kind !== "invalid"), invalid: text.filter((e) => e && e.kind === "invalid") };
    const lines = (Array.isArray(text) ? text : String(text == null ? "" : text).split(/\r?\n/))
      .flatMap((l) => (/#/.test(l) ? [l] : String(l).split(/[,;]|\s{2,}|\t/)))
      .map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    const entries = [], invalid = [];
    for (const l of lines) { const e = parseEntry(l); if (!e) continue; (e.kind === "invalid" ? invalid : entries).push(e); }
    return { entries, invalid };
  }

  /** Does a domain scope entry cover hostname h? */
  function domainMatch(entry, h) {
    h = normHost(h);
    if (entry.wildcard === "sub") return h.endsWith("." + entry.domain);
    if (entry.wildcard === "apex+sub") return h === entry.domain || h.endsWith("." + entry.domain);
    return h === entry.domain;
  }

  /** Parse a target (IP, CIDR, range, hostname, URL) the same way as entries, but no wildcards. */
  function parseTarget(t) {
    const e = parseEntry(String(t == null ? "" : t).replace(/\s+#.*$/, ""));
    if (!e) return { kind: "invalid", raw: String(t || ""), error: "empty" };
    if (e.kind === "domain" && e.wildcard) return Object.assign(e, { kind: "domain", wildcardTarget: true });
    return e;
  }

  /** Relationship between a scope entry and a target: "full" (target entirely covered), "partial", or null. */
  function relate(entry, target) {
    if (entry.kind === "net" && target.kind === "net") {
      if (S().contains(entry, target)) return "full";
      return S().overlaps(entry, target) ? "partial" : null;
    }
    if (entry.kind === "domain" && target.kind === "domain") {
      if (target.wildcardTarget) {                                   // "*.x.com" target vs entries
        const d = target.domain, under = d === entry.domain || d.endsWith("." + entry.domain);
        if (entry.wildcard && under) return "full";                   // *.a.x.com is inside *.x.com / .x.com
        return entry.domain.endsWith("." + d) ? "partial" : null;     // a single host under the wildcard
      }
      return domainMatch(entry, target.domain) ? "full" : null;
    }
    return null;
  }

  /**
   * Verdicts: "in" — covered by in-scope and touches nothing out of scope;
   *           "out" — matches an out-of-scope entry (overrides in-scope);
   *           "partial" — a network/wildcard target only partly in scope, or partly excluded;
   *           "unlisted" — matches nothing (treat as out of scope);
   *           "unresolved" — a hostname checked against IP-only scope (resolve it first);
   *           "invalid".
   */
  function check(target, scope) {
    scope = scope || {};
    const ins = parseList(scope.in || scope.inScope || "").entries, outs = parseList(scope.out || scope.outScope || "").entries;
    const t = typeof target === "object" && target && target.kind ? target : parseTarget(target);
    const res = { target: t, verdict: "invalid", inMatches: [], outMatches: [], reason: "" };
    if (t.kind === "invalid") { res.reason = t.error || "not a recognisable target"; return res; }
    for (const e of ins) { const r = relate(e, t); if (r) res.inMatches.push({ entry: e, rel: r }); }
    for (const e of outs) { const r = relate(e, t); if (r) res.outMatches.push({ entry: e, rel: r }); }
    const fullIn = res.inMatches.some((m) => m.rel === "full"), fullOut = res.outMatches.some((m) => m.rel === "full");
    const lbl = (ms) => ms.map((m) => m.entry.label).join(", ");
    if (fullOut) { res.verdict = "out"; res.reason = `excluded by out-of-scope ${lbl(res.outMatches.filter((m) => m.rel === "full"))}`; }
    else if (res.outMatches.length && (fullIn || res.inMatches.length)) { res.verdict = "partial"; res.reason = `partly excluded by ${lbl(res.outMatches)} — test only the in-scope part`; }
    else if (res.outMatches.length) { res.verdict = "out"; res.reason = `overlaps out-of-scope ${lbl(res.outMatches)} and is not in scope`; }
    else if (fullIn) { res.verdict = "in"; res.reason = `covered by ${lbl(res.inMatches.filter((m) => m.rel === "full"))}`; }
    else if (res.inMatches.length && t.kind === "net" && coveredByUnion(ins, t)) { res.verdict = "in"; res.reason = `covered by ${lbl(res.inMatches)} together`; }
    else if (res.inMatches.length) { res.verdict = "partial"; res.reason = `only partly covered by ${lbl(res.inMatches)}`; }
    else if (t.kind === "domain" && !ins.some((e) => e.kind === "domain") && ins.some((e) => e.kind === "net")) { res.verdict = "unresolved"; res.reason = "scope lists only addresses — resolve the hostname and check its IPs"; }
    else { res.verdict = "unlisted"; res.reason = "not listed in scope — treat as out of scope until confirmed in writing"; }
    return res;
  }
  function coveredByUnion(entries, t) {
    const iv = entries.filter((e) => e.kind === "net" && e.v === t.v && e.end >= t.start && e.start <= t.end).map((e) => [e.start, e.end]).sort((a, b) => (a[0] < b[0] ? -1 : 1));
    let cur = t.start;
    for (const [s, e] of iv) { if (s > cur) return false; if (e >= cur) cur = e + 1n; if (cur > t.end) return true; }
    return cur > t.end;
  }
  /** Check many targets; returns array of results in input order. */
  const checkMany = (targets, scope) => (Array.isArray(targets) ? targets : String(targets || "").split(/[\r\n,]+/)).map((x) => String(x).trim()).filter(Boolean).map((x) => Object.assign(check(x, scope), { input: x }));

  /** Address count summary for a list. */
  function summarise(text) {
    const { entries, invalid } = parseList(text);
    const out = { v4: 0n, v6: 0n, domains: 0, wildcards: 0, invalid: invalid.length, entries: entries.length };
    for (const e of entries) {
      if (e.kind === "net") out["v" + e.v] += e.size;
      else if (e.wildcard) out.wildcards++; else out.domains++;
    }
    return out;
  }

  W.eng.scope = { normHost, parseEntry, parseList, parseTarget, domainMatch, relate, check, checkMany, summarise };
})(typeof window !== "undefined" ? window.W : globalThis.W);
