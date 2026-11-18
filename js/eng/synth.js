/* Yoroi rule synthesis — W.eng.synth. Port of Katana's defense/synth.py.
 *
 * Draft a detection rule from the malicious log events you mark, then grade it. The goal is a rule that
 * fires on the bad activity (recall — no false negatives) and stays quiet on everything else (precision —
 * no false positives). Given a log plus the indices of the malicious events it:
 *   1. mines shared field values out of the positive events (command lines, images, URIs, IPs, user
 *      agents, status codes, event ids, …),
 *   2. assembles candidate Sigma rules — the simplest discriminator, a precision-first AND of fields common
 *      to every positive (greedy set cover over the benign events), and the best FP-free single feature,
 *   3. grades each with the real W.eng.sigma engine against the whole log: TP / FP / FN, precision, recall,
 *      F1 and a verdict (exact · tight · good · loose · leaky).
 *
 *   synthesize({text, fmt?, indices, baseline?, title?, max_candidates?}) → {title, positives, negatives,
 *     baseline_events, fields_mined, candidates:[{rule, valid, conditions, grade}], recommended, block_ips, notes, marked}
 */
(function (W) {
  "use strict";
  const S = () => W.eng.sigma, LG = () => W.eng.logs;

  // Field names are what W.eng.sigma.fieldValue resolves, so mined values match exactly when the rule runs.
  const FIELDS = [
    ["CommandLine", "contains"], ["Image", "endswith"], ["ParentImage", "endswith"],
    ["cs-uri", "contains"], ["cs-method", "eq"], ["sc-status", "eq"], ["cs-user-agent", "contains"],
    ["c-ip", "eq"], ["QueryName", "contains"], ["TargetFilename", "endswith"], ["service", "eq"],
    ["program", "eq"], ["EventID", "eq"], ["action", "eq"],
  ];
  const TOKEN_RE = /[A-Za-z0-9_./\\:%@+-]{4,}/g;
  const NOISE = new Set(["http", "https", "the", "and", "for", "from", "with", "true", "false", "null", "none", "port"]);

  const val = (ev, field) => { const v = S().fieldValue(ev, field); return v == null ? null : typeof v === "string" ? v : Array.isArray(v) ? v.join(",") : typeof v === "object" ? JSON.stringify(v) : String(v); };
  const basename = (p) => { const parts = p.trim().split(/[\\/]/); const last = parts[parts.length - 1]; return last ? last : p.trim(); };
  const stripChars = (s, chars) => { let a = 0, b = s.length; while (a < b && chars.includes(s[a])) a++; while (b > a && chars.includes(s[b - 1])) b--; return s.slice(a, b); };
  /** Python's round-half-to-even. */
  const pyRound = (x) => { const f = Math.floor(x), r = x - f; return r > 0.5 ? f + 1 : r < 0.5 ? f : f % 2 === 0 ? f : f + 1; };
  const r3 = (x) => Math.round(x * 1000) / 1000;

  /** Meaningful substrings of a free-text value, plus the whole thing if it's short. */
  function tokens(value) {
    const out = [], v = value.trim();
    if (v.length >= 4 && v.length <= 60) out.push(v);
    for (const m of v.match(TOKEN_RE) || []) {
      const t = stripChars(m, "./\\:-");
      if (t.length >= 4 && !NOISE.has(t.toLowerCase()) && !/^\d+$/.test(t)) out.push(t);
    }
    const seen = new Set(), uniq = [];
    for (const t of out) { const k = t.toLowerCase(); if (!seen.has(k)) { seen.add(k); uniq.push(t); } }
    return uniq.slice(0, 40);
  }

  /** Case-insensitive single-condition match, mirroring the Sigma engine's semantics. */
  function match(ev, field, mode, value) {
    let v = val(ev, field);
    if (v == null) return false;
    v = v.toLowerCase();
    const t = value.toLowerCase();
    if (mode === "contains") return v.includes(t);
    if (mode === "endswith") return v.endsWith(t.replace(/^[\\/]+/, ""));
    return v === t;
  }

  /** Stable sort, descending by a tuple key. */
  function sortDesc(arr, key) {
    const k = arr.map((x, i) => [key(x), i, x]);
    k.sort((a, b) => { for (let j = 0; j < a[0].length; j++) { if (a[0][j] !== b[0][j]) return a[0][j] < b[0][j] ? 1 : -1; } return a[1] - b[1]; });
    return k.map((x) => x[2]);
  }

  function candidates(P, N) {
    const nump = P.length, cands = new Map();
    for (const [field, mode] of FIELDS) {
      const vals = [];
      for (const e of P) {
        const v = val(e, field);
        if (v == null) continue;
        if (mode === "endswith") vals.push(basename(v));
        else if (mode === "contains") vals.push(...tokens(v));
        else vals.push(v);
      }
      const tally = new Map();
      for (const v of vals) if (!tally.has(v.toLowerCase())) tally.set(v.toLowerCase(), v);
      for (const [low, disp] of tally) {
        const condVal = mode === "endswith" && !/^[\\/]/.test(disp) ? "\\" + disp : disp;
        const key = field + "\u0000" + mode + "\u0000" + low;
        if (cands.has(key)) continue;
        const pos = P.filter((e) => match(e, field, mode, condVal)).map((e) => e.i);
        if (!pos.length) continue;
        const neg = N.filter((e) => match(e, field, mode, condVal)).map((e) => e.i);
        cands.set(key, { field, mode, value: condVal, pos: new Set(pos), neg: new Set(neg), pcov: pos.length / nump, nhit: neg.length });
      }
    }
    const numn = Math.max(1, N.length);
    const out = [...cands.values()].filter((c) => c.pcov >= 0.5 || c.pos.size >= 3);
    return sortDesc(out, (c) => [c.pcov - c.nhit / numn, c.pcov, -c.nhit]);
  }

  /** AND together features common to (nearly) all positives to exclude the most benign events. */
  function greedyAnd(anchors, P, N) {
    const pset = new Set(P.map((e) => e.i));
    const need = Math.max(1, pyRound(0.9 * P.length));
    const keep = anchors.filter((c) => c.pos.size >= need);
    const chosen = [];
    let remaining = new Set(N.map((e) => e.i)), cur = new Set(pset);
    for (let round = 0; round < 4 && remaining.size; round++) {
      let best = null, bestExcl = 0;
      for (const c of keep) {
        if (chosen.includes(c)) continue;
        let excl = 0; for (const n of remaining) if (!c.neg.has(n)) excl++;
        let np = 0; for (const p of cur) if (c.pos.has(p)) np++;
        if (np < Math.max(1, pyRound(0.9 * pset.size))) continue;
        if (excl > bestExcl) { best = c; bestExcl = excl; }
      }
      if (!best || bestExcl === 0) break;
      chosen.push(best);
      remaining = new Set([...remaining].filter((n) => best.neg.has(n)));
      cur = new Set([...cur].filter((p) => best.pos.has(p)));
    }
    return chosen;
  }

  const rid = () => { let s = ""; for (let i = 0; i < 10; i++) s += "0123456789abcdef"[Math.floor(Math.random() * 16)]; return s; };
  const yq = (s) => "'" + String(s).replace(/'/g, "''") + "'";

  function specToSigma(title, conditions) {
    const L = [`title: ${yq(title)}`, `id: yoroi-synth-${rid()}`, "status: experimental",
      "description: Synthesised by Yoroi from marked malicious log events. Review before deploying.",
      "logsource:", "    category: any", "detection:"];
    const names = [];
    conditions.forEach((c, n) => {
      const sel = `selection${n + 1}`;
      names.push(sel);
      const mod = c.mode === "eq" ? "" : "|" + c.mode;
      L.push(`    ${sel}:`, `        ${c.field}${mod}:`, `            - ${yq(c.value)}`);
    });
    L.push("    condition: " + names.join(" and "), "level: medium");
    return L.join("\n") + "\n";
  }

  /** Grade rule text against events with the real Sigma engine. */
  function grade(ruleText, events, pset, nset) {
    const { rules, errors } = S().compile(ruleText);
    if (!rules.length) return { valid: false, errors: errors.length ? errors : ["rule did not compile"] };
    const matched = new Set();
    for (const h of S().run(rules, events)) for (const i of h.events) matched.add(i);
    // sigma.run caps events at 300 per rule — recount exhaustively for an exact grade
    if ([...matched].length >= 300) { matched.clear(); for (const e of events) if (rules.some((r) => r.applies(e) && r.match(e))) matched.add(e.i); }
    const tp = [...matched].filter((i) => pset.has(i)).length, fp = [...matched].filter((i) => nset.has(i)).length;
    const fnList = [...pset].filter((i) => !matched.has(i)), fn = fnList.length;
    const precision = tp + fp ? tp / (tp + fp) : 0, recall = tp + fn ? tp / (tp + fn) : 0;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
    const verdict = recall === 1 && precision === 1 ? "exact" : precision === 1 && recall >= 0.8 ? "tight"
      : precision >= 0.9 && recall >= 0.8 ? "good" : recall < 0.8 ? "leaky" : "loose";
    const num = (a, b) => a - b;
    return { valid: true, errors, tp, fp, fn, precision: r3(precision), recall: r3(recall), f1: r3(f1), verdict,
      matched: [...matched].sort(num).slice(0, 300), fp_events: [...matched].filter((i) => nset.has(i)).sort(num).slice(0, 50), fn_events: fnList.sort(num).slice(0, 50) };
  }

  function ips(events) {
    const out = [];
    for (const e of events) {
      const ip = e.ip || val(e, "c-ip");
      if (ip && LG().isPublic(String(ip)) && !out.includes(String(ip))) out.push(String(ip));
    }
    return out.slice(0, 50);
  }

  function autoTitle(P) {
    for (const field of ["action", "service", "program"]) {
      const vals = new Set(P.map((e) => val(e, field)).filter(Boolean));
      if (vals.size === 1) return `Malicious ${[...vals][0]} activity`.slice(0, 80);
    }
    return `Marked malicious ${P[0].fmt || "log"} activity`.slice(0, 80);
  }

  function synthesize(body) {
    body = body || {};
    const text = body.text || "";
    if (!String(text).trim()) throw new Error("paste the log, then mark which events are malicious");
    const { events: evs } = LG().parse(text, body.fmt || "auto");
    const byI = new Map(evs.map((e) => [e.i, e]));
    const indices = new Set((body.indices || []).map(Number).filter(Number.isInteger));
    if (!indices.size) throw new Error("mark at least one malicious event to synthesise a rule from");
    const P = [...indices].sort((a, b) => a - b).filter((i) => byI.has(i)).map((i) => byI.get(i));
    if (!P.length) throw new Error("none of the marked event indices are in this log");
    let N = evs.filter((e) => !indices.has(e.i));

    let baseN = 0;      // optional separate benign baseline — strengthens false-positive grading
    if (String(body.baseline || "").trim()) {
      const bevs = LG().parse(body.baseline, "auto").events;
      const off = evs.length ? Math.max(...evs.map((e) => e.i)) + 1 : 0;
      bevs.forEach((e, j) => { e.i = off + j; });
      N = N.concat(bevs);
      baseN = bevs.length;
    }
    const all = P.concat(N), pset = new Set(P.map((e) => e.i)), nset = new Set(N.map((e) => e.i));
    const cands = candidates(P, N);
    const title = String(body.title || "").trim().slice(0, 80) || autoTitle(P);

    const specs = [];
    if (cands.length) {
      specs.push([cands[0]]);                                                      // (a) simplest single discriminator
      const anded = greedyAnd(cands, P, N);
      if (anded.length && !(anded.length === 1 && anded[0] === cands[0])) specs.push(anded);   // (b) precision-first AND
      const clean = cands.find((c) => c.nhit === 0);                                // (c) best FP-free single feature
      if (clean && !specs.some((s) => s.length === 1 && s[0] === clean)) specs.push([clean]);
    }
    const graded = [], seen = new Set();
    for (const conds of specs) {
      const sig = conds.map((c) => c.field + "|" + c.mode + "|" + c.value.toLowerCase()).sort().join("\n");
      if (seen.has(sig)) continue;
      seen.add(sig);
      const rule = specToSigma(title, conds);
      const g = grade(rule, all, pset, nset);
      graded.push({ rule, valid: !!g.valid, conditions: conds.map((c) => ({ field: c.field, mode: c.mode, value: c.value })), grade: g });
    }
    const best = sortDesc(graded, (r) => [r.valid ? 1 : 0, r.grade.f1 || 0, -r.conditions.length]);

    const notes = [];
    if (!N.length) notes.push("No benign events to test against — false-positive rate is unmeasured. Add a baseline log.");
    if (cands.length && cands[0].nhit && cands.every((c) => c.nhit)) notes.push("Every mined field also appears in benign traffic — the best rule still carries some false-positive risk.");
    if (!best.length) notes.push("Couldn't mine a usable field from the marked events — they share no stable value. Mark a tighter set.");
    return { title, positives: P.length, negatives: N.length, baseline_events: baseN, fields_mined: cands.length,
      candidates: best.slice(0, +body.max_candidates || 4), recommended: best.length ? 0 : null, block_ips: ips(P), notes,
      marked: [...pset].sort((a, b) => a - b) };
  }

  /** "0-3, 7 9" → [0,1,2,3,7,9] (helper for the manual "malicious line numbers" box). */
  function parseIndices(s) {
    const out = new Set();
    for (const m of String(s || "").matchAll(/(\d+)\s*(?:-|–|\.\.)\s*(\d+)|(\d+)/g)) {
      if (m[3] != null) out.add(+m[3]);
      else { const a = +m[1], b = +m[2]; for (let i = Math.min(a, b); i <= Math.max(a, b) && out.size < 100000; i++) out.add(i); }
    }
    return [...out].sort((a, b) => a - b);
  }

  W.eng.synth = { synthesize, grade, parseIndices, tokens, FIELDS };
})(typeof window !== "undefined" ? window.W : globalThis.W);
