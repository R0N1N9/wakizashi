/* CVSS v3.1 engine (FIRST specification, incl. the 3.1 Roundup and the 3.0 vector prefix).
 *   parse("CVSS:3.1/AV:N/AC:L/...") → {metrics, errors}
 *   score(metricsOrVector) → {base, temporal, environmental, severity…, subscores, vector}
 *   vector(metrics) → canonical string (only non-"X" optional metrics)
 *   severity(n) → "None"|"Low"|"Medium"|"High"|"Critical" */
(function (W) {
  "use strict";
  const M = {
    // base
    AV: { name: "Attack Vector", group: "base", opts: { N: ["Network", 0.85], A: ["Adjacent", 0.62], L: ["Local", 0.55], P: ["Physical", 0.2] } },
    AC: { name: "Attack Complexity", group: "base", opts: { L: ["Low", 0.77], H: ["High", 0.44] } },
    PR: { name: "Privileges Required", group: "base", opts: { N: ["None", 0.85], L: ["Low", 0.62], H: ["High", 0.27] } },
    UI: { name: "User Interaction", group: "base", opts: { N: ["None", 0.85], R: ["Required", 0.62] } },
    S: { name: "Scope", group: "base", opts: { U: ["Unchanged"], C: ["Changed"] } },
    C: { name: "Confidentiality", group: "base", opts: { H: ["High", 0.56], L: ["Low", 0.22], N: ["None", 0] } },
    I: { name: "Integrity", group: "base", opts: { H: ["High", 0.56], L: ["Low", 0.22], N: ["None", 0] } },
    A: { name: "Availability", group: "base", opts: { H: ["High", 0.56], L: ["Low", 0.22], N: ["None", 0] } },
    // temporal
    E: { name: "Exploit Code Maturity", group: "temporal", opts: { X: ["Not Defined", 1], H: ["High", 1], F: ["Functional", 0.97], P: ["Proof-of-Concept", 0.94], U: ["Unproven", 0.91] } },
    RL: { name: "Remediation Level", group: "temporal", opts: { X: ["Not Defined", 1], U: ["Unavailable", 1], W: ["Workaround", 0.97], T: ["Temporary Fix", 0.96], O: ["Official Fix", 0.95] } },
    RC: { name: "Report Confidence", group: "temporal", opts: { X: ["Not Defined", 1], C: ["Confirmed", 1], R: ["Reasonable", 0.96], U: ["Unknown", 0.92] } },
    // environmental
    CR: { name: "Confidentiality Requirement", group: "environmental", opts: { X: ["Not Defined", 1], H: ["High", 1.5], M: ["Medium", 1], L: ["Low", 0.5] } },
    IR: { name: "Integrity Requirement", group: "environmental", opts: { X: ["Not Defined", 1], H: ["High", 1.5], M: ["Medium", 1], L: ["Low", 0.5] } },
    AR: { name: "Availability Requirement", group: "environmental", opts: { X: ["Not Defined", 1], H: ["High", 1.5], M: ["Medium", 1], L: ["Low", 0.5] } },
  };
  for (const b of ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]) {
    M["M" + b] = { name: "Modified " + M[b].name, group: "environmental", base: b, opts: Object.assign({ X: ["Not Defined"] }, M[b].opts) };
  }
  const BASE = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  const ORDER = BASE.concat(["E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]);

  /** FIRST CVSS v3.1 Roundup: smallest number with one decimal ≥ input, robust to float error. */
  function roundup(x) {
    const i = Math.round(x * 100000);
    return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
  }
  const severity = (s) => (s == null ? null : s === 0 ? "None" : s < 4 ? "Low" : s < 7 ? "Medium" : s < 9 ? "High" : "Critical");

  /** Parse a vector. Base metrics are mandatory; optional ones default to X. */
  function parse(str) {
    const errors = [], metrics = {};
    let s = String(str == null ? "" : str).trim().replace(/^\(|\)$/g, "");
    let version = "3.1";
    const pm = /^CVSS:(\d\.\d)\//i.exec(s);
    if (pm) { version = pm[1]; s = s.slice(pm[0].length); if (version !== "3.1" && version !== "3.0") errors.push(`unsupported CVSS version ${version} (this calculator scores v3.0/v3.1)`); }
    for (const part of s.split("/").filter(Boolean)) {
      const [k, v, extra] = part.split(":");
      const key = (k || "").toUpperCase(), val = (v || "").toUpperCase();
      if (extra !== undefined || !M[key]) { errors.push(`unknown metric “${part}”`); continue; }
      if (!(val in M[key].opts)) { errors.push(`invalid value “${v}” for ${key}`); continue; }
      if (key in metrics) { errors.push(`duplicate metric ${key}`); continue; }
      metrics[key] = val;
    }
    for (const b of BASE) if (!(b in metrics)) errors.push(`missing base metric ${b}`);
    for (const k of ORDER) if (!(k in metrics) && !BASE.includes(k)) metrics[k] = "X";
    return { version, metrics, errors, ok: !errors.length };
  }
  /** Canonical vector string. */
  function vector(m, version = "3.1") {
    return `CVSS:${version}/` + ORDER.filter((k) => m[k] && (BASE.includes(k) || m[k] !== "X")).map((k) => `${k}:${m[k]}`).join("/");
  }
  const w = (k, v) => M[k].opts[v][1];

  /** Score a metrics object or vector string. Throws on an invalid vector. */
  function score(input) {
    let m = input, version = "3.1";
    if (typeof input === "string") { const p = parse(input); if (!p.ok) throw new Error(p.errors.join("; ")); m = p.metrics; version = p.version; }
    else { m = Object.assign({}, input); for (const b of BASE) if (!m[b]) throw new Error(`missing base metric ${b}`); for (const k of ORDER) if (!m[k]) m[k] = "X"; }
    // ---- base
    const changed = m.S === "C";
    const pr = (v, ch) => (v === "L" ? (ch ? 0.68 : 0.62) : v === "H" ? (ch ? 0.5 : 0.27) : 0.85);
    const iss = 1 - (1 - w("C", m.C)) * (1 - w("I", m.I)) * (1 - w("A", m.A));
    const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const exploit = 8.22 * w("AV", m.AV) * w("AC", m.AC) * pr(m.PR, changed) * w("UI", m.UI);
    const base = impact <= 0 ? 0 : changed ? roundup(Math.min(1.08 * (impact + exploit), 10)) : roundup(Math.min(impact + exploit, 10));
    // ---- temporal
    const tm = w("E", m.E) * w("RL", m.RL) * w("RC", m.RC);
    const temporal = roundup(base * tm);
    // ---- environmental
    const mod = (k) => (m["M" + k] && m["M" + k] !== "X" ? m["M" + k] : m[k]);
    const mChanged = mod("S") === "C";
    const miss = Math.min(1 - (1 - w("CR", m.CR) * w("C", mod("C"))) * (1 - w("IR", m.IR) * w("I", mod("I"))) * (1 - w("AR", m.AR) * w("A", mod("A"))), 0.915);
    const mImpact = !mChanged ? 6.42 * miss : version === "3.0"
      ? 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss - 0.02, 15)          // v3.0 formula
      : 7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);
    const mExploit = 8.22 * w("AV", mod("AV")) * w("AC", mod("AC")) * pr(mod("PR"), mChanged) * w("UI", mod("UI"));
    const environmental = mImpact <= 0 ? 0 : mChanged
      ? roundup(roundup(Math.min(1.08 * (mImpact + mExploit), 10)) * tm)
      : roundup(roundup(Math.min(mImpact + mExploit, 10)) * tm);
    const hasT = ["E", "RL", "RC"].some((k) => m[k] !== "X");
    const hasE = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"].some((k) => m[k] !== "X");
    const r1 = (x) => Math.round(x * 10) / 10;
    const overall = hasE ? environmental : hasT ? temporal : base;
    return {
      version, metrics: m, vector: vector(m, version),
      base, baseSeverity: severity(base), temporal, temporalSeverity: severity(temporal), environmental, environmentalSeverity: severity(environmental),
      impact: r1(Math.max(0, impact)), exploitability: r1(exploit), modifiedImpact: r1(Math.max(0, mImpact)),
      hasTemporal: hasT, hasEnvironmental: hasE, overall, overallSeverity: severity(overall),
    };
  }
  /** Lower-case severity key for badges: critical | high | medium | low | info. */
  const sevKey = (s) => ({ Critical: "critical", High: "high", Medium: "medium", Low: "low", None: "info" })[s] || "info";

  W.eng.cvss = { METRICS: M, BASE, ORDER, roundup, severity, sevKey, parse, vector, score };
})(typeof window !== "undefined" ? window.W : globalThis.W);
