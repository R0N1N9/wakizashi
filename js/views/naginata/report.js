(function () {
  "use strict";
  const { $, esc, ui } = W;
  const K = (k) => "naginata.report." + k;
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const SEV_L = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" };
  const STAT = [["open", "Open"], ["retest", "Ready for retest"], ["fixed", "Remediated"], ["accepted", "Risk accepted"], ["fp", "False positive"]];
  const STAT_L = Object.fromEntries(STAT);
  const FIELDS = ["title", "severity", "cvss", "assets", "description", "evidence", "remediation", "references", "status"];

  // ------------------------------------------------------------------ model
  const load = () => W.store.get(K("findings"), []);
  const save = (f) => W.store.set(K("findings"), f);
  const meta = () => Object.assign({ title: "", author: "", classification: "Confidential", date: new Date().toISOString().slice(0, 10), summary: "", methodology: "" }, W.store.get(K("meta"), {}));
  const scopeNow = () => ({ in: W.store.get("naginata.scope.in", ""), out: W.store.get("naginata.scope.out", "") });
  const engagement = () => W.store.get("naginata.scope.engagement", {});
  const hasScope = (s) => !!(s.in.trim() || s.out.trim());

  function cvssOf(f) {
    if (!f.cvss || !f.cvss.trim()) return null;
    try { return W.eng.cvss.score(f.cvss.trim()); } catch { return { error: true }; }
  }
  /** Effective severity: manual, or derived from the CVSS score when set to auto. */
  function sevOf(f) {
    if (f.severity && f.severity !== "auto") return f.severity;
    const c = cvssOf(f);
    return c && !c.error ? W.eng.cvss.sevKey(c.overallSeverity) : "info";
  }
  const assetList = (f) => String(f.assets || "").split(/\r?\n|,/).map((s) => s.trim()).filter(Boolean);
  function assetChecks(f, sc) {
    if (!hasScope(sc)) return assetList(f).map((a) => ({ asset: a, verdict: null }));
    return assetList(f).map((a) => { const r = W.eng.scope.check(a, sc); return { asset: a, verdict: r.verdict, reason: r.reason }; });
  }
  const offScope = (chk) => chk.filter((c) => c.verdict && c.verdict !== "in");
  function sorted(list) {
    const rank = (f) => SEVS.indexOf(sevOf(f));
    return list.slice().sort((a, b) => rank(a) - rank(b) || ((cvssOf(b) || {}).overall || 0) - ((cvssOf(a) || {}).overall || 0) || String(a.created).localeCompare(String(b.created)));
  }
  const refId = (i) => "F-" + String(i + 1).padStart(2, "0");

  // ------------------------------------------------------------------ exporters
  function fence(text) {
    const runs = String(text).match(/`{3,}/g) || [];
    const n = Math.max(3, ...runs.map((r) => r.length + 1));
    return "`".repeat(n);
  }
  const mdInline = (s) => String(s || "").replace(/([\\`*_[\]<>|])/g, "\\$1").replace(/\r?\n/g, " ");
  function toMarkdown() {
    const m = meta(), e = engagement(), sc = scopeNow(), list = sorted(load());
    const counts = Object.fromEntries(SEVS.map((s) => [s, list.filter((f) => sevOf(f) === s).length]));
    const L = [];
    L.push(`# ${mdInline(m.title || e.name || "Security assessment report")}`, "");
    const facts = [["Client", e.client], ["Engagement", e.name], ["Testing window", e.start || e.end ? `${e.start || "?"} → ${e.end || "?"}` : ""], ["Author", m.author], ["Date", m.date], ["Classification", m.classification]].filter((x) => x[1]);
    if (facts.length) L.push(facts.map(([k, v]) => `**${k}:** ${mdInline(v)}`).join("  \n"), "");
    if (m.summary.trim()) L.push("## Executive summary", "", m.summary.trim(), "");
    L.push("## Summary of findings", "", "| ID | Title | Severity | CVSS | Status |", "|---|---|---|---|---|");
    list.forEach((f, i) => { const c = cvssOf(f); L.push(`| ${refId(i)} | ${mdInline(f.title || "Untitled")} | ${SEV_L[sevOf(f)]} | ${c && !c.error ? c.overall.toFixed(1) : "—"} | ${STAT_L[f.status] || "Open"} |`); });
    L.push("", SEVS.map((s) => `${SEV_L[s]}: ${counts[s]}`).join(" · "), "");
    if (hasScope(sc)) {
      L.push("## Scope", "", "**In scope**", "", ...W.eng.scope.parseList(sc.in).entries.map((x) => `- \`${x.label}\``), "");
      const outs = W.eng.scope.parseList(sc.out).entries; if (outs.length) L.push("**Out of scope**", "", ...outs.map((x) => `- \`${x.label}\``), "");
    }
    if (m.methodology.trim()) L.push("## Methodology", "", m.methodology.trim(), "");
    L.push("## Findings", "");
    list.forEach((f, i) => {
      const c = cvssOf(f), chk = assetChecks(f, sc);
      L.push(`### ${refId(i)} — ${mdInline(f.title || "Untitled")}`, "");
      L.push(`**Severity:** ${SEV_L[sevOf(f)]}${c && !c.error ? `  \n**CVSS v3.1:** ${c.overall.toFixed(1)} (\`${c.vector}\`)` : ""}  \n**Status:** ${STAT_L[f.status] || "Open"}`, "");
      if (chk.length) { L.push("**Affected assets:**", ""); for (const a of chk) L.push(`- \`${a.asset.replace(/`/g, "'")}\`${a.verdict && a.verdict !== "in" ? ` — ⚠ ${a.verdict === "out" ? "OUT OF SCOPE" : a.verdict.toUpperCase()}: ${mdInline(a.reason)}` : ""}`); L.push(""); }
      for (const [k, label] of [["description", "Description"], ["remediation", "Remediation"]]) if (String(f[k] || "").trim()) L.push(`#### ${label}`, "", String(f[k]).trim(), "");
      if (String(f.evidence || "").trim()) { const fz = fence(f.evidence); L.push("#### Evidence", "", fz, String(f.evidence).replace(/\s+$/, ""), fz, ""); }
      const refs = String(f.references || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (refs.length) L.push("#### References", "", ...refs.map((r) => `- ${r}`), "");
    });
    L.push("---", `_Generated with Wakizashi · ${W.nowIso()}_`, "");
    return L.join("\n");
  }

  const CSS = `:root{--ink:#14202b;--dim:#5b6b7b;--line:#d7dee6;--crit:#b3132b;--high:#c65a00;--med:#9a7a00;--low:#1f5fbf;--info:#4b6b8a;--ok:#16794a}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:#fff}
main{max-width:920px;margin:0 auto;padding:32px 20px 60px}h1{font-size:28px;margin:0 0 6px}h2{font-size:20px;margin:34px 0 10px;border-bottom:2px solid var(--ink);padding-bottom:4px}
h3{font-size:17px;margin:0}h4{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin:16px 0 6px}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:2px 14px;font-size:14px;margin:12px 0}.facts dt{color:var(--dim)}.facts dd{margin:0}
.cls{display:inline-block;border:1px solid var(--crit);color:var(--crit);font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;padding:2px 8px;border-radius:3px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim)}
.tw{overflow-x:auto}.sev{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:2px 7px;border-radius:3px;color:#fff;white-space:nowrap}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.f{border:1px solid var(--line);border-left:5px solid var(--info);border-radius:6px;padding:16px 18px;margin:18px 0;break-inside:avoid-page}
.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}
.fh{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.meta{font-size:13px;color:var(--dim);margin-top:6px}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
code{background:#f1f4f7;padding:1px 4px;border-radius:3px;word-break:break-all}pre{background:#0f1720;color:#e3ebf3;padding:12px;border-radius:5px;white-space:pre-wrap;word-break:break-word;overflow:auto}
.txt{white-space:pre-wrap;word-break:break-word}.warn{color:var(--crit);font-weight:600}.counts{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
footer{margin-top:40px;font-size:12px;color:var(--dim)}a{color:var(--low);word-break:break-all}@media print{main{padding:0}.f{page-break-inside:avoid}}`;
  const safeUrl = (u) => /^https?:\/\/[^\s"'<>]+$/i.test(u);
  function toHtml() {
    const m = meta(), e = engagement(), sc = scopeNow(), list = sorted(load());
    const title = m.title || e.name || "Security assessment report";
    const counts = Object.fromEntries(SEVS.map((s) => [s, list.filter((f) => sevOf(f) === s).length]));
    const facts = [["Client", e.client], ["Engagement", e.name], ["Testing window", e.start || e.end ? `${e.start || "?"} → ${e.end || "?"}` : ""], ["Author", m.author], ["Date", m.date]].filter((x) => x[1]);
    const txt = (s) => `<div class="txt">${esc(String(s).trim())}</div>`;
    const sev = (s) => `<span class="sev ${s}">${esc(SEV_L[s])}</span>`;
    const body = [];
    body.push(`<header>${m.classification ? `<span class="cls">${esc(m.classification)}</span>` : ""}<h1>${esc(title)}</h1>${facts.length ? `<dl class="facts">${facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>` : ""}</header>`);
    if (m.summary.trim()) body.push(`<h2>Executive summary</h2>${txt(m.summary)}`);
    body.push(`<h2>Summary of findings</h2><div class="counts">${SEVS.map((s) => `${sev(s)} <b>${counts[s]}</b>`).join("&nbsp; ")}</div>
      <div class="tw"><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Status</th></tr></thead><tbody>${list.map((f, i) => { const c = cvssOf(f); return `<tr><td><a href="#${refId(i)}">${refId(i)}</a></td><td>${esc(f.title || "Untitled")}</td><td>${sev(sevOf(f))}</td><td>${c && !c.error ? c.overall.toFixed(1) : "—"}</td><td>${esc(STAT_L[f.status] || "Open")}</td></tr>`; }).join("") || '<tr><td colspan="5">No findings recorded.</td></tr>'}</tbody></table></div>`);
    if (hasScope(sc)) {
      const ins = W.eng.scope.parseList(sc.in).entries, outs = W.eng.scope.parseList(sc.out).entries;
      body.push(`<h2>Scope</h2><h4>In scope</h4><p>${ins.map((x) => `<code>${esc(x.label)}</code>`).join(" ") || "—"}</p>${outs.length ? `<h4>Out of scope</h4><p>${outs.map((x) => `<code>${esc(x.label)}</code>`).join(" ")}</p>` : ""}`);
    }
    if (m.methodology.trim()) body.push(`<h2>Methodology</h2>${txt(m.methodology)}`);
    body.push(`<h2>Findings</h2>`);
    list.forEach((f, i) => {
      const c = cvssOf(f), s = sevOf(f), chk = assetChecks(f, sc);
      const refs = String(f.references || "").split(/\r?\n/).map((r) => r.trim()).filter(Boolean);
      body.push(`<section class="f ${s}" id="${refId(i)}"><div class="fh"><h3>${refId(i)} — ${esc(f.title || "Untitled")}</h3>${sev(s)}</div>
        <div class="meta">${c && !c.error ? `CVSS v3.1 <b>${c.overall.toFixed(1)}</b> · <code>${esc(c.vector)}</code> · ` : ""}Status: ${esc(STAT_L[f.status] || "Open")}</div>
        ${chk.length ? `<h4>Affected assets</h4><ul>${chk.map((a) => `<li><code>${esc(a.asset)}</code>${a.verdict && a.verdict !== "in" ? ` <span class="warn">⚠ ${esc(a.verdict === "out" ? "OUT OF SCOPE" : a.verdict.toUpperCase())} — ${esc(a.reason)}</span>` : ""}</li>`).join("")}</ul>` : ""}
        ${String(f.description || "").trim() ? `<h4>Description</h4>${txt(f.description)}` : ""}
        ${String(f.evidence || "").trim() ? `<h4>Evidence</h4><pre>${esc(String(f.evidence).replace(/\s+$/, ""))}</pre>` : ""}
        ${String(f.remediation || "").trim() ? `<h4>Remediation</h4>${txt(f.remediation)}` : ""}
        ${refs.length ? `<h4>References</h4><ul>${refs.map((r) => `<li>${safeUrl(r) ? `<a href="${esc(r)}" rel="noopener noreferrer">${esc(r)}</a>` : esc(r)}</li>`).join("")}</ul>` : ""}</section>`);
    });
    body.push(`<footer>Generated with Wakizashi · ${esc(W.nowIso())}</footer>`);
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>${esc(title)}</title><style>${CSS}</style></head><body><main>
${body.join("\n")}
</main></body></html>`;
  }
  W.naginataReport = { toMarkdown, toHtml, sevOf, assetChecks };      // exposed for the browser test harness

  // ------------------------------------------------------------------ view
  W.tool("naginata", "report", {
    name: "Report", order: 60,
    desc: "Write up findings with severity, CVSS, affected assets (scope-checked), evidence and fixes — export Markdown or HTML.",
    icon: '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4M9 12h6M9 16h6M9 8h2"/>',
    render(el, arg) {
      W.roeGate(el, () => {
        let sel = W.store.get(K("sel"), null);
        if (arg && typeof arg === "object") {                                  // prefill from CVSS / Headers
          const f = blank();
          for (const k of FIELDS) if (arg[k] != null) f[k] = String(arg[k]);
          if (arg.cvss && !arg.severity) f.severity = "auto";
          const list = load(); list.push(f); save(list); sel = f.id; W.store.set(K("sel"), sel);
          setTimeout(() => W.toast("New finding created"), 0);
        }
        const m = meta();
        el.innerHTML = ui.head("Report", "Findings writer", "Findings are saved in this browser. Affected assets are checked against the Scope board — anything outside it is flagged before it reaches the report.") + `
          <div id="rp-stats"></div>
          <details class="panel" id="rp-meta-box" ${m.title || m.summary ? "" : "open"}><summary class="ptitle" style="cursor:pointer;margin:0">Report details</summary><div class="spacer"></div>
            <div class="grid g2">
              <div><label class="lbl" for="rp-m-title">Report title</label><input id="rp-m-title" type="text" maxlength="200" placeholder="${esc(engagement().name || "External penetration test")}"></div>
              <div><label class="lbl" for="rp-m-author">Author / tester</label><input id="rp-m-author" type="text" maxlength="160"></div>
              <div><label class="lbl" for="rp-m-date">Report date</label><input id="rp-m-date" type="date"></div>
              <div><label class="lbl" for="rp-m-class">Classification</label><input id="rp-m-class" type="text" maxlength="60"></div>
            </div><div class="spacer"></div>
            <label class="lbl" for="rp-m-summary">Executive summary</label><textarea id="rp-m-summary" rows="4"></textarea>
            <div class="spacer"></div><label class="lbl" for="rp-m-method">Methodology</label><textarea id="rp-m-method" rows="3" placeholder="Approach, standards followed (OWASP WSTG, PTES), tools, limitations…"></textarea>
          </details>
          <div class="row"><button class="btn pri" id="rp-new">${W.icon(W.I.plus)} New finding</button>
            <button class="btn" id="rp-md">${W.icon(W.I.dl)} Markdown</button><button class="btn" id="rp-html">${W.icon(W.I.dl)} HTML report</button>
            <button class="btn ghost" id="rp-json">${W.icon(W.I.dl)} JSON</button><label class="btn ghost">${W.icon(W.I.up)} Import<input type="file" id="rp-imp" accept=".json,application/json"></label>
            <button class="btn ghost" id="rp-preview">Preview</button></div>
          <div class="spacer"></div>
          <div class="grid g2" style="align-items:start">
            <div class="panel"><h2>Findings</h2><div class="ng-flist" id="rp-list"></div></div>
            <div id="rp-edit"></div>
          </div>`;

        // ---- meta
        const mf = { title: "#rp-m-title", author: "#rp-m-author", date: "#rp-m-date", classification: "#rp-m-class", summary: "#rp-m-summary", methodology: "#rp-m-method" };
        for (const [k, s] of Object.entries(mf)) { $(s).value = m[k] || ""; $(s).addEventListener("input", W.debounce(() => { const o = meta(); o[k] = $(s).value; W.store.set(K("meta"), o); }, 200)); }

        function blank() { return { id: W.uid(), title: "", severity: "auto", cvss: "", assets: "", description: "", evidence: "", remediation: "", references: "", status: "open", created: W.nowIso(), updated: W.nowIso() }; }
        $("#rp-new").onclick = () => { const f = blank(); const l = load(); l.push(f); save(l); sel = f.id; W.store.set(K("sel"), sel); drawList(); drawEdit(); setTimeout(() => $("#rp-f-title") && $("#rp-f-title").focus(), 0); };

        function drawStats() {
          const l = load(), c = Object.fromEntries(SEVS.map((s) => [s, 0])); for (const f of l) c[sevOf(f)]++;
          const sc = scopeNow(), off = hasScope(sc) ? l.filter((f) => offScope(assetChecks(f, sc)).length).length : 0;
          $("#rp-stats").innerHTML = `<div class="grid g4">${ui.stat(l.length, "Findings", true)}${ui.stat(c.critical + c.high, "Critical + high")}${ui.stat(l.filter((f) => f.status === "open" || !f.status).length, "Open")}${ui.stat(off, "Out-of-scope assets")}</div>`
            + (!hasScope(sc) ? `<div class="callout warn small">No scope recorded yet — add it on the <a href="#/naginata/scope">Scope board</a> so affected assets can be checked.</div><div class="spacer"></div>` : "");
        }
        function drawList() {
          drawStats();
          const l = sorted(load()), sc = scopeNow();
          $("#rp-list").innerHTML = l.length ? l.map((f, i) => {
            const s = sevOf(f), c = cvssOf(f), off = offScope(assetChecks(f, sc));
            return `<div class="finding ${s}${f.id === sel ? " on" : ""}" data-id="${esc(f.id)}" tabindex="0" role="button"><header><span class="tiny mono faint">${refId(i)}</span>${ui.sev(s)}<h3>${esc(f.title || "Untitled finding")}</h3></header>
              <div class="det">${c && !c.error ? `CVSS ${c.overall.toFixed(1)} · ` : c && c.error ? '<span class="c-crit">invalid CVSS</span> · ' : ""}${esc(STAT_L[f.status] || "Open")} · ${assetList(f).length} asset(s)${off.length ? ` · <span class="c-crit">${off.length} not in scope</span>` : ""}</div></div>`;
          }).join("") : ui.empty("NO FINDINGS", "Create one, or send one here from the CVSS or Headers tools.");
        }
        const pick = (e) => { const c = e.target.closest(".finding[data-id]"); if (!c) return; sel = c.dataset.id; W.store.set(K("sel"), sel); drawList(); drawEdit(); if (innerWidth < 640) $("#rp-edit").scrollIntoView({ behavior: "smooth", block: "start" }); };
        $("#rp-list").addEventListener("click", pick);
        $("#rp-list").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(e); } });

        function drawEdit() {
          const f = load().find((x) => x.id === sel), box = $("#rp-edit");
          if (!f) { box.innerHTML = ui.panel("Edit", ui.empty("SELECT A FINDING", "Pick one on the left, or create a new one.")); return; }
          box.innerHTML = ui.panel("Edit finding", `
            <label class="lbl" for="rp-f-title">Title</label><input id="rp-f-title" type="text" maxlength="200" placeholder="Stored XSS in profile display name">
            <div class="spacer"></div>
            <div class="grid g2">
              <div><label class="lbl" for="rp-f-severity">Severity</label><select id="rp-f-severity"><option value="auto">Auto (from CVSS)</option>${SEVS.map((s) => `<option value="${s}">${SEV_L[s]}</option>`).join("")}</select></div>
              <div><label class="lbl" for="rp-f-status">Status</label><select id="rp-f-status">${STAT.map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select></div>
            </div><div class="spacer"></div>
            <label class="lbl" for="rp-f-cvss">CVSS v3.1 vector</label>
            <div class="row"><input id="rp-f-cvss" type="text" style="flex:1;min-width:180px" spellcheck="false" autocapitalize="off" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"><button class="btn sm" id="rp-f-calc">Calculator</button></div>
            <div id="rp-f-cvss-r" class="small" style="margin-top:6px"></div>
            <div class="spacer"></div>
            <label class="lbl" for="rp-f-assets">Affected assets — one per line</label><textarea id="rp-f-assets" rows="3" spellcheck="false" autocapitalize="off" placeholder="app.example.com&#10;10.0.4.12:8443"></textarea>
            <div id="rp-f-assets-r"></div>
            <div class="spacer"></div><label class="lbl" for="rp-f-description">Description</label><textarea id="rp-f-description" rows="5" placeholder="What the issue is, where it is, and its impact."></textarea>
            <div class="spacer"></div><label class="lbl" for="rp-f-evidence">Evidence</label><textarea id="rp-f-evidence" rows="5" spellcheck="false" placeholder="Request/response excerpts, steps to reproduce, screenshots referenced by name. Redact secrets."></textarea>
            <div class="spacer"></div><label class="lbl" for="rp-f-remediation">Remediation</label><textarea id="rp-f-remediation" rows="4"></textarea>
            <div class="spacer"></div><label class="lbl" for="rp-f-references">References — one per line</label><textarea id="rp-f-references" rows="2" spellcheck="false" placeholder="https://cwe.mitre.org/data/definitions/79.html"></textarea>
            <div class="spacer"></div>
            <div class="row"><button class="btn ghost" id="rp-f-dup">Duplicate</button><button class="btn danger" id="rp-f-del">${W.icon(W.I.trash)} Delete</button><span class="small faint" id="rp-f-saved"></span></div>`);
          for (const k of FIELDS) $("#rp-f-" + k).value = f[k] || (k === "severity" ? "auto" : k === "status" ? "open" : "");
          const persist = W.debounce(() => {
            const l = load(), it = l.find((x) => x.id === sel); if (!it) return;
            for (const k of FIELDS) it[k] = String($("#rp-f-" + k).value).slice(0, k === "evidence" ? 50000 : 20000);
            it.updated = W.nowIso(); save(l); drawList(); $("#rp-f-saved").textContent = "saved " + new Date().toLocaleTimeString();
          }, 300);
          for (const k of FIELDS) $("#rp-f-" + k).addEventListener(k === "severity" || k === "status" ? "change" : "input", () => { if (k === "cvss" || k === "severity") cvssLine(); if (k === "assets") assetLine(); persist(); });
          function cvssLine() {
            const v = $("#rp-f-cvss").value.trim(), r = $("#rp-f-cvss-r");
            if (!v) { r.innerHTML = '<span class="faint">No vector — set severity manually, or open the calculator.</span>'; return; }
            const p = W.eng.cvss.parse(v);
            if (!p.ok) { r.innerHTML = `<span class="c-crit">${esc(p.errors.join("; "))}</span>`; return; }
            const c = W.eng.cvss.score(p.metrics), k = W.eng.cvss.sevKey(c.overallSeverity), manual = $("#rp-f-severity").value;
            r.innerHTML = `${ui.sev(k)} <b class="mono">${c.overall.toFixed(1)}</b> <span class="muted">${esc(c.overallSeverity)} · base ${c.base.toFixed(1)}</span>${manual !== "auto" && manual !== k ? ` <span class="c-med">— severity overridden to ${esc(SEV_L[manual])}</span>` : ""}`;
          }
          function assetLine() {
            const sc = scopeNow(), chk = assetChecks({ assets: $("#rp-f-assets").value }, sc), r = $("#rp-f-assets-r");
            if (!chk.length) { r.innerHTML = ""; return; }
            if (!hasScope(sc)) { r.innerHTML = `<div class="small faint" style="margin-top:6px">No scope recorded — assets can't be checked.</div>`; return; }
            const V = { in: ["in scope", "ok"], out: ["OUT OF SCOPE", "crit"], partial: ["partial", "med"], unlisted: ["not listed", "high"], unresolved: ["resolve first", "info"], invalid: ["invalid", ""] };
            r.innerHTML = `<div style="margin-top:6px">${chk.map((a) => `<div class="row small" style="gap:6px;margin:3px 0">${ui.badge(V[a.verdict][0], V[a.verdict][1])}<span class="mono break">${esc(a.asset)}</span>${a.verdict !== "in" ? `<span class="faint">${esc(a.reason)}</span>` : ""}</div>`).join("")}</div>`
              + (offScope(chk).length ? `<div class="callout bad small" style="margin-top:6px">${offScope(chk).length} asset(s) aren't covered by the scope. Confirm authorisation before reporting (or testing) them.</div>` : "");
          }
          cvssLine(); assetLine();
          $("#rp-f-calc").onclick = () => W.go("naginata", "cvss", $("#rp-f-cvss").value.trim() || undefined);
          $("#rp-f-del").onclick = () => { if (!confirm("Delete this finding?")) return; save(load().filter((x) => x.id !== sel)); sel = null; W.store.del(K("sel")); drawList(); drawEdit(); };
          $("#rp-f-dup").onclick = () => { const l = load(), it = l.find((x) => x.id === sel); if (!it) return; const c = Object.assign({}, it, { id: W.uid(), title: (it.title || "Untitled") + " (copy)", created: W.nowIso() }); l.push(c); save(l); sel = c.id; drawList(); drawEdit(); };
        }

        // ---- export / import
        const fname = (ext) => `report-${(meta().title || engagement().name || "findings").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 50) || "findings"}.${ext}`;
        $("#rp-md").onclick = () => W.download(fname("md"), toMarkdown(), "text/markdown;charset=utf-8");
        $("#rp-html").onclick = () => W.download(fname("html"), toHtml(), "text/html;charset=utf-8");
        $("#rp-json").onclick = () => W.download(fname("json"), JSON.stringify({ app: "wakizashi", kind: "naginata.report", exported: W.nowIso(), meta: meta(), findings: load() }, null, 2), "application/json");
        $("#rp-preview").onclick = () => W.modal(`<pre class="out" style="max-height:65vh">${esc(toMarkdown())}</pre><div class="spacer"></div><button class="btn" id="rp-pv-copy">${W.icon(W.I.copy)} Copy Markdown</button>`, { title: "Report preview (Markdown)" }) && ($("#rp-pv-copy").onclick = () => W.copy(toMarkdown()));
        $("#rp-imp").onchange = async (e) => {
          const file = e.target.files[0]; e.target.value = ""; if (!file) return;
          try {
            const j = JSON.parse(await W.readFile(file));
            if (!j || j.kind !== "naginata.report" || !Array.isArray(j.findings)) throw new Error("not a Wakizashi report export");
            const merge = load().length && confirm("OK = add to the existing findings · Cancel = replace them");
            const clean = j.findings.filter((x) => x && typeof x === "object").map((x) => { const f = blank(); for (const k of FIELDS) if (x[k] != null) f[k] = String(x[k]); if (!SEVS.includes(f.severity)) f.severity = "auto"; if (!STAT_L[f.status]) f.status = "open"; f.created = String(x.created || f.created); return f; });
            save(merge ? load().concat(clean) : clean);
            if (j.meta && typeof j.meta === "object") { const o = meta(); for (const k of Object.keys(o)) if (j.meta[k] != null) o[k] = String(j.meta[k]); W.store.set(K("meta"), o); }
            W.toast(`${clean.length} finding(s) imported`); W.go("naginata", "report");
          } catch (err) { W.toast(err.message, 1); }
        };
        drawList(); drawEdit();
      });
    },
  });
})();
