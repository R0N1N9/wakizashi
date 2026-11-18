(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const VERDICTS = ["", "malicious", "suspicious", "info", "clean"];

  W.tool("yumi", "case", {
    name: "Case", order: 30,
    desc: "Investigations shared by every layer — indicators, verdicts, notes; export Markdown, CSV, JSON or STIX.",
    help: {
      steps: ["Create or pick the active case — every layer adds indicators to it.", "Add items, set verdicts, tags and notes.", "Export as a Markdown report, CSV, JSON or STIX 2.1 to share."],
      tips: ["Cases live only in this browser — export them, or take a backup from Settings."],
    },
    icon: W.I.case,
    render(el) {
      const draw = () => {
        const ws = W.Case.ws, c = W.Case.active();
        const q = (W.store.get("yumi.case.q", "") || "").toLowerCase();
        const items = c.items.filter((x) => !q || (x.value + " " + x.type + " " + (x.tags || []).join(" ") + " " + (x.note || "")).toLowerCase().includes(q));
        const byV = (v) => c.items.filter((x) => x.verdict === v).length;
        el.innerHTML = ui.head("Case", "Investigations", "Every layer adds to the active case. Cases live only in this browser — export to share.") + `
          <div class="panel"><div class="row">
            <select id="cs-sel" style="flex:1;min-width:180px" aria-label="Active case">${ws.cases.map((x) => `<option value="${esc(x.id)}" ${x.id === c.id ? "selected" : ""}>${esc(x.name)} (${x.items.length})</option>`).join("")}</select>
            <button class="btn sm" id="cs-new">${W.icon(W.I.plus)} New</button><button class="btn sm" id="cs-ren">Rename</button><button class="btn sm danger" id="cs-del">${W.icon(W.I.trash)}</button></div></div>
          <div class="grid g4">${ui.stat(c.items.length, "Indicators", true)}${ui.stat(byV("malicious"), "Malicious")}${ui.stat(byV("suspicious"), "Suspicious")}${ui.stat(W.uniq(c.items.map((x) => x.type)).length, "Types")}</div>
          <div class="grid g2">
            ${ui.panel("Add indicators", `<textarea id="cs-add" rows="3" spellcheck="false" placeholder="One per line, or paste any text — indicators are extracted"></textarea><div class="spacer"></div>
              <div class="row"><button class="btn sm pri" id="cs-addgo">${W.icon(W.I.plus)} Add</button><label class="btn sm ghost">${W.icon(W.I.up)} Import JSON / CSV / text<input type="file" id="cs-imp" accept=".json,.csv,.txt"></label></div>`)}
            ${ui.panel("Export", `<div class="row"><button class="btn sm" data-x="md">${W.icon(W.I.dl)} Markdown report</button><button class="btn sm" data-x="csv">CSV</button><button class="btn sm" data-x="json">JSON</button>
              <select id="cs-tlp" style="width:auto">${["clear", "green", "amber", "red"].map((t) => `<option ${t === "amber" ? "selected" : ""}>${t}</option>`).join("")}</select><button class="btn sm" data-x="stix">STIX 2.1</button></div>
              <div class="spacer"></div><label class="lbl" for="cs-notes">Analyst notes</label><textarea id="cs-notes" rows="4">${esc(c.notes || "")}</textarea>`)}
          </div>
          <div class="panel"><div class="row" style="justify-content:space-between"><h2 style="margin:0">Indicators</h2>
            <input type="search" id="cs-q" placeholder="filter…" value="${esc(q)}" style="max-width:260px"></div><div class="spacer"></div>
            ${items.length ? `<div class="tablewrap"><table class="tbl"><thead><tr><th>Value</th><th>Type</th><th>Verdict</th><th class="hide-sm">Tags / note</th><th></th></tr></thead><tbody>
              ${items.map((x) => `<tr data-v="${esc(x.value)}"><td class="mono"><button class="chip" data-a="pivot">${esc(x.value)}</button></td><td class="small">${esc(x.type)}</td>
                <td><select data-a="verdict" style="min-height:32px;padding:4px 26px 4px 8px;font-size:12px">${VERDICTS.map((v) => `<option value="${v}" ${(x.verdict || "") === v ? "selected" : ""}>${v || "—"}</option>`).join("")}</select></td>
                <td class="small hide-sm">${(x.tags || []).map((t) => ui.badge(t)).join(" ")} <span class="muted">${esc(x.note || "")}</span></td>
                <td><button class="btn sm ghost" data-a="del" aria-label="Remove">${W.icon(W.I.x)}</button></td></tr>`).join("")}</tbody></table></div>`
              : ui.empty("EMPTY CASE", "Add indicators here, or from Extract, Workbench, Hunt, Phish…")}</div>`;
        $("#cs-sel").onchange = (e) => { W.Case.activate(e.target.value); draw(); };
        $("#cs-new").onclick = () => { const n = prompt("Case name", "Investigation " + new Date().toISOString().slice(0, 10)); if (n) { W.Case.create(n); draw(); } };
        $("#cs-ren").onclick = () => { const n = prompt("Rename case", c.name); if (n) { W.Case.update((ws2, a) => { a.name = n.slice(0, 120); }); draw(); } };
        $("#cs-del").onclick = () => {
          if (ws.cases.length < 2) return W.toast("Can't delete the last case", 1);
          if (!confirm(`Delete case “${c.name}” and its ${c.items.length} indicator(s)?`)) return;
          W.Case.update((ws2) => { ws2.cases = ws2.cases.filter((x) => x.id !== c.id); ws2.active = ws2.cases[0].id; }); draw();
        };
        $("#cs-notes").oninput = W.debounce((e) => W.Case.update((ws2, a) => { a.notes = e.target.value; }), 400);
        $("#cs-q").oninput = W.debounce((e) => { W.store.set("yumi.case.q", e.target.value); draw(); $("#cs-q").focus(); }, 250);
        $("#cs-addgo").onclick = () => addText($("#cs-add").value);
        $("#cs-imp").onchange = async (e) => {
          const f = e.target.files[0]; if (!f) return; const t = await W.readFile(f);
          try { const j = JSON.parse(t); const arr = Array.isArray(j) ? j : j.items || []; W.Case.add(arr.map((x) => (typeof x === "string" ? { value: x } : x))); draw(); }
          catch { addText(t); }
        };
        function addText(t) {
          if (!t.trim()) return;
          const lines = t.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
          const simple = lines.every((l) => W.detectType(l));
          W.Case.add(simple ? lines.map((value) => ({ value })) : W.eng.ioc.toItems(W.eng.ioc.extract(t))); draw();
        }
        el.querySelector(".tbl") && el.querySelector(".tbl").addEventListener("change", (e) => {
          const s = e.target.closest('[data-a="verdict"]'); if (!s) return; const v = s.closest("tr").dataset.v;
          W.Case.update((ws2, a) => { const it = a.items.find((x) => x.value === v); if (it) it.verdict = s.value || null; });
        });
        el.querySelector(".tbl") && el.querySelector(".tbl").addEventListener("click", (e) => {
          const b = e.target.closest("[data-a]"); if (!b || b.tagName === "SELECT") return; const v = b.closest("tr").dataset.v;
          if (b.dataset.a === "pivot") W.go("yumi", "pivot", v);
          if (b.dataset.a === "del") { W.Case.update((ws2, a) => { a.items = a.items.filter((x) => x.value !== v); }); draw(); }
        });
        $$("[data-x]", el).forEach((b) => (b.onclick = () => exportCase(b.dataset.x, W.Case.active())));
      };
      draw();
    },
  });

  async function exportCase(kind, c) {
    const slug = c.name.replace(/[^\w.-]+/g, "_").slice(0, 60) || "case";
    if (kind === "json") return W.download(`case_${slug}.json`, JSON.stringify(c, null, 2), "application/json");
    if (kind === "csv") return W.download(`case_${slug}.csv`, "value,type,verdict,tags,note,added\n" + c.items.map((x) => [x.value, x.type, x.verdict || "", (x.tags || []).join(";"), x.note || "", x.added].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n"), "text/csv");
    if (kind === "stix") {
      const tlp = W.$("#cs-tlp").value, r = await W.eng.stix.bundle(c.items, { tlp });
      W.download(W.eng.stix.filename("case-" + slug), JSON.stringify(r.bundle, null, 2), "application/json");
      return W.toast(`STIX bundle: ${r.stats.indicators} indicator(s), ${r.stats.vulnerabilities} CVE(s)${r.stats.skipped ? `, ${r.stats.skipped} skipped` : ""}`);
    }
    const by = (v) => c.items.filter((x) => x.verdict === v).length;
    const md = [`# Threat Intelligence Report: ${c.name}`, "", `*Generated ${new Date().toISOString()} by Wakizashi · TLP:CLEAR unless marked otherwise*`, "",
      "## Summary", "", `- Indicators: **${c.items.length}**`, `- Malicious: **${by("malicious")}** · Suspicious: **${by("suspicious")}**`, "",
      "## Analyst notes", "", c.notes || "_None_", "", "## Indicators (defanged)", "", "| Indicator | Type | Verdict | Tags |", "|---|---|---|---|",
      ...c.items.map((x) => `| \`${W.eng.ioc.defang(x.value)}\` | ${x.type} | ${x.verdict || "—"} | ${(x.tags || []).join(", ")} |`), ""].join("\n");
    W.download(`report_${slug}.md`, md, "text/markdown");
  }
})();
