(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const FP = { low: "ok", medium: "warn", high: "bad" };

  W.tool("yumi", "workbench", {
    name: "Workbench", order: 20,
    desc: "Report → ATT&CK mapping, attribution, Sigma + YARA, a STIX bundle and a ready-made case.",
    help: {
      steps: ["Paste a threat report, load a file, or Fetch a CTI article by URL.", "Press Enrich to map behaviour to MITRE ATT&CK, suggest attribution and draft Sigma + YARA.", "Export a Markdown brief or STIX bundle, add the rules to your YARA library, or send them to Yoroi to hunt logs or scan files."],
      tips: ["Inferred techniques are suggestions — check them against the report.", "Fetch is the only step that uses the network."],
    },
    icon: '<path d="M3 7l6-4 6 4M3 7v10l6 4 6-4M3 7l6 4 6-4M9 11v10"/><path d="M16 14l2 2 4-4"/>',
    render(el, arg) {
      el.innerHTML = ui.head("Workbench", "Enrichment", "Paste a threat report — or fetch a CTI article. Wakizashi maps behaviour to MITRE ATT&CK (labelled <i>and</i> inferred), notes the actor and tooling, drafts Sigma and YARA with false-positive risk, then builds a case and a STIX 2.1 bundle for OpenCTI.") + `
        <div class="panel">
          <label class="lbl" for="wb-url">Article link (optional)</label>
          <div class="row"><input id="wb-url" type="url" placeholder="https://vendor.example/blog/threat-report" spellcheck="false" style="flex:1;min-width:200px"><button class="btn" id="wb-fetch">Fetch</button></div>
          <div class="tiny faint" style="margin-top:6px">Fetching runs from your browser; many sites block cross-origin reads — if so, paste the text below.</div>
          <div class="spacer"></div>
          <label class="lbl" for="wb-in">Report text</label>
          <textarea id="wb-in" rows="9" spellcheck="false" placeholder="Paste the report, advisory, sandbox notes or IOC dump…"></textarea>
          <div class="spacer"></div>
          <div class="row"><button class="btn pri" id="wb-go">Enrich</button>
            <label class="btn ghost">${W.icon(W.I.up)} Load file<input type="file" id="wb-file" accept=".txt,.md,.html,.htm,.json,.csv,.log,text/*"></label>
            <span class="grow"></span><label class="lbl" style="margin:0" for="wb-tlp">TLP</label>
            <select id="wb-tlp" style="width:auto;min-width:110px">${["clear", "green", "amber", "red"].map((t) => `<option value="${t}" ${t === W.store.get("yumi.workbench.tlp", "amber") ? "selected" : ""}>${t.toUpperCase()}</option>`).join("")}</select></div>
        </div><div id="wb-out"></div>`;
      let source = null, titleHint = "";
      if (arg) $("#wb-in").value = String(arg);
      $("#wb-file").onchange = async (e) => { const f = e.target.files[0]; if (!f) return; let t = await W.readFile(f); if (/\.html?$/i.test(f.name)) t = W.eng.workbench.stripHtml(t); $("#wb-in").value = t; source = f.name; };
      W.act("#wb-fetch", async () => {
        const url = $("#wb-url").value.trim();
        if (!/^https:\/\/\S+\.\S+/i.test(url)) throw new Error("enter a full https:// link");
        let r;
        try { r = await fetch(url, { credentials: "omit", referrerPolicy: "no-referrer" }); }
        catch { throw new Error("the site blocked a cross-origin read (CORS) — open it, copy the article text, and paste it here"); }
        if (!r.ok) throw new Error(`could not fetch the article (HTTP ${r.status})`);
        const html = await r.text();
        const m = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html);
        titleHint = m ? W.eng.workbench.stripHtml(m[1]).slice(0, 140) : "";
        $("#wb-in").value = W.eng.workbench.stripHtml(html).slice(0, 200000);
        source = url; W.toast("Article fetched — review the text, then Enrich");
      });
      W.act("#wb-go", async () => {
        const text = $("#wb-in").value;
        if (!text.trim()) throw new Error("paste a report first");
        const tlp = $("#wb-tlp").value; W.store.set("yumi.workbench.tlp", tlp);
        $("#wb-out").innerHTML = ui.panel("", ui.loader("ENRICHING"));
        const r = await W.eng.workbench.enrich({ text, tlp, source: source || ($("#wb-url").value.trim() || null), title: titleHint });
        draw(r);
      });

      function rulePanel(kind, label, d) {
        const fp = d.fp || { level: "high", reasons: [] };
        return `<section class="panel" data-kind="${kind}"><div class="row" style="justify-content:space-between">
            <h2 style="margin:0">${esc(label)}</h2>
            <span class="row">${ui.badge(d.valid === false ? "check syntax" : "valid", d.valid === false ? "bad" : "ok")}${ui.badge("FP risk: " + fp.level, FP[fp.level])}</span></div>
          <p class="muted small">${esc((fp.reasons || [])[0] || "")}</p>
          <pre class="out" style="max-height:260px">${esc(d.rule || "")}</pre>
          <div class="spacer"></div><div class="row"><button class="btn sm" data-a="copy">${W.icon(W.I.copy)} Copy</button><button class="btn sm" data-a="dl">${W.icon(W.I.dl)} Download</button>
            ${kind === "yara" ? '<button class="btn sm" data-a="yumi">＋ YARA library</button><button class="btn sm" data-a="yoroi">⇨ Yoroi (scan files)</button>' : '<button class="btn sm" data-a="yoroi">⇨ Yoroi (hunt logs)</button>'}</div>
          <div class="spacer"></div><label class="lbl">Test against ${kind === "yara" ? "sample text" : "sample log lines"}</label>
          <textarea data-t="sample" rows="3" spellcheck="false" placeholder="${kind === "yara" ? "paste strings or file text…" : "paste a few log lines…"}"></textarea>
          <div class="spacer"></div><button class="btn sm" data-a="test">${W.icon(W.I.play)} Test</button> <span data-t="res" class="small"></span></section>`;
      }

      function draw(r) {
        const s = r.summary, st = r.stix.stats;
        const tech = (t) => `<a class="chip" href="https://attack.mitre.org/techniques/${esc(t.id.replace(".", "/"))}/" target="_blank" rel="noopener noreferrer" title="${esc(t.tactic)}${t.evidence ? " — matched: " + esc(t.evidence) : ""}" style="${t.inferred ? "border-style:dashed" : ""}"><b>${esc(t.id)}</b>&nbsp;${esc(t.name)}</a>`;
        $("#wb-out").innerHTML = `
          <div class="panel"><div class="row" style="justify-content:space-between">
              <div style="min-width:0"><span class="lbl">Enriched</span><b class="break">${esc(r.title)}</b>${r.source ? `<div class="tiny faint break">${esc(r.source)}</div>` : ""}</div>
              ${ui.badge("TLP:" + r.stix.tlp.toUpperCase(), "acc")}</div>
            <div class="spacer"></div>
            <div class="grid g4">${ui.stat(s.indicators, "Indicators", true)}${ui.stat(s.techniques, `ATT&CK (${s.labeled} labelled / ${s.inferred} inferred)`)}${ui.stat(s.actors, "Named actors")}${ui.stat(st.objects, "STIX objects")}</div>
            <div class="row"><button class="btn pri" id="wb-case">${W.icon(W.I.case)} Create case (${r.case.items.length})</button>
              <button class="btn" id="wb-stix">${W.icon(W.I.dl)} STIX bundle</button><button class="btn" id="wb-md">${W.icon(W.I.dl)} Markdown brief</button></div>
            <div id="wb-act" class="small" style="margin-top:8px"></div></div>
          <div class="grid g2">
            <section class="panel"><h2>Attribution</h2><p class="muted small" style="margin-top:0">${esc(r.attribution.note)}</p>
              <span class="lbl">Named threat actor(s)</span><div>${r.attribution.actors.map((a) => ui.badge(a, "crit")).join(" ") || '<span class="faint small">none</span>'}</div><div class="spacer"></div>
              <span class="lbl">Tooling / malware</span><div>${r.attribution.malware.map((a) => ui.badge(a, "high")).join(" ") || '<span class="faint small">none</span>'}</div></section>
            <section class="panel"><h2>MITRE ATT&amp;CK</h2>
              <span class="lbl">Labelled in the report (${r.attack.labeled.length})</span><div>${r.attack.labeled.map(tech).join("") || '<span class="faint small">none</span>'}</div><div class="spacer"></div>
              <span class="lbl">Inferred from behaviour (${r.attack.inferred.length}) — verify these</span><div>${r.attack.inferred.map(tech).join("") || '<span class="faint small">none</span>'}</div></section>
          </div>
          ${r.attack.tactics.length ? ui.panel("Kill-chain coverage", ui.bars(r.attack.tactics.map(([t, v]) => [t, v.length]))) : ""}
          <div class="grid g2">${rulePanel("sigma", "Sigma draft", r.sigma)}${rulePanel("yara", "YARA draft", r.yara)}</div>
          ${ui.panel(`Indicators (${r.case.items.length})`, ui.table(["Value", "Type"], r.case.items.slice(0, 200).map((x) => [x.value, x.type]), { mono: true, max: 360 }))}
          ${r.artifacts.length ? ui.panel("Host artifacts", r.artifacts.map((g) => `<div class="small"><b>${esc(g.label)}</b> ${g.items.slice(0, 12).map((v) => ui.chip(v)).join("")}</div>`).join("")) : ""}`;
        $("#wb-case").onclick = () => {
          const id = W.Case.create(r.case.name, { notes: r.case.notes.join("\n"), tags: r.case.tags });
          W.Case.add(r.case.items.map((x) => Object.assign({}, x, { tags: r.case.tags })), true);
          $("#wb-act").innerHTML = `${ui.badge("case created", "ok")} <b>${esc(r.case.name)}</b> with ${r.case.items.length} indicator(s) — <a href="#/yumi/case">open case →</a>`;
          W.toast("Case created"); void id;
        };
        $("#wb-stix").onclick = () => W.download(r.stix.filename, r.stix.json, "application/json");
        $("#wb-md").onclick = () => W.download("wakizashi-brief.md", brief(r), "text/markdown");
        $$("#wb-out section[data-kind]").forEach((card) => {
          const kind = card.dataset.kind, d = kind === "sigma" ? r.sigma : r.yara;
          card.addEventListener("click", async (e) => {
            const a = e.target.closest("[data-a]"); if (!a) return;
            if (a.dataset.a === "copy") W.copy(d.rule);
            if (a.dataset.a === "dl") W.download(kind === "yara" ? "wakizashi.yar" : "wakizashi.yml", d.rule);
            if (a.dataset.a === "yumi") { const lib = W.store.get("yumi.yara.library", []); lib.unshift({ id: W.uid(), name: "workbench_" + W.eng.yaragen.ruleName(r.title).slice(0, 40), text: d.rule, added: W.nowIso() }); W.store.set("yumi.yara.library", lib); W.toast("Saved to the YARA library"); }
            if (a.dataset.a === "yoroi") {
              const key = kind === "yara" ? "yoroi.yara.rules" : "yoroi.rules.sigma", lst = W.store.get(key, []);
              lst.unshift({ id: W.uid(), name: "workbench: " + r.title.slice(0, 60), text: d.rule, enabled: true, updated: W.nowIso(), source: "yumi" });
              W.store.set(key, lst); W.toast(kind === "yara" ? "Enabled in Yoroi's YARA scanner" : "Enabled in Yoroi's log hunting");
            }
            if (a.dataset.a === "test") {
              const sample = card.querySelector('[data-t="sample"]').value, res = card.querySelector('[data-t="res"]');
              if (!sample.trim()) return W.toast("Paste a sample first", 1);
              res.innerHTML = testRule(kind, d.rule, sample);
            }
          });
        });
      }
      if (arg) $("#wb-go").click();
    },
  });

  const BENIGN = `Jan 10 09:14:02 web01 sshd[1123]: Accepted password for alice from 10.0.0.5 port 51110 ssh2
Jan 10 09:15:44 web01 CRON[2201]: (root) CMD (/usr/bin/backup.sh)
10.0.0.5 - - [10/Jan/2026:09:16:10 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0)"
Jan 10 09:17:01 db01 systemd[1]: Started Session 42 of user postgres.`;
  function testRule(kind, rule, sample) {
    if (kind === "yara") {
      if (!W.eng.yara) return ui.badge("YARA engine not loaded", "warn");
      const { rules, errors } = W.eng.yara.compile(rule);
      if (!rules.length) return `<span class="c-crit">${esc(errors.join("; "))}</span>`;
      const hit = W.eng.yara.scan(rules, W.bytes(sample)).some((h) => !h.error), benign = W.eng.yara.scan(rules, W.bytes(BENIGN)).some((h) => !h.error);
      return `${ui.badge(hit ? "matched" : "no match", hit ? "ok" : "")} ${benign ? ui.badge("also matched benign baseline — FP-prone", "bad") : '<span class="muted tiny">clean on the benign baseline</span>'}`;
    }
    if (!W.eng.sigma || !W.eng.logs) return ui.badge("Sigma engine not loaded", "warn");
    const c = W.eng.sigma.compile(rule);
    if (!c.rules.length) return `<span class="c-crit">${esc(c.errors.join("; "))}</span>`;
    const ev = W.eng.logs.parse(sample, "auto").events, hits = W.eng.sigma.run(c.rules, ev);
    const n = new Set(hits.flatMap((h) => h.events)).size;
    const benign = W.eng.sigma.run(c.rules, W.eng.logs.parse(BENIGN, "auto").events).length > 0;
    return `${ui.badge(n ? `matched ${n} of ${ev.length} event(s)` : "no match", n ? "ok" : "")} ${benign ? ui.badge("also matched benign baseline — FP-prone", "bad") : '<span class="muted tiny">clean on the benign baseline</span>'}`;
  }

  function brief(r) {
    const L = [`# ${r.title}`, "", `*Wakizashi enrichment · ${new Date().toISOString()} · TLP:${r.stix.tlp.toUpperCase()}*`, ""];
    if (r.source) L.push(`Source: ${r.source}`, "");
    L.push("## Attribution", "", r.attribution.note, "");
    if (r.attribution.malware.length) L.push("Tooling: " + r.attribution.malware.join(", "), "");
    L.push("## MITRE ATT&CK", "", "| ID | Technique | Tactic | Source |", "|---|---|---|---|");
    for (const t of r.attack.all) L.push(`| ${t.id} | ${t.name} | ${t.tactic} | ${t.inferred ? "inferred (" + t.evidence + ")" : "labelled"} |`);
    L.push("", "## Indicators (defanged)", "");
    for (const x of r.case.items) L.push(`- \`${W.eng.ioc.defang(x.value)}\` (${x.type})`);
    L.push("", "## Sigma", "", "```yaml", r.sigma.rule.trim(), "```", "", "## YARA", "", "```yara", r.yara.rule.trim(), "```", "");
    return L.join("\n");
  }
})();
