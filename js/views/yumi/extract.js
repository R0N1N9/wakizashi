(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const SAMPLE = `Incident summary — loader campaign
Beacons to update-cdn[.]ddns[.]net and 185[.]220[.]101[.]5 via hxxps://185.220.101.5/gate.php
Dropper sha256: 44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f
Exploits CVE-2023-23397 (T1566.002). Contact: ops[at]bad-mail[.]com
Mutex Global\\MyBotMutex_v3, pipe \\\\.\\pipe\\winsvc_44
PDB C:\\Users\\devbox\\source\\loader\\Release\\loader.pdb  BTC bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh`;

  W.tool("yumi", "extract", {
    name: "Extract", order: 10,
    desc: "Pull IOCs and host artifacts out of any text — refang, dedupe, export, add to a case.",
    icon: '<path d="M4 4h16v6H4zM4 14h7v6H4zM15 14h5v6h-5z"/>',
    render(el, arg) {
      el.innerHTML = ui.head("Extract", "Indicators & artifacts", "Paste a report, log, email or sandbox dump. Defanged indicators (<code>hxxp</code>, <code>[.]</code>, <code>[at]</code>) are refanged automatically.") + `
        <div class="panel">
          <textarea id="ex-in" rows="8" spellcheck="false" placeholder="Paste text here — or drop a .txt / .log / .eml / .json file below"></textarea>
          <div class="spacer"></div>
          <div class="row">
            <button class="btn pri" id="ex-go">${W.icon(W.I.search)} Extract</button>
            <label class="btn ghost">${W.icon(W.I.up)} Load file<input type="file" id="ex-file" accept=".txt,.log,.md,.csv,.json,.eml,.html,.xml,text/*"></label>
            <button class="btn ghost" id="ex-sample">Sample</button>
            <span class="grow"></span>
            <label class="check"><input type="checkbox" id="ex-priv"> include private IPs</label>
          </div>
        </div>
        <div id="ex-out"></div>`;
      const ta = $("#ex-in");
      if (arg) ta.value = String(arg);
      $("#ex-sample").onclick = () => { ta.value = SAMPLE; run(); };
      $("#ex-file").onchange = async (e) => { const f = e.target.files[0]; if (!f) return; ta.value = await W.readFile(f); run(); };
      $("#ex-go").onclick = run;
      let tab = W.store.get("yumi.extract.tab", "iocs");
      function run() {
        const text = ta.value;
        if (!text.trim()) return W.toast("Paste some text first", 1);
        const iocs = W.eng.ioc.extract(text, { includePrivate: $("#ex-priv").checked });
        const arts = W.eng.ioc.artifacts(text);
        const n = W.eng.ioc.count(iocs);
        $("#ex-out").innerHTML = `<div class="grid g4">${ui.stat(n, "Indicators", true)}${ui.stat(Object.keys(iocs).length, "Types")}${ui.stat(arts.total, "Host artifacts")}${ui.stat(W.fmt.num(text.length), "Characters")}</div>
          <div class="tabs" id="ex-tabs"><button data-tab="iocs" class="${tab === "iocs" ? "on" : ""}">Indicators (${n})</button><button data-tab="arts" class="${tab === "arts" ? "on" : ""}">Host artifacts (${arts.total})</button></div>
          <div id="ex-body"></div>`;
        W.tabs($("#ex-tabs"), (t) => { tab = t; W.store.set("yumi.extract.tab", t); body(); });
        const body = () => (tab === "arts" ? drawArts(arts) : drawIocs(iocs));
        body();
      }
      function drawIocs(iocs) {
        const flat = Object.entries(iocs).flatMap(([k, vs]) => vs.map((v) => ({ k, v })));
        const box = $("#ex-body");
        if (!flat.length) { box.innerHTML = ui.panel("", ui.empty("NO INDICATORS", "Nothing indicator-shaped in that text.")); return; }
        box.innerHTML = `<div class="panel"><div class="row">
            <button class="btn sm pri" id="ex-case">${W.icon(W.I.case)} Add all to case</button>
            <button class="btn sm" id="ex-copy">${W.icon(W.I.copy)} Copy</button>
            <button class="btn sm" id="ex-defang">Copy defanged</button>
            <button class="btn sm" id="ex-csv">${W.icon(W.I.dl)} CSV</button>
            <button class="btn sm" id="ex-json">${W.icon(W.I.dl)} JSON</button>
            <button class="btn sm" id="ex-wb">Enrich in workbench →</button>
          </div></div>
          ${Object.entries(iocs).map(([k, vs]) => `<div class="panel"><h2>${esc(W.eng.ioc.LABEL[k] || k)} <span class="faint">(${vs.length})</span></h2>
            <div>${vs.map((v) => `<button class="chip" data-v="${esc(v)}" data-k="${esc(k)}" title="Pivot on ${esc(v)}">${esc(v)}</button>`).join("")}</div></div>`).join("")}`;
        box.onclick = (e) => { const c = e.target.closest(".chip[data-v]"); if (c) W.go("yumi", "pivot", c.dataset.v); };
        $("#ex-case").onclick = () => W.Case.add(W.eng.ioc.toItems(iocs));
        $("#ex-copy").onclick = () => W.copy(flat.map((x) => x.v).join("\n"), `Copied ${flat.length} indicator(s)`);
        $("#ex-defang").onclick = () => W.copy(flat.map((x) => W.eng.ioc.defang(x.v)).join("\n"), "Copied defanged");
        $("#ex-csv").onclick = () => W.download("iocs.csv", "type,value\n" + flat.map((x) => `${x.k},"${x.v.replace(/"/g, '""')}"`).join("\n"), "text/csv");
        $("#ex-json").onclick = () => W.download("iocs.json", JSON.stringify(iocs, null, 2), "application/json");
        $("#ex-wb").onclick = () => W.go("yumi", "workbench", $("#ex-in").value);
      }
      function drawArts(arts) {
        const box = $("#ex-body");
        if (!arts.total) { box.innerHTML = ui.panel("", ui.empty("NO HOST ARTIFACTS", "No PDB paths, mutexes, pipes, registry keys, GUIDs, user-agents, wallets or .onion addresses found.")); return; }
        box.innerHTML = arts.groups.map((g, gi) => `<div class="panel"><div class="row" style="justify-content:space-between">
            <h2 style="margin:0">${esc(g.label)} <span class="faint">(${g.items.length})</span></h2>
            <span class="row">${ui.badge(g.confidence + " confidence", g.confidence === "high" ? "ok" : "warn")}
              ${g.huntable ? `<button class="btn sm" data-yara="${gi}">YARA rule</button>` : ""}<button class="btn sm" data-case="${gi}">${W.icon(W.I.case)} Case</button><button class="btn sm" data-copy="${gi}">${W.icon(W.I.copy)}</button></span></div>
            <p class="muted small">${esc(g.note)}</p><div>${g.items.map((v) => ui.chip(v)).join("")}</div></div>`).join("");
        box.onclick = (e) => {
          const b = e.target.closest("button"); if (!b) return;
          const g = arts.groups[+(b.dataset.yara || b.dataset.case || b.dataset.copy)]; if (!g) return;
          if (b.dataset.copy != null) W.copy(g.items.join("\n"));
          if (b.dataset.case != null) W.Case.add(g.items.map((v) => ({ value: v, type: "artifact", tags: [g.kind] })));
          if (b.dataset.yara != null) W.go("yumi", "yara", { strings: g.items, name: "host_" + g.kind });
        };
      }
      if (arg) run();
    },
  });
})();
