(function () {
  "use strict";
  const { $, esc, ui } = W;
  const BAND = { "malicious indicators": "bad", suspicious: "warn", "low signal": "ok" };

  W.tool("yumi", "triage", {
    name: "Triage", order: 50,
    desc: "Static file analysis — hashes, imphash, PE/ELF/PDF/Office/APK structure, capabilities, embedded IOCs.",
    help: {
      steps: ["Drop a suspicious file onto the drop zone.", "Read hashes (incl. imphash), structure (PE/ELF/PDF/Office/APK), capabilities and embedded IOCs.", "Pivot on the SHA-256, add the hash to your case, or export the result as JSON."],
      tips: ["The file never leaves this device — only you decide whether to look its hash up."],
    },
    icon: '<path d="M14 3H6v18h12V7z"/><path d="M14 3v4h4M9 13h6M9 17h4"/>',
    render(el) {
      el.innerHTML = ui.head("Triage", "Static analysis", "PEStudio-style triage of a suspicious file. The file never leaves this device — only you decide whether to look its hash up anywhere.") +
        ui.panel("", ui.drop("tr-drop", "Drop a file (or tap to choose) — up to 100 MB")) + `<div id="tr-out"></div>`;
      W.dropZone("tr-drop", async (f) => {
        if (f.size > 100 * 1048576) return W.toast("File is over 100 MB", 1);
        $("#tr-out").innerHTML = ui.panel("", ui.loader("ANALYSING " + f.name));
        try { draw(await W.eng.triage.analyze(await W.readFile(f, "buffer"), f.name)); }
        catch (e) { $("#tr-out").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; }
      });
    },
  });

  function draw(r) {
    const ind = r.indicators, d = r.details || {};
    const scalar = Object.entries(d).filter(([k, v]) => !["Sections", "imports", "Listing", "Keywords", "DEX files", "Native ABIs", "External targets"].includes(k) && v != null && typeof v !== "object");
    const iocCount = Object.values(r.iocs).reduce((n, v) => n + v.length, 0);
    W.$("#tr-out").innerHTML = `
      <div class="panel"><div class="row" style="justify-content:space-between"><div style="min-width:0"><span class="lbl">File</span><b class="break">${esc(r.name)}</b> <span class="muted small">${esc(r.type)} · ${W.fmt.bytes(r.size)}</span></div>
        <div class="row">${ui.badge(ind.band, BAND[ind.band], true)}<span class="mono small">score ${ind.score}/100</span></div></div>
        <div class="spacer"></div><div class="meter"><i style="width:${ind.score}%;background:${ind.score >= 60 ? "var(--crit)" : ind.score >= 25 ? "var(--high)" : "var(--ok)"}"></i></div>
        <div class="spacer"></div><div class="row"><button class="btn sm" id="tr-pivot">Pivot on SHA-256</button><button class="btn sm" id="tr-case">${W.icon(W.I.case)} Hash to case</button>
          <button class="btn sm" id="tr-iocs" ${iocCount ? "" : "disabled"}>${W.icon(W.I.case)} Embedded IOCs (${iocCount}) to case</button><button class="btn sm" id="tr-json">${W.icon(W.I.dl)} JSON</button></div></div>
      <div class="grid g2">
        ${ui.panel("Hashes", ui.kv([["MD5", r.hashes.md5], ["SHA-1", r.hashes.sha1], ["SHA-256", r.hashes.sha256], ["Entropy", r.entropy + " bits/byte"], ["ImpHash", d.ImpHash || ""]].map(([k, v]) => [k, v ? `<code>${esc(v)}</code>` : "", true])))}
        ${ui.panel("Structure", scalar.length ? ui.kv(scalar.map(([k, v]) => [k, String(v)])) : '<span class="muted small">No format-specific details for this type.</span>')}
      </div>
      ${ui.panel(`Indicators (${ind.items.length})`, ind.items.length ? ind.items.map((i) => `<div class="finding ${i.severity}"><header>${ui.sev(i.severity)}<h3>${esc(i.title)}</h3>${i.tech ? `<a class="chip" href="https://attack.mitre.org/techniques/${esc(i.tech)}/" target="_blank" rel="noopener noreferrer">${esc(i.tech)}</a>` : ""}</header>${i.detail ? `<div class="det mono">${esc(i.detail)}</div>` : ""}</div>`).join("") : ui.empty("NOTHING NOTABLE", "No suspicious structure, imports or strings."))}
      ${d.Sections ? ui.panel("PE sections", ui.table(["Name", "Virtual", "Raw", "Entropy", "Flags"], d.Sections.map((s) => [s.name, W.fmt.bytes(s.vsize), W.fmt.bytes(s.rsize), s.entropy, (s.exec ? "X" : "") + (s.write ? "W" : "")]), { mono: true })) : ""}
      ${d.imports && d.imports.length ? ui.panel(`Imports (${d.imports.length} DLLs)`, `<div class="tablewrap" style="max-height:340px">${d.imports.map((i) => `<div style="padding:8px 10px;border-bottom:1px solid var(--line)"><b class="mono small">${esc(i.dll)}</b> <span class="faint tiny">${i.funcs.length}</span><div class="tiny mono muted break">${i.funcs.map((f) => ind.apis.includes(f.toLowerCase()) ? `<span class="c-high">${esc(f)}</span>` : esc(f)).join(", ")}</div></div>`).join("")}</div>`) : ""}
      ${d.Listing ? ui.panel(`Archive contents (${d.Entries})`, `<pre class="out" style="max-height:260px">${esc(d.Listing.join("\n"))}</pre>${(d["External targets"] || []).length ? `<div class="spacer"></div><div class="callout bad">External targets: ${d["External targets"].map((u) => ui.chip(u)).join("")}</div>` : ""}`) : ""}
      ${d.Keywords ? ui.panel("PDF keywords", ui.table(["Keyword", "Count"], Object.entries(d.Keywords), { mono: true })) : ""}
      ${iocCount ? ui.panel("Embedded indicators", Object.entries(r.iocs).map(([k, vs]) => `<div class="small"><b>${esc(W.eng.ioc.LABEL[k] || k)}</b> ${vs.slice(0, 40).map((v) => ui.chip(v)).join("")}</div>`).join("")) : ""}
      ${ui.panel(`Strings (${r.strings_count})`, `<pre class="out" style="max-height:300px">${esc(r.strings_sample.slice(0, 300).join("\n"))}</pre>`)}`;
    W.$("#tr-pivot").onclick = () => W.go("yumi", "pivot", r.hashes.sha256);
    W.$("#tr-case").onclick = () => W.Case.add([{ value: r.hashes.sha256, type: "sha256", note: `${r.name} · ${r.type} · ${W.fmt.bytes(r.size)}`, verdict: ind.band === "malicious indicators" ? "malicious" : ind.band === "suspicious" ? "suspicious" : null }]);
    W.$("#tr-iocs").onclick = () => W.Case.add(W.eng.ioc.toItems(r.iocs, { note: "embedded in " + r.name }));
    W.$("#tr-json").onclick = () => W.download(`triage_${r.hashes.sha256.slice(0, 12)}.json`, JSON.stringify(r, null, 2), "application/json");
  }
})();
