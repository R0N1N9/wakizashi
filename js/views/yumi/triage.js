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

  // Direct, no-key dynamic-analysis / intel links for a sample, keyed by its hash. Opening a link
  // just searches that service for the hash — nothing is uploaded from the browser.
  function sbLinks(h) {
    const s = (h && (h.sha256 || h.sha1 || h.md5)) || "";
    if (!s) return [];
    const e = encodeURIComponent(s);
    return [
      ["VirusTotal", `https://www.virustotal.com/gui/file/${e}`, "sandbox"],
      ["Hybrid Analysis", `https://www.hybrid-analysis.com/sample/${e}`, "sandbox"],
      ["Hatching Triage", `https://tria.ge/s?q=${e}`, "sandbox"],
      ["ANY.RUN", `https://app.any.run/submissions/#filehash:${e}`, "sandbox"],
      ["Joe Sandbox", `https://www.joesandbox.com/search?q=${e}`, "sandbox"],
      ["Intezer", `https://analyze.intezer.com/files/${e}`, "sandbox"],
      ["Filescan.io", `https://www.filescan.io/search-result?query=${e}`, "sandbox"],
      ["MalwareBazaar", `https://bazaar.abuse.ch/sample/${e}/`, "intel"],
      ["ThreatFox", `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e}`, "intel"],
      ["MalShare", `https://malshare.com/sample.php?action=detail&hash=${e}`, "intel"],
      ["Kaspersky OpenTIP", `https://opentip.kaspersky.com/${e}`, "intel"],
      ["Cisco Talos", `https://talosintelligence.com/sha_searches?hash=${e}`, "intel"],
      ["Maltiverse", `https://maltiverse.com/sample/${e}`, "intel"],
    ];
  }
  function sbPanel(h) {
    const links = sbLinks(h); if (!links.length) return "";
    const row = (kind) => `<div class="row" style="flex-wrap:wrap;gap:6px">${links.filter((x) => x[2] === kind).map(([n, u]) => `<a class="btn sm" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(n)} ↗</a>`).join("")}</div>`;
    return ui.panel("Dynamic analysis — open directly",
      `<div class="muted small" style="margin-bottom:8px">No API key needed — each opens that sandbox or intel feed searched for this sample's hash (nothing is uploaded from here).</div>
       <div class="lbl">Sandboxes</div>${row("sandbox")}<div class="spacer"></div><div class="lbl">Intel feeds</div>${row("intel")}`);
  }

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
      ${sbPanel(r.hashes)}
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
