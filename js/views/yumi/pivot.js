(function () {
  "use strict";
  const { $, esc, ui } = W;
  const CAT_LABEL = { reputation: "Reputation", intel: "Threat intel", infrastructure: "Infrastructure", sandbox: "Sandboxes", context: "Context",
    exposure: "Exposure", chain: "Blockchain", persona: "Persona / accounts" };

  W.tool("yumi", "pivot", {
    name: "Pivot", order: 15,
    desc: "One indicator → every reputation, intel and infrastructure page worth opening.",
    help: {
      steps: ["Type an IP, domain, URL, hash, CVE, email, ASN, wallet, ATT&CK id or @username and press Pivot.", "Open the reputation, intel and infrastructure links you want — or Open all.", "Add the indicator to your case when it matters."],
      tips: ["Nothing is queried until you open a link, so pivoting is private by default."],
    },
    icon: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2"/><path d="M12 1v5M12 18v5M1 12h5M18 12h5"/>',
    render(el, arg) {
      const recent = W.store.get("yumi.pivot.recent", []);
      el.innerHTML = ui.head("Pivot", "OSINT pivots", "Type an IP, domain, URL, hash, CVE, email, ASN, wallet, ATT&CK id or @username. Wakizashi only builds the links — nothing is queried until you open one.") + `
        <div class="panel"><div class="row">
          <input id="pv-in" type="text" placeholder="185.220.101.5 · evil[.]example · 44d88612… · CVE-2024-3400 · @handle" spellcheck="false" autocapitalize="off" autocomplete="off" style="flex:1;min-width:200px">
          <button class="btn pri" id="pv-go">Pivot</button></div>
          ${recent.length ? `<div class="spacer"></div><div class="tiny muted">Recent: ${recent.map((r) => `<button class="chip" data-r="${esc(r)}">${esc(r)}</button>`).join("")}</div>` : ""}
        </div><div id="pv-out"></div>`;
      const inp = $("#pv-in");
      const go = () => {
        const v = inp.value.trim(); if (!v) return;
        const r = W.eng.pivot.links(v);
        if (!r.type) { $("#pv-out").innerHTML = ui.panel("", ui.empty("UNRECOGNISED", "That doesn't look like an indicator. Try Extract for free text.")); return; }
        W.store.set("yumi.pivot.recent", [r.value].concat(recent.filter((x) => x !== r.value)).slice(0, 8));
        const n = Object.values(r.groups).reduce((a, g) => a + g.length, 0);
        $("#pv-out").innerHTML = `<div class="panel"><div class="row" style="justify-content:space-between">
            <div><span class="lbl">Indicator</span><code style="font-size:15px">${esc(r.value)}</code> ${ui.badge(r.type, "acc")}</div>
            <div class="row"><button class="btn sm" id="pv-case">${W.icon(W.I.case)} Add to case</button><button class="btn sm" id="pv-copy">${W.icon(W.I.copy)} Copy</button><button class="btn sm" id="pv-def">Defanged</button><button class="btn sm" id="pv-all">Open all (${n})</button></div></div></div>
          <div class="grid g3">${Object.entries(r.groups).map(([cat, ls]) => `<div class="panel"><h2>${esc(CAT_LABEL[cat] || cat)}</h2>
            ${ls.map((l) => `<a class="row" style="justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)" href="${esc(l.url)}" target="_blank" rel="noopener noreferrer"><span>${esc(l.name)}</span><span class="faint">${W.icon(W.I.link).replace("<svg", '<svg width="15" height="15"')}</span></a>`).join("")}</div>`).join("")}</div>`;
        $("#pv-case").onclick = () => W.Case.add([{ value: r.value, type: r.type }]);
        $("#pv-copy").onclick = () => W.copy(r.value);
        $("#pv-def").onclick = () => W.copy(W.eng.ioc.defang(r.value), "Copied defanged");
        $("#pv-all").onclick = () => {
          if (!confirm(`Open ${n} tabs? Each service will see that you looked up ${r.value}.`)) return;
          Object.values(r.groups).flat().forEach((l) => window.open(l.url, "_blank", "noopener"));
        };
      };
      $("#pv-go").onclick = go;
      inp.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
      el.addEventListener("click", (e) => { const b = e.target.closest("[data-r]"); if (b) { inp.value = b.dataset.r; go(); } });
      if (arg) { inp.value = String(arg); go(); } else inp.focus();
    },
  });
})();
