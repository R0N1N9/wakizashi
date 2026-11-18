(function () {
  "use strict";
  const { $, esc, ui } = W;
  const K = (k) => "naginata.cvss." + k;
  const GROUPS = [
    ["base", "Base metrics", ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]],
    ["temporal", "Temporal metrics", ["E", "RL", "RC"]],
    ["environmental", "Environmental — requirements", ["CR", "IR", "AR"]],
    ["modified", "Environmental — modified base", ["MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]],
  ];
  const HELP = {
    AV: "How remote the attacker can be.", AC: "Conditions beyond the attacker's control.", PR: "Privileges needed before exploiting.", UI: "Does a user other than the attacker have to act?",
    S: "Does impact reach beyond the vulnerable component's security authority?", C: "Information disclosure.", I: "Data modification.", A: "Service disruption.",
  };
  const DEFAULT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

  W.tool("naginata", "cvss", {
    name: "CVSS", order: 30,
    desc: "CVSS v3.1 calculator — base, temporal and environmental scores, severity, vector parse and export.",
    help: {
      steps: ["Pick the base metrics (and optional temporal/environmental ones) — or paste a vector and press Load.", "Read the score and severity.", "Copy the vector, or start a New finding in Report with it."],
      tips: ["v3.0 vectors are accepted and scored as v3.1."],
    },
    icon: '<path d="M4 20h16"/><path d="M6 16v-4M10 16V8M14 16v-6M18 16V5"/>',
    render(el, arg) {
      W.roeGate(el, () => {
        const M = W.eng.cvss.METRICS;
        let m = W.eng.cvss.parse(typeof arg === "string" && arg ? arg : W.store.get(K("vector"), DEFAULT)).metrics;
        for (const b of W.eng.cvss.BASE) if (!m[b]) m = W.eng.cvss.parse(DEFAULT).metrics;
        let open = W.store.get(K("open"), { temporal: false, environmental: false, modified: false });
        el.innerHTML = ui.head("CVSS", "v3.1 calculator", "Score a finding from its metrics, or paste a vector string. Scores follow the FIRST v3.1 specification (v3.0 vectors are accepted).") + `
          <div class="panel ng-sticky">
            <div class="ng-score">
              <div class="col" style="flex:none;min-width:0"><div class="lbl">Base</div><div class="ng-cvss-n" id="cv-base">—</div><div id="cv-base-s"></div></div>
              <div class="col" style="flex:none;min-width:0"><div class="lbl">Temporal</div><div class="ng-cvss-n" id="cv-temp">—</div><div id="cv-temp-s"></div></div>
              <div class="col" style="flex:none;min-width:0"><div class="lbl">Environmental</div><div class="ng-cvss-n" id="cv-env">—</div><div id="cv-env-s"></div></div>
              <div class="col"><div class="lbl">Vector</div><div class="ng-vec" id="cv-vec"></div>
                <div class="row" style="margin-top:6px"><button class="btn sm" id="cv-copy">${W.icon(W.I.copy)} Copy</button><button class="btn sm" id="cv-report">${W.icon(W.I.plus)} New finding</button><button class="btn ghost sm" id="cv-reset">Reset</button></div></div>
            </div>
          </div>
          <div class="panel"><label class="lbl" for="cv-in">Paste a vector</label>
            <div class="row"><input id="cv-in" type="text" style="flex:1;min-width:200px" spellcheck="false" autocapitalize="off" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"><button class="btn pri" id="cv-parse">Load</button></div>
            <div id="cv-err"></div></div>
          ${GROUPS.map(([g, title, keys]) => `<div class="panel"><h2>${esc(title)}${g === "base" ? "" : ` <button class="btn ghost sm" data-toggle="${g}" style="margin-left:auto">${open[g] ? "Hide" : "Show"}</button>`}</h2>
            <div class="ng-metrics" id="cv-g-${g}" ${g !== "base" && !open[g] ? "hidden" : ""}>${keys.map((k) => `<div class="ng-metric"><div class="lbl" title="${esc(HELP[k] || "")}">${esc(M[k].name)} (${k})</div>
              ${ui.seg("cv-m-" + k, Object.entries(M[k].opts).map(([v, o]) => [v, o[0]]), m[k])}${HELP[k] ? `<div class="tiny faint" style="margin-top:4px">${esc(HELP[k])}</div>` : ""}</div>`).join("")}</div></div>`).join("")}
          <div class="panel"><h2>Sub-scores</h2><div id="cv-sub"></div></div>`;

        for (const k of W.eng.cvss.ORDER) W.seg("cv-m-" + k, (v) => { m[k] = v; update(); });
        el.querySelectorAll("[data-toggle]").forEach((b) => (b.onclick = () => {
          const g = b.dataset.toggle; open[g] = !open[g]; W.store.set(K("open"), open);
          $("#cv-g-" + g).hidden = !open[g]; b.textContent = open[g] ? "Hide" : "Show";
        }));
        const setSegs = () => { for (const k of W.eng.cvss.ORDER) W.$$(`#cv-m-${k} button`).forEach((b) => b.classList.toggle("on", b.dataset.v === m[k])); };
        const load = (vec) => {
          const p = W.eng.cvss.parse(vec);
          if (!p.ok) { $("#cv-err").innerHTML = `<div class="callout bad" style="margin-top:8px">${p.errors.map(esc).join("<br>")}</div>`; return false; }
          $("#cv-err").innerHTML = ""; m = p.metrics; setSegs(); update();
          for (const [g, , keys] of GROUPS) if (g !== "base" && keys.some((k) => m[k] !== "X") && !open[g]) el.querySelector(`[data-toggle="${g}"]`).click();
          return true;
        };
        $("#cv-parse").onclick = () => load($("#cv-in").value);
        $("#cv-in").addEventListener("keydown", (e) => { if (e.key === "Enter") load($("#cv-in").value); });
        $("#cv-reset").onclick = () => { $("#cv-in").value = ""; load(DEFAULT); };

        let cur;
        function show(id, n, sev) {
          const k = W.eng.cvss.sevKey(sev);
          $(id).textContent = n.toFixed(1); $(id).className = "ng-cvss-n " + k;
          $(id + "-s").innerHTML = ui.badge(sev, k, k === "critical" || k === "high");
        }
        function update() {
          cur = W.eng.cvss.score(m);
          W.store.set(K("vector"), cur.vector);
          show("#cv-base", cur.base, cur.baseSeverity);
          show("#cv-temp", cur.temporal, cur.temporalSeverity);
          show("#cv-env", cur.environmental, cur.environmentalSeverity);
          $("#cv-vec").textContent = cur.vector;
          $("#cv-sub").innerHTML = ui.kv([["Impact", cur.impact.toFixed(1)], ["Exploitability", cur.exploitability.toFixed(1)], ["Modified impact", cur.modifiedImpact.toFixed(1)],
            ["Overall", `${cur.overall.toFixed(1)} ${cur.overallSeverity} (${cur.hasEnvironmental ? "environmental" : cur.hasTemporal ? "temporal" : "base"})`],
            ["Scope", m.S === "C" ? "Changed — impact extends beyond the vulnerable component" : "Unchanged"]]);
        }
        $("#cv-copy").onclick = () => W.copy(cur.vector, "Vector copied");
        $("#cv-report").onclick = () => W.go("naginata", "report", { cvss: cur.vector });
        if (typeof arg === "string" && arg) { $("#cv-in").value = arg; load(arg); } else update();
      });
    },
  });
})();
