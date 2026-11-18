(function () {
  "use strict";
  const { $, esc, ui } = W;
  const F = () => W.eng.footprint;

  W.tool("kemuridama", "footprint", {
    name: "Footprint", order: 70,
    desc: "Self-OSINT: lookup links for your usernames, emails, phone and name, data-broker opt-outs, and an OPSEC checklist that tracks your progress.",
    help: {
      steps: ["Enter your usernames, emails, phone and name, then press Build.", "Open the lookup links to see yourself the way an adversary would, and use the data-broker opt-out links.", "Tick off the OPSEC checklist as you go — progress is saved."],
      tips: ["Wakizashi only builds links; there's no scraping and no background requests."],
    },
    icon: '<path d="M12 2a7 7 0 0 0-7 7v10l2.5-2 2.5 2 2-2 2 2 2.5-2 2.5 2V9a7 7 0 0 0-7-7z"/><circle cx="9.5" cy="10" r="1"/><circle cx="14.5" cy="10" r="1"/>',
    render(el, arg) {
      let tab = typeof arg === "string" ? "lookup" : W.kmz.store("footprint", "tab", "lookup");
      el.innerHTML = ui.head("Footprint", "Exposure audit", "Look yourself up the way an adversary would, then shrink what they'd find. Wakizashi builds the links; you open them — no scraping, no background requests.") +
        W.kmz.tabs("fp-tabs", [["lookup", "Look yourself up"], ["brokers", "Data brokers"], ["dossier", "OPSEC checklist"]], tab) + `<div id="fp-body"></div>`;
      W.tabs($("#fp-tabs"), (t) => { tab = t; W.kmz.put("footprint", "tab", t); draw(); });
      draw();
      function draw() { ({ lookup: drawLookup, brokers: drawBrokers, dossier: drawDossier })[tab](); }

      function drawLookup() {
        $("#fp-body").innerHTML = `<div class="panel"><label class="lbl" for="fp-in">Username, email, phone number, full name or domain</label>
            <div class="row" style="flex-wrap:nowrap"><input type="text" id="fp-in" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="@handle · you@example.com · +44 20 7946 0123 · Jane Example"><button class="btn pri" id="fp-go">${W.icon(W.I.search)} Build</button></div>
            <div class="spacer"></div><div class="row"><span class="tiny muted">Treat as</span>${ui.seg("fp-kind", [["auto", "Auto"], ["username", "Username"], ["email", "Email"], ["phone", "Phone"], ["name", "Name"], ["domain", "Domain"]], "auto")}</div>
            <p class="tiny muted">What you type is not stored. Each site you open sees your query (and your IP) — use a private window or VPN if that matters.</p></div><div id="fp-out"></div>`;
        const kind = W.seg("fp-kind", () => go());
        const inp = $("#fp-in");
        if (typeof arg === "string") inp.value = arg;
        const go = () => {
          const v = inp.value.trim(); if (!v) { $("#fp-out").innerHTML = ""; return; }
          const r = F().links(v, kind() === "auto" ? null : kind());
          $("#fp-out").innerHTML = `<div class="callout small">Treating <b>${esc(r.value)}</b> as a <b>${esc(r.kind)}</b>. ${esc(r.note)}</div><div class="spacer"></div>` +
            r.groups.map((g) => ui.panel(g.title, `<div class="km-links">${g.items.map((it) => `<a href="${esc(it.url)}" target="_blank" rel="noopener noreferrer">${esc(it.label)}${it.note ? `<small>${esc(it.note)}</small>` : it.cat ? `<small>${esc(it.cat)}</small>` : ""}</a>`).join("")}</div>`)).join("");
        };
        $("#fp-go").onclick = go;
        inp.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
        if (inp.value) go();
      }

      function drawBrokers() {
        const done = W.kmz.store("footprint", "brokers", {});
        const n = F().BROKERS.filter((b) => done[b.name]).length;
        $("#fp-body").innerHTML = `<div class="panel"><div class="row" style="justify-content:space-between"><span class="small">${n} of ${F().BROKERS.length} opt-outs submitted</span><span class="tiny muted">Brokers re-list from new data — re-check every ~90 days.</span></div>
            <div class="spacer"></div>${W.kmz.meter(n / F().BROKERS.length, n === F().BROKERS.length ? "ok" : "medium")}<div class="spacer"></div>
            ${F().BROKERS.map((b) => { const d = done[b.name]; const stale = d && Date.now() - Date.parse(d) > 90 * 864e5;
              return `<div class="km-q"><input type="checkbox" data-fpb="${esc(b.name)}" ${d ? "checked" : ""} aria-label="Opt-out submitted for ${esc(b.name)}"><div class="t"><b>${esc(b.name)}</b> ${W.kmz.ext(b.url, "opt-out page ↗")}<small>${d ? `submitted ${esc(W.fmt.ago(d))}${stale ? " — time to re-check" : ""}` : "not done yet"}</small></div></div>`; }).join("")}</div>`;
        $("#fp-body").querySelectorAll("[data-fpb]").forEach((c) => (c.onchange = () => { const d = W.kmz.store("footprint", "brokers", {}); if (c.checked) d[c.dataset.fpb] = W.nowIso(); else delete d[c.dataset.fpb]; W.kmz.put("footprint", "brokers", d); drawBrokers(); }));
      }

      function drawDossier() {
        const ans = W.kmz.store("footprint", "answers", {});
        const s = F().score(ans), lvl = s.score >= 75 ? "ok" : s.score >= 50 ? "medium" : "high";
        $("#fp-body").innerHTML = `<div class="grid g3"><div class="panel stat"><div class="n acc km-big">${s.score}<span class="small muted">/100</span></div><div class="l">OPSEC posture · grade ${esc(s.grade)}</div><div class="spacer"></div>${W.kmz.meter(s.score / 100, lvl)}</div>
            <div class="panel"><h2>By domain</h2>${ui.bars(s.domains.map((d) => [d.label, d.pct]))}</div>
            <div class="panel"><h2>Fix next</h2>${s.priorities.slice(0, 3).map((g) => `<div class="small" style="margin-bottom:6px">${W.kmz.sev(g.weight >= 8 ? "high" : "medium")} ${esc(g.fix)}</div>`).join("") || '<span class="c-ok small">All done — re-check every few months.</span>'}</div></div>
          <div class="panel"><div class="row" style="justify-content:space-between"><span class="small muted">${s.answered}/${s.total} answered · progress is saved on this device only (Katana DOSSIER weights)</span><button class="btn sm ghost" id="fp-reset">Reset</button></div>
            ${Object.entries(F().DOMAINS).map(([d, label]) => `<div class="spacer"></div><span class="lbl">${esc(label)}</span>${F().QUESTIONS.filter((q) => q.domain === d).map((q) => `<label class="km-q"><input type="checkbox" data-fpq="${q.id}" ${ans[q.id] ? "checked" : ""}><span class="t">${esc(q.text)} <span class="tiny faint">· weight ${q.weight}</span>${ans[q.id] ? "" : `<small>${esc(q.fix)}</small>`}</span></label>`).join("")}`).join("")}</div>`;
        $("#fp-body").querySelectorAll("[data-fpq]").forEach((c) => (c.onchange = () => { const a = W.kmz.store("footprint", "answers", {}); a[c.dataset.fpq] = c.checked; W.kmz.put("footprint", "answers", a); const y = window.scrollY; drawDossier(); window.scrollTo(0, y); }));
        $("#fp-reset").onclick = () => { if (confirm("Clear your checklist answers?")) { W.store.del("kemuridama.footprint.answers"); drawDossier(); } };
      }
    },
  });
})();
