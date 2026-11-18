/* Yoroi · RESPOND — incident board run through the NIST SP 800-61 phases: playbooks become checklists,
 * IOCs are tracked (→ BLOCK / case), ATT&CK techniques, evidence hashes with chain of custody, a timeline,
 * and a Markdown report. State lives in `yoroi.respond.incidents` (array) + `yoroi.respond.active`. */
(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const KEY = "yoroi.respond.incidents", ACT = "yoroi.respond.active", FILT = "yoroi.respond.filter", WHO = "yoroi.respond.analyst";
  const P = () => W.eng.playbooks;
  const ICON = '<path d="M12 3v3M12 18v3M3 12h3M18 12h3"/><circle cx="12" cy="12" r="5"/><path d="M12 9.5V12l1.8 1.2"/>';

  const load = () => { const l = W.store.get(KEY, []); return Array.isArray(l) ? l : []; };
  const save = (l) => W.store.set(KEY, l);

  W.tool("yoroi", "respond", {
    name: "Respond", order: 70, icon: ICON,
    desc: "Incident board: NIST 800-61 phases, playbook checklists, IOCs, evidence, timeline, Markdown report.",
    help: {
      steps: ["Open an incident and pick a playbook.", "Work through the NIST SP 800-61 phases, ticking checklist items and adding IOCs, ATT&CK techniques, evidence and timeline entries.", "Export a Markdown incident report when you're done."],
      tips: ["Incidents are stored only in this browser."],
    },
    render(el, arg) {
      if (arg && typeof arg === "object" && arg.title) {           // W.go("yoroi","respond",{title, severity, iocs, origin, playbook, summary})
        const l = load(), inc = P().newIncident(arg, l); l.unshift(inc); save(l); W.store.set(ACT, inc.id);
      } else if (typeof arg === "string" && arg.trim()) {          // newline-separated IOCs → new incident
        const l = load(), inc = P().newIncident({ title: "New incident", origin: "handoff", iocs: P().extractIocs(arg) }, l); l.unshift(inc); save(l); W.store.set(ACT, inc.id);
      }
      board(el);
    },
  });

  function board(el) {
    const all = load(), filt = W.store.get(FILT, "open");
    const list = all.filter((i) => filt === "all" || (filt === "open" ? i.status !== "closed" : i.status === "closed"));
    let act = all.find((i) => i.id === W.store.get(ACT)) || list[0] || null;
    const open = all.filter((i) => i.status !== "closed").length;
    el.innerHTML = ui.head("RESPOND", "Incident response", "Run incidents through the NIST SP 800-61 phases — playbook checklists, indicators, ATT&CK, evidence chain of custody and a timeline — then export a Markdown report. Stored only in this browser.") +
      `<div class="grid g3">${ui.stat(open, "Open", 1)}${ui.stat(all.filter((i) => i.status === "contained").length, "Contained")}${ui.stat(all.filter((i) => i.status !== "closed" && ["critical", "high"].includes(i.severity)).length, "High / critical open")}</div>
      <div class="yb-board"><div>
        ${ui.panel("", `<div class="row">${ui.seg("rs-f", [["open", "Open"], ["closed", "Closed"], ["all", "All"]], filt)}<span class="grow"></span>${ui.btn(W.icon(W.I.plus) + "New", 'id="rs-new"', "sm pri")}</div>
          <div class="spacer"></div><div id="rs-list">${list.length ? list.map((i) => `<button type="button" class="yb-inc ${i.severity} ${act && i.id === act.id ? "on" : ""}" data-id="${esc(i.id)}">
            <span class="col" style="flex:1;min-width:0"><b class="break">${esc(i.title)}</b><span class="tiny muted">${esc(i.id)} · ${esc(i.status)} · ${esc(W.fmt.ago(i.updated))}</span>
            ${i.origin ? `<span class="tiny faint">⚑ ${esc(i.origin)}</span>` : ""}</span>${ui.sev(i.severity)}</button>`).join("") : ui.empty("NO INCIDENTS", filt === "open" ? "Nothing open. Good." : "")}</div>`)}
        ${ui.panel("Playbooks", P().PLAYBOOKS.map((p) => `<div class="yb-pb"><div class="row"><b class="small">${esc(p.name)}</b>${ui.sev(p.severity)}</div><div class="tiny faint mono">${p.attack.map(esc).join(" · ")} · ${Object.values(p.steps).flat().length} steps</div></div>`).join(""))}
      </div><div id="rs-detail">${act ? "" : ui.panel("", ui.empty("SELECT OR CREATE AN INCIDENT", "PHISH, HUNT and YARA findings can open incidents here; BLOCK turns their IOCs into countermeasures."))}</div></div>`;
    W.seg("rs-f", (v) => { W.store.set(FILT, v); board(el); });
    $("#rs-new").onclick = () => { const l = load(), inc = P().newIncident({ title: "New incident", owner: W.store.get(WHO, "") }, l); l.unshift(inc); save(l); W.store.set(ACT, inc.id); W.store.set(FILT, "open"); board(el); setTimeout(() => { const t = $("#ri-title"); if (t) t.select(); }, 30); };
    $("#rs-list").onclick = (e) => { const d = e.target.closest("[data-id]"); if (!d) return; W.store.set(ACT, d.dataset.id); board(el); if (window.matchMedia("(max-width: 959px)").matches) $("#rs-detail").scrollIntoView({ behavior: "smooth" }); };
    if (act) detail($("#rs-detail"), act.id, () => board(el));
  }

  function detail(box, id, rerender) {
    const l = load(), inc = l.find((i) => i.id === id);
    if (!inc) return;
    inc.evidence = inc.evidence || []; inc.attack = inc.attack || []; inc.iocs = inc.iocs || []; inc.tasks = inc.tasks || []; inc.timeline = inc.timeline || [];
    const PB = P(), phases = PB.PHASES, pi = phases.findIndex(([k]) => k === inc.phase);
    const done = inc.tasks.filter((t) => t.done).length;
    const commit = (logKind, logText, rr) => { if (logText) PB.log(inc, logKind, logText); else inc.updated = W.nowIso(); save(l); if (rr) rerender(); };
    const toolLinks = (text) => Object.entries(PB.TOOL_LINKS).filter(([k, [ly, t]]) => new RegExp(`\\b${k}\\b`).test(text) && W.tools[ly] && W.tools[ly][t])
      .map(([k, [ly, t]]) => `<button type="button" class="yb-tl" data-go="${ly}/${t}">→ ${esc(k)}</button>`).join("");
    box.innerHTML = `<section class="panel">
        <input type="text" id="ri-title" class="yb-title" value="${esc(inc.title)}" aria-label="Incident title">
        <div class="spacer"></div><div class="row"><span class="mono small muted">${esc(inc.id)}</span>
          <select id="ri-sev" style="width:auto" aria-label="Severity">${PB.SEVS.map((s) => `<option ${s === inc.severity ? "selected" : ""}>${s}</option>`).join("")}</select>
          <select id="ri-st" style="width:auto" aria-label="Status">${PB.STATUSES.map((s) => `<option ${s === inc.status ? "selected" : ""}>${s}</option>`).join("")}</select>
          <input type="text" id="ri-own" value="${esc(inc.owner || "")}" placeholder="owner" style="width:150px" aria-label="Owner">
          <span class="grow"></span><span class="tiny faint">opened ${esc(W.fmt.ts(inc.created))}${inc.origin ? ` · ⚑ ${esc(inc.origin)}` : ""}</span></div>
        <div class="spacer"></div><div class="yb-phases">${phases.map(([k, n], i) => `<button type="button" data-p="${k}" class="${i === pi ? "on" : i < pi ? "past" : ""}" title="${esc(n)}"><b>${i + 1}</b><span>${esc(n.split(" ")[0].replace("/", ""))}</span></button>`).join("")}</div>
        <div class="spacer"></div><label class="lbl" for="ri-sum">Summary</label><textarea id="ri-sum" rows="3" style="min-height:70px" placeholder="What happened, impact, current status…">${esc(inc.summary || "")}</textarea>
        ${inc.phase === "lessons" || inc.lessons ? `<div class="spacer"></div><label class="lbl" for="ri-les">Lessons learned</label><textarea id="ri-les" rows="3" style="min-height:70px">${esc(inc.lessons || "")}</textarea>` : ""}
        <div class="spacer"></div><div class="row">${ui.btn(W.icon(W.I.dl) + "Report .md", 'id="ri-rep"', "sm pri")}${ui.btn(W.icon(W.I.copy) + "Copy report", 'id="ri-repc"', "sm")}${ui.btn("JSON", 'id="ri-json"', "sm ghost")}<span class="grow"></span>${ui.btn(W.icon(W.I.trash) + "Delete", 'id="ri-del"', "sm danger")}</div></section>
      <section class="panel"><div class="row"><h2 style="margin:0">Response checklist <span class="muted">${done}/${inc.tasks.length}</span></h2><span class="grow"></span>
          <select id="ri-pb" style="width:auto;max-width:100%" aria-label="Apply playbook"><option value="">Apply playbook…</option>${PB.PLAYBOOKS.map((p) => `<option value="${esc(p.id)}" ${p.id === inc.playbook ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></div>
        ${inc.tasks.length ? `<div class="spacer"></div><div class="meter"><i style="width:${((100 * done) / inc.tasks.length).toFixed(0)}%"></i></div>` : ""}<div class="spacer"></div>
        ${inc.tasks.length ? phases.map(([k, n]) => { const ts = inc.tasks.map((t, i) => [t, i]).filter(([t]) => t.phase === k); return ts.length ? `<div class="yb-phase ${k === inc.phase ? "cur" : ""}"><div class="lbl">${esc(n)} · ${ts.filter(([t]) => t.done).length}/${ts.length}</div>
          ${ts.map(([t, i]) => `<label class="yb-task ${t.done ? "done" : ""}"><input type="checkbox" data-task="${i}" ${t.done ? "checked" : ""}><span>${esc(t.text)}${t.done && t.at ? ` <span class="tiny faint">✓ ${esc(W.fmt.ago(t.at))}${t.by ? " · " + esc(t.by) : ""}</span>` : ""}</span>${toolLinks(t.text)}</label>`).join("")}</div>` : ""; }).join("")
          : ui.empty("NO TASKS YET", "Apply a playbook above, or add tasks to the current phase.")}
        <div class="row" style="flex-wrap:nowrap"><input type="text" id="ri-tt" placeholder="Add a task to the current phase…" aria-label="New task">${ui.btn("Add", 'id="ri-addt"', "sm")}</div></section>
      <div class="grid g2">
        <section class="panel"><div class="row"><h2 style="margin:0">Indicators <span class="muted">(${inc.iocs.length})</span></h2><span class="grow"></span>
            ${inc.iocs.length ? ui.btn("Block", 'id="ri-blk"', "sm") + ui.btn(W.icon(W.I.case) + "Case", 'id="ri-case"', "sm") + ui.btn("Defanged", 'id="ri-def"', "sm ghost") : ""}</div><div class="spacer"></div>
          <div id="ri-iocs">${inc.iocs.map((x, i) => `<span class="chip" title="${esc(x.type)}${x.note ? " · " + esc(x.note) : ""}"><span class="break">${esc(x.value)}</span><button type="button" class="yb-x" data-rm="${i}" aria-label="Remove">✕</button></span>`).join("") || `<span class="muted small">none yet</span>`}</div>
          <div class="spacer"></div><textarea id="ri-it" rows="2" style="min-height:56px" placeholder="Paste indicators or any text — IOCs are extracted and refanged"></textarea>
          <div class="spacer"></div>${ui.btn("Extract + add", 'id="ri-addi"', "sm")}</section>
        <section class="panel"><h2>ATT&amp;CK techniques</h2><div>${inc.attack.map((t) => `<span class="chip"><b class="mono">${esc(t)}</b> <span class="tiny muted">${esc(PB.TECHNIQUES[t] || "")}</span><button type="button" class="yb-x" data-rt="${esc(t)}" aria-label="Remove">✕</button></span>`).join("") || `<span class="muted small">none yet</span>`}</div>
          <div class="spacer"></div><div class="row" style="flex-wrap:nowrap"><input type="text" id="ri-at" placeholder="T1566.001" list="ri-tl" aria-label="Technique ID"><datalist id="ri-tl">${Object.entries(PB.TECHNIQUES).map(([k, v]) => `<option value="${esc(k)}">${esc(v)}</option>`).join("")}</datalist>${ui.btn("Add", 'id="ri-adda"', "sm")}</div></section>
      </div>
      <div class="grid g2">
        <section class="panel"><h2>Evidence &amp; chain of custody</h2>${ui.drop("ri-ev", "Drop evidence — hashed locally (SHA-256 + MD5); only the hashes are kept")}
          <div class="spacer"></div>${inc.evidence.map((e, i) => `<div class="finding info"><header><h3 class="break">${esc(e.name)}</h3><span class="tiny muted">${esc(W.fmt.bytes(e.size))}</span>${ui.btn("+ Custody", `data-cust="${i}"`, "sm ghost")}</header>
            <div class="det mono tiny break">sha256 ${esc(e.sha256)}<br>md5 ${esc(e.md5)}</div>
            ${(e.custody || []).map((c) => `<div class="det tiny">${esc(W.fmt.ts(c.t))} · <b>${esc(c.action)}</b>${c.by ? " · " + esc(c.by) : ""}${c.note ? " — " + esc(c.note) : ""}</div>`).join("")}</div>`).join("") || `<span class="muted small">No evidence recorded.</span>`}</section>
        <section class="panel"><h2>Timeline</h2><div class="row" style="flex-wrap:nowrap"><input type="text" id="ri-nt" placeholder="Note or action taken…" aria-label="Timeline entry">
            <select id="ri-nk" style="width:auto;flex:none" aria-label="Kind"><option value="note">note</option><option value="action">action</option><option value="finding">finding</option></select>${ui.btn("Log", 'id="ri-log"', "sm")}</div>
          <div class="spacer"></div><div class="yb-tl-list">${inc.timeline.map((t) => `<div class="yb-ev k-${esc(t.kind)}"><div class="tiny faint mono">${esc(W.fmt.ts(t.t))} · ${esc(String(t.kind).toUpperCase())}</div><div class="small break">${esc(t.text)}</div></div>`).join("")}</div></section>
      </div>`;

    const deb = (fn) => W.debounce(fn, 350);
    $("#ri-title").addEventListener("input", deb((e) => { inc.title = e.target.value.trim() || "Untitled"; commit(); }));
    $("#ri-title").addEventListener("change", rerender);
    $("#ri-sum").addEventListener("input", deb((e) => { inc.summary = e.target.value; commit(); }));
    const les = $("#ri-les"); if (les) les.addEventListener("input", deb((e) => { inc.lessons = e.target.value; commit(); }));
    $("#ri-own").addEventListener("change", (e) => { inc.owner = e.target.value.trim(); W.store.set(WHO, inc.owner); commit("action", `Owner set to ${inc.owner || "—"}`); });
    $("#ri-sev").onchange = (e) => { const o = inc.severity; inc.severity = e.target.value; commit("action", `Severity ${o} → ${inc.severity}`, true); };
    $("#ri-st").onchange = (e) => { const o = inc.status; inc.status = e.target.value; commit("action", `Status ${o} → ${inc.status}`, true); };
    $$(".yb-phases button", box).forEach((b) => (b.onclick = () => { if (b.dataset.p === inc.phase) return; inc.phase = b.dataset.p; commit("action", `Phase → ${Object.fromEntries(phases)[inc.phase]}`, true); }));
    $("#ri-pb").onchange = (e) => { if (!e.target.value) return; PB.apply(inc, e.target.value); commit(null, null, true); };
    box.addEventListener("change", (e) => {
      const c = e.target.closest("input[data-task]"); if (!c) return;
      const t = inc.tasks[+c.dataset.task]; t.done = c.checked; t.at = W.nowIso(); t.by = inc.owner || W.store.get(WHO, "");
      commit(c.checked ? "action" : "note", `${c.checked ? "✓" : "↺"} ${t.text}`, true);
    });
    const addTask = () => { const v = $("#ri-tt").value.trim(); if (!v) return; inc.tasks.push({ phase: inc.phase, text: v, done: false }); commit(null, null, true); };
    $("#ri-addt").onclick = addTask; $("#ri-tt").addEventListener("keydown", (e) => { if (e.key === "Enter") addTask(); });
    $("#ri-addi").onclick = () => {
      const v = $("#ri-it").value; if (!v.trim()) return;
      const items = PB.extractIocs(v); if (!items.length) return W.toast("No indicators recognised", 1);
      PB.addIocs(inc, items); commit(null, null, true);
    };
    box.addEventListener("click", (e) => {
      const rm = e.target.closest("[data-rm]"); if (rm) { const x = inc.iocs.splice(+rm.dataset.rm, 1)[0]; commit("note", `Indicator removed: ${x.value}`, true); return; }
      const rt = e.target.closest("[data-rt]"); if (rt) { inc.attack = inc.attack.filter((t) => t !== rt.dataset.rt); commit(null, null, true); return; }
      const g = e.target.closest("[data-go]"); if (g) { e.preventDefault(); const [ly, t] = g.dataset.go.split("/"); W.go(ly, t, ly === "yoroi" && t === "block" ? inc.iocs.map((x) => x.value).join("\n") : undefined); return; }
      const cu = e.target.closest("[data-cust]"); if (cu) custody(inc, +cu.dataset.cust, commit, rerender);
    });
    const addA = () => { const v = $("#ri-at").value.trim().toUpperCase(); if (!/^T\d{4}(\.\d{3})?$/.test(v)) return W.toast("Use a technique ID like T1059.001", 1); if (!inc.attack.includes(v)) inc.attack.push(v); commit(null, null, true); };
    $("#ri-adda").onclick = addA; $("#ri-at").addEventListener("keydown", (e) => { if (e.key === "Enter") addA(); });
    const blk = $("#ri-blk"); if (blk) blk.onclick = () => W.go("yoroi", "block", inc.iocs.map((x) => x.value).join("\n"));
    const cs = $("#ri-case"); if (cs) cs.onclick = () => W.Case.add(inc.iocs.map((x) => ({ value: x.value, type: x.type, tags: ["incident", inc.id], note: inc.title })));
    const df = $("#ri-def"); if (df) df.onclick = () => W.copy(inc.iocs.map((x) => W.defang(x.value)).join("\n"), "Defanged IOCs copied");
    const logIt = () => { const v = $("#ri-nt").value.trim(); if (!v) return; commit($("#ri-nk").value, v, true); };
    $("#ri-log").onclick = logIt; $("#ri-nt").addEventListener("keydown", (e) => { if (e.key === "Enter") logIt(); });
    $("#ri-rep").onclick = () => W.download(`${inc.id}.md`, PB.report(inc), "text/markdown;charset=utf-8");
    $("#ri-repc").onclick = () => W.copy(PB.report(inc), "Report copied (Markdown)");
    $("#ri-json").onclick = () => W.download(`${inc.id}.json`, JSON.stringify(inc, null, 2), "application/json");
    $("#ri-del").onclick = () => { if (!confirm(`Delete ${inc.id}? This cannot be undone.`)) return; save(l.filter((i) => i !== inc)); W.store.del(ACT); rerender(); };
    W.dropZone("ri-ev", async (f) => {
      try {
        const b = await W.readFile(f, "buffer");
        const sha256 = await W.hash.sha("SHA-256", b).catch(() => (W.eng.phish ? W.eng.phish.sha256(b) : ""));
        const ev = { name: f.name, size: f.size, type: f.type || "", sha256, md5: W.hash.md5(b), added: W.nowIso(),
          custody: [{ t: W.nowIso(), action: "collected", by: inc.owner || W.store.get(WHO, ""), note: "hashed in browser; content not stored" }] };
        inc.evidence.unshift(ev);
        commit("evidence", `Evidence added: ${f.name} (sha256 ${sha256.slice(0, 16)}…)`, true);
      } catch (e) { W.toast(e.message || String(e), 1); }
    }, { multiple: true });
  }

  function custody(inc, i, commit, rerender) {
    const ev = inc.evidence[i]; if (!ev) return;
    const m = W.modal(`<div class="col"><label class="lbl" for="cu-a">Action</label><select id="cu-a">${["transferred", "analyzed", "copied", "stored", "returned", "destroyed", "released"].map((a) => `<option>${a}</option>`).join("")}</select>
      <label class="lbl" for="cu-by">By</label><input type="text" id="cu-by" value="${esc(inc.owner || W.store.get(WHO, ""))}">
      <label class="lbl" for="cu-n">Note</label><input type="text" id="cu-n" placeholder="to whom, where, why"><div class="spacer"></div>${ui.btn("Record", 'id="cu-go"', "pri")}</div>`, { title: `Custody · ${ev.name}` });
    $("#cu-go", m).onclick = () => {
      const c = { t: W.nowIso(), action: $("#cu-a", m).value, by: $("#cu-by", m).value.trim(), note: $("#cu-n", m).value.trim() };
      (ev.custody = ev.custody || []).push(c);
      W.closeModal(); commit("evidence", `Custody: ${ev.name} ${c.action}${c.by ? " by " + c.by : ""}`, true);
    };
  }
})();
