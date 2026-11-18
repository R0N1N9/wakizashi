/* Yoroi · RULES — built-in detections (toggles + thresholds), custom Sigma library (edit, validate, test, import/export)
 * and the bundled Sigma rules. HUNT reads the same store keys:
 *   yoroi.rules.disabled    [ids]                      — detection ids and bundled-Sigma ids that are switched off
 *   yoroi.rules.sigma       [{id,name,text,enabled,updated}]
 *   yoroi.rules.thresholds  {brute_count, …}           — overrides of W.eng.detect.DEFAULTS */
(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const K = { off: "yoroi.rules.disabled", sigma: "yoroi.rules.sigma", th: "yoroi.rules.thresholds", tab: "yoroi.rules.tab" };
  const TEMPLATE = String.raw`title: My detection
id: my-rule-0001
status: experimental
description: What this rule catches and why it matters.
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains|windash:
            - ' -enc '
            - ' -EncodedCommand '
    filter:
        ParentImage|endswith: '\explorer.exe'
    condition: selection and not filter
falsepositives:
    - Admin scripts
level: high`;

  const getOff = () => new Set(W.store.get(K.off, []) || []);
  const setOff = (s) => W.store.set(K.off, [...s]);
  const lib = () => W.store.get(K.sigma, []) || [];
  const sevOf = (lvl) => (lvl === "informational" ? "info" : lvl);

  W.tool("yoroi", "rules", {
    name: "Rules", order: 20,
    desc: "Toggle detections, tune thresholds, write and test Sigma rules for HUNT.",
    help: {
      steps: ["Switch built-in detections on or off and tune their thresholds.", "Write a new Sigma rule (or Import .yml), Validate it, and Run test against sample logs.", "Save — HUNT uses your library straight away."],
      tips: ["Export your rules to back them up; Reset to defaults undoes tuning."],
    },
    icon: '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    render(el, arg) {
      const fromArg = typeof arg === "string" && /title\s*:/.test(arg);
      let tab = fromArg ? "sigma" : W.store.get(K.tab, "builtin");
      if (!["builtin", "sigma", "bundled"].includes(tab)) tab = "builtin";
      el.innerHTML = ui.head("Rules", "Detection library", "Built-in behavioural detections and Sigma rules that HUNT runs. Everything is stored in this browser; switch rules off, tune thresholds, or write your own Sigma and test it against logs.") + `
        <div class="tabs" id="ru-tabs">${[["builtin", "Detections"], ["sigma", "Sigma library"], ["bundled", "Bundled Sigma"]].map(([k, l]) => `<button type="button" data-tab="${k}" class="${k === tab ? "on" : ""}">${l}</button>`).join("")}</div>
        <div id="ru-body"></div>`;
      const show = (t, a) => { tab = t; W.store.set(K.tab, t); (t === "builtin" ? builtin : t === "sigma" ? sigmaTab : bundled)($("#ru-body"), a); };
      W.tabs($("#ru-tabs"), (t) => show(t));
      show(tab, fromArg ? arg : null);
    },
  });

  // ---------------------------------------------------------------- built-in detections
  function builtin(out) {
    const off = getOff(), cat = W.eng.detect.catalog(), th = Object.assign({}, W.eng.detect.DEFAULTS, W.store.get(K.th, {}) || {});
    out.innerHTML = `<section class="panel"><div class="row"><h2 style="margin:0">Behavioural detections</h2><span class="grow"></span>
        <span class="muted tiny" id="ru-bcount"></span><button type="button" class="btn sm ghost" id="ru-ball">All on</button></div><div class="spacer"></div>
        <div class="tablewrap"><table class="tbl"><thead><tr><th>On</th><th>Detection</th><th>Severity</th><th>ATT&amp;CK</th></tr></thead><tbody>
        ${cat.map((d) => `<tr><td><input type="checkbox" data-id="${esc(d.id)}" aria-label="Enable ${esc(d.name)}" ${off.has(d.id) ? "" : "checked"}></td>
          <td><b>${esc(d.name)}</b> <span class="mono faint tiny nowrap">${esc(d.id)}</span><div class="muted small">${esc(d.desc)}</div></td>
          <td>${ui.sev(d.severity)}</td><td>${d.attack.map((t) => ui.badge(t, "acc")).join(" ")}</td></tr>`).join("")}</tbody></table></div></section>
      <section class="panel"><h2>Thresholds</h2>
        <div class="grid g3">${Object.keys(W.eng.detect.DEFAULTS).map((k) => `<div><label class="lbl" for="ru-th-${k}">${esc(W.eng.detect.THRESHOLD_HELP[k] || k)}</label>
          <input type="number" min="0" id="ru-th-${k}" data-th="${k}" value="${esc(th[k])}"></div>`).join("")}</div>
        <div class="spacer"></div><div class="row"><button type="button" class="btn sm" id="ru-thsave">Save thresholds</button><button type="button" class="btn sm ghost" id="ru-threset">Reset to defaults</button>
        <span class="muted tiny">Hunts use these immediately.</span></div></section>`;
    const count = () => { $("#ru-bcount").textContent = `${cat.filter((d) => !getOff().has(d.id)).length} of ${cat.length} enabled`; };
    count();
    out.querySelectorAll("input[data-id]").forEach((c) => c.addEventListener("change", () => { const s = getOff(); if (c.checked) s.delete(c.dataset.id); else s.add(c.dataset.id); setOff(s); count(); }));
    $("#ru-ball").addEventListener("click", () => { const s = getOff(); cat.forEach((d) => s.delete(d.id)); setOff(s); builtin(out); W.toast("All detections enabled"); });
    $("#ru-thsave").addEventListener("click", () => {
      const o = {};
      for (const i of $$("[data-th]", out)) { const v = Number(i.value); if (!Number.isFinite(v) || v < 0) return W.toast(`Invalid value for ${i.dataset.th}`, 1); if (v !== W.eng.detect.DEFAULTS[i.dataset.th]) o[i.dataset.th] = v; }
      W.store.set(K.th, o); W.toast("Thresholds saved");
    });
    $("#ru-threset").addEventListener("click", () => { W.store.del(K.th); builtin(out); W.toast("Thresholds reset"); });
  }

  // ---------------------------------------------------------------- bundled Sigma
  function bundled(out) {
    const off = getOff();
    let rules = [];
    try { rules = W.eng.sigma.builtinRules(); } catch (e) { out.innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; return; }
    out.innerHTML = `<section class="panel"><div class="row"><h2 style="margin:0">Bundled Sigma rules</h2><span class="grow"></span>
        <button type="button" class="btn sm ghost" id="ru-src">View source</button><button type="button" class="btn sm ghost" id="ru-copyb">Copy into my library</button></div><div class="spacer"></div>
      ${rules.map((r) => `<div class="finding ${esc(sevOf(r.level))}"><header><input type="checkbox" data-b="${esc(r.id)}" aria-label="Enable ${esc(r.title)}" ${off.has(r.id) ? "" : "checked"}>
        <h3>${esc(r.title)}</h3>${ui.sev(sevOf(r.level))}</header>
        <div class="det">${esc(r.doc.description || "")}</div>
        <div class="yo-meta tiny"><span class="mono muted">${esc(r.id)} · ${esc(Object.values(r.logsource).join(" / "))}</span>${r.attack.map((t) => ui.badge(t, "acc")).join(" ")}</div></div>`).join("")}</section>`;
    out.querySelectorAll("[data-b]").forEach((c) => c.addEventListener("change", () => { const s = getOff(); if (c.checked) s.delete(c.dataset.b); else s.add(c.dataset.b); setOff(s); }));
    $("#ru-src").addEventListener("click", () => W.modal(`<pre class="out">${esc(W.eng.sigma.BUILTIN)}</pre>`, { title: "Bundled Sigma rules" }));
    $("#ru-copyb").addEventListener("click", () => {
      const L = lib(); L.unshift({ id: W.uid(), name: "Bundled rules (copy)", text: W.eng.sigma.BUILTIN, enabled: false, updated: W.nowIso() });
      W.store.set(K.sigma, L); W.toast("Copied as a disabled rule set — edit it in Sigma library");
    });
  }

  // ---------------------------------------------------------------- Sigma library
  function sigmaTab(out, newText) {
    out.innerHTML = `<div class="grid g2 yo-split">
      <div>
        <section class="panel"><h2>My Sigma rules</h2><div id="ru-list"></div><div class="spacer"></div>
          <div class="row"><button type="button" class="btn sm pri" id="ru-new">${W.icon(W.I.plus)} New rule</button>
          <label class="btn sm ghost">${W.icon(W.I.up)} Import .yml<input type="file" id="ru-imp" accept=".yml,.yaml,.txt,text/yaml" multiple></label>
          <button type="button" class="btn sm ghost" id="ru-exp">${W.icon(W.I.dl)} Export</button></div></section>
        <section class="panel"><h2>Test against logs</h2>
          <textarea id="ru-logs" rows="6" spellcheck="false" placeholder="Paste log lines to test the rule in the editor…"></textarea>
          <div class="spacer"></div><div class="row"><button type="button" class="btn sm pri" id="ru-run">${W.icon(W.I.play)} Run test</button>
          <select id="ru-sample" style="width:auto"><option value="">Load a sample…</option>${Object.keys((W.yoroiHunt || {}).SAMPLES || {}).map((k) => `<option>${esc(k)}</option>`).join("")}</select></div>
          <div id="ru-tout"></div></section>
      </div>
      <div><section class="panel">
        <div class="row"><input type="text" id="ru-name" placeholder="Rule set name" style="flex:1;min-width:160px"><label class="check"><input type="checkbox" id="ru-en" checked> enabled</label></div>
        <div class="spacer"></div><textarea id="ru-text" class="yo-code" spellcheck="false" autocapitalize="off" aria-label="Sigma rule YAML"></textarea>
        <div class="spacer"></div><div class="row"><button type="button" class="btn sm" id="ru-val">${W.icon(W.I.check)} Validate</button><button type="button" class="btn sm pri" id="ru-save">Save</button>
          <button type="button" class="btn sm ghost" id="ru-copy">${W.icon(W.I.copy)} Copy</button><span class="grow"></span><button type="button" class="btn sm danger" id="ru-del">${W.icon(W.I.trash)} Delete</button></div>
        <div id="ru-msg"></div></section></div></div>`;
    let cur = null;      // index into lib()
    const drawList = () => {
      const L = lib();
      $("#ru-list").innerHTML = L.length ? `<div class="tablewrap"><table class="tbl"><tbody>${L.map((r, i) => `<tr class="${cur === i ? "yo-sel" : ""}"><td style="width:34px"><input type="checkbox" data-en="${i}" aria-label="Enable ${esc(r.name)}" ${r.enabled === false ? "" : "checked"}></td>
        <td><button type="button" class="yo-link" data-i="${i}">${esc(r.name || "untitled")}</button><div class="faint tiny">${r.enabled === false ? "disabled" : "enabled"} · ${esc(W.fmt.ago(r.updated))}</div></td></tr>`).join("")}</tbody></table></div>`
        : ui.empty("NONE YET", "Create a rule, import a .yml, or save one from SYNTH.");
    };
    const edit = (i, text, name) => {
      cur = i; const r = i == null ? null : lib()[i];
      $("#ru-name").value = r ? r.name || "" : name || "";
      $("#ru-en").checked = r ? r.enabled !== false : true;
      $("#ru-text").value = r ? r.text || "" : text || TEMPLATE;
      $("#ru-msg").innerHTML = ""; drawList();
    };
    const validate = () => {
      const v = W.eng.sigma.compile($("#ru-text").value);
      $("#ru-msg").innerHTML = `<div class="spacer"></div><div class="callout ${v.errors.length ? (v.rules.length ? "warn" : "bad") : "ok"}">${v.rules.length} rule(s) compiled${v.rules.length ? ": " + v.rules.map((r) => `<b>${esc(r.title)}</b> ${ui.sev(sevOf(r.level))}`).join(", ") : ""}${v.errors.length ? "<br>" + v.errors.map(esc).join("<br>") : ""}</div>`;
      return v;
    };
    $("#ru-list").addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) edit(+b.dataset.i); });
    $("#ru-list").addEventListener("change", (e) => { const c = e.target.closest("[data-en]"); if (!c) return; const L = lib(); L[+c.dataset.en].enabled = c.checked; W.store.set(K.sigma, L); drawList(); });
    $("#ru-new").addEventListener("click", () => edit(null));
    $("#ru-imp").addEventListener("change", async (e) => {
      const files = [...e.target.files]; e.target.value = "";
      if (!files.length) return;
      const L = lib(); let ok = 0, bad = 0;
      for (const f of files.slice(0, 50)) {
        const text = await W.readFile(f, "text"); const v = W.eng.sigma.compile(text);
        if (!v.rules.length) { bad++; continue; }
        L.unshift({ id: W.uid(), name: f.name.replace(/\.(ya?ml|txt)$/i, ""), text, enabled: true, updated: W.nowIso() }); ok++;
      }
      W.store.set(K.sigma, L); edit(ok ? 0 : null);
      W.toast(`Imported ${ok} rule file(s)${bad ? ` · ${bad} had no valid rule` : ""}`, !ok);
    });
    $("#ru-exp").addEventListener("click", () => { const L = lib(); if (!L.length) return W.toast("Nothing to export", 1); W.download("yoroi-sigma-rules.yml", L.map((r) => r.text.trim()).join("\n---\n") + "\n", "text/yaml"); });
    $("#ru-val").addEventListener("click", validate);
    $("#ru-copy").addEventListener("click", () => W.copy($("#ru-text").value, "Rule copied"));
    $("#ru-save").addEventListener("click", () => {
      const v = validate();
      if (!v.rules.length) return W.toast("Fix the errors before saving", 1);
      const L = lib();
      const rec = { id: cur != null && L[cur] ? L[cur].id : W.uid(), name: $("#ru-name").value.trim() || v.rules[0].title, text: $("#ru-text").value, enabled: $("#ru-en").checked, updated: W.nowIso() };
      if (cur != null && L[cur]) L[cur] = rec; else { L.unshift(rec); cur = 0; }
      W.store.set(K.sigma, L); drawList(); W.toast(rec.enabled ? "Saved — HUNT will run it" : "Saved (disabled)");
    });
    $("#ru-del").addEventListener("click", () => {
      if (cur == null) return W.toast("Pick a saved rule to delete", 1);
      if (!confirm("Delete this rule set?")) return;
      const L = lib(); L.splice(cur, 1); W.store.set(K.sigma, L); edit(L.length ? 0 : null);
    });
    $("#ru-sample").addEventListener("change", (e) => { const k = e.target.value; if (k && W.yoroiHunt) $("#ru-logs").value = W.yoroiHunt.SAMPLES[k](); e.target.value = ""; });
    W.act("#ru-run", () => {
      const v = W.eng.sigma.compile($("#ru-text").value);
      const logs = $("#ru-logs").value, tout = $("#ru-tout");
      if (!v.rules.length) { tout.innerHTML = `<div class="spacer"></div><div class="callout bad">${(v.errors.length ? v.errors : ["no rule"]).map(esc).join("<br>")}</div>`; return; }
      if (!logs.trim()) return W.toast("Paste some logs or load a sample", 1);
      const p = W.eng.logs.parse(logs);
      const hits = W.eng.sigma.run(v.rules, p.events), idx = new Set(hits.flatMap((h) => h.events));
      const rows = p.events.filter((e) => idx.has(e.i));
      tout.innerHTML = `<div class="spacer"></div><div class="callout ${rows.length ? "" : "warn"}"><b>${rows.length}</b> of ${W.fmt.num(p.events.length)} ${esc(p.fmt)} event(s) matched${hits.length ? " · " + hits.map((h) => `${esc(h.name)} ×${h.count}`).join(", ") : ""}.
          ${v.rules.some((r) => r.fmts) ? `<span class="faint">Rules only run on events their logsource maps to.</span>` : ""}</div>
        ${rows.length ? `<div class="spacer"></div>${ui.table(["#", "Time", "Message"], rows.slice(0, 200).map((e) => [String(e.i), e.ts || "—", String(e.msg).slice(0, 220)]), { max: 320 })}` : ""}
        <div class="spacer"></div><div class="row"><button type="button" class="btn sm ghost" id="ru-syn">⚙ Synthesise a rule from these logs</button></div>`;
      $("#ru-syn").addEventListener("click", () => W.go("yoroi", "synth", { text: logs, fmt: "auto", indices: [...idx], title: "" }));
    });
    const L = lib();
    if (newText) edit(null, newText, (/^title:\s*(.+)$/m.exec(newText) || [])[1] || "");
    else edit(L.length ? 0 : null);
  }
})();
