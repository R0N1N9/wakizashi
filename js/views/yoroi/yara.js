/* Yoroi · YARA — scan dropped files (or pasted text) with the bundled + custom YARA-lite rules, manage the
 * custom rule library (`yoroi.yara.rules`, shared with Yumi's YARA builder) and toggle bundled rules
 * (`yoroi.yara.disabled`). Everything is scanned locally; files never leave the device. */
(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const KEY = "yoroi.yara.rules", OFF = "yoroi.yara.disabled", TAB = "yoroi.yara.tab";
  const MAX = 100 * 1024 * 1024;
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const TEMPLATE = `rule My_Detection : custom
{
    meta:
        description = "What this rule detects"
        severity = "medium"
        author = "me"
    strings:
        $s1 = "suspicious string" nocase ascii wide
        $h1 = { 4D 5A ?? 00 [0-8] 50 45 }
        $r1 = /cmd(\\.exe)?\\s+\\/c\\s+/ nocase
    condition:
        filesize < 10MB and (2 of ($s*, $r*) or $h1 at 0)
}
`;
  let RESULTS = [];          // survives tab switches within the session
  let EDIT = null;           // id of the rule set in the editor (null = new)

  const lib = () => { const l = W.store.get(KEY, []); return Array.isArray(l) ? l : []; };
  const saveLib = (l) => W.store.set(KEY, l);
  const disabled = () => new Set(W.store.get(OFF, []) || []);
  const sevOf = (h) => W.eng.yara.severity(h);
  const worst = (hits) => hits.filter((h) => !h.error).map(sevOf).sort((a, b) => SEVS.indexOf(a) - SEVS.indexOf(b))[0] || null;
  const srcBadge = (s) => ui.badge(s || "user", s === "yumi" ? "acc" : s === "import" ? "info" : "");

  /** Every rule that's switched on: bundled minus disabled + enabled custom sets. */
  function active() {
    const off = disabled(), Y = W.eng.yara;
    const rules = Y.builtin().filter((r) => !off.has(r.name)), errors = [];
    let custom = 0;
    for (const set of lib()) {
      if (set.enabled === false) continue;
      const c = Y.compile(set.text || "");
      for (const e of c.errors) errors.push(`${set.name}: ${e}`);
      // rule names must be unique across sets for references/caching to stay sane
      for (const r of c.rules) { rules.push(r); custom++; }
    }
    return { rules, errors, builtin: rules.length - custom, custom };
  }

  const ICON = '<path d="M4 4h10l6 6v10H4z"/><path d="M14 4v6h6"/><path d="M8 14h3M8 17h6"/><circle cx="16.5" cy="15.5" r="2.5"/><path d="M18.4 17.4 20 19"/>';

  W.tool("yoroi", "yara", {
    name: "YARA", order: 40, icon: ICON,
    desc: "Scan files with bundled + custom YARA-lite rules and manage your rule library.",
    render(el, arg) {
      el.innerHTML = ui.head("YARA", "File scanner", "Drop one or many files — they are scanned in this browser with the bundled rules plus your enabled custom rules (including rules sent from Yumi). Nothing is uploaded.") +
        `<div class="tabs" id="yr-tabs">${[["scan", "Scan"], ["library", "Custom rules"], ["bundled", "Bundled rules"]].map(([k, l]) => `<button type="button" data-tab="${k}">${l}</button>`).join("")}</div><div id="yr-body"></div>`;
      const box = $("#yr-tabs");
      const show = (t) => { W.store.set(TAB, t); $$("button[data-tab]", box).forEach((b) => b.classList.toggle("on", b.dataset.tab === t)); ({ scan, library, bundled })[t]($("#yr-body")); };
      W.tabs(box, show);
      if (typeof arg === "string" && /\brule\s+[A-Za-z_]\w*/.test(arg)) { EDIT = null; show("library"); $("#yr-text").value = arg; $("#yr-name").value = (/\brule\s+([A-Za-z_]\w*)/.exec(arg) || [])[1] || ""; validate(); return; }
      show(["scan", "library", "bundled"].includes(W.store.get(TAB)) ? W.store.get(TAB) : "scan");
      if (typeof arg === "string" && arg) { $("#yr-txt").value = arg; $("#yr-txtbox").open = true; scanText(); }
    },
  });

  // ------------------------------------------------------------------ scan tab
  function scan(b) {
    const a = active();
    b.innerHTML = `<div class="grid g3">${ui.stat(a.rules.length, "Rules active", 1)}${ui.stat(a.builtin, "Bundled")}${ui.stat(a.custom, "Custom")}</div>
      ${a.errors.length ? `<div class="callout warn"><b>Some custom rules didn't compile</b> and are skipped:<div class="tiny mono break">${a.errors.slice(0, 6).map(esc).join("<br>")}${a.errors.length > 6 ? "<br>…" : ""}</div></div><div class="spacer"></div>` : ""}
      ${ui.panel("Scan files", `${ui.drop("yr-drop", "Drop files to scan, or tap to choose (up to 50 at once)")}
        <div class="spacer"></div>
        <details class="yb-details" id="yr-txtbox"><summary class="small muted">…or scan pasted text (scripts, mail bodies, logs)</summary>
          <div class="spacer"></div><textarea id="yr-txt" rows="5" spellcheck="false" placeholder="Paste text to scan with the same rules"></textarea>
          <div class="spacer"></div><button class="btn pri" id="yr-txtgo">${W.icon(W.I.search)}Scan text</button></details>`)}
      <div class="row" id="yr-sumrow"></div><div class="spacer"></div><div id="yr-out"></div>`;
    W.dropZone("yr-drop", (f) => scanFile(f), { multiple: true });
    W.act("#yr-txtgo", scanText);
    draw();
  }

  async function scanBytes(name, bytes, size, truncated) {
    const t0 = performance.now();
    const a = active();
    const hits = W.eng.yara.scan(a.rules, bytes);
    const ms = Math.round(performance.now() - t0);
    let sha256 = "";
    try { sha256 = await W.hash.sha("SHA-256", bytes); } catch { sha256 = W.eng.phish ? W.eng.phish.sha256(bytes) : ""; }
    RESULTS.unshift({ id: W.uid(), name, size, sha256, md5: W.hash.md5(bytes), hits, ms, rules: a.rules.length, truncated, at: W.nowIso() });
    if (RESULTS.length > 200) RESULTS.length = 200;
    draw();
  }
  async function scanFile(f) {
    const out = $("#yr-out"); if (out && !RESULTS.length) out.innerHTML = ui.panel("", ui.loader("SCANNING " + f.name.toUpperCase()));
    try {
      let bytes = await W.readFile(f.size > MAX ? f.slice(0, MAX) : f, "buffer");
      await scanBytes(f.name, bytes, f.size, f.size > MAX);
      bytes = null;
    } catch (e) { W.toast(`${f.name}: ${e.message || e}`, 1); }
  }
  async function scanText() {
    const t = $("#yr-txt").value;
    if (!t.trim()) throw new Error("paste some text first");
    await scanBytes("pasted text", W.bytes(t), W.bytes(t).length, false);
  }

  function hitHtml(h) {
    if (h.error) return `<div class="det">${ui.badge("error", "warn")} <b class="mono">${esc(h.rule)}</b> — ${esc(h.error)}</div>`;
    const sev = sevOf(h), m = h.meta || {};
    const extra = Object.entries(m).filter(([k]) => !["description", "severity"].includes(k)).slice(0, 6);
    return `<div class="yb-hit">
      <div class="row">${ui.sev(sev, true)}<b class="mono break">${esc(h.rule)}</b>${(h.tags || []).map((t) => ui.chip(t)).join("")}</div>
      ${m.description ? `<div class="det">${esc(m.description)}</div>` : ""}
      ${extra.length ? `<div class="tiny faint break">${extra.map(([k, v]) => `${esc(k)}: ${esc(v)}`).join(" · ")}</div>` : ""}
      ${h.strings.length ? ui.table(["String", "Count", "First @", "Preview"], h.strings.map((s) => [s.id, s.count, "0x" + s.first.toString(16), `<code>${esc(s.preview)}</code>`].map((c, i) => (i === 3 ? c : esc(c)))), { raw: true, max: 220 }) : `<div class="tiny faint">condition-only match (no strings)</div>`}
    </div>`;
  }

  function draw() {
    const out = $("#yr-out"), sum = $("#yr-sumrow");
    if (!out) return;
    if (!RESULTS.length) { out.innerHTML = ui.panel("", ui.empty("NO SCANS YET", "Drop files above. Tip: a PHP file with system($_GET[...]) trips the webshell rule.")); sum.innerHTML = ""; return; }
    const flagged = RESULTS.filter((r) => r.hits.some((h) => !h.error));
    sum.innerHTML = `<span class="small muted">${RESULTS.length} scanned · <b class="${flagged.length ? "c-crit" : ""}">${flagged.length} with matches</b></span><span class="grow"></span>
      ${flagged.length ? ui.btn(W.icon(W.I.case) + "Add flagged hashes to case", 'id="yr-case"', "sm") : ""}
      ${ui.btn(W.icon(W.I.dl) + "Report", 'id="yr-rep"', "sm")}${ui.btn(W.icon(W.I.trash) + "Clear", 'id="yr-clr"', "sm ghost")}`;
    const order = (r) => { const w = worst(r.hits); return w ? SEVS.indexOf(w) : 9; };
    const list = RESULTS.slice().sort((a, b) => order(a) - order(b));
    out.innerHTML = list.map((r) => {
      const w = worst(r.hits), real = r.hits.filter((h) => !h.error);
      return `<div class="finding ${w || "ok"}" data-id="${esc(r.id)}"><header>${w ? ui.sev(w, true) : ui.badge("clean", "ok", 1)}<h3 class="break">${esc(r.name)}</h3>
          <span class="tiny muted">${esc(W.fmt.bytes(r.size))} · ${real.length} match${real.length === 1 ? "" : "es"} · ${r.rules} rules · ${r.ms} ms</span></header>
        <div class="det mono tiny break">sha256 ${esc(r.sha256)}<br>md5 ${esc(r.md5)}</div>
        ${r.truncated ? `<div class="det tiny" style="color:var(--med)">Only the first ${W.fmt.bytes(MAX)} were scanned (filesize conditions see the truncated size).</div>` : ""}
        ${r.hits.length ? `<div class="spacer"></div>${r.hits.map(hitHtml).join("")}` : `<div class="det">No enabled rule matched.</div>`}
        <div class="row" style="margin-top:8px">${ui.btn(W.icon(W.I.copy) + "SHA-256", `data-a="copy" data-id="${esc(r.id)}"`, "sm ghost")}
          ${real.length ? ui.btn(W.icon(W.I.case) + "Add to case", `data-a="case" data-id="${esc(r.id)}"`, "sm ghost") + ui.btn("Block hash", `data-a="block" data-id="${esc(r.id)}"`, "sm ghost") : ""}</div></div>`;
    }).join("");
    out.onclick = (e) => {
      const b = e.target.closest("button[data-a]"); if (!b) return;
      const r = RESULTS.find((x) => x.id === b.dataset.id); if (!r) return;
      if (b.dataset.a === "copy") W.copy(r.sha256, "SHA-256 copied");
      if (b.dataset.a === "case") W.Case.add([{ value: r.sha256, type: "sha256", verdict: "malicious", tags: ["yara", ...r.hits.filter((h) => !h.error).map((h) => h.rule)], note: `YARA: ${r.name}` }]);
      if (b.dataset.a === "block") W.go("yoroi", "block", r.sha256);
    };
    const c = $("#yr-case"); if (c) c.onclick = () => W.Case.add(flagged.map((r) => ({ value: r.sha256, type: "sha256", verdict: "malicious", tags: ["yara", ...r.hits.filter((h) => !h.error).map((h) => h.rule)], note: `YARA: ${r.name}` })));
    $("#yr-clr").onclick = () => { RESULTS = []; draw(); };
    $("#yr-rep").onclick = () => W.download(`wakizashi-yara-${W.nowIso().slice(0, 10)}.md`, report());
  }

  function report() {
    const L = ["# YARA scan report", "", `Generated by Wakizashi (Yoroi · YARA) on ${W.nowIso()}.`, ""];
    for (const r of RESULTS) {
      const real = r.hits.filter((h) => !h.error);
      L.push(`## ${r.name.replace(/[\r\n#]/g, " ")}`, "", `- Size: ${r.size} bytes`, `- SHA-256: \`${r.sha256}\``, `- MD5: \`${r.md5}\``, `- Rules evaluated: ${r.rules}`, `- Matches: ${real.length}`, "");
      for (const h of real) {
        L.push(`### ${h.rule} (${sevOf(h)})`, "", h.meta.description ? h.meta.description + "\n" : "");
        for (const s of h.strings) L.push(`- \`${s.id}\` × ${s.count}, first at 0x${s.first.toString(16)}: \`${s.preview.replace(/`/g, "'")}\``);
        L.push("");
      }
    }
    return L.join("\n");
  }

  // ------------------------------------------------------------------ custom rule library
  function library(b) {
    b.innerHTML = `<div class="grid g2 yb-split"><div>
        ${ui.panel("Custom rule sets", `<div id="yr-list"></div><div class="spacer"></div>
          <div class="row">${ui.btn(W.icon(W.I.plus) + "New", 'id="yr-new"', "sm pri")}
            <label class="btn sm ghost">${W.icon(W.I.up)}Import .yar<input type="file" id="yr-imp" accept=".yar,.yara,.txt,.rule,.rules" hidden></label>
            ${ui.btn(W.icon(W.I.dl) + "Export all", 'id="yr-exp"', "sm ghost")}</div>`)}
        <div class="callout small">Rule sets from <b>Yumi</b> (YARA builder / workbench) land here tagged <span class="badge acc">yumi</span>. Rules reference earlier rules in the same set by name; <code>private</code> rules are evaluated but never reported.</div>
      </div><div>${ui.panel("Editor", `<div class="row"><input type="text" id="yr-name" placeholder="Rule set name" style="flex:1;min-width:160px">
          <label class="check"><input type="checkbox" id="yr-en" checked> enabled</label></div><div class="spacer"></div>
        <textarea id="yr-text" class="yb-code" spellcheck="false" autocapitalize="off" autocomplete="off"></textarea>
        <div class="spacer"></div><div class="row">${ui.btn(W.icon(W.I.check) + "Validate", 'id="yr-val"', "sm")}${ui.btn("Save", 'id="yr-save"', "sm pri")}
          ${ui.btn("Duplicate", 'id="yr-dup"', "sm ghost")}<span class="grow"></span>${ui.btn(W.icon(W.I.trash) + "Delete", 'id="yr-del"', "sm danger")}</div>
        <div class="spacer"></div><div id="yr-msg"></div>`)}</div></div>`;
    drawList(); edit(EDIT);
    $("#yr-list").addEventListener("click", (e) => {
      const tog = e.target.closest("input[data-tog]");
      if (tog) { const l = lib(), s = l.find((x) => x.id === tog.dataset.tog); if (s) { s.enabled = tog.checked; s.updated = W.nowIso(); saveLib(l); } drawList(); return; }
      const it = e.target.closest("[data-id]"); if (it) edit(it.dataset.id);
    });
    $("#yr-new").onclick = () => edit(null);
    $("#yr-imp").addEventListener("change", async (e) => {
      const f = e.target.files[0]; e.target.value = ""; if (!f) return;
      const text = await W.readFile(f, "text");
      const l = lib(), rec = { id: W.uid(), name: f.name.replace(/\.(yara?|txt|rules?)$/i, ""), text, enabled: true, updated: W.nowIso(), source: "import" };
      l.unshift(rec); saveLib(l); edit(rec.id); validate(); W.toast(`Imported ${f.name}`);
    });
    $("#yr-exp").onclick = () => { const l = lib(); if (!l.length) return W.toast("No custom rules yet", 1); W.download("wakizashi-custom.yar", l.map((s) => `// ---- ${s.name.replace(/[\r\n]/g, " ")} (${s.source || "user"}, ${s.enabled === false ? "disabled" : "enabled"})\n${s.text}`).join("\n\n")); };
    $("#yr-val").onclick = validate;
    $("#yr-save").onclick = () => {
      const v = validate(); if (!v.rules.length) return W.toast("Fix the errors before saving", 1);
      const l = lib(), cur = l.find((x) => x.id === EDIT);
      const rec = { id: cur ? cur.id : W.uid(), name: $("#yr-name").value.trim() || v.rules[0].name, text: $("#yr-text").value, enabled: $("#yr-en").checked, updated: W.nowIso(), source: cur ? cur.source || "user" : "user" };
      if (cur) Object.assign(cur, rec); else l.unshift(rec);
      saveLib(l); EDIT = rec.id; drawList(); W.toast(v.errors.length ? "Saved (with warnings)" : "Saved");
    };
    $("#yr-dup").onclick = () => { $("#yr-name").value = ($("#yr-name").value || "rules") + " copy"; EDIT = null; drawList(); W.toast("Editing a copy — Save to keep it"); };
    $("#yr-del").onclick = () => {
      if (EDIT == null) return edit(null);
      const l = lib(), s = l.find((x) => x.id === EDIT); if (!s || !confirm(`Delete “${s.name}”?`)) return;
      saveLib(l.filter((x) => x.id !== EDIT)); edit(null);
    };
  }
  function drawList() {
    const l = lib(), box = $("#yr-list"); if (!box) return;
    box.innerHTML = l.length ? l.map((s) => {
      const c = W.eng.yara.compile(s.text || "");
      return `<div class="yb-item ${s.id === EDIT ? "on" : ""}" data-id="${esc(s.id)}"><input type="checkbox" data-tog="${esc(s.id)}" ${s.enabled === false ? "" : "checked"} aria-label="Enable ${esc(s.name)}">
        <div class="col" style="flex:1"><b class="break">${esc(s.name)}</b><span class="tiny muted">${c.rules.length} rule${c.rules.length === 1 ? "" : "s"}${c.errors.length ? ` · <span style="color:var(--med)">${c.errors.length} error${c.errors.length === 1 ? "" : "s"}</span>` : ""} · ${esc(W.fmt.ago(s.updated))}</span></div>${srcBadge(s.source)}</div>`;
    }).join("") : ui.empty("NO CUSTOM RULES", "Create one, import a .yar, or send rules from Yumi.");
  }
  function edit(id) {
    const s = id == null ? null : lib().find((x) => x.id === id);
    EDIT = s ? s.id : null;
    if (!$("#yr-text")) return;
    $("#yr-name").value = s ? s.name : "";
    $("#yr-en").checked = s ? s.enabled !== false : true;
    $("#yr-text").value = s ? s.text : TEMPLATE;
    $("#yr-msg").innerHTML = s && s.source === "yumi" ? `<div class="callout small">From Yumi · edits stay local to Yoroi.</div>` : "";
    drawList();
  }
  function validate() {
    const v = W.eng.yara.validate($("#yr-text").value);
    $("#yr-msg").innerHTML = `<div class="callout ${v.errors.length ? (v.rules.length ? "warn" : "bad") : "ok"}">${v.rules.length ? `${W.icon(W.I.check)} ${v.rules.length} rule(s) compiled: ${v.rules.map((r) => `<code>${esc(r.name)}</code>${r.private ? " (private)" : ""}`).join(" ")}` : "<b>No rules compiled.</b>"}
      ${v.errors.length ? `<div class="tiny mono break" style="margin-top:6px">${v.errors.map(esc).join("<br>")}</div>` : ""}</div>`;
    return v;
  }

  // ------------------------------------------------------------------ bundled rules
  function bundled(b) {
    const off = disabled(), rs = W.eng.yara.builtin();
    b.innerHTML = ui.panel(`Bundled rules (${rs.length - rs.filter((r) => off.has(r.name)).length}/${rs.length} on)`, `
      ${ui.table(["On", "Rule", "Severity", "Description", ""], rs.map((r) => [
        `<input type="checkbox" data-b="${esc(r.name)}" ${off.has(r.name) ? "" : "checked"} aria-label="Enable ${esc(r.name)}">`,
        `<span class="mono small break">${esc(r.name)}</span>`, ui.sev(W.eng.yara.severity({ meta: r.meta })), esc(r.meta.description || ""),
        ui.btn("View", `data-v="${esc(r.name)}"`, "sm ghost")]), { raw: true })}
      <div class="spacer"></div><div class="row">${ui.btn("View all source", 'id="yr-all"', "sm ghost")}${ui.btn("Enable all", 'id="yr-on"', "sm ghost")}
        ${ui.btn(W.icon(W.I.dl) + "Download .yar", 'id="yr-dlb"', "sm ghost")}</div>
      <div class="spacer"></div><div class="callout small">Ported from Katana's Aegis YARA-lite pack, plus Wakizashi additions (encoded PowerShell, WSH droppers, LNK launchers, miners, EICAR).</div>`);
    b.onclick = (e) => {
      const v = e.target.closest("[data-v]");
      if (v) { const r = rs.find((x) => x.name === v.dataset.v); W.modal(`<pre class="out">${esc(r.src)}</pre>`, { title: r.name }); }
    };
    b.onchange = (e) => {
      const c = e.target.closest("input[data-b]"); if (!c) return;
      const s = disabled(); c.checked ? s.delete(c.dataset.b) : s.add(c.dataset.b); W.store.set(OFF, [...s]); bundled(b);
    };
    $("#yr-all").onclick = () => W.modal(`<pre class="out">${esc(W.eng.yara.BUILTIN.trim())}</pre>`, { title: "Bundled YARA-lite rules" });
    $("#yr-on").onclick = () => { W.store.set(OFF, []); bundled(b); };
    $("#yr-dlb").onclick = () => W.download("wakizashi-bundled.yar", W.eng.yara.BUILTIN.trim() + "\n");
  }
})();
