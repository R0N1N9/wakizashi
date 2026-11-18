(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const LIB = "yumi.yara.library";

  W.tool("yumi", "yara", {
    name: "YARA", order: 40,
    desc: "Build YARA rules from IOCs, a sample, strings or a template; validate, test and keep a library.",
    icon: '<path d="M4 4h16v4H4zM4 10h10v4H4zM4 16h7v4H4z"/><path d="M17 14l2 2 3-4"/>',
    render(el, arg) {
      let tab = arg && arg.strings ? "build" : W.store.get("yumi.yara.tab", "iocs");
      el.innerHTML = ui.head("YARA", "Rule builder", "Generate signatures from threat intel, validate them with the built-in YARA-lite engine, test against a file, and keep a local library. Send rules to Yoroi to scan files.") + `
        <div class="tabs" id="yg-tabs">${[["iocs", "From IOCs"], ["sample", "From sample"], ["build", "Builder"], ["lib", "Library"]].map(([k, l]) => `<button data-tab="${k}" class="${k === tab ? "on" : ""}">${l}</button>`).join("")}</div>
        <div id="yg-body"></div><div id="yg-out"></div>`;
      W.tabs($("#yg-tabs"), (t) => { tab = t; W.store.set("yumi.yara.tab", t); body(); });
      const body = () => {
        $("#yg-out").innerHTML = "";
        const b = $("#yg-body");
        if (tab === "iocs") {
          b.innerHTML = ui.panel("", `<label class="lbl" for="yg-iocs">IOCs or report text</label><textarea id="yg-iocs" rows="7" spellcheck="false" placeholder="Domains, IPs, URLs, emails, hashes — or a whole report"></textarea>
            <div class="spacer"></div><button class="btn pri" id="yg-go">Generate</button>`);
          W.act("#yg-go", () => { const t = $("#yg-iocs").value; if (!t.trim()) throw new Error("paste some IOCs first"); show(W.eng.yaragen.fromIocs(t)); });
        } else if (tab === "sample") {
          b.innerHTML = ui.panel("", ui.drop("yg-drop", "Drop a sample (or tap to choose) — strings and hashes are extracted locally") + `<div class="spacer"></div><div id="yg-sinfo"></div>`);
          W.dropZone("yg-drop", async (f) => {
            $("#yg-sinfo").innerHTML = ui.loader("ANALYSING");
            const r = await W.eng.yaragen.fromSample(await W.readFile(f, "buffer"), f.name);
            $("#yg-sinfo").innerHTML = ui.kv([["File", f.name], ["Type", r.filetype], ["Size", W.fmt.bytes(r.size)], ["Entropy", r.entropy.toFixed(2)], ["SHA-256", `<code>${esc(r.hashes.sha256)}</code>`, true], ["Candidates", String(r.candidates.length)]]);
            show(r);
          });
        } else if (tab === "build") builder(b, arg && arg.strings ? arg : null);
        else library(b);
      };
      function builder(b, pre) {
        const tpl = W.eng.yaragen.TEMPLATES;
        b.innerHTML = ui.panel("", `<div class="grid g2"><div class="col"><label class="lbl" for="yb-name">Rule name</label><input id="yb-name" value="${esc(pre ? pre.name : "my_rule")}"></div>
            <div class="col"><label class="lbl" for="yb-tpl">Start from template</label><select id="yb-tpl"><option value="">—</option>${tpl.map((t, i) => `<option value="${i}">${esc(t.name)}</option>`).join("")}</select></div></div>
          <div class="spacer"></div><label class="lbl" for="yb-desc">Description</label><input id="yb-desc" placeholder="What this rule detects">
          <div class="spacer"></div><label class="lbl" for="yb-strs">Strings — one per line. Prefix <code>hex:</code> for hex, <code>re:</code> for regex</label>
          <textarea id="yb-strs" rows="6" spellcheck="false" placeholder="evil-c2.example&#10;hex:4D 5A 90 00&#10;re:\\$_(GET|POST)\\[">${esc(pre ? pre.strings.join("\n") : "")}</textarea>
          <div class="spacer"></div><div class="row"><label class="check"><input type="checkbox" id="yb-wide" checked> ascii + wide</label><label class="check"><input type="checkbox" id="yb-nocase"> nocase</label><label class="check"><input type="checkbox" id="yb-mz"> PE files only (MZ)</label></div>
          <div class="row"><label class="lbl" style="margin:0">Condition</label>${ui.seg("yb-cond", [["any", "any of them"], ["all", "all of them"], ["n", "N of them"]], "any")}<input id="yb-n" type="number" min="1" value="2" style="width:80px"></div>
          <div class="spacer"></div><button class="btn pri" id="yb-go">Build</button>`);
        let cond = "any"; W.seg("yb-cond", (v) => (cond = v));
        $("#yb-tpl").onchange = (e) => { const t = tpl[+e.target.value]; if (!t) return; $("#yb-name").value = t.spec.name; $("#yb-desc").value = t.spec.meta.description || ""; $("#yb-strs").value = t.spec.strings.map((s) => (s.type === "regex" ? "re:" : s.type === "hex" ? "hex:" : "") + s.value).join("\n"); $("#yb-mz").checked = !!t.spec.mz; };
        W.act("#yb-go", () => {
          const m = []; if ($("#yb-wide").checked) m.push("ascii", "wide"); if ($("#yb-nocase").checked) m.push("nocase");
          const strings = $("#yb-strs").value.split(/\r?\n/).filter((l) => l.trim()).map((l, i) => {
            const hex = /^hex:/i.test(l), re = /^re:/i.test(l);
            return { id: `$s${i + 1}`, type: hex ? "hex" : re ? "regex" : "text", value: l.replace(/^(hex|re):/i, ""), modifiers: hex ? [] : re ? m.filter((x) => x === "nocase") : m };
          });
          show(W.eng.yaragen.generate({ name: $("#yb-name").value, tags: ["wakizashi"], meta: { description: $("#yb-desc").value, author: "Wakizashi" }, strings, condition_mode: cond, n: +$("#yb-n").value, mz: $("#yb-mz").checked }));
        });
        if (pre) $("#yb-go").click();
      }
      function show(r) {
        $("#yg-out").innerHTML = ui.panel("Rule", `<div class="row">${ui.badge(r.valid ? "valid" : "check syntax", r.valid ? "ok" : "bad")}${(r.errors || []).length ? `<span class="small c-crit">${esc(r.errors.join("; "))}</span>` : ""}</div><div class="spacer"></div>
          <textarea id="yg-rule" rows="14" spellcheck="false">${esc(r.rule)}</textarea><div class="spacer"></div>
          <div class="row"><button class="btn sm" id="yg-copy">${W.icon(W.I.copy)} Copy</button><button class="btn sm" id="yg-dl">${W.icon(W.I.dl)} .yar</button><button class="btn sm" id="yg-val">Validate</button>
            <button class="btn sm" id="yg-save">＋ Library</button><button class="btn sm" id="yg-yoroi">⇨ Enable in Yoroi</button></div>
          <div class="spacer"></div>${ui.drop("yg-test", "Test: drop a file to scan with this rule")}<div id="yg-tres" class="spacer"></div>`);
        const rule = () => $("#yg-rule").value;
        $("#yg-copy").onclick = () => W.copy(rule());
        $("#yg-dl").onclick = () => W.download((rule().match(/rule\s+(\w+)/) || [, "rule"])[1] + ".yar", rule());
        $("#yg-val").onclick = () => { const v = W.eng.yaragen.validate(rule()); W.toast(v.engine === false ? "YARA engine not loaded" : v.valid ? `Valid — ${v.rules.length} rule(s)` : "Errors: " + v.errors.join("; "), !v.valid); };
        $("#yg-save").onclick = () => { const lib = W.store.get(LIB, []); lib.unshift({ id: W.uid(), name: (rule().match(/rule\s+(\w+)/) || [, "rule"])[1], text: rule(), added: W.nowIso() }); W.store.set(LIB, lib); W.toast("Saved to library"); };
        $("#yg-yoroi").onclick = () => toYoroi((rule().match(/rule\s+(\w+)/) || [, "rule"])[1], rule());
        W.dropZone("yg-test", async (f) => {
          if (!W.eng.yara) return W.toast("YARA engine not loaded", 1);
          const { rules, errors } = W.eng.yara.compile(rule()); if (!rules.length) return W.toast(errors.join("; ") || "rule did not compile", 1);
          const hits = W.eng.yara.scan(rules, await W.readFile(f, "buffer")).filter((h) => !h.error);
          $("#yg-tres").innerHTML = hits.length ? hits.map((h) => `<div class="finding high"><header>${ui.badge("match", "ok", true)}<h3>${esc(h.rule)}</h3><span class="tiny muted">${esc(f.name)}</span></header>${(h.strings || []).map((s) => `<div class="tiny mono muted">${esc(s.id)} ×${s.count} @${s.first}: ${esc(s.preview)}</div>`).join("")}</div>`).join("")
            : `<div class="callout">${esc(f.name)}: no match.</div>`;
        });
      }
      function library(b) {
        const lib = W.store.get(LIB, []);
        b.innerHTML = ui.panel(`Library (${lib.length})`, lib.length ? lib.map((r, i) => `<div class="finding info"><header><h3 class="mono">${esc(r.name)}</h3><span class="tiny muted">${esc(W.fmt.ago(r.added))}</span>
            <button class="btn sm" data-i="${i}" data-a="open">Open</button><button class="btn sm" data-i="${i}" data-a="yoroi">⇨ Yoroi</button><button class="btn sm ghost" data-i="${i}" data-a="del">${W.icon(W.I.trash)}</button></header></div>`).join("")
          + `<div class="spacer"></div><div class="row"><button class="btn sm" id="yl-exp">${W.icon(W.I.dl)} Export all (.yar)</button></div>`
          : ui.empty("EMPTY", "Rules you save land here."));
        b.onclick = (e) => {
          const x = e.target.closest("[data-a]"); if (!x) return; const r = lib[+x.dataset.i];
          if (x.dataset.a === "open") show({ rule: r.text, valid: W.eng.yaragen.validate(r.text).valid, errors: [] });
          if (x.dataset.a === "yoroi") toYoroi(r.name, r.text);
          if (x.dataset.a === "del" && confirm(`Delete ${r.name}?`)) { lib.splice(+x.dataset.i, 1); W.store.set(LIB, lib); library(b); }
        };
        if ($("#yl-exp")) $("#yl-exp").onclick = () => W.download("wakizashi-rules.yar", lib.map((r) => r.text).join("\n\n"));
      }
      function toYoroi(name, text) {
        const l = W.store.get("yoroi.yara.rules", []);
        l.unshift({ id: W.uid(), name: "yumi: " + name, text, enabled: true, updated: W.nowIso(), source: "yumi" });
        W.store.set("yoroi.yara.rules", l); W.toast("Enabled in Yoroi's YARA scanner");
      }
      body();
    },
  });
})();
