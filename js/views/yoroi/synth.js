/* Yoroi · SYNTH — draft a Sigma rule from marked malicious log events and grade it with the real engine.
 * arg (from HUNT's ⚙ Rule): {text, fmt, indices:[event i], title}. Or paste a log and mark events by hand. */
(function () {
  "use strict";
  const { $, esc, ui } = W;
  const VERDICT = {
    exact: ["ok", "EXACT", "Catches every marked event and fires on nothing else."],
    tight: ["ok", "TIGHT", "No false positives; catches at least 80% of the marked events."],
    good: ["info", "GOOD", "Precise and high-recall, with minor noise."],
    loose: ["warn", "LOOSE · FP", "Also fires on benign events — tighten it before deploying."],
    leaky: ["crit", "LEAKY · FN", "Misses some marked events — widen the selection."],
  };
  const pct = (x) => (x == null ? "—" : Math.round(x * 100) + "%");
  const BIG = 1048576;
  let STATE = null;      // {text, fmt, title, idx, baseline, res}

  W.tool("yoroi", "synth", {
    name: "Synth", order: 30,
    desc: "Turn marked malicious log lines into a graded Sigma rule (precision / recall / F1).",
    icon: '<path d="M4 6h10M4 12h7M4 18h10"/><path d="M18 4v4M16 6h4M17 13l1.2 2.6L21 17l-2.8 1.2L17 21l-1.2-2.8L13 17l2.8-1.4z"/>',
    render(el, arg) {
      if (arg && typeof arg === "object" && arg.text != null) STATE = { text: String(arg.text), fmt: arg.fmt || "auto", title: arg.title || "", idx: (arg.indices || []).map(Number), baseline: "", res: null, from: arg.from };
      else if (typeof arg === "string") STATE = { text: arg, fmt: "auto", title: "", idx: [], baseline: "", res: null };
      const st = STATE || { text: "", fmt: "auto", title: "", idx: [], baseline: "", res: null };
      el.innerHTML = ui.head("Synth", "Rule from logs", "Mark the malicious events in a log; Yoroi mines the fields they share, drafts candidate Sigma rules and grades each against the whole log — true/false positives, misses, precision, recall and F1.") + `
        ${st.from === "hunt" ? `<div class="row" style="margin:-6px 0 12px"><a href="#/yoroi/hunt" class="small">${W.icon(W.I.back)} Back to Hunt results</a></div>` : ""}
        <section class="panel">
          <label class="lbl" for="sy-text">Log</label>
          <textarea id="sy-text" rows="8" spellcheck="false" autocapitalize="off" placeholder="Paste the log (any format HUNT understands)…"></textarea>
          <div class="spacer"></div>
          <div class="grid g3">
            <div><label class="lbl" for="sy-idx">Malicious event numbers</label><input type="text" id="sy-idx" placeholder="e.g. 0-5, 9, 12" autocomplete="off"></div>
            <div><label class="lbl" for="sy-title">Rule title</label><input type="text" id="sy-title" maxlength="80" placeholder="auto"></div>
            <div><label class="lbl" for="sy-fmt">Format</label><select id="sy-fmt">${W.eng.logs.FORMATS.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("")}</select></div>
          </div>
          <div class="spacer"></div>
          <details class="yo-details"><summary class="small muted">Optional: benign baseline log (strengthens false-positive grading)</summary>
            <div class="spacer"></div><textarea id="sy-base" rows="4" spellcheck="false" placeholder="Paste known-good traffic from the same source…"></textarea></details>
          <div class="spacer"></div>
          <div class="row"><button type="button" class="btn pri" id="sy-go">⚙ Synthesise</button><button type="button" class="btn ghost" id="sy-pick">Pick events</button>
            <span class="muted tiny" id="sy-hint"></span></div>
        </section>
        <div id="sy-picker"></div><div id="sy-out"></div>`;
      const ta = $("#sy-text");
      let held = null;      // big log text kept out of the textarea
      if (st.text.length > BIG) { held = st.text; ta.placeholder = `Log from Hunt — ${W.fmt.bytes(st.text.length)} (too big to show). Type or paste to replace it.`; }
      else ta.value = st.text;
      ta.addEventListener("input", () => { held = null; $("#sy-picker").innerHTML = ""; });
      $("#sy-idx").value = compress(st.idx);
      $("#sy-title").value = st.title;
      $("#sy-fmt").value = st.fmt;
      $("#sy-base").value = st.baseline || "";
      const hint = () => { const n = W.eng.synth.parseIndices($("#sy-idx").value).length; $("#sy-hint").textContent = n ? `${n} event(s) marked` : "Mark events by number, or use Pick events."; };
      $("#sy-idx").addEventListener("input", hint); hint();
      const text = () => (held != null ? held : ta.value);

      $("#sy-pick").addEventListener("click", () => picker($("#sy-picker"), text(), $("#sy-fmt").value, () => { hint(); }));
      const go = async () => {
        const body = { text: text(), fmt: $("#sy-fmt").value, indices: W.eng.synth.parseIndices($("#sy-idx").value), title: $("#sy-title").value, baseline: $("#sy-base").value };
        $("#sy-out").innerHTML = `<section class="panel">${ui.loader("MINING FIELDS + GRADING")}</section>`;
        await new Promise((r) => setTimeout(r, 30));
        let res;
        try { res = W.eng.synth.synthesize(body); }
        catch (e) { $("#sy-out").innerHTML = `<div class="callout warn">${esc(e.message)}</div>`; return; }
        STATE = { text: body.text, fmt: body.fmt, title: body.title, idx: body.indices, baseline: body.baseline, res, from: st.from };
        results($("#sy-out"), res);
      };
      W.act("#sy-go", go);
      if (arg && st.text && st.idx.length) go();
      else if (st.res) results($("#sy-out"), st.res);
    },
  });

  /** [0,1,2,3,7] → "0-3, 7" */
  function compress(idx) {
    const s = [...new Set(idx)].sort((a, b) => a - b), out = [];
    for (let i = 0; i < s.length; i++) { let j = i; while (j + 1 < s.length && s[j + 1] === s[j] + 1) j++; out.push(j > i ? `${s[i]}-${s[j]}` : String(s[i])); i = j; }
    return out.join(", ");
  }

  function picker(box, text, fmt, onChange) {
    if (!text.trim()) return W.toast("Paste a log first", 1);
    const evs = W.eng.logs.parse(text, fmt).events;
    const marked = new Set(W.eng.synth.parseIndices($("#sy-idx").value));
    let q = "", limit = 300;
    box.innerHTML = `<section class="panel"><div class="row"><h2 style="margin:0">Pick malicious events</h2><span class="grow"></span>
        <input type="search" id="sy-q" placeholder="filter…" style="max-width:240px"><button type="button" class="btn sm ghost" id="sy-markall">Mark shown</button><button type="button" class="btn sm ghost" id="sy-none">Clear</button></div>
      <div class="spacer"></div><div class="tablewrap yo-evt" style="max-height:420px"><table class="tbl"><thead><tr><th>Bad</th><th>#</th><th>Time</th><th>IP</th><th>Message</th></tr></thead><tbody id="sy-rows"></tbody></table></div>
      <div class="row" style="margin-top:8px"><span class="muted tiny" id="sy-pc"></span><span class="grow"></span><button type="button" class="btn sm ghost" id="sy-more">Show more</button></div></section>`;
    const shown = () => (q ? evs.filter((e) => (e.msg + " " + (e.ip || "") + " " + (e.user || "")).toLowerCase().includes(q)) : evs);
    const sync = () => { $("#sy-idx").value = compress([...marked]); onChange(); };
    const draw = () => {
      const rows = shown();
      $("#sy-rows").innerHTML = rows.slice(0, limit).map((e) => `<tr class="${marked.has(e.i) ? "yo-flag" : ""}"><td><input type="checkbox" data-m="${e.i}" aria-label="Mark event ${e.i}" ${marked.has(e.i) ? "checked" : ""}></td>
        <td class="mono faint">${e.i}</td><td class="mono nowrap">${esc(e.ts || "—")}</td><td class="mono nowrap">${esc(e.ip || "")}</td><td class="yo-msg">${esc(String(e.msg).slice(0, 220))}</td></tr>`).join("") || `<tr><td colspan="5">${ui.empty("NO EVENTS")}</td></tr>`;
      $("#sy-pc").textContent = `${W.fmt.num(rows.length)} event(s) · ${marked.size} marked`;
      $("#sy-more").hidden = rows.length <= limit;
    };
    $("#sy-rows").addEventListener("change", (e) => { const c = e.target.closest("[data-m]"); if (!c) return; const i = +c.dataset.m; if (c.checked) marked.add(i); else marked.delete(i); c.closest("tr").classList.toggle("yo-flag", c.checked); sync(); $("#sy-pc").textContent = `${W.fmt.num(shown().length)} event(s) · ${marked.size} marked`; });
    $("#sy-q").addEventListener("input", W.debounce(() => { q = $("#sy-q").value.toLowerCase().trim(); draw(); }, 150));
    $("#sy-markall").addEventListener("click", () => { shown().slice(0, limit).forEach((e) => marked.add(e.i)); sync(); draw(); });
    $("#sy-none").addEventListener("click", () => { marked.clear(); sync(); draw(); });
    $("#sy-more").addEventListener("click", () => { limit += 500; draw(); });
    draw();
  }

  function card(c, i, best) {
    const g = c.grade || {};
    const [cls, label, blurb] = VERDICT[g.verdict] || ["", "INVALID", (g.errors || []).join("; ")];
    const conds = c.conditions.map((k) => `<code>${esc(k.field)}${k.mode === "eq" ? " =" : "|" + esc(k.mode)}</code> <span class="mono break">${esc(String(k.value))}</span>`).join(" <b class='c-acc'>AND</b> ");
    return `<section class="panel yo-cand" data-ci="${i}">
      <div class="row">${ui.badge(label, cls, true)}${best ? ui.badge("RECOMMENDED", "acc", true) : ""}
        <span class="mono small">precision ${pct(g.precision)} · recall ${pct(g.recall)} · F1 ${g.f1 != null ? g.f1 : "—"}</span><span class="grow"></span>
        <span class="mono small"><b class="c-ok">${g.tp || 0} TP</b> · <b class="c-crit">${g.fp || 0} FP</b> · <b class="c-med">${g.fn || 0} FN</b></span></div>
      <div class="small muted" style="margin:8px 0 4px">${esc(blurb)}</div>
      <div class="small" style="margin:4px 0 10px">${conds || '<span class="muted">—</span>'}</div>
      <pre class="out" style="max-height:240px">${esc(c.rule)}</pre>
      ${g.fp_events && g.fp_events.length ? `<div class="tiny muted" style="margin-top:6px">False positives on event #${g.fp_events.slice(0, 20).join(", #")}${g.fp > 20 ? " …" : ""}</div>` : ""}
      ${g.fn_events && g.fn_events.length ? `<div class="tiny muted" style="margin-top:4px">Missed event #${g.fn_events.slice(0, 20).join(", #")}${g.fn > 20 ? " …" : ""}</div>` : ""}
      <div class="spacer"></div><div class="row"><button type="button" class="btn sm" data-sa="copy">${W.icon(W.I.copy)} Copy</button>
        <button type="button" class="btn sm pri" data-sa="save">${W.icon(W.I.plus)} Save to Sigma rules</button>
        <button type="button" class="btn sm ghost" data-sa="dl">${W.icon(W.I.dl)} .yml</button></div></section>`;
  }

  function results(out, r) {
    if (!r.candidates.length) {
      out.innerHTML = `<div class="callout warn">${(r.notes.length ? r.notes : ["No usable discriminator found in the marked events."]).map(esc).join("<br>")}</div>`;
      return;
    }
    out.innerHTML = `<section class="panel"><h2>Synthesised — ${esc(r.title)}</h2>
        <div class="grid g4">${ui.stat(String(r.positives), "Marked malicious", true)}${ui.stat(String(r.negatives), "Other events" + (r.baseline_events ? ` (${r.baseline_events} baseline)` : ""))}${ui.stat(String(r.fields_mined), "Fields mined")}${ui.stat(String(r.candidates.length), "Candidates")}</div>
        ${r.notes.length ? `<div class="callout warn">${r.notes.map(esc).join("<br>")}</div>` : ""}
        ${r.block_ips.length ? `<div class="spacer"></div><div class="callout"><b>Attacker IPs in the marked events:</b> ${r.block_ips.slice(0, 20).map((x) => ui.chip(x)).join("")}${r.block_ips.length > 20 ? ` <span class="faint">+${r.block_ips.length - 20}</span>` : ""}
          <div class="spacer"></div><button type="button" class="btn sm" id="sy-block">⛔ Send ${r.block_ips.length} IP(s) to Block</button></div>` : ""}
      </section>
      <div id="sy-cards">${r.candidates.map((c, i) => card(c, i, i === r.recommended)).join("")}</div>`;
    $("#sy-cards").addEventListener("click", (e) => {
      const b = e.target.closest("[data-sa]"); if (!b) return;
      const c = r.candidates[+b.closest("[data-ci]").dataset.ci];
      if (b.dataset.sa === "copy") return W.copy(c.rule, "Rule copied");
      if (b.dataset.sa === "dl") return W.download(r.title.replace(/[^\w.-]+/g, "_").slice(0, 60) + ".yml", c.rule, "text/yaml");
      if (b.dataset.sa === "save") {
        const L = W.store.get("yoroi.rules.sigma", []) || [];
        L.unshift({ id: W.uid(), name: r.title, text: c.rule, enabled: true, updated: W.nowIso() });
        W.store.set("yoroi.rules.sigma", L);
        W.toast("Saved to Sigma rules — enabled for future hunts");
        b.disabled = true; b.textContent = "Saved";
      }
    });
    const blk = $("#sy-block");
    if (blk) blk.addEventListener("click", () => {
      if (!(W.tools.yoroi && W.tools.yoroi.block)) return W.copy(r.block_ips.join("\n"), "Block tool not installed — IPs copied");
      W.go("yoroi", "block", r.block_ips.join("\n"));
    });
  }
})();
