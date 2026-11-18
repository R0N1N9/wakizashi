/* Kemuridama view kit — small helpers shared by the Kemuridama tool views (DOM only touched when called). */
(function () {
  "use strict";
  const { esc } = W;
  const SEV = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info", ok: "ok" };
  const K = (W.kmz = {
    sev: (s, fill) => W.ui.badge(s || "info", SEV[s] || "", fill),
    /** <a> for an external link: new tab, no referrer, escaped. */
    ext: (url, label, cls) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer"${cls ? ` class="${cls}"` : ""}>${esc(label || url)}</a>`,
    /** copy button whose value is kept in a per-view map (no giant attributes) */
    copies: new Map(),
    copyBtn(value, label, cls) { const id = "c" + W.uid(); K.copies.set(id, String(value)); return `<button type="button" class="btn sm ghost ${cls || ""}" data-kcopy="${id}" title="Copy">${W.icon(W.I.copy)}${label ? " " + esc(label) : ""}</button>`; },
    /** wire [data-kcopy] buttons inside el (call once per render) */
    wireCopy(el) { el.addEventListener("click", (e) => { const b = e.target.closest("[data-kcopy]"); if (b && K.copies.has(b.dataset.kcopy)) W.copy(K.copies.get(b.dataset.kcopy)); }); },
    /** score meter 0..1 coloured by level */
    meter(frac, level) { const pct = Math.round(100 * W.clamp(frac, 0, 1)); return `<div class="meter km-meter ${level || ""}"><i style="width:${pct}%"></i></div>`; },
    tabs(id, list, cur) { return `<div class="tabs" id="${id}">${list.map(([v, l]) => `<button type="button" data-tab="${esc(v)}" class="${v === cur ? "on" : ""}">${esc(l)}</button>`).join("")}</div>`; },
    /** strength line for a passphrase input: meter + label + crack time */
    strengthHtml(pw, extra) {
      if (!pw) return `<div class="km-str">${K.meter(0)}<span class="tiny faint">Type a passphrase to see its strength. Nothing is stored.</span></div>`;
      const r = W.eng.passgen.estimate(pw, extra);
      const lvl = ["critical", "high", "medium", "ok", "ok"][r.score];
      return `<div class="km-str">${K.meter((r.score + 1) / 5, lvl)}<span class="tiny"><b class="km-s${r.score}">${esc(r.label)}</b> · ~10<sup>${r.log10.toFixed(1)}</sup> guesses · offline fast-hash crack: <b>${esc(r.crack.offline_fast.text)}</b>${r.warning ? ` · <span class="c-high">${esc(r.warning)}</span>` : ""}</span></div>`;
    },
    fileBytes: (f) => W.readFile(f, "buffer"),
    save(name, bytes, mime) { W.download(name, new Blob([bytes], { type: mime || "application/octet-stream" })); },
    store: (tool, key, def) => W.store.get(`kemuridama.${tool}.${key}`, def),
    put: (tool, key, v) => W.store.set(`kemuridama.${tool}.${key}`, v),
  });
})();
