/* Wakizashi shell: layers, routing, header / rail / dock, layer home grids, settings, PWA install + offline.
   Loaded last — every engine and view has registered itself by the time boot() runs. */
(function () {
  "use strict";
  const { $, $$, esc, ui } = W;

  // ------------------------------------------------------------------ layers (mirror Katana)
  const MARK = {
    yumi: '<svg viewBox="0 0 32 32" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="16" cy="16" r="12"/><circle cx="16" cy="16" r="6.5"/><path d="M16 16l10-7"/></g><circle cx="16" cy="16" r="1.6" fill="currentColor"/><circle cx="22.5" cy="11.5" r="1.6" fill="currentColor"/></svg>',
    yoroi: '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M7 5 h10 a2 2 0 0 1 2 2 v9 a4 4 0 0 1 -4 4 h-6 a4 4 0 0 1 -4 -4 v-9 a2 2 0 0 1 2 -2 z"/><path d="M5 9 h14 M5 12.4 h14 M5.6 15.8 h12.8"/><path d="M9 5v3.5 M13 5v3.5"/></svg>',
    naginata: '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20 L14.5 9.5"/><path d="M14.5 9.5 C17 6 19 5 21 3.5 C20 6 18.5 8 15.5 9 Z"/><path d="M20 20 L9.5 9.5"/><path d="M9.5 9.5 C7 6 5 5 3 3.5 C4 6 5.5 8 8.5 9 Z"/></svg>',
    kemuridama: '<svg viewBox="0 0 32 32" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 16s4.5-8 12-8c1.8 0 3.4.4 4.8 1M28 16s-4.5 8-12 8c-1.8 0-3.4-.4-4.8-1"/><circle cx="16" cy="16" r="3"/><path d="M6 26 26 6"/></g></svg>',
  };
  W.layer("yumi", { name: "Yumi", kanji: "弓", role: "CTI", tag: "Threat intel", accent: "#2fd6cf", mark: MARK.yumi,
    blurb: "Extract, enrich and package threat intelligence — IOCs, ATT&CK, YARA, STIX — entirely in your browser." });
  W.layer("yoroi", { name: "Yoroi", kanji: "鎧", role: "Defense", tag: "Blue team", accent: "#4d8bff", mark: MARK.yoroi,
    blurb: "Hunt through logs, test detections, scan files with YARA and turn findings into countermeasures." });
  W.layer("naginata", { name: "Naginata", kanji: "薙刀", role: "Offense", tag: "Red team", accent: "#ff4b5c", mark: MARK.naginata,
    blurb: "Plan and analyse authorised engagements — recon builders, header and token audits, scoring and reporting." });
  W.layer("kemuridama", { name: "Kemuridama", kanji: "煙玉", role: "Counterintel", tag: "OPSEC", accent: "#a855f7", mark: MARK.kemuridama,
    blurb: "Protect your own footprint — strip metadata, encrypt, check what you leak and build cover identities." });

  // ------------------------------------------------------------------ routing
  let pending;
  W.go = (layer, tool, arg) => {
    pending = arg;
    const h = "#/" + [layer, tool].filter(Boolean).join("/");
    if (location.hash === h) route(); else location.hash = h;
  };
  const parse = () => {
    const p = location.hash.replace(/^#\/?/, "").split("?")[0].split("/").filter(Boolean);
    if (p[0] === "settings") return { settings: true };
    const layer = W.getLayer(p[0]) ? p[0] : W.store.get("ui.layer", "yumi");
    const tool = p[1] && W.tools[layer] && W.tools[layer][p[1]] ? p[1] : null;
    return { layer, tool };
  };

  function route() {
    const r = parse(), view = $("#view");
    const arg = pending; pending = undefined;
    if (r.settings) { paintChrome(W.store.get("ui.layer", "yumi"), null, true); renderSettings(view); return finish("Settings"); }
    W.store.set("ui.layer", r.layer);
    paintChrome(r.layer, r.tool, false);
    const L = W.getLayer(r.layer);
    if (!r.tool) { renderHome(view, L); return finish(L.name); }
    const T = W.tools[r.layer][r.tool];
    view.innerHTML = `<div class="wrap"><div class="backbar"><a href="#/${r.layer}">${W.icon(W.I.back)}${esc(L.name)}</a></div><div id="tool"></div></div>`;
    const el = $("#tool");
    try {
      const p = T.render(el, arg);
      if (p && p.catch) p.catch((e) => fail(el, e));
    } catch (e) { fail(el, e); }
    finish(`${T.name} · ${L.name}`);
  }
  function fail(el, e) {
    console.error(e);
    el.insertAdjacentHTML("beforeend", `<div class="callout bad"><b>This tool hit an error.</b> ${esc(e && e.message || e)}</div>`);
  }
  function finish(title) {
    document.title = `${title} · Wakizashi`;
    window.scrollTo(0, 0);
    const v = $("#view"); if (v && document.activeElement && document.activeElement !== document.body && !v.contains(document.activeElement)) v.focus({ preventScroll: true });
  }

  // ------------------------------------------------------------------ chrome
  function paintChrome(layer, tool, settings) {
    document.body.dataset.layer = layer;
    $$(".ltab").forEach((b) => b.classList.toggle("on", !settings && b.dataset.l === layer));
    $$("#dock button[data-l]").forEach((b) => b.classList.toggle("on", !settings && b.dataset.l === layer));
    $("#dock-set").classList.toggle("on", !!settings);
    const L = W.getLayer(layer);
    $("#rail").innerHTML = `<div class="rail-head">${L.mark}<div><b>${esc(L.name.toUpperCase())}</b><small>${esc(L.role)} · ${esc(L.tag)}</small></div><span class="lk" aria-hidden="true">${esc(L.kanji)}</span></div>
      <a href="#/${layer}" class="${!tool && !settings ? "on" : ""}">${W.icon('<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>')}Overview</a>
      ${W.toolsOf(layer).map((t) => `<a href="#/${layer}/${t.id}" class="${t.id === tool ? "on" : ""}">${W.icon(t.icon || W.I.file)}${esc(t.name)}</a>`).join("")}
      <div class="sep"></div><a href="#/settings" class="${settings ? "on" : ""}">${W.icon(W.I.gear)}Settings</a>`;
    paintCase();
  }
  function paintCase() {
    const c = W.Case.active();
    const el = $("#case-pill"); if (el) { el.querySelector("span").textContent = `${c.name} (${c.items.length})`; el.title = `Active case: ${c.name}`; }
  }
  W.on("case", paintCase);

  function buildChrome() {
    $("#ltabs").innerHTML = W.layers.map((l) => `<button class="ltab" data-l="${l.id}" style="--lc:${l.accent}" title="${esc(l.name)} — ${esc(l.role)}">${l.mark}<span>${esc(l.role)}<small>${esc(l.name)} · ${esc(l.kanji)}</small></span></button>`).join("");
    $("#dock").innerHTML = W.layers.map((l) => `<button data-l="${l.id}" style="--lc:${l.accent}" aria-label="${esc(l.name)} — ${esc(l.role)}">${l.mark}<span>${esc(l.role)}</span></button>`).join("")
      + `<button id="dock-set" style="--lc:var(--brand)" aria-label="Settings">${W.icon(W.I.gear)}<span>More</span></button>`;
    const pick = (e) => { const b = e.target.closest("[data-l]"); if (b) W.go(b.dataset.l); };
    $("#ltabs").addEventListener("click", pick);
    $("#dock").addEventListener("click", (e) => { if (e.target.closest("#dock-set")) return (location.hash = "#/settings"); pick(e); });
    $("#case-pill").addEventListener("click", () => (W.tools.yumi && W.tools.yumi.case ? W.go("yumi", "case") : null));
    $("#modal-x").addEventListener("click", W.closeModal);
    $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") W.closeModal(); });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") W.closeModal();
      if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); openLookup(); }
    });
    $("#lookup-btn").addEventListener("click", openLookup);
  }

  // ------------------------------------------------------------------ quick lookup (header search)
  function openLookup() {
    const body = W.modal(`<label class="lbl" for="lk-in">Indicator, hash, domain, @username — or paste a block of text</label>
      <textarea id="lk-in" rows="4" placeholder="evil[.]example, 44d88612fea8…, CVE-2024-3400, @handle — or a whole report" spellcheck="false" autocapitalize="off"></textarea>
      <div class="spacer"></div><div class="row"><button class="btn pri" id="lk-go">Go</button><span class="muted small" id="lk-hint">Press / anywhere to open this.</span></div>`, { title: "Quick lookup" });
    const inp = $("#lk-in", body); inp.focus();
    const hint = () => { const v = inp.value.trim(); const t = W.detectType(v); $("#lk-hint").textContent = !v ? "Press / anywhere to open this." : v.includes("\n") || !t ? "Multiple lines → extract indicators" : `Detected ${t} → pivot`; };
    inp.addEventListener("input", hint);
    const go = () => {
      const v = inp.value.trim(); if (!v) return;
      W.closeModal();
      const t = W.detectType(v);
      if (!v.includes("\n") && t && W.tools.yumi.pivot) W.go("yumi", "pivot", v);
      else if (W.tools.yumi.extract) W.go("yumi", "extract", v);
    };
    $("#lk-go", body).onclick = go;
    inp.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey && !inp.value.includes("\n")) { e.preventDefault(); go(); } });
  }
  W.openLookup = openLookup;

  // ------------------------------------------------------------------ layer home (Karambit-style grid)
  function renderHome(el, L) {
    const tools = W.toolsOf(L.id);
    const c = W.Case.active();
    el.innerHTML = `<div class="wrap">
      <div class="hero">${L.mark.replace("<svg", '<svg class="hm"')}<div><h1>${esc(L.name.toUpperCase())}</h1><p><b class="c-acc">${esc(L.role)}</b> · ${esc(L.blurb)}</p></div><span class="hk" aria-hidden="true">${esc(L.kanji)}</span></div>
      <div class="tiles">${tools.map((t) => `<a class="tile" href="#/${L.id}/${t.id}">${W.icon(t.icon || W.I.file)}<div><b>${esc(t.name)}</b><span>${esc(t.desc)}</span></div></a>`).join("") || ui.empty("NO TOOLS YET", "This layer is still being forged.")}</div>
      <div class="spacer"></div>
      <div class="row small muted" style="justify-content:space-between"><span>Active case: <b class="c-acc">${esc(c.name)}</b> · ${c.items.length} indicator(s)</span><span>${tools.length} tool(s) · runs 100% on this device</span></div>
    </div>`;
  }

  // ------------------------------------------------------------------ settings
  async function renderSettings(el) {
    const est = navigator.storage && navigator.storage.estimate ? await navigator.storage.estimate().catch(() => null) : null;
    const total = W.layers.reduce((n, l) => n + W.toolsOf(l.id).length, 0);
    el.innerHTML = `<div class="wrap">${ui.head("Settings", "", "Your data lives in this browser only. Export it to move between devices, or wipe it.")}
      <div class="grid g2">
        ${ui.panel("Install", `<p class="muted small" style="margin-top:0">Wakizashi is a progressive web app: install it to get a home-screen icon, full-screen window and offline use.</p>
          <div class="row"><button class="btn pri" id="st-inst" ${deferredInstall ? "" : "disabled"}>${W.icon(W.I.install)} Install app</button>
          <span class="muted small" id="st-inst-n">${isStandalone() ? "Running as an installed app." : deferredInstall ? "" : "On iPhone/iPad: Share → Add to Home Screen. Elsewhere use your browser's install option."}</span></div>
          <div class="spacer"></div>${ui.kv([["Offline", navigator.serviceWorker && navigator.serviceWorker.controller ? "ready — works without a connection" : "not yet (reload once online)"], ["Secure context", window.isSecureContext ? "yes" : "no — hashing & crypto need https"], ["Storage used", est ? W.fmt.bytes(est.usage) + " of " + W.fmt.bytes(est.quota) : "—"]])}`)}
        ${ui.panel("Your data", `<p class="muted small" style="margin-top:0">Cases, rule libraries, notes and settings. Nothing is synced or uploaded.</p>
          <div class="row"><button class="btn" id="st-exp">${W.icon(W.I.dl)} Export backup</button>
          <label class="btn">${W.icon(W.I.up)} Import backup<input type="file" id="st-imp" accept=".json,application/json"></label>
          <button class="btn danger" id="st-wipe">${W.icon(W.I.trash)} Wipe all data</button></div>
          <div class="spacer"></div>${ui.kv([["Stored keys", String(W.store.keys().length)], ["Cases", String(W.Case.ws.cases.length)]])}`)}
        ${ui.panel("Defaults", `<label class="lbl" for="st-layer">Open on</label><select id="st-layer">${W.layers.map((l) => `<option value="${l.id}" ${W.store.get("ui.layer", "yumi") === l.id ? "selected" : ""}>${esc(l.name)} — ${esc(l.role)}</option>`).join("")}</select>
          <div class="spacer"></div><label class="check"><input type="checkbox" id="st-scan" ${W.store.get("ui.scanlines", true) ? "checked" : ""}> CRT scanlines</label>
          <label class="check"><input type="checkbox" id="st-roe" ${W.roeOk() ? "checked" : ""}> Naginata rules-of-engagement acknowledged</label>`)}
        ${ui.panel("About", `${ui.kv([["Wakizashi", "脇差 · v" + W.VERSION], ["Family", "Katana (desktop) · Karambit (Android) · Wakizashi (web)"], ["Tools", total + " across " + W.layers.length + " layers"], ["Privacy", "No telemetry, no accounts, no CDNs — everything runs on this device."]])}
          <div class="spacer"></div><p class="muted small" style="margin:0">By RoninSec. Use offensive tooling only on systems you're authorised to test.</p>`)}
      </div></div>`;
    $("#st-exp").onclick = () => W.download(`wakizashi-backup-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify({ app: "wakizashi", version: W.VERSION, exported: W.nowIso(), data: W.store.dump() }, null, 2), "application/json");
    $("#st-imp").onchange = async (e) => {
      const f = e.target.files[0]; if (!f) return;
      try { const j = JSON.parse(await W.readFile(f)); if (!j || j.app !== "wakizashi" || typeof j.data !== "object") throw new Error("not a Wakizashi backup");
        if (!confirm(`Import ${Object.keys(j.data).length} stored item(s)? Existing items with the same keys are replaced.`)) return;
        W.store.load(j.data); W.toast("Backup imported"); route(); } catch (err) { W.toast(err.message, 1); }
    };
    $("#st-wipe").onclick = () => { if (!confirm("Wipe every case, library and setting stored by Wakizashi in this browser?")) return; W.store.clear(); W.toast("All Wakizashi data wiped"); route(); };
    $("#st-layer").onchange = (e) => W.store.set("ui.layer", e.target.value);
    $("#st-scan").onchange = (e) => { W.store.set("ui.scanlines", e.target.checked); $("#scan").hidden = !e.target.checked; };
    $("#st-roe").onchange = (e) => (e.target.checked ? W.store.set("roe.ack", W.nowIso()) : W.store.del("roe.ack"));
    $("#st-inst").onclick = async () => { if (!deferredInstall) return; deferredInstall.prompt(); await deferredInstall.userChoice.catch(() => null); deferredInstall = null; renderSettings(el); };
  }

  // ------------------------------------------------------------------ PWA: install + offline
  let deferredInstall = null;
  const isStandalone = () => matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  window.addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); deferredInstall = e; $("#install-btn").hidden = false; });
  window.addEventListener("appinstalled", () => { deferredInstall = null; $("#install-btn").hidden = true; W.toast("Wakizashi installed"); });
  function registerSW() {
    if (!("serviceWorker" in navigator) || !(location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1")) return;
    navigator.serviceWorker.register("sw.js").then((reg) => {
      reg.addEventListener("updatefound", () => {
        const nw = reg.installing; if (!nw) return;
        nw.addEventListener("statechange", () => { if (nw.state === "installed" && navigator.serviceWorker.controller) W.toast("Update ready — reload to get the latest Wakizashi"); });
      });
    }).catch((e) => console.warn("service worker:", e));
  }

  // ------------------------------------------------------------------ boot
  function boot() {
    buildChrome();
    $("#scan").hidden = !W.store.get("ui.scanlines", true);
    $("#install-btn").addEventListener("click", () => (location.hash = "#/settings"));
    window.addEventListener("hashchange", route);
    route();
    registerSW();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
