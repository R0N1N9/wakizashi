(function () {
  "use strict";
  const { $, esc, ui } = W;
  const FONTS = ["Arial", "Helvetica", "Times New Roman", "Courier New", "Verdana", "Georgia", "Trebuchet MS", "Segoe UI", "Calibri", "Cambria", "Consolas", "Tahoma",
    "Comic Sans MS", "Impact", "Palatino Linotype", "Lucida Console", "Menlo", "Monaco", "SF Pro Text", "Helvetica Neue", "Avenir", "Futura", "Gill Sans", "Ubuntu",
    "DejaVu Sans", "Liberation Sans", "Noto Sans", "Roboto", "Cantarell", "Fira Sans", "Source Code Pro", "Wingdings", "MS Gothic", "Meiryo", "SimSun", "Malgun Gothic"];

  // ---- local fact gathering (nothing leaves the page) ----
  function canvasHash() {
    const draw = () => { const c = document.createElement("canvas"); c.width = 280; c.height = 60; const g = c.getContext("2d"); if (!g) return null;
      g.textBaseline = "top"; g.font = "16px 'Arial'"; g.fillStyle = "#f60"; g.fillRect(100, 1, 62, 20); g.fillStyle = "#069"; g.fillText("Kemuridama ☁ 煙玉 0.123", 2, 15);
      g.fillStyle = "rgba(102,204,0,0.7)"; g.fillText("Kemuridama ☁ 煙玉 0.123", 4, 17); g.globalCompositeOperation = "multiply"; g.fillStyle = "rgb(255,0,255)"; g.beginPath(); g.arc(50, 30, 25, 0, Math.PI * 2); g.fill();
      return c.toDataURL(); };
    try { const a = draw(), b = draw(); if (!a) return null; return { hash: W.hash.md5(a), noise: a !== b }; } catch { return null; }
  }
  function webgl() {
    try { const c = document.createElement("canvas"); const gl = c.getContext("webgl") || c.getContext("experimental-webgl"); if (!gl) return null;
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      const r = { vendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR), renderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER) };
      const lose = gl.getExtension("WEBGL_lose_context"); if (lose) lose.loseContext();
      return r; } catch { return null; }
  }
  function fonts() {
    const c = document.createElement("canvas").getContext("2d"); if (!c) return [];
    const text = "mmmmmmmmmmlli1WQ@#", base = ["monospace", "serif", "sans-serif"], w = {};
    for (const b of base) { c.font = `72px ${b}`; w[b] = c.measureText(text).width; }
    return FONTS.filter((f) => base.some((b) => { c.font = `72px '${f}', ${b}`; return c.measureText(text).width !== w[b]; }));
  }
  async function gather() {
    const n = navigator, s = screen, f = {};
    f.ua = n.userAgent; f.languages = Array.from(n.languages || [n.language]); f.platform = n.platform;
    try { f.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { /* none */ }
    f.tzOffset = -new Date().getTimezoneOffset();
    f.screen = { w: s.width, h: s.height, availW: s.availWidth, availH: s.availHeight, depth: s.colorDepth }; f.dpr = +(window.devicePixelRatio || 1).toFixed(2);
    f.cores = n.hardwareConcurrency; f.memory = n.deviceMemory; f.cookies = n.cookieEnabled;
    try { f.localStorage = !!window.localStorage; } catch { f.localStorage = false; }
    f.indexedDB = !!window.indexedDB; f.dnt = n.doNotTrack === "1" || window.doNotTrack === "1"; f.gpc = !!n.globalPrivacyControl;
    f.touchPoints = n.maxTouchPoints || 0; f.mobile = /Mobi|Android|iPhone|iPad/.test(f.ua); f.webdriver = !!n.webdriver; f.pdfViewer = n.pdfViewerEnabled;
    f.colorScheme = matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; f.reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches; f.contrast = matchMedia("(prefers-contrast: more)").matches;
    if (n.userAgentData) {
      f.uaHints = { brands: (n.userAgentData.brands || []).map((b) => `${b.brand} ${b.version}`), mobile: n.userAgentData.mobile, platform: n.userAgentData.platform };
      try { Object.assign(f.uaHints, await n.userAgentData.getHighEntropyValues(["platformVersion", "model", "architecture", "bitness"])); f.uaHints.arch = f.uaHints.architecture; } catch { /* denied */ }
    }
    const cv = canvasHash(); if (cv) { f.canvasHash = cv.hash; f.canvasNoise = cv.noise; }
    const gl = webgl(); if (gl) { f.webglVendor = gl.vendor; f.webglRenderer = gl.renderer; }
    const AC = window.AudioContext || window.webkitAudioContext;
    f.audio = !!AC;
    if (AC) { try { const ac = new AC(); f.sampleRate = ac.sampleRate; f.audioChannels = ac.destination.maxChannelCount; ac.close && ac.close(); } catch { /* blocked */ } }
    f.fonts = fonts(); f.fontsTested = FONTS.length;
    f.webrtc = typeof window.RTCPeerConnection === "function";
    if (n.mediaDevices && n.mediaDevices.enumerateDevices) { try { const d = await n.mediaDevices.enumerateDevices(); f.media = d.reduce((o, x) => { o[x.kind] = (o[x.kind] || 0) + 1; return o; }, {}); } catch { /* none */ } }
    return f;
  }

  W.tool("kemuridama", "mirror", {
    name: "Mirror", order: 30,
    desc: "What every website can read about this browser — each signal rated for how identifying it is, with a uniqueness estimate and fixes.",
    help: {
      steps: ["Open the tool to see what this browser hands every site, each signal rated for how identifying it is.", "Read the uniqueness estimate and apply the fixes; Re-scan to compare.", "Persona section: add personas (or import saved decoys) and Compare writing samples."],
      tips: [],
    },
    icon: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2"/>',
    render(el) {
      let tab = W.kmz.store("mirror", "tab", "fp");
      el.innerHTML = ui.head("Mirror", "What sites see", "Your browser hands any page these facts without asking. Mirror reads them locally (no requests, nothing stored) and estimates how much they single you out.") +
        W.kmz.tabs("mi-tabs", [["fp", "Fingerprint"], ["stylo", "Writing style"], ["personas", "Persona hygiene"]], tab) + `<div id="mi-body"></div>`;
      W.kmz.wireCopy(el);
      W.tabs($("#mi-tabs"), (t) => { tab = t; W.kmz.put("mirror", "tab", t); draw(); });
      draw();
      function draw() { ({ fp: drawFp, stylo: drawStylo, personas: drawPersonas })[tab](); }

      async function drawFp() {
        const body = $("#mi-body");
        body.innerHTML = `<div class="panel">${ui.loader("READING THIS BROWSER")}</div>`;
        const facts = await gather(), r = W.eng.mirror.score(facts);
        if (tab !== "fp") return;
        const lvl = r.unique ? "critical" : r.effectiveBits >= r.populationBits - 6 ? "high" : r.effectiveBits >= 18 ? "medium" : "ok";
        const order = { high: 0, medium: 1, low: 2 };
        body.innerHTML = `<div class="grid g3">
            <div class="panel stat"><div class="n acc km-big">${esc(r.effectiveBits)}<span class="small muted"> bits</span></div><div class="l">estimated identifying information</div></div>
            <div class="panel stat"><div class="n">1 in ${esc(W.eng.mirror.fmtBig(r.oneIn))}</div><div class="l">browsers would share this exact mix</div></div>
            <div class="panel"><div class="row" style="justify-content:space-between">${W.kmz.sev(lvl, true)}<span class="tiny muted">${r.signals.length} signals</span></div><p class="small" style="margin:10px 0 6px"><b>${esc(r.verdict)}</b></p>${W.kmz.meter(r.effectiveBits / 40, lvl)}</div>
          </div>
          <div class="callout small"><b>How the estimate works:</b> each signal gets a surprisal score (bits ≈ how rare its value is, from published studies — EFF Panopticlick, AmIUnique). Signals overlap, so the sum is discounted by 30%. ${esc(r.note)} It's an order-of-magnitude guide, not a lab measurement.</div>
          <div class="spacer"></div>
          <div class="panel"><h2>Signals</h2>${ui.table(["Signal", "Value", "Bits", "Rating"], r.signals.slice().sort((a, b) => order[a.rating] - order[b.rating] || b.bits - a.bits).map((s) =>
            [`<b>${esc(s.label)}</b><div class="tiny muted">${esc(s.why)}</div>`, `<span class="break mono small">${esc(s.value)}</span>`, `<span class="mono">${esc(s.bits)}</span>`, W.kmz.sev(s.rating)]), { raw: true })}
            <div class="spacer"></div><div class="row"><button class="btn" id="mi-re">${W.icon(W.I.refresh)} Re-scan</button>${W.kmz.copyBtn(JSON.stringify({ facts, score: { bits: r.bits, effectiveBits: r.effectiveBits, signals: r.signals } }, null, 2), "Copy report (JSON)")}</div></div>
          <div class="panel"><h2>Hardening</h2>${r.tips.map((t) => `<div class="finding info"><div class="small">${esc(t)}</div></div>`).join("")}
            <p class="tiny muted">Not measured here because they need the network: your IP address and its location, WebRTC IP leaks, TLS/HTTP-2 fingerprints. Every site you visit sees your IP.</p></div>`;
        $("#mi-re").onclick = drawFp;
      }

      function drawStylo() {
        const saved = W.kmz.store("mirror", "samples", [{ label: "Real me", text: "" }, { label: "Persona", text: "" }]);
        const body = $("#mi-body");
        body.innerHTML = `<div class="panel"><p class="small muted" style="margin-top:0">Function-word stylometry (port of Katana's MIRROR): how often you use “the”, “of”, contractions and punctuation is an involuntary fingerprint. Paste writing from your real identity and from a persona — a high similarity means the persona could be linked to you. 200+ words per sample for a real signal.</p>
          <div id="mi-samples" class="grid g2"></div><div class="spacer"></div>
          <div class="row"><button class="btn pri" id="mi-run">Compare</button><button class="btn ghost" id="mi-add">${W.icon(W.I.plus)} Sample</button><label class="check"><input type="checkbox" id="mi-keep" ${W.kmz.store("mirror", "keep", false) ? "checked" : ""}> keep samples on this device</label></div></div><div id="mi-sout"></div>`;
        let samples = saved;
        const paintS = () => { $("#mi-samples").innerHTML = samples.map((s, i) => `<div><input type="text" data-sl="${i}" value="${esc(s.label)}" aria-label="Sample label" style="margin-bottom:6px"><textarea data-st="${i}" rows="7" placeholder="Paste text…">${esc(s.text)}</textarea></div>`).join(""); };
        paintS();
        const read = () => { samples = samples.map((s, i) => ({ label: $(`[data-sl="${i}"]`).value, text: $(`[data-st="${i}"]`).value })); if ($("#mi-keep").checked) W.kmz.put("mirror", "samples", samples); };
        $("#mi-keep").onchange = (e) => { W.kmz.put("mirror", "keep", e.target.checked); if (!e.target.checked) W.store.del("kemuridama.mirror.samples"); else read(); };
        $("#mi-add").onclick = () => { read(); samples.push({ label: `Sample ${samples.length + 1}`, text: "" }); paintS(); };
        $("#mi-run").onclick = () => {
          read();
          try {
            const r = W.eng.mirror.stylometry(samples);
            const tells = r.tells.filter((t) => t.hits.length);
            $("#mi-sout").innerHTML = `<div class="panel"><h2>Similarity</h2>${ui.table(["Pair", "Similarity", "Verdict"], r.pairs.map((p) => [`${esc(p.a)} ↔ ${esc(p.b)}`, `<span class="mono">${esc(p.similarity)}</span>`,
              `${W.kmz.sev(p.verdict.startsWith("same") ? "high" : p.verdict.startsWith("possible") ? "medium" : "ok")} ${esc(p.verdict)}${p.low_confidence ? ' <span class="tiny faint">(short samples — low confidence)</span>' : ""}`]), { raw: true })}
              <div class="spacer"></div><h2>Locale tells</h2>${tells.length ? tells.map((t) => `<div class="finding medium"><header><h3>${esc(t.label || "Sample")}</h3></header><div class="det">${t.hits.map((h) => `<b>${esc(h.tell)}</b>: ${h.examples.map((x) => ui.chip(x)).join("")}`).join("<br>")}</div></div>`).join("") : ui.empty("NO TELLS", "No regional spelling, time-zone, emoji or date-format habits spotted.")}
              <p class="tiny muted">${esc(r.note)}</p></div>`;
          } catch (e) { $("#mi-sout").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; }
        };
      }

      function drawPersonas() {
        let ps = W.kmz.store("mirror", "personas", []);
        const body = $("#mi-body");
        const save = () => W.kmz.put("mirror", "personas", ps);
        const split = (s) => String(s || "").split(/[,\n]/).map((x) => x.trim()).filter(Boolean);
        const paint = () => {
          const r = ps.length ? W.eng.mirror.contamination(ps) : null;
          body.innerHTML = `<div class="panel"><p class="small muted" style="margin-top:0">List the identities you keep apart (your real one included). A handle, email or avatar that appears in more than one persona links them — this is Katana's burn-risk check. Stored only in this browser.</p>
            <div class="grid g2">
              <div><label class="lbl" for="mi-pn">Persona name</label><input type="text" id="mi-pn" placeholder="e.g. Forum alt"></div>
              <div><label class="lbl" for="mi-ph">Handles (comma-separated)</label><input type="text" id="mi-ph" autocapitalize="off" spellcheck="false"></div>
              <div><label class="lbl" for="mi-pe">Emails</label><input type="text" id="mi-pe" autocapitalize="off" spellcheck="false"></div>
              <div><label class="lbl" for="mi-pa">Avatars (image hash / URL)</label><input type="text" id="mi-pa" autocapitalize="off" spellcheck="false"></div>
            </div><div class="spacer"></div><label class="lbl" for="mi-pnote">Cover notes</label><input type="text" id="mi-pnote" placeholder="backstory, purpose…">
            <div class="spacer"></div><div class="row"><button class="btn pri" id="mi-padd">${W.icon(W.I.plus)} Add persona</button><button class="btn ghost" id="mi-pimp">Import saved decoys</button></div></div>
            ${r ? `<div class="panel"><h2>Burn risk</h2><p class="small">${esc(r.summary)}</p>
              ${r.collisions.map((c) => `<div class="callout bad small">Shared ${esc(c.kind.replace(/s$/, ""))} <b>${esc(c.value)}</b> — ${esc(c.shared_by.join(" ↔ "))}</div>`).join("")}<div class="spacer"></div>
              ${ui.table(["Persona", "Score", "Why", ""], r.risks.map((x) => [esc(x.persona), `${W.kmz.sev(x.level)} <span class="mono">${x.score}</span>`, esc(x.reasons.join("; ") || "—"), `<button class="btn sm ghost" data-mipx="${esc(x.persona)}" aria-label="Delete persona">${W.icon(W.I.trash)}</button>`]), { raw: true })}</div>` : ""}`;
          $("#mi-padd").onclick = () => {
            const p = { name: $("#mi-pn").value.trim() || `Persona ${ps.length + 1}`, handles: split($("#mi-ph").value), emails: split($("#mi-pe").value), avatars: split($("#mi-pa").value), notes: $("#mi-pnote").value.trim() };
            if (!p.handles.length && !p.emails.length && !p.avatars.length) return W.toast("Add at least one handle, email or avatar", 1);
            ps = ps.filter((x) => x.name !== p.name).concat(p); save(); paint();
          };
          $("#mi-pimp").onclick = () => {
            const saved = W.kmz.store("decoy", "saved", []);
            if (!saved.length) return W.toast("No saved decoy personas yet — make some in Decoy", 1);
            for (const d of saved) if (!ps.some((x) => x.name === d.name.full)) ps.push({ name: d.name.full, handles: d.handles.slice(0, 3), emails: (d.emails || []).filter((e) => /@/.test(e.value)).map((e) => e.value), avatars: [], notes: "decoy " + d.seed });
            save(); paint();
          };
          body.querySelectorAll("[data-mipx]").forEach((b) => (b.onclick = () => { ps = ps.filter((x) => x.name !== b.dataset.mipx); save(); paint(); }));
        };
        paint();
      }
    },
  });
})();
