/* Yoroi · POSTURE — audit *this* browser/device with local APIs only (secure context, GPC/DNT, storage,
 * permission states, WebRTC host candidates with no STUN server, client hints, fingerprint surface,
 * service worker, install state…). DOM/API probing lives here; scoring is W.eng.posture (pure). */
(function () {
  "use strict";
  const { $, esc, ui } = W;
  const ICON = '<path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-6"/><path d="M7 14h.01M12 10h.01M17 14h.01"/>';
  const ST = { pass: ["ok", "PASS"], warn: ["medium", "WARN"], fail: ["critical", "FAIL"], info: ["info", "INFO"] };
  let LAST = null;

  const withTimeout = (p, ms, dflt) => Promise.race([Promise.resolve(p).catch(() => dflt), new Promise((r) => setTimeout(() => r(dflt), ms))]);

  async function iceProbe() {
    const RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (!RTC) return { available: false };
    const lines = [];
    let pc;
    try {
      pc = new RTC({ iceServers: [] });               // no STUN/TURN → nothing leaves the machine
      pc.createDataChannel("wkz-probe");
      const done = new Promise((res) => {
        pc.onicecandidate = (e) => { if (e.candidate && e.candidate.candidate) lines.push(e.candidate.candidate); else res(); };
        pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") res(); };
      });
      await pc.setLocalDescription(await pc.createOffer());
      await withTimeout(done, 1500);
      const sdp = (pc.localDescription && pc.localDescription.sdp) || "";
      for (const m of sdp.match(/^a=(candidate:.*)$/gm) || []) lines.push(m.slice(2));
    } catch (e) { return { available: true, leak: "unknown", error: String(e && e.message || e) }; }
    finally { try { pc && pc.close(); } catch { /* ignore */ } }
    return Object.assign({ available: true, candidates: lines.length }, W.eng.posture.classifyCandidates(lines));
  }

  async function gather() {
    const n = navigator, f = {
      now: new Date().toISOString(), secureContext: !!window.isSecureContext, protocol: location.protocol, origin: location.origin,
      cookieEnabled: n.cookieEnabled, dnt: n.doNotTrack || window.doNotTrack || null,
      gpc: "globalPrivacyControl" in n ? !!n.globalPrivacyControl : undefined,
      ua: n.userAgent, webdriver: !!n.webdriver, languages: Array.from(n.languages || []), hardwareConcurrency: n.hardwareConcurrency || null,
      deviceMemory: n.deviceMemory || null, plugins: n.plugins ? n.plugins.length : 0, maxTouchPoints: n.maxTouchPoints || 0,
      timezone: (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || null,
      screen: { w: screen.width, h: screen.height, dpr: window.devicePixelRatio || 1, colorDepth: screen.colorDepth },
      crossOriginIsolated: !!window.crossOriginIsolated,
      standalone: !!((window.matchMedia && matchMedia("(display-mode: standalone)").matches) || n.standalone === true),
      serviceWorker: { supported: "serviceWorker" in n, controlled: !!(n.serviceWorker && n.serviceWorker.controller) },
      thirdPartyCookies: "unknown",
    };
    if (n.userAgentData) {
      const d = n.userAgentData;
      f.uaData = { brands: d.brands, mobile: d.mobile, platform: d.platform };
      const he = await withTimeout(d.getHighEntropyValues && d.getHighEntropyValues(["platformVersion", "fullVersionList", "architecture", "model"]), 800, null);
      if (he) Object.assign(f.uaData, { platformVersion: he.platformVersion, fullVersionList: he.fullVersionList, architecture: he.architecture, model: he.model, highEntropy: true });
    }
    f.storage = { supported: !!(n.storage && n.storage.persisted) };
    if (f.storage.supported) {
      f.storage.persisted = await withTimeout(n.storage.persisted(), 800, null);
      const est = await withTimeout(n.storage.estimate && n.storage.estimate(), 800, null);
      if (est) Object.assign(f.storage, { quota: est.quota, usage: est.usage });
    }
    f.permissions = {};
    for (const [name, desc] of [["camera"], ["microphone"], ["geolocation"], ["notifications"], ["clipboard-read"], ["midi", { name: "midi", sysex: true }]]) {
      if (!n.permissions || !n.permissions.query) { f.permissions[name] = "unsupported"; continue; }
      const r = await withTimeout(n.permissions.query(desc || { name }), 800, null);
      f.permissions[name] = r ? r.state : "unsupported";
    }
    f.webrtc = await iceProbe();
    f.apis = {
      getBattery: typeof n.getBattery === "function", bluetooth: "bluetooth" in n, usb: "usb" in n, serial: "serial" in n, hid: "hid" in n,
      storageAccess: typeof document.hasStorageAccess === "function", cookieStore: "cookieStore" in window,
      platformAuthenticator: window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
        ? await withTimeout(PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(), 1200, null) : null,
    };
    try {
      const gl = document.createElement("canvas").getContext("webgl");
      if (gl) { f.apis.webgl = true; const dbg = gl.getExtension("WEBGL_debug_renderer_info"); if (dbg) f.apis.webglRenderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL); }
    } catch { /* ignore */ }
    return f;
  }

  W.tool("yoroi", "posture", {
    name: "Posture", order: 80, icon: ICON,
    desc: "Audit this browser and device: updates, privacy signals, permissions, WebRTC leaks — scored 0–100 with fixes.",
    render(el) {
      el.innerHTML = ui.head("POSTURE", "Browser posture", "A read-only audit of <b>this</b> browser and device using only local APIs — nothing is sent anywhere, and the WebRTC probe uses no STUN server. Each control is weighted into a 0–100 score with a concrete fix.") +
        `<div class="row">${ui.btn(W.icon(W.I.refresh) + "Run audit", 'id="po-go"', "pri")}<span class="grow"></span><span class="tiny faint" id="po-when"></span></div><div class="spacer"></div><div id="po-out">${ui.panel("", ui.loader("PROBING"))}</div>`;
      W.act("#po-go", run);
      run();
    },
  });

  async function run() {
    const out = $("#po-out"); if (!out) return;
    if (!LAST) out.innerHTML = ui.panel("", ui.loader("PROBING"));
    const facts = await gather();
    const r = W.eng.posture.evaluate(facts);
    LAST = { facts, r };
    if ($("#po-out")) draw();
  }

  function ring(score, posture) {
    const c = 2 * Math.PI * 52, col = score >= 90 ? "var(--ok)" : score >= 75 ? "var(--acc)" : score >= 55 ? "var(--med)" : "var(--crit)";
    return `<svg class="yb-ring" viewBox="0 0 120 120" role="img" aria-label="Score ${score} of 100"><circle cx="60" cy="60" r="52" fill="none" stroke="var(--line)" stroke-width="10"/>
      <circle cx="60" cy="60" r="52" fill="none" stroke="${col}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${((c * score) / 100).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 60 60)" style="filter:drop-shadow(0 0 6px ${col})"/>
      <text x="60" y="62" text-anchor="middle" dominant-baseline="middle" fill="var(--text)" font-family="var(--mono)" font-size="30" font-weight="700">${score}</text>
      <text x="60" y="88" text-anchor="middle" fill="var(--dim)" font-family="var(--mono)" font-size="9" letter-spacing="2">${esc(posture)}</text></svg>`;
  }

  function draw() {
    const { facts, r } = LAST, out = $("#po-out");
    $("#po-when").textContent = "Audited " + W.fmt.ts(facts.now);
    const groups = [...new Set(r.checks.map((c) => c.group))];
    const b = r.browser;
    out.innerHTML = `<section class="panel yb-score-panel"><div class="row" style="gap:18px;align-items:center">${ring(r.score, r.posture)}
        <div class="col" style="flex:1;min-width:200px"><b>${esc(b.name)}${b.major ? " " + esc(b.major) : ""} · ${esc(b.os)}${b.platformVersion ? " " + esc(b.platformVersion) : b.osVersion ? " " + esc(b.osVersion) : ""}${b.mobile ? " · mobile" : ""}</b>
          <span class="small muted">${r.counts.fail} failing · ${r.counts.warn} warnings · ${r.counts.pass} passing · ${r.counts.info} informational</span>
          <div class="spacer"></div><div class="row">${facts.storage && facts.storage.persisted === false ? ui.btn("Request persistent storage", 'id="po-persist"', "sm") : ""}
            ${ui.btn(W.icon(W.I.dl) + "Report .md", 'id="po-md"', "sm")}${ui.btn("JSON", 'id="po-json"', "sm ghost")}</div></div></div></section>
      ${ui.panel(`Prioritised fixes (${r.fixes.length})`, r.fixes.length ? `<ol class="yb-fixes">${r.fixes.map((c) => `<li><div class="row">${ui.sev(ST[c.status][0], c.status === "fail")}<b>${esc(c.title)}</b><span class="tiny faint">weight ${c.weight}</span></div>
        <div class="small muted break">${esc(c.detail)}</div><div class="small break">→ ${esc(c.fix)}</div></li>`).join("")}</ol>` : `<div class="callout ok">Nothing to fix — this browser is in good shape.</div>`)}
      ${groups.map((g) => ui.panel(g, r.checks.filter((c) => c.group === g).map((c) => `<div class="finding ${ST[c.status][0]}"><header>${ui.badge(ST[c.status][1], ST[c.status][0], c.status === "fail")}<h3>${esc(c.title)}</h3>${c.weight ? `<span class="tiny faint">w${c.weight}</span>` : ""}</header>
        <div class="det break">${esc(c.detail)}</div>${c.fix && c.status !== "pass" ? `<div class="det small break">→ ${esc(c.fix)}</div>` : ""}</div>`).join(""))).join("")}
      ${ui.panel("Raw facts", `<details class="yb-details"><summary class="small muted">Everything the audit read (stays on this device)</summary><div class="spacer"></div><pre class="out">${esc(JSON.stringify(facts, null, 2))}</pre></details>`)}`;
    const ps = $("#po-persist");
    if (ps) W.act(ps, async () => { const ok = navigator.storage && navigator.storage.persist ? await navigator.storage.persist() : false; W.toast(ok ? "Persistent storage granted" : "The browser declined — installing the app usually helps", !ok); await run(); });
    $("#po-json").onclick = () => W.download(`posture-${facts.now.slice(0, 10)}.json`, JSON.stringify(LAST, null, 2), "application/json");
    $("#po-md").onclick = () => W.download(`posture-${facts.now.slice(0, 10)}.md`, markdown(r, facts), "text/markdown;charset=utf-8");
  }

  function markdown(r, f) {
    const L = [`# Browser posture — ${r.score}/100 (${r.posture})`, "", `- Browser: ${r.browser.name} ${r.browser.major || ""} on ${r.browser.os}`, `- Audited: ${f.now}`, `- Origin: ${f.origin}`, "", "## Fixes, in priority order", ""];
    r.fixes.forEach((c, i) => L.push(`${i + 1}. **${c.title}** (${c.status}, weight ${c.weight}) — ${c.detail}  \n   → ${c.fix}`));
    if (!r.fixes.length) L.push("_None._");
    L.push("", "## All checks", "", "| Status | Check | Detail |", "|---|---|---|");
    for (const c of r.checks) L.push(`| ${c.status.toUpperCase()} | ${c.title} | ${String(c.detail).replace(/\|/g, "\\|")} |`);
    L.push("", "_Generated locally by Wakizashi (Yoroi · Posture)._", "");
    return L.join("\n");
  }
})();
