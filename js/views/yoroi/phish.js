/* Yoroi · PHISH — paste a reported email's raw source (or drop the .eml) → sender auth, relay path,
 * lookalike links, attachments, lures, verdict. IOCs go to the case or to BLOCK; one click opens a
 * phishing incident in RESPOND. All parsing is local; links are never opened. */
(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const LV = { high: "high", med: "medium", low: "low" };
  let RES = null, RAW = "";

  const SAMPLE = `Return-Path: <bounce@paypa1-secure.top>
Received: from mx.example.org (mx.example.org [10.0.0.5])
	by mail.example.org with LMTP id 77AB; Thu, 14 Nov 2026 08:00:05 +0000
Received: from mail.paypa1-secure.top (unknown [203.0.113.99])
	by mx.example.org with ESMTP id 4XYZ; Thu, 14 Nov 2026 07:59:12 +0000
Received: from [192.168.1.20] (host.example.net [198.51.100.45])
	by mail.paypa1-secure.top with ESMTPSA id 1AA; Thu, 14 Nov 2026 07:59:10 +0000
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=paypa1-secure.top; dkim=none; dmarc=fail header.from=paypal.com
From: "PayPal Security" <service@paypal.com>
Reply-To: resolution-center@paypa1-secure.top
To: victim@example.org
Subject: Urgent: your account will be suspended within 24 hours
Date: Thu, 14 Nov 2026 07:59:10 +0000
Message-ID: <abc123@paypa1-secure.top>
X-Mailer: PHPMailer 6.1
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/html; charset=utf-8

<p>We noticed unusual sign-in activity. Verify your account immediately or it will be suspended.</p>
<p><a href="http://paypa1-secure.top/signin/verify?session=8812">https://www.paypal.com/signin</a></p>
<p><a href="https://bit.ly/3xYzAbC">View your case</a></p>
--b1
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Case-8812.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA==
--b1--
`;

  const ICON = '<path d="M3 6h18v12H3z"/><path d="m3 7 9 6 9-6"/><path d="M15.5 15.5 19 19"/><circle cx="14" cy="14" r="2.2"/>';

  W.tool("yoroi", "phish", {
    name: "Phish", order: 50, icon: ICON,
    desc: "Triage a reported email: SPF/DKIM/DMARC, relay path, lookalike links, attachments, verdict.",
    help: {
      steps: ["Paste the full source of a reported email (headers + body) or Load .eml.", "Read the verdict: SPF/DKIM/DMARC, relay path, lookalike links, link-text mismatches and attachments."],
      tips: ["Gmail: ⋮ → Show original. Outlook: File → Properties → Internet headers (or save the message as .eml)."],
    },
    render(el, arg) {
      el.innerHTML = ui.head("PHISH", "Email triage", "Paste the full source of a reported email (headers + body) or drop the .eml. Sender authentication, relay hops, lookalike and mismatched links, attachments and pressure language are analysed locally — nothing is fetched.") +
        ui.panel("Raw message", `<textarea id="ph-t" rows="8" spellcheck="false" autocapitalize="off" placeholder="Outlook: File → Properties → Internet headers (+ body) · Gmail: ⋮ → Show original · Apple Mail: View → Message → Raw Source"></textarea>
          <div class="spacer"></div><div class="row">${ui.btn(W.icon(W.I.search) + "Analyse", 'id="ph-go"', "pri")}
          <label class="btn ghost">${W.icon(W.I.up)}Load .eml<input type="file" id="ph-f" accept=".eml,.txt,.msg,message/rfc822" hidden></label>
          ${ui.btn("Sample", 'id="ph-s"', "ghost")}<span class="grow"></span><span class="tiny faint">Stays on this device — never uploaded.</span></div>`) +
        `<div id="ph-out"></div>`;
      const t = $("#ph-t");
      ["dragenter", "dragover"].forEach((ev) => t.addEventListener(ev, (e) => { e.preventDefault(); t.classList.add("yb-over"); }));
      ["dragleave", "drop"].forEach((ev) => t.addEventListener(ev, () => t.classList.remove("yb-over")));
      t.addEventListener("drop", async (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) { t.value = await W.readFile(f, "text"); run(); } });
      W.act("#ph-go", run);
      $("#ph-f").addEventListener("change", async (e) => { const f = e.target.files[0]; e.target.value = ""; if (f) { t.value = await W.readFile(f, "text"); run(); } });
      $("#ph-s").onclick = () => { t.value = SAMPLE; run(); };
      if (typeof arg === "string" && arg.trim()) { t.value = arg; run(); }
      else if (RES) { t.value = RAW; draw(); }
    },
  });

  function run() {
    const raw = $("#ph-t").value;
    if (!raw.trim()) throw new Error("paste an email first");
    RAW = raw; RES = W.eng.phish.analyze(raw);
    draw();
  }

  const lvBadge = (l) => ui.sev(LV[l] || "info");
  const defang = (u) => W.defang(String(u || ""));

  function draw() {
    const r = RES, h = r.headers, out = $("#ph-out");
    const vk = { malicious: "crit", suspicious: "high", "likely benign": "ok" }[r.verdict];
    const hosts = r.iocs.domain;
    const auth = (k) => { const v = h.auth[k]; return v ? ui.badge(v, v === "pass" ? "ok" : ["fail", "softfail", "permerror"].includes(v) ? "crit" : "warn") : ui.badge("none", "warn"); };
    out.innerHTML = `
      <section class="panel yb-verdict ${vk}"><div class="row">
        <span class="badge fill ${vk} yb-big">${esc(r.verdict)}</span>
        <div class="col" style="flex:1;min-width:200px"><b class="break">${esc(r.subject || "(no subject)")}</b><span class="small muted mono break">${esc(r.from || "")}</span></div>
        <div class="col yb-score"><span class="tiny muted">RISK SCORE</span><b class="mono">${r.score}</b></div></div>
        <div class="spacer"></div><div class="meter"><i style="width:${Math.min(100, (r.score / 20) * 100).toFixed(0)}%;background:var(--${vk === "ok" ? "ok" : vk === "high" ? "high" : "crit"})"></i></div>
        <div class="spacer"></div><div class="row">
          ${ui.btn(W.icon(W.I.case) + "Add IOCs to case", 'id="ph-case"', "sm pri")}${ui.btn("Send to Block", 'id="ph-blk"', "sm")}
          ${ui.btn(W.icon(W.I.plus) + "Open phishing incident", 'id="ph-inc"', "sm")}${ui.btn(W.icon(W.I.dl) + "JSON", 'id="ph-json"', "sm ghost")}</div></section>
      <div class="grid g2 yb-split">
        ${ui.panel(`Red flags (${r.redflags.length})`, r.redflags.length ? r.redflags.map((f) => `<div class="finding ${LV[f.level]}"><header>${lvBadge(f.level)}${ui.badge(f.src, "info")}<h3 class="break">${esc(f.text)}</h3></header></div>`).join("") : ui.empty("NO RED FLAGS", "Nothing suspicious found — still verify the sender out-of-band if in doubt."))}
        ${ui.panel("Sender & authentication", `<div class="row">${["spf", "dkim", "dmarc"].map((k) => `<span class="small mono">${k.toUpperCase()}</span>${auth(k)}`).join('<span class="faint">·</span>')}</div><div class="spacer"></div>
          ${ui.kv([["From", h.summary.From], ["Reply-To", h.summary["Reply-To"]], ["Return-Path", h.summary["Return-Path"]], ["To", h.summary.To], ["Date", h.summary.Date],
            ["Origin IP", h.origin_ip ? `<code>${esc(h.origin_ip)}</code> ${ui.btn("Pivot", `data-pv="${esc(h.origin_ip)}"`, "sm ghost")}` : "—", true],
            ["Mailer", h.summary["X-Mailer"]], ["Message-ID", h.summary["Message-ID"]], ["MIME parts", r.parts]])}`)}
      </div>
      ${h.hops.length ? ui.panel(`Relay path (${h.hops.length} hops, origin first)`, ui.table(["#", "From", "By", "IP", "Time", "Delay"], h.hops.map((x, i) => [i + 1,
        `<span class="mono small break">${esc(x.from || "?")}</span>`, `<span class="mono small break">${esc(x.by || "?")}</span>`,
        x.ip ? `<code>${esc(x.ip)}</code>${W.eng.block && !W.eng.block.isPublicIp(x.ip) ? ` <span class="tiny faint">private</span>` : ""}` : "—",
        `<span class="small nowrap">${esc(x.date ? String(x.date).replace("T", " ") : "—")}</span>`,
        x.delay_s == null ? "—" : `<span class="mono small ${x.delay_s < 0 || x.delay_s > 3600 ? "c-crit" : ""}">${x.delay_s >= 0 ? "+" : ""}${esc(fmtDelay(x.delay_s))}</span>`]), { raw: true })) : ""}
      ${ui.panel(`Links (${r.urls.length})`, r.urls.length ? ui.table(["URL (defanged)", "Shown text", "Flags", ""], r.urls.map((u) => [
        `<span class="mono small break">${esc(defang(u.url))}</span>`, `<span class="small break">${esc(u.text)}</span>`,
        u.flags.length ? u.flags.map((f) => ui.badge(f.text, LV[f.level])).join(" ") : ui.badge("no flags", "ok"),
        u.host ? ui.btn("Pivot", `data-pv="${esc(u.host)}"`, "sm ghost") : ""]), { raw: true }) : ui.empty("NO LINKS"))}
      ${r.attachments.length ? ui.panel(`Attachments (${r.attachments.length})`, r.attachments.map((a) => {
        const top = a.flags.some((f) => f.level === "high") ? "high" : a.flags.length ? "medium" : "ok";
        return `<div class="finding ${top}"><header>${top === "ok" ? ui.badge("no flags", "ok") : ui.sev(top, true)}<h3 class="break">${esc(a.name)}</h3><span class="tiny muted">${esc(a.detected || a.type)} · ${esc(W.fmt.bytes(a.size))}${a.entropy ? ` · entropy ${a.entropy.toFixed(2)}` : ""}</span></header>
          ${a.hashes.sha256 ? `<div class="det mono tiny break">sha256 ${esc(a.hashes.sha256)}<br>md5 ${esc(a.hashes.md5)}</div>` : ""}
          ${a.flags.map((f) => `<div class="det">${lvBadge(f.level)} ${esc(f.text)}</div>`).join("")}
          ${(a.iocs.url || []).length ? `<div class="det tiny">Embedded URLs: ${a.iocs.url.slice(0, 8).map((u) => `<code>${esc(defang(u))}</code>`).join(" ")}</div>` : ""}</div>`;
      }).join("")) : ""}
      ${r.forms.length || r.lures.length ? `<div class="grid g2">${ui.panel("Pressure language", r.lures.length ? r.lures.map((x) => ui.chip(x)).join("") : ui.empty("NONE"))}
        ${ui.panel("Embedded forms", r.forms.length ? r.forms.map((f) => `<div class="mono small break">→ ${esc(defang(f || "(posts to itself)"))}</div>`).join("") : ui.empty("NONE"))}</div>` : ""}
      ${ui.panel("Indicators", iocBlock(r))}
      ${ui.panel("Response templates", `<div class="tabs" id="ph-tt">${[["reporter", "Reply to reporter"], ["users", "Warn users"], ["block", "Block request"]].map(([k, l], i) => `<button type="button" data-tab="${k}" class="${i ? "" : "on"}">${l}</button>`).join("")}</div>
        <pre class="out" id="ph-tpl"></pre><div class="spacer"></div>${ui.btn(W.icon(W.I.copy) + "Copy", 'id="ph-cp"', "sm")}`)}
      ${r.body_preview ? ui.panel("Body preview (text only)", `<div class="small muted break yb-preview">${esc(r.body_preview)}</div>`) : ""}`;

    const T = templates(r, hosts);
    let cur = "reporter";
    const showT = () => ($("#ph-tpl").textContent = T[cur]);
    showT();
    W.tabs($("#ph-tt"), (k) => { cur = k; showT(); });
    $("#ph-cp").onclick = () => W.copy(T[cur], "Template copied");
    $("#ph-case").onclick = () => {
      const items = [];
      for (const [type, vals] of Object.entries(r.iocs)) for (const v of vals) if (type !== "email" || v !== (W.eng.phish.parseAddr(h.summary.From).addr || "").toLowerCase() || r.verdict !== "likely benign")
        items.push({ value: v, type: type === "domain" ? "domain" : type, verdict: r.verdict === "malicious" ? "malicious" : r.verdict === "suspicious" ? "suspicious" : null, tags: ["phish"], note: `PHISH: ${(r.subject || "").slice(0, 80)}` });
      if (!items.length) return W.toast("No indicators to add", 1);
      W.Case.add(items);
    };
    $("#ph-blk").onclick = () => { if (!r.blockable.length) return W.toast("No blockable indicators", 1); W.go("yoroi", "block", r.blockable.join("\n")); };
    $("#ph-json").onclick = () => W.download(`phish-${W.nowIso().slice(0, 19).replace(/:/g, "")}.json`, JSON.stringify(r, null, 2), "application/json");
    $("#ph-inc").onclick = () => {
      const P = W.eng.playbooks, list = W.store.get("yoroi.respond.incidents", []) || [];
      const inc = P.newIncident({ title: `Phishing: ${(r.subject || "reported email").slice(0, 70)}`, severity: r.verdict === "malicious" ? "high" : "medium", origin: "PHISH",
        summary: `Reported email from ${r.from || "?"} rated ${r.verdict} (score ${r.score}).\nTop flags: ${r.redflags.slice(0, 5).map((f) => f.text).join("; ")}`, playbook: "phishing",
        iocs: r.blockable.map((v) => ({ value: v, note: "phish" })) }, list);
      P.log(inc, "finding", `[PHISH] verdict ${r.verdict}, score ${r.score}`);
      const t0 = inc.tasks.find((x) => /Run PHISH triage/.test(x.text)); if (t0) { t0.done = true; t0.at = W.nowIso(); }
      list.unshift(inc); W.store.set("yoroi.respond.incidents", list); W.store.set("yoroi.respond.active", inc.id);
      W.toast(`${inc.id} opened`); W.go("yoroi", "respond");
    };
    const cpd = $("#ph-cpd"); if (cpd) cpd.onclick = () => W.copy(Object.values(r.iocs).flat().map((x) => W.defang(x)).join("\n"), "Defanged IOCs copied");
    out.onclick = (e) => {
      const p = e.target.closest("[data-pv]"); if (!p) return;
      if (W.tools.yumi && W.tools.yumi.pivot) W.go("yumi", "pivot", p.dataset.pv); else W.copy(p.dataset.pv);
    };
  }

  function fmtDelay(s) { const a = Math.abs(s); return (s < 0 ? "-" : "") + (a < 120 ? a + "s" : a < 7200 ? Math.round(a / 60) + "m" : (a / 3600).toFixed(1) + "h"); }

  function iocBlock(r) {
    const rows = Object.entries(r.iocs).filter(([, v]) => v.length);
    if (!rows.length) return ui.empty("NO INDICATORS");
    return rows.map(([k, v]) => `<div class="yb-iocrow"><span class="lbl">${esc(k)} (${v.length})</span><div>${v.slice(0, 40).map((x) => ui.chip(k === "url" ? defang(x) : x, ' title="' + esc(x) + '"')).join("")}${v.length > 40 ? `<span class="tiny faint">+${v.length - 40} more</span>` : ""}</div></div>`).join("") +
      `<div class="spacer"></div>${ui.btn(W.icon(W.I.copy) + "Copy defanged", 'id="ph-cpd"', "sm ghost")}`;
  }

  function templates(r, hosts) {
    const h = r.headers, who = (W.store.get("yoroi.respond.analyst") || "Security Operations");
    return {
      reporter: `Hi,\n\nThank you for reporting the email "${r.subject || ""}". Our analysis rates it as ${r.verdict.toUpperCase()}.\n\n${r.verdict === "likely benign" ? "It appears legitimate, but stay cautious with links and attachments." : "Please do not click any links, open attachments or reply. If you already did, contact the security team right away and change your password."}\n\nWe have taken action to protect other users. Reporting suspicious mail helps keep everyone safe - thank you.\n\n${who}`,
      users: `Subject: Security notice - phishing email in circulation\n\nA phishing email is targeting our staff.\n\n  Subject: ${r.subject || ""}\n  Appears to be from: ${r.from || ""}\n\nIf you received it: do not click links or open attachments, and delete it. If you entered your password or opened an attachment, contact the security team immediately.\n\n${who}`,
      block: `Request: block phishing infrastructure (${W.nowIso()})\n\nSender: ${r.from || ""}\nReturn-Path: ${h.summary["Return-Path"] || ""}\nOrigin IP: ${h.origin_ip || "n/a"}\n\nDomains / hosts:\n${hosts.map((x) => "  " + W.defang(x)).join("\n") || "  none"}\n\nURLs:\n${r.urls.map((u) => "  " + W.defang(u.url)).join("\n") || "  none"}\n\nAttachment hashes (SHA256):\n${r.attachments.map((a) => "  " + (a.hashes.sha256 || "")).join("\n") || "  none"}\n\nRequested actions: block at mail gateway, web proxy / DNS filter, and purge from mailboxes.`,
    };
  }
})();
