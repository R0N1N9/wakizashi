/* RESPOND playbooks, organised by NIST SP 800-61 phases (port of Katana defense/playbooks.py), plus the
 * pure incident model the Respond view stores in `yoroi.respond.incidents`.
 *
 *   W.eng.playbooks.PHASES      [[id, name], …]  detect → contain → eradicate → recover → lessons
 *   W.eng.playbooks.PLAYBOOKS   [{id, name, severity, attack, steps: {phase: [text]}}]
 *   W.eng.playbooks.get(id)
 *   W.eng.playbooks.newIncident({title, severity, origin, summary, playbook, iocs}) → incident
 *   W.eng.playbooks.apply(incident, playbookId) → number of tasks added
 *   W.eng.playbooks.report(incident) → Markdown
 * Tool names in CAPS inside steps (PHISH, BLOCK, YARA, HUNT, RULES, PIVOT…) are linked by the view.
 */
(function (W) {
  "use strict";

  const PHASES = [["detect", "Detection & Analysis"], ["contain", "Containment"], ["eradicate", "Eradication"],
    ["recover", "Recovery"], ["lessons", "Post-Incident / Lessons Learned"]];
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const STATUSES = ["open", "contained", "closed"];

  const PLAYBOOKS = [
    { id: "phishing", name: "Phishing / malicious email", severity: "medium", attack: ["T1566", "T1204"], steps: {
      detect: ["Collect the reported email as .eml (full headers) and add it as evidence",
        "Run PHISH triage: sender auth (SPF/DKIM/DMARC), URLs, attachments",
        "Search mail logs for the same sender, subject, URL or attachment hash across all mailboxes",
        "Identify every recipient and who clicked / opened / replied (proxy, EDR, mail logs)",
        "If credentials were entered: identify the accounts and check sign-in logs since the click"],
      contain: ["Purge the message from all mailboxes", "Block sender domain/address and URLs at mail gateway and proxy (BLOCK)",
        "Reset passwords and revoke sessions/tokens for any account that submitted credentials",
        "Isolate any endpoint that executed an attachment"],
      eradicate: ["Remove malicious inbox rules / forwarding added by the attacker",
        "Remove dropped files and persistence from affected endpoints", "Re-image if execution is confirmed"],
      recover: ["Re-enable accounts with MFA enforced", "Monitor affected accounts for 14 days (impossible travel, new MFA devices)"],
      lessons: ["Notify users with a short awareness note on this lure", "Tune mail filtering rules",
        "Record IOCs in the threat-intel platform"] } },
    { id: "ransomware", name: "Ransomware", severity: "critical", attack: ["T1486", "T1490", "T1021"], steps: {
      detect: ["Identify patient zero, ransom note, file extension and strain (ID Ransomware / note text)",
        "Determine scope: which hosts, shares and backups are encrypted", "Check for data exfiltration (double extortion): large outbound transfers, rclone, MEGA",
        "Preserve volatile evidence (memory, running processes) on at least one host before shutdown"],
      contain: ["Isolate infected hosts from the network (EDR isolation or pull the cable - keep powered on)",
        "Disable compromised accounts, especially domain admins; reset KRBTGT twice (10h apart) if AD is compromised",
        "Block known C2 and exfil destinations (BLOCK)", "Take backups offline to protect them",
        "Shut down SMB/RDP between network segments"],
      eradicate: ["Find and remove initial access vector (VPN, RDP, phishing, exploited CVE)",
        "Remove persistence: services, scheduled tasks, GPOs, new accounts",
        "Patch the exploited vulnerability", "Rebuild affected systems from known-good images"],
      recover: ["Restore from verified clean backups (scan before reconnecting)", "Rotate all privileged credentials and service account passwords",
        "Bring systems back by priority with heightened monitoring"],
      lessons: ["Engage legal / insurance / regulators per notification obligations", "Do not pay without legal + executive decision",
        "Test backup restore and segmentation improvements", "Report to law enforcement / CISA / national CERT"] } },
    { id: "bec", name: "Business email compromise", severity: "high", attack: ["T1078", "T1114", "T1657"], steps: {
      detect: ["Confirm the compromised mailbox and review sign-in logs (IPs, user agents, MFA)", "List inbox rules, forwarding, delegates and OAuth app consents",
        "Identify fraudulent emails sent (invoices, bank-detail changes) and their recipients",
        "Check whether a payment was made and its amount / destination account"],
      contain: ["Reset password, revoke all sessions and refresh tokens, re-register MFA", "Remove malicious rules, forwarding and app consents",
        "Contact the bank immediately to recall any fraudulent transfer", "Warn external recipients of fraudulent mail"],
      eradicate: ["Block attacker IPs / lookalike domains (BLOCK)", "Search for the same attacker infrastructure across other mailboxes"],
      recover: ["Enforce phishing-resistant MFA and conditional access", "Monitor the mailbox for 30 days"],
      lessons: ["Introduce out-of-band verification for payment detail changes", "Register common lookalike domains",
        "File a report with IC3 / local police"] } },
    { id: "account", name: "Compromised account", severity: "high", attack: ["T1078", "T1110"], steps: {
      detect: ["Review authentication logs: source IPs, geolocation, failed vs successful attempts (HUNT)",
        "Determine how credentials were obtained (phishing, reuse, brute force, infostealer)",
        "List resources accessed and actions taken by the account since the first malicious logon"],
      contain: ["Disable or reset the account and revoke sessions/tokens", "Block the attacker IPs (BLOCK)", "Remove attacker-added MFA devices, keys or API tokens"],
      eradicate: ["Remove any persistence created with the account (new users, keys, rules, roles)",
        "Scan the user's endpoints for infostealers (YARA)"],
      recover: ["Restore access with MFA enforced", "Monitor for re-use of the leaked password elsewhere"],
      lessons: ["Enforce MFA / password manager / breached-password checks", "Lower brute-force thresholds and alerting"] } },
    { id: "malware", name: "Malware on endpoint", severity: "high", attack: ["T1204", "T1059", "T1547"], steps: {
      detect: ["Collect the sample hash and scan it with YARA; check reputation (PIVOT)",
        "Identify execution chain (parent process, user, initial vector)", "Search all endpoints for the same hash / filename / C2"],
      contain: ["Isolate the host", "Block hash, C2 domains and IPs (BLOCK)", "Disable the affected user if credentials may be stolen"],
      eradicate: ["Remove malware and persistence; prefer re-image for anything beyond adware",
        "Reset credentials used on the host (browser-saved passwords included for infostealers)"],
      recover: ["Restore the host and user data", "Verify EDR/AV is healthy and up to date"],
      lessons: ["Add detections for the observed behaviour (RULES)", "Close the delivery vector"] } },
    { id: "webapp", name: "Web application compromise", severity: "high", attack: ["T1190", "T1505.003"], steps: {
      detect: ["Review access logs for exploitation (HUNT web detections)", "Look for web shells (YARA webshell rule, FIM diff of web root)",
        "Identify the vulnerable component and version"],
      contain: ["Put the app behind a WAF rule or take it offline", "Block attacker IPs (BLOCK)", "Rotate app secrets, DB credentials and API keys"],
      eradicate: ["Remove web shells and unauthorised files", "Patch or upgrade the vulnerable component", "Review DB for injected content / new admin users"],
      recover: ["Redeploy from a clean build", "Re-baseline FIM for the web root"],
      lessons: ["Add the exploit pattern to detections (RULES)", "Schedule dependency scanning in CI"] } },
    { id: "insider", name: "Insider threat / data theft", severity: "high", attack: ["T1567", "T1052", "T1005"], steps: {
      detect: ["Coordinate with HR and Legal before any action", "Review DLP, cloud-storage uploads, USB use and email to personal addresses",
        "Preserve evidence with chain of custody"],
      contain: ["Restrict access in coordination with HR", "Revoke tokens / sessions on personal devices"],
      eradicate: ["Recover or confirm deletion of exfiltrated data where possible"],
      recover: ["Review access rights of the user's peer group"],
      lessons: ["Improve DLP coverage and joiner/mover/leaver process"] } },
    { id: "ddos", name: "Denial of service", severity: "medium", attack: ["T1498", "T1499"], steps: {
      detect: ["Confirm it is an attack (not a traffic spike / misconfiguration)", "Identify attack type: volumetric, protocol, application layer",
        "Capture traffic samples (PCAP) for top sources and patterns"],
      contain: ["Engage ISP / DDoS mitigation provider / CDN", "Apply rate limits and geo/IP blocks (BLOCK)", "Scale or fail over critical services"],
      eradicate: ["Close any amplification sources on your own network (open resolvers, memcached, NTP)"],
      recover: ["Remove temporary blocks gradually and monitor"],
      lessons: ["Pre-arrange DDoS protection and runbook contacts"] } },
    { id: "cloud", name: "Cloud credential / account abuse", severity: "high", attack: ["T1078.004", "T1098.001", "T1530"], steps: {
      detect: ["Review CloudTrail/activity logs for the access key or principal (HUNT)", "List resources created (instances, keys, users, roles) and data accessed",
        "Check billing for crypto-mining spikes"],
      contain: ["Deactivate the exposed access keys; attach a deny-all policy to the principal", "Revoke active sessions",
        "Restore logging/guardrails if they were disabled"],
      eradicate: ["Delete attacker-created users, roles, keys and resources", "Find where the key leaked (git history, CI logs, public bucket)"],
      recover: ["Issue new least-privilege credentials", "Enable organisation-wide guardrails (SCPs, GuardDuty)"],
      lessons: ["Move to short-lived credentials / workload identity", "Add secret scanning to repos and CI"] } },
  ];

  /** ATT&CK names for the techniques the playbooks reference (offline label lookup). */
  const TECHNIQUES = {
    T1005: "Data from Local System", T1021: "Remote Services", T1052: "Exfiltration Over Physical Medium", T1059: "Command and Scripting Interpreter",
    T1071: "Application Layer Protocol", T1078: "Valid Accounts", "T1078.004": "Cloud Accounts", "T1098.001": "Additional Cloud Credentials",
    T1110: "Brute Force", T1114: "Email Collection", T1190: "Exploit Public-Facing Application", T1204: "User Execution",
    T1486: "Data Encrypted for Impact", T1490: "Inhibit System Recovery", T1498: "Network Denial of Service", T1499: "Endpoint Denial of Service",
    "T1505.003": "Web Shell", T1530: "Data from Cloud Storage", T1547: "Boot or Logon Autostart Execution", T1566: "Phishing",
    "T1566.001": "Spearphishing Attachment", "T1566.002": "Spearphishing Link", T1567: "Exfiltration Over Web Service", T1657: "Financial Theft",
  };

  /** CAPS keywords in step text → Wakizashi tool [layer, id]. */
  const TOOL_LINKS = { PHISH: ["yoroi", "phish"], BLOCK: ["yoroi", "block"], YARA: ["yoroi", "yara"], HUNT: ["yoroi", "hunt"], RULES: ["yoroi", "rules"], PIVOT: ["yumi", "pivot"] };

  const get = (id) => PLAYBOOKS.find((p) => p.id === id) || null;
  const now = () => new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const sevRank = (s) => { const i = SEVS.indexOf(s); return i < 0 ? 2 : i; };

  function nextId(existing) {
    const y = new Date().getUTCFullYear();
    let max = 0;
    for (const i of existing || []) { const m = /^IR-(\d{4})-(\d+)$/.exec(i.id || ""); if (m && +m[1] === y) max = Math.max(max, +m[2]); }
    return `IR-${y}-${String(max + 1).padStart(3, "0")}`;
  }

  function log(inc, kind, text, at) { inc.timeline.unshift({ t: at || now(), kind: kind || "note", text: String(text) }); inc.updated = at || now(); }

  function newIncident(o = {}, existing = []) {
    const t = now();
    const inc = { id: nextId(existing), title: String(o.title || "New incident").slice(0, 160), severity: SEVS.includes(o.severity) ? o.severity : "medium",
      status: "open", phase: "detect", owner: o.owner || "", origin: o.origin || "", summary: o.summary || "", lessons: "", playbook: null,
      tasks: [], iocs: [], attack: [], timeline: [], evidence: [], created: t, updated: t };
    log(inc, "action", `Incident opened${o.origin ? " from " + o.origin : ""}`, t);
    if (o.playbook) apply(inc, o.playbook);
    if (o.iocs && o.iocs.length) addIocs(inc, o.iocs);
    return inc;
  }

  function apply(inc, pid) {
    const p = get(pid); if (!p) return 0;
    let n = 0;
    for (const [ph] of PHASES) for (const s of p.steps[ph] || []) if (!inc.tasks.some((x) => x.text === s)) { inc.tasks.push({ phase: ph, text: s, done: false }); n++; }
    inc.playbook = p.id;
    for (const a of p.attack) if (!inc.attack.includes(a)) inc.attack.push(a);
    if (sevRank(p.severity) < sevRank(inc.severity)) inc.severity = p.severity;
    log(inc, "action", `Playbook applied: ${p.name} (${n} tasks)`);
    return n;
  }

  function addIocs(inc, items) {
    let n = 0;
    for (const it of items || []) {
      const v = W.refang(String((it && it.value) != null ? it.value : it).trim());
      if (!v || inc.iocs.some((x) => x.value === v)) continue;
      inc.iocs.push({ value: v, type: (it && it.type) || W.detectType(v) || "other", note: (it && it.note) || "", added: now() });
      n++;
    }
    if (n) log(inc, "finding", `${n} indicator(s) added`);
    return n;
  }

  /** Pull indicator-looking tokens out of free text (refanged, typed, deduped). */
  function extractIocs(text) {
    const out = [];
    for (let tok of W.refang(String(text || "")).split(/[\s,;|<>()"'`]+/)) {
      tok = tok.replace(/^[[{]+|[\]}.:!?]+$/g, "");
      if (!tok) continue;
      const t = W.detectType(tok);
      if (t && !out.some((x) => x.value === tok)) out.push({ value: tok, type: t });
    }
    return out;
  }

  const mdEsc = (s) => String(s == null ? "" : s).replace(/([\\`*_[\]<>|])/g, "\\$1").replace(/\n/g, " ");

  function report(inc) {
    const done = inc.tasks.filter((t) => t.done).length;
    const pb = get(inc.playbook);
    const L = [`# ${mdEsc(inc.id)} — ${mdEsc(inc.title)}`, "",
      `| Field | Value |`, `|---|---|`,
      `| Severity | ${mdEsc(inc.severity)} |`, `| Status | ${mdEsc(inc.status)} |`,
      `| Phase | ${mdEsc((PHASES.find(([k]) => k === inc.phase) || [, inc.phase])[1])} |`,
      `| Owner | ${mdEsc(inc.owner || "—")} |`, `| Origin | ${mdEsc(inc.origin || "—")} |`,
      `| Playbook | ${mdEsc(pb ? pb.name : "—")} |`, `| Opened | ${mdEsc(inc.created)} |`, `| Updated | ${mdEsc(inc.updated)} |`,
      `| Tasks | ${done}/${inc.tasks.length} complete |`, "",
      "## Summary", "", inc.summary ? String(inc.summary) : "_No summary yet._", ""];
    L.push("## Response checklist (NIST SP 800-61)", "");
    for (const [k, n] of PHASES) {
      const ts = inc.tasks.filter((t) => t.phase === k);
      if (!ts.length) continue;
      L.push(`### ${n}`, "");
      for (const t of ts) L.push(`- [${t.done ? "x" : " "}] ${mdEsc(t.text)}${t.done && t.at ? ` _(done ${mdEsc(t.at)}${t.by ? " by " + mdEsc(t.by) : ""})_` : ""}`);
      L.push("");
    }
    L.push("## Indicators", "");
    if (inc.iocs.length) { L.push("| Type | Value (defanged) | Note |", "|---|---|---|"); for (const x of inc.iocs) L.push(`| ${mdEsc(x.type)} | \`${String(W.defang(x.value)).replace(/`/g, "'")}\` | ${mdEsc(x.note)} |`); }
    else L.push("_None recorded._");
    L.push("", "## ATT&CK techniques", "");
    L.push(inc.attack.length ? inc.attack.map((t) => `- ${mdEsc(t)}${TECHNIQUES[t] ? " — " + TECHNIQUES[t] : ""}`).join("\n") : "_None recorded._");
    if ((inc.evidence || []).length) {
      L.push("", "## Evidence", "", "| Name | Size | SHA-256 | Custody |", "|---|---|---|---|");
      for (const e of inc.evidence) L.push(`| ${mdEsc(e.name)} | ${e.size} | \`${mdEsc(e.sha256)}\` | ${(e.custody || []).map((c) => mdEsc(`${c.t} ${c.action}${c.by ? " by " + c.by : ""}`)).join("; ")} |`);
    }
    if (inc.lessons) L.push("", "## Lessons learned", "", String(inc.lessons));
    L.push("", "## Timeline", "");
    for (const t of inc.timeline.slice().reverse()) L.push(`- \`${mdEsc(t.t)}\` **${mdEsc(String(t.kind).toUpperCase())}** ${mdEsc(t.text)}`);
    L.push("", `_Generated by Wakizashi (Yoroi · Respond) on ${now()}. Indicators are defanged._`, "");
    return L.join("\n");
  }

  W.eng.playbooks = { PHASES, PLAYBOOKS, SEVS, STATUSES, TECHNIQUES, TOOL_LINKS, get, newIncident, apply, addIocs, extractIocs, log, report, nextId };
})(typeof window !== "undefined" ? window.W : globalThis.W);
