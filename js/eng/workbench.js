/* Enrichment workbench (port of katana/cti/workbench.py): from a threat report →
   IOCs + host artifacts, ATT&CK mapping (labelled vs inferred), attribution, drafted Sigma + YARA with
   false-positive risk, an enriched STIX 2.1 bundle and a ready-made case. */
(function (W) {
  "use strict";

  const ATTACK = {
    "T1566.001": ["Spearphishing Attachment", "Initial Access"], "T1566.002": ["Spearphishing Link", "Initial Access"],
    "T1190": ["Exploit Public-Facing Application", "Initial Access"], "T1133": ["External Remote Services", "Initial Access"], "T1078": ["Valid Accounts", "Initial Access"],
    "T1189": ["Drive-by Compromise", "Initial Access"], "T1195.002": ["Compromise Software Supply Chain", "Initial Access"],
    "T1204.002": ["User Execution: Malicious File", "Execution"], "T1204.001": ["User Execution: Malicious Link", "Execution"],
    "T1059.001": ["PowerShell", "Execution"], "T1059.003": ["Windows Command Shell", "Execution"], "T1059.004": ["Unix Shell", "Execution"],
    "T1059.005": ["Visual Basic", "Execution"], "T1059.007": ["JavaScript", "Execution"], "T1047": ["Windows Management Instrumentation", "Execution"],
    "T1053.005": ["Scheduled Task", "Persistence"], "T1053.003": ["Cron", "Persistence"], "T1547.001": ["Registry Run Keys / Startup Folder", "Persistence"],
    "T1543.003": ["Windows Service", "Persistence"], "T1574.002": ["DLL Side-Loading", "Persistence"], "T1136": ["Create Account", "Persistence"], "T1505.003": ["Web Shell", "Persistence"],
    "T1055": ["Process Injection", "Defense Evasion"], "T1027": ["Obfuscated Files or Information", "Defense Evasion"], "T1140": ["Deobfuscate/Decode Files or Information", "Defense Evasion"],
    "T1112": ["Modify Registry", "Defense Evasion"], "T1070.004": ["File Deletion", "Defense Evasion"], "T1070.001": ["Clear Windows Event Logs", "Defense Evasion"],
    "T1218.011": ["Rundll32", "Defense Evasion"], "T1218.005": ["Mshta", "Defense Evasion"], "T1218.010": ["Regsvr32", "Defense Evasion"], "T1497": ["Virtualization/Sandbox Evasion", "Defense Evasion"],
    "T1562.001": ["Disable or Modify Tools", "Defense Evasion"], "T1036": ["Masquerading", "Defense Evasion"],
    "T1003.001": ["LSASS Memory", "Credential Access"], "T1003": ["OS Credential Dumping", "Credential Access"], "T1552.001": ["Credentials In Files", "Credential Access"],
    "T1110": ["Brute Force", "Credential Access"], "T1555.003": ["Credentials from Web Browsers", "Credential Access"], "T1056.001": ["Keylogging", "Collection"],
    "T1082": ["System Information Discovery", "Discovery"], "T1057": ["Process Discovery", "Discovery"], "T1016": ["System Network Configuration Discovery", "Discovery"],
    "T1033": ["System Owner/User Discovery", "Discovery"], "T1087": ["Account Discovery", "Discovery"], "T1018": ["Remote System Discovery", "Discovery"], "T1046": ["Network Service Discovery", "Discovery"],
    "T1021.001": ["Remote Desktop Protocol", "Lateral Movement"], "T1021.002": ["SMB/Windows Admin Shares", "Lateral Movement"], "T1570": ["Lateral Tool Transfer", "Lateral Movement"],
    "T1113": ["Screen Capture", "Collection"], "T1560": ["Archive Collected Data", "Collection"], "T1005": ["Data from Local System", "Collection"],
    "T1071.001": ["Application Layer Protocol: Web", "Command and Control"], "T1071.004": ["DNS", "Command and Control"], "T1105": ["Ingress Tool Transfer", "Command and Control"],
    "T1573": ["Encrypted Channel", "Command and Control"], "T1572": ["Protocol Tunneling", "Command and Control"], "T1090": ["Proxy", "Command and Control"], "T1219": ["Remote Access Software", "Command and Control"],
    "T1041": ["Exfiltration Over C2 Channel", "Exfiltration"], "T1567.002": ["Exfiltration to Cloud Storage", "Exfiltration"],
    "T1486": ["Data Encrypted for Impact", "Impact"], "T1490": ["Inhibit System Recovery", "Impact"], "T1485": ["Data Destruction", "Impact"], "T1489": ["Service Stop", "Impact"],
  };
  const TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
  const KW = [
    ["spearphishing attachment|malicious attachment|weaponi[sz]ed (doc|attachment)", "T1566.001"],
    ["spearphishing link|phishing link|malicious (url|link)", "T1566.002"],
    ["exploit(s|ed|ing)? (a )?public[- ]facing|exploited? CVE|n-day|0-?day", "T1190"],
    ["\\bvpn\\b.*(access|credential)|remote access service|citrix|rdp gateway", "T1133"],
    ["valid accounts|stolen credentials|compromised (credentials|accounts)", "T1078"],
    ["watering hole|drive-by", "T1189"], ["supply[- ]chain", "T1195.002"],
    ["user (opens|executes|double-?clicks)|lure|decoy document", "T1204.002"],
    ["\\bpowershell\\b|\\bpwsh\\b|-enc |-encodedcommand", "T1059.001"],
    ["cmd\\.exe|cmd /c|command shell", "T1059.003"], ["/bin/(ba)?sh|bash -c|shell script", "T1059.004"],
    ["vbscript|\\.vbs\\b|wscript|cscript", "T1059.005"], ["javascript dropper|\\.js(e)? (file|dropper|loader)|jscript", "T1059.007"],
    ["\\bwmi\\b|wmic|win32_process|management instrumentation", "T1047"],
    ["scheduled task|schtasks|task scheduler", "T1053.005"], ["\\bcron(tab)?\\b", "T1053.003"],
    ["run key|currentversion\\\\run|registry run|startup folder", "T1547.001"],
    ["\\bsc create\\b|new (windows )?service|installs? a service", "T1543.003"],
    ["dll side-?load|side-?loading|search[- ]order hijack", "T1574.002"],
    ["creates? (a )?(new |local |admin(istrator)? )?(user|account)|net user .* /add", "T1136"],
    ["web ?shell", "T1505.003"],
    ["process injection|inject(ed|s)? into|process hollowing|reflective (dll|load)", "T1055"],
    ["obfuscat|packed binary|encoded (command|payload)|xor[- ]encod|base64", "T1027"],
    ["deobfuscat|decodes? the payload|decrypts? the (payload|config)", "T1140"],
    ["modif(y|ies) the registry|sets? a registry value", "T1112"],
    ["delete(s|d)? (itself|logs|shadow)|self-delete", "T1070.004"], ["wevtutil cl|clear(s|ed)? (the )?event logs?", "T1070.001"],
    ["\\brundll32\\b", "T1218.011"], ["\\bmshta\\b", "T1218.005"], ["\\bregsvr32\\b", "T1218.010"],
    ["sandbox evasion|anti-vm|anti-sandbox|checks? for (a )?(vm|sandbox)", "T1497"],
    ["disables? (windows )?defender|tamper protection|kills? (av|antivirus|edr)", "T1562.001"],
    ["masquerad|disguised as|renamed to look like", "T1036"],
    ["\\blsass\\b", "T1003.001"], ["mimikatz|credential dump|dump(s|ing)? credentials", "T1003"],
    ["password (spray|brute)|brute[- ]?forc", "T1110"], ["browser (credentials|passwords|cookies)|login data", "T1555.003"],
    ["keylog", "T1056.001"],
    ["systeminfo|system information", "T1082"], ["tasklist|enumerate(s)? processes", "T1057"],
    ["ipconfig|network configuration", "T1016"], ["\\bwhoami\\b", "T1033"], ["net (user|group)|account discovery|adfind", "T1087"],
    ["net view|remote system discovery|ping sweep", "T1018"], ["port scan|network scan|nmap|masscan", "T1046"],
    ["\\brdp\\b|remote desktop|:3389", "T1021.001"], ["\\bsmb\\b|admin\\$|\\bc\\$|psexec|:445", "T1021.002"],
    ["lateral tool transfer|copies? (the )?tool|copies? itself to", "T1570"],
    ["screenshot|screen capture", "T1113"], ["\\b(rar|7z|zip)s? (the )?(data|files)|archiv(es|ed) (the )?(data|files)", "T1560"],
    ["https? (c2|beacon)|web protocol c2|http(s)? beacon", "T1071.001"],
    ["dns (c2|tunnel|beacon)|dns-over", "T1071.004"],
    ["ingress tool|downloads? (a|the|and runs?) (payload|file|tool)|certutil|bitsadmin", "T1105"],
    ["encrypted (channel|c2)|tls c2", "T1573"], ["protocol tunnel|socks proxy|tunnel(s|ing)? traffic|ngrok|cloudflared", "T1572"],
    ["anydesk|teamviewer|screenconnect|atera|splashtop|remote (monitoring|management) tool", "T1219"],
    ["exfiltrat.* over (the )?c2", "T1041"], ["exfiltrat.*(mega|dropbox|cloud storage|s3)|rclone", "T1567.002"],
    ["ransomware|encrypts? (the )?files|data encrypted for impact", "T1486"],
    ["vssadmin|shadow cop(y|ies)|bcdedit|inhibit.*recovery", "T1490"], ["wiper|wipes? (the )?(disk|data)", "T1485"],
    ["stops? (the )?services?|net stop|taskkill", "T1489"],
  ].map(([p, id]) => [new RegExp(p, "i"), id]);
  const TID_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

  function attack(text) {
    const labeled = [...new Set(String(text).match(TID_RE) || [])].map((t) => t.toUpperCase()).sort();
    const out = [], seen = new Set();
    for (const id of labeled) { const [name, tactic] = ATTACK[id] || ["(see MITRE ATT&CK)", ""]; out.push({ id, name, tactic, inferred: false }); seen.add(id); }
    for (const [rx, id] of KW) {
      if (seen.has(id)) continue;
      const m = rx.exec(text);
      if (m) { const [name, tactic] = ATTACK[id] || [id, ""]; out.push({ id, name, tactic, inferred: true, evidence: m[0].slice(0, 50) }); seen.add(id); }
    }
    out.sort((a, b) => (a.inferred - b.inferred) || a.id.localeCompare(b.id));
    return out;
  }

  const ACTORS = {
    "apt28": "APT28 (Fancy Bear)", "fancy bear": "APT28 (Fancy Bear)", "sofacy": "APT28 (Fancy Bear)", "sednit": "APT28 (Fancy Bear)", "forest blizzard": "APT28 (Fancy Bear)",
    "apt29": "APT29 (Cozy Bear)", "cozy bear": "APT29 (Cozy Bear)", "nobelium": "APT29 (Cozy Bear)", "midnight blizzard": "APT29 (Cozy Bear)",
    "lazarus": "Lazarus Group", "hidden cobra": "Lazarus Group", "apt38": "APT38 (Lazarus)", "kimsuky": "Kimsuky", "andariel": "Andariel",
    "fin7": "FIN7", "carbanak": "FIN7 / Carbanak", "fin11": "FIN11", "fin8": "FIN8",
    "conti": "Conti", "lockbit": "LockBit", "alphv": "ALPHV / BlackCat", "blackcat": "ALPHV / BlackCat", "revil": "REvil / Sodinokibi", "clop": "Cl0p", "cl0p": "Cl0p",
    "black basta": "Black Basta", "royal ransomware": "Royal", "akira": "Akira", "play ransomware": "Play", "rhysida": "Rhysida", "8base": "8Base", "medusa": "Medusa", "blacksuit": "BlackSuit",
    "sandworm": "Sandworm", "seashell blizzard": "Sandworm", "turla": "Turla", "gamaredon": "Gamaredon", "apt41": "APT41 (Winnti)", "winnti": "APT41 (Winnti)", "apt10": "APT10 (Stone Panda)",
    "mustang panda": "Mustang Panda", "volt typhoon": "Volt Typhoon", "salt typhoon": "Salt Typhoon", "silk typhoon": "Silk Typhoon (Hafnium)", "hafnium": "Silk Typhoon (Hafnium)",
    "ta505": "TA505", "ta551": "TA551", "ta577": "TA577", "wizard spider": "Wizard Spider", "scattered spider": "Scattered Spider", "lapsus": "LAPSUS$",
    "charming kitten": "APT35 (Charming Kitten)", "apt35": "APT35 (Charming Kitten)", "apt33": "APT33 (Elfin)", "apt34": "APT34 (OilRig)", "oilrig": "APT34 (OilRig)", "muddywater": "MuddyWater",
    "evil corp": "Evil Corp", "darkside": "DarkSide", "storm-0558": "Storm-0558",
  };
  const ACTOR_RE = /\b(?:APT[- ]?\d{1,3}|FIN\d{1,2}|UNC\d{3,5}|TA\d{3,4}|Storm-\d{3,4}|DEV-\d{3,4})\b/gi;
  const MALWARE = ["cobalt strike", "emotet", "qakbot", "qbot", "trickbot", "icedid", "bumblebee", "gootloader", "raspberry robin", "brute ratel", "sliver", "havoc",
    "plugx", "shadowpad", "agent tesla", "remcos", "asyncrat", "njrat", "quasar", "formbook", "redline", "vidar", "lumma", "stealc", "raccoon", "socgholish", "darkgate",
    "pikabot", "latrodectus", "metasploit", "mimikatz", "impacket", "rclone", "anydesk", "screenconnect", "systembc", "ursnif", "dridex", "netsupport"];

  function attribution(text) {
    const low = String(text).toLowerCase(), actors = [], seen = new Set();
    for (const [alias, canon] of Object.entries(ACTORS)) if (new RegExp("\\b" + alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b").test(low) && !seen.has(canon)) { actors.push(canon); seen.add(canon); }
    for (const m of String(text).match(ACTOR_RE) || []) {
      const norm = m.toUpperCase().replace(/[\s-]/g, "");
      if ([...seen].some((a) => a.toUpperCase().replace(/[\s-]/g, "").includes(norm))) continue;
      const name = m.replace(/^apt[- ]/i, "APT").toUpperCase().replace(/^STORM/, "Storm").replace(/^DEV/, "DEV");
      actors.push(name); seen.add(name);
    }
    const malware = MALWARE.filter((m) => new RegExp("\\b" + m.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b").test(low)).sort();
    const note = actors.length ? "Named in the report: " + actors.slice(0, 6).join(", ")
      : malware.length ? `No named actor; tooling seen (${malware.slice(0, 4).join(", ")}) may help cluster it` : "No named threat actor or known tooling detected — treat as unattributed";
    return { actors: actors.slice(0, 6), malware: malware.slice(0, 10), note };
  }

  const HASH_RE = /^[0-9a-fA-F]{32,128}$/, IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/, DOM_RE = /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i;
  function fpRisk(values) {
    const vals = values.filter(Boolean);
    if (!vals.length) return { level: "high", indicators: 0, reasons: ["no indicators — the rule would match nothing or everything"] };
    const specific = vals.filter((v) => HASH_RE.test(v) || v.endsWith(".onion") || v.includes("\\") || v.length >= 16).length;
    const medium = vals.filter((v) => IP_RE.test(v) || DOM_RE.test(v)).length;
    if (specific) return { level: "low", indicators: vals.length, reasons: [`${specific} highly-distinctive indicator(s) (hash / mutex / path / .onion) — attacker-chosen, rarely collide`] };
    if (medium >= 2) return { level: "medium", indicators: vals.length, reasons: ["only network indicators (IPs / domains) — these rotate and can be shared/CDN-hosted, so expect some noise"] };
    return { level: "high", indicators: vals.length, reasons: ["only short or generic tokens — this will match broadly; tighten it before deploying"] };
  }
  const yq = (v) => "'" + String(v).replace(/'/g, "''") + "'";
  function draftSigma(title, net, hashes, host, techniques) {
    const tags = ["    - attack.command_and_control"].concat((techniques || []).slice(0, 8).map((t) => "    - attack." + t.id.toLowerCase()));
    const L = [`title: ${String(title).replace(/[\r\n:]+/g, " ").slice(0, 120)}`, `id: wakizashi-${W.uid()}`, "status: experimental",
      "description: Auto-drafted from a threat report by Wakizashi. Review and tune before deploying.", "tags:", ...tags, "logsource:", "    category: any", "detection:"];
    const conds = [];
    const sel = (name, field, vals) => { if (!vals.length) return; L.push(`    ${name}:`, `        ${field}|contains:`, ...vals.map((v) => `            - ${yq(v)}`)); conds.push(name); };
    sel("selection_network", "message", net); sel("selection_files", "message", hashes); sel("selection_host", "CommandLine", host);
    if (!conds.length) { L.push("    selection_network:", "        message|contains:", "            - 'REPLACE-ME'"); conds.push("selection_network"); }
    L.push("    condition: " + conds.join(" or "));
    const rule = L.join("\n") + "\n";
    let valid = true, errors = [];
    if (W.eng.sigma) { const c = W.eng.sigma.compile(rule); valid = c.rules.length > 0 && !c.errors.length; errors = c.errors; }
    return { rule, valid, errors, fp: fpRisk(net.concat(hashes, host)), counts: { network: net.length, hashes: hashes.length, host: host.length } };
  }

  function title(text) {
    for (const line of String(text).split(/\r?\n/)) { const l = line.replace(/^[\s#*\-]+|[\s#*\-]+$/g, ""); if (l.length >= 6) return l.slice(0, 70); }
    return "Threat report indicators";
  }

  /** enrich({text, title?, tlp?, source?}) → full workbench result (async: STIX ids use SHA-1). */
  async function enrich(opts) {
    const text = String(opts.text || "").slice(0, 400000);
    if (!text.trim()) throw new Error("paste a threat report, or fetch a CTI article, to work from");
    const ttl = (opts.title || "").trim() || title(text);
    const iocs = W.eng.ioc.extract(text, { includePrivate: false });
    const arts = W.eng.ioc.artifacts(text);
    const net = ["domain", "ipv4", "ipv6", "url", "email"].flatMap((k) => (iocs[k] || []).slice(0, 20));
    const hashes = ["sha256", "sha1", "md5"].flatMap((k) => (iocs[k] || []).slice(0, 10));
    const host = arts.groups.filter((g) => ["mutex", "pipe", "service", "registry", "useragent", "pdb"].includes(g.kind)).flatMap((g) => g.items.slice(0, 10));
    const atk = attack(text), attr = attribution(text);
    const sigma = draftSigma(ttl, net, hashes, host, atk);
    const yara = W.eng.yaragen.fromIocs(text);
    // host artifacts make the YARA rule far more specific — fold the best ones in
    if (host.length) {
      const extra = host.slice(0, 12).map((v, i) => ({ id: `$h${i + 1}`, type: "text", value: v, modifiers: ["ascii", "wide"] }));
      const spec = Object.assign({}, yara.spec, { strings: (yara.spec.strings || []).concat(extra) });
      Object.assign(yara, W.eng.yaragen.generate(spec));
    }
    yara.fp = fpRisk(net.concat(hashes, arts.groups.flatMap((g) => g.items)));
    const items = W.eng.ioc.toItems(iocs, { verdict: "malicious" }).filter((x) => ["url", "domain", "ipv4", "ipv6", "email", "md5", "sha1", "sha256", "sha512", "cve"].includes(x.type))
      .map((x) => (x.type === "cve" ? Object.assign(x, { verdict: "suspicious" }) : x));
    const actor = attr.actors[0] || null;
    const tlp = opts.tlp || "amber";
    const built = await W.eng.stix.enriched(items, atk.map((t) => ({ id: t.id, name: t.name })), actor, { tlp, producer: "Wakizashi" });
    const labeled = atk.filter((t) => !t.inferred), inferred = atk.filter((t) => t.inferred);
    const notes = [
      "Source: " + (opts.source || "pasted report"),
      "Attribution — " + attr.note,
      attr.malware.length ? "Tooling / malware: " + attr.malware.join(", ") : null,
      `ATT&CK: ${labeled.length} technique(s) already labelled, ${inferred.length} inferred from described behaviour.`,
      inferred.length ? "Newly mapped (inferred): " + inferred.slice(0, 12).map((t) => `${t.id} ${t.name}`).join(", ") : null,
      `Signatures drafted — Sigma (${sigma.fp.level} FP risk), YARA (${yara.fp.level} FP risk).`,
    ].filter(Boolean);
    const prefix = actor && !ttl.toLowerCase().includes(actor.toLowerCase()) ? actor + " — " : "";
    return {
      title: ttl, source: opts.source || null, iocs, artifacts: arts.groups, sigma, yara,
      attack: { labeled, inferred, all: atk, tactics: TACTIC_ORDER.map((t) => [t, atk.filter((x) => x.tactic === t)]).filter(([, v]) => v.length) },
      attribution: attr,
      stix: { bundle: built.bundle, json: JSON.stringify(built.bundle, null, 2), stats: built.stats, filename: W.eng.stix.filename("wakizashi-enriched"), tlp },
      case: { name: (prefix + ttl).slice(0, 80), items, notes, tags: attr.actors.concat(attr.malware.slice(0, 4)) },
      summary: { network: net.length, hashes: hashes.length, host_artifacts: host.length, techniques: atk.length, labeled: labeled.length, inferred: inferred.length, actors: attr.actors.length, indicators: items.length },
    };
  }

  /** Best-effort article text from HTML (no DOM — works in Node too). */
  function stripHtml(h) {
    h = String(h).replace(/<(script|style|noscript|template|svg|head)\b[\s\S]*?<\/\1>/gi, " ").replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|li|h[1-6]|tr|section|article|pre)>/gi, "\n").replace(/<[^>]+>/g, " ");
    h = h.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'")
      .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n)).replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)));
    return h.replace(/[ \t ]+/g, " ").replace(/\n[ \t]*\n[ \t]*\n+/g, "\n\n").trim();
  }

  W.eng.workbench = { enrich, attack, attribution, draftSigma, fpRisk, stripHtml, title, ATTACK, TACTIC_ORDER };
})(typeof window !== "undefined" ? window.W : globalThis.W);
