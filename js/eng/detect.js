/* Yoroi built-in behavioural detections — W.eng.detect. Port of Katana's defense/detect.py.
 * Runs over normalised events from W.eng.logs.parse and returns findings:
 *   {rule, name, severity, attack:[technique ids], title, detail, events:[event i], count, entities:{ip:[],user:[],host:[]}}
 *
 *   W.eng.detect.run(events, thresholds?, disabled?)   → findings (sorted: severity, then count)
 *   W.eng.detect.catalog()                              → [{id, name, severity, attack, desc}]
 *   W.eng.detect.DEFAULTS                               → default thresholds
 */
(function (W) {
  "use strict";

  const DEFAULTS = {
    brute_count: 10,        // failed logons from one source…
    brute_window_min: 10,   // …inside this many minutes
    spray_users: 5,         // distinct accounts failed by one source
    scan_404: 30,           // 404s from one client = content discovery
    business_start: 7,
    business_end: 19,
  };
  const THRESHOLD_HELP = {
    brute_count: "Failed logons from one source that count as brute force",
    brute_window_min: "…inside this many minutes",
    spray_users: "Distinct accounts failed by one source = password spray",
    scan_404: "404s from one client = content discovery",
    business_start: "Business hours start (hour, 0–23)",
    business_end: "Business hours end (hour, 0–23)",
  };
  const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const DETECTIONS = [];
  const L = () => W.eng.logs;

  function detection(id, name, severity, attack, desc, fn) { DETECTIONS.push({ id, name, severity, attack, desc, fn }); }
  function finding(d, title, events, detail, opts = {}) {
    const uniq = [...new Set(events)].sort((a, b) => a - b);
    return { rule: d.id, name: d.name, severity: opts.severity || d.severity, attack: opts.attack || d.attack,
      title, detail: detail || "", events: uniq.slice(0, 300), count: uniq.length, entities: opts.entities || {} };
  }
  const one = (v) => (v ? [v] : []);
  const ms = (e) => L().toMs(e.ts);
  const group = () => new Map();
  const push = (m, k, v) => { let a = m.get(k); if (!a) m.set(k, (a = [])); a.push(v); return a; };
  const fget = (e, k) => { const v = e.fields[k]; return v == null ? "" : String(v); };

  function cmd(e) {
    const f = e.fields;
    let c = f.CommandLine || f.ScriptBlockText || "";
    if (!c && (e.fmt === "syslog" || e.fmt === "text")) c = e.msg;
    return String(c);
  }
  const image = (e) => String(e.fields.Image || e.fields.NewProcessName || "").toLowerCase();
  const parent = (e) => String(e.fields.ParentImage || e.fields.ParentProcessName || "").toLowerCase();

  /** items: sorted [[ms, idx, extra]] → densest run inside any sliding window */
  function byWindow(items, windowS) {
    let best = [], j = 0;
    for (let i = 0; i < items.length; i++) {
      while (items[i][0] != null && items[j][0] != null && (items[i][0] - items[j][0]) / 1000 > windowS) j++;
      if (i - j + 1 > best.length) best = items.slice(j, i + 1);
    }
    return best;
  }
  const byTime = (a, b) => (a[0] == null) - (b[0] == null) || (a[0] || 0) - (b[0] || 0);
  const list = (arr, n) => arr.slice(0, n).join(", ") + (arr.length > n ? " …" : "");

  // ------------------------------------------------------------------ authentication
  detection("AG-AUTH-001", "Brute force", "high", ["T1110.001"], "Many failed logons from one source inside a short window.", (evs, th, d, out) => {
    const fails = group();
    for (const e of evs) if (e.action === "auth_fail" && e.ip) push(fails, e.ip, [ms(e), e.i, e.user]);
    for (const [ip, items] of fails) {
      items.sort(byTime);
      const timed = items.filter((x) => x[0] != null);
      const win = timed.length ? byWindow(timed, th.brute_window_min * 60) : items;
      if (win.length >= th.brute_count) {
        const users = [...new Set(items.map((x) => x[2]).filter(Boolean))].sort();
        out.push(finding(d, `${items.length} failed logons from ${ip}`, items.map((x) => x[1]),
          `Peak: ${win.length} failures within ${th.brute_window_min} min. Accounts tried: ${list(users, 12)}`,
          { entities: { ip: [ip], user: users.slice(0, 50) } }));
      }
    }
  });

  detection("AG-AUTH-002", "Password spraying", "high", ["T1110.003"], "One source fails against many different accounts.", (evs, th, d, out) => {
    const by = group();
    for (const e of evs) if (e.action === "auth_fail" && e.ip && e.user) {
      let u = by.get(e.ip); if (!u) by.set(e.ip, (u = group()));
      push(u, e.user.toLowerCase(), e.i);
    }
    for (const [ip, users] of by) if (users.size >= th.spray_users) {
      const names = [...users.keys()].sort();
      out.push(finding(d, `${ip} tried ${users.size} different accounts`, [...users.values()].flat(), "Accounts: " + names.slice(0, 20).join(", "),
        { entities: { ip: [ip], user: names.slice(0, 50) } }));
    }
  });

  detection("AG-AUTH-003", "Successful logon after brute force", "critical", ["T1110", "T1078"],
    "A source that failed repeatedly then logged on successfully: likely compromised credentials.", (evs, th, d, out) => {
      const fails = group();
      for (const e of evs) {
        if (!e.ip) continue;
        if (e.action === "auth_fail") push(fails, e.ip, e.i);
        else if (e.action === "auth_ok" && (fails.get(e.ip) || []).length >= Math.max(5, Math.floor(th.brute_count / 2))) {
          const f = fails.get(e.ip);
          out.push(finding(d, `${e.user || "account"} logged on from ${e.ip} after ${f.length} failures`, f.slice(-50).concat([e.i]),
            "Treat the account as compromised until proven otherwise.", { entities: { ip: [e.ip], user: one(e.user) } }));
          fails.set(e.ip, []);
        }
      }
    });

  detection("AG-AUTH-004", "Root / Administrator remote logon", "medium", ["T1078.003"],
    "Direct interactive logon with a built-in superuser account over the network.", (evs, th, d, out) => {
      const hits = group();
      for (const e of evs) if (e.action === "auth_ok" && ["root", "administrator", "admin"].includes((e.user || "").toLowerCase()) && e.ip && e.ip !== "127.0.0.1" && e.ip !== "::1")
        push(hits, e.user + "\u0000" + e.ip, e.i);
      for (const [k, idx] of hits) {
        const [u, ip] = k.split("\u0000");
        out.push(finding(d, `${u} logged on remotely from ${ip}`, idx, "Disable direct superuser logons; use named accounts + sudo/UAC.", { entities: { ip: [ip], user: [u] } }));
      }
    });

  detection("AG-AUTH-005", "Possible impossible travel", "medium", ["T1078"],
    "Same account logs on from different public networks within an hour (offline heuristic; geo check optional).", (evs, th, d, out) => {
      const by = group();
      for (const e of evs) if (e.action === "auth_ok" && e.user && e.ts && L().isPublic(e.ip)) push(by, e.user.toLowerCase(), [ms(e), e.ip, e.i]);
      for (const [u, items] of by) {
        items.sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) || a[2] - b[2]);
        for (let k = 0; k + 1 < items.length; k++) {
          const a = items[k], b = items[k + 1];
          if (a[0] != null && b[0] != null && a[1] !== b[1] && (b[0] - a[0]) / 1000 <= 3600) {
            const na = L().parseCidr(a[1] + (a[1].includes(":") ? "/32" : "/16"));
            if (!L().inCidr(b[1], na)) {
              out.push(finding(d, `${u}: ${a[1]} → ${b[1]} in ${Math.floor((b[0] - a[0]) / 60000)} min`, [a[2], b[2]],
                "Different /16 networks. Geolocate both IPs to confirm.", { entities: { user: [u], ip: [a[1], b[1]] } }));
              break;
            }
          }
        }
      }
    });

  detection("AG-AUTH-006", "Logon outside business hours", "low", ["T1078"], "Successful logons outside the configured business hours.", (evs, th, d, out) => {
    const by = group(), s = th.business_start, en = th.business_end;
    for (const e of evs) if (e.action === "auth_ok" && e.ts) {
      const t = ms(e); if (t == null) continue;
      const dt = new Date(t), h = dt.getUTCHours(), wd = dt.getUTCDay();
      if (h < s || h >= en || wd === 0 || wd === 6) push(by, e.user || "?", e.i);
    }
    for (const [u, idx] of by) out.push(finding(d, `${u}: ${idx.length} off-hours logon(s)`, idx,
      `Business hours are ${String(s).padStart(2, "0")}:00-${String(en).padStart(2, "0")}:00 Mon-Fri.`, { entities: { user: [u] } }));
  });

  detection("AG-AUTH-007", "Account lockouts", "medium", ["T1110"], "Accounts were locked out (Windows 4740).", (evs, th, d, out) => {
    const idx = evs.filter((e) => e.action === "lockout").map((e) => e.i);
    if (idx.length) {
      const users = [...new Set(idx.map((i) => evs[i].user).filter(Boolean))].sort();
      out.push(finding(d, `${idx.length} lockout event(s)`, idx, "Accounts: " + users.slice(0, 20).join(", "), { entities: { user: users } }));
    }
  });

  detection("AG-AUTH-008", "Kerberoasting (RC4 service tickets)", "high", ["T1558.003"], "Many TGS requests with RC4 encryption (0x17) from one account.", (evs, th, d, out) => {
    const by = group();
    for (const e of evs) if (e.eid === "4769" && ["0x17", "23"].includes(fget(e, "TicketEncryptionType").toLowerCase()) && !fget(e, "ServiceName").endsWith("$"))
      push(by, e.user || "?", e.i);
    for (const [u, idx] of by) if (idx.length >= 3) out.push(finding(d, `${u} requested ${idx.length} RC4 service tickets`, idx, "", { entities: { user: [u] } }));
  });

  // ------------------------------------------------------------------ accounts & privileges
  const ADMIN_GROUPS = /\b(sudo|wheel|admin|adm|root|administrators|domain admins|enterprise admins|schema admins|backup operators|account operators|remote desktop users)\b/i;

  detection("AG-ACCT-001", "New account created", "medium", ["T1136"], "A local, domain or cloud account was created.", (evs, th, d, out) => {
    for (const e of evs) if (e.action === "user_add")
      out.push(finding(d, `Account created: ${e.user || "?"}`, [e.i], `Host ${e.host || "?"} via ${e.src || e.eid}`, { entities: { user: one(e.user) } }));
  });

  detection("AG-ACCT-002", "Added to privileged group", "high", ["T1098"], "An account was added to an administrative group.", (evs, th, d, out) => {
    for (const e of evs) {
      if (e.action !== "group_add") continue;
      const f = e.fields;
      const grp = String(f.group || f.TargetUserName || f.GroupName || f["requestParameters.groupName"] || "");
      out.push(finding(d, `${e.user || "?"} added to group ${grp || "?"}`, [e.i], "", { severity: ADMIN_GROUPS.test(grp) ? "high" : "medium", entities: { user: one(e.user) } }));
    }
  });

  const SUDO_RX = /(\/bin\/(ba|z|k|da)?sh\b|\bsu\b|\/etc\/(sudoers|shadow|passwd)|visudo|chmod\s+[0-7]*4[0-7]{3}|python\S*\s+-c|\bvi(m)?\b\s+\/etc\/)/i;
  detection("AG-ACCT-003", "Privilege escalation via sudo to root shell", "medium", ["T1548.003"], "sudo used to start an interactive shell or edit sensitive files.", (evs, th, d, out) => {
    for (const e of evs) if (e.action === "sudo" && SUDO_RX.test(fget(e, "CommandLine")))
      out.push(finding(d, `${e.user} ran: ${fget(e, "CommandLine").slice(0, 120)}`, [e.i], "", { entities: { user: one(e.user) } }));
  });

  // ------------------------------------------------------------------ defense evasion
  const CLEAR_RX = /(history\s+-c|rm\s+(-\w+\s+)*\S*(\.bash_history|\/var\/log\/)|wevtutil(\.exe)?\s+cl\b|Clear-EventLog|auditctl\s+-D|journalctl\s+--vacuum|shred\s+.*?\/var\/log|unset\s+HISTFILE|HISTSIZE=0)/i;
  detection("AG-EVA-001", "Audit log cleared or logging stopped", "high", ["T1070.001", "T1562.008"],
    "Security/System log cleared (1102/104), CloudTrail stopped/deleted, or shell history wiped.", (evs, th, d, out) => {
      for (const e of evs) {
        const c = cmd(e);
        if (e.action === "log_clear" || CLEAR_RX.test(c))
          out.push(finding(d, `${e.eid || "Command"}: ${(c || e.msg).slice(0, 120)}`, [e.i], `Host ${e.host || "?"} user ${e.user || "?"}`, { entities: { user: one(e.user) } }));
      }
    });

  const AV_RX = /(Set-MpPreference\s+.*-Disable\w+\s+\$?true|DisableRealtimeMonitoring|Add-MpPreference\s+-Exclusion|netsh\s+(adv)?firewall\s+set\s+\w*\s*(opmode|state)\s+(disable|off)|ufw\s+disable|systemctl\s+(stop|disable)\s+(auditd|falcon|sentinel|wazuh|osquery|firewalld|apparmor)|setenforce\s+0|sc\s+(stop|delete)\s+(windefend|sense|mpssvc)|tamperprotection)/i;
  detection("AG-EVA-002", "Security tooling tampered", "high", ["T1562.001"], "Defender/AV disabled, firewall turned off, or EDR services stopped.", (evs, th, d, out) => {
    for (const e of evs) { const c = cmd(e); if (e.action === "av_disabled" || AV_RX.test(c)) out.push(finding(d, (c || e.msg).slice(0, 140), [e.i], "", { entities: { user: one(e.user) } })); }
  });

  // ------------------------------------------------------------------ execution
  const RE_ENC = /(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{16,})/i;
  const RE_PS_SUS = /(FromBase64String|IEX\s*\(|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|iwr\s+http|Start-BitsTransfer|-w(indowstyle)?\s+h(idden)?|-nop\b|bypass|Reflection\.Assembly|VirtualAlloc|AmsiUtils|amsiInitFailed)/gi;

  /** Decode a PowerShell -EncodedCommand blob (UTF-16LE, or UTF-8 fallback). */
  function decodePs(b64) {
    try {
      const raw = W.fromB64(b64);
      if (!raw.length) return null;
      let txt = "";
      if (raw[1] === 0) { for (let i = 0; i + 1 < raw.length; i += 2) txt += String.fromCharCode(raw[i] | (raw[i + 1] << 8)); }
      else txt = W.utf8(raw);
      return txt.slice(0, 2000);
    } catch { return null; }
  }

  detection("AG-EXE-001", "Encoded / obfuscated PowerShell", "high", ["T1059.001", "T1027"],
    "PowerShell with -EncodedCommand, download cradles, AMSI bypass or hidden windows.", (evs, th, d, out) => {
      for (const e of evs) {
        const c = cmd(e), lc = c.toLowerCase();
        if (!c || (!lc.includes("powershell") && !lc.includes("pwsh") && e.eid !== "4104" && !image(e).includes("powershell"))) continue;
        const m = RE_ENC.exec(c);
        const sus = [...c.matchAll(RE_PS_SUS)].map((x) => x[1]);
        if (m || sus.length >= 1) {
          const dec = m ? decodePs(m[1]) : null;
          const detail = dec ? "Decoded: " + dec : "Indicators: " + [...new Set(sus)].sort().join(", ");
          out.push(finding(d, c.slice(0, 160), [e.i], detail, { severity: m || sus.length >= 2 ? "high" : "medium", entities: { user: one(e.user), host: one(e.host) } }));
        }
      }
    });

  const LOLBINS = [
    [/certutil(\.exe)?\s+.*(-urlcache|-decode|-encode|-verifyctl|-split)/i, "certutil download/decode", "T1105"],
    [/mshta(\.exe)?\s+.*(https?:|javascript:|vbscript:)/i, "mshta remote script", "T1218.005"],
    [/rundll32(\.exe)?\s+.*(javascript:|\\\\|https?:|,#\d|comsvcs)/i, "rundll32 abuse", "T1218.011"],
    [/regsvr32(\.exe)?\s+.*(\/i:\s*https?:|scrobj)/i, "regsvr32 squiblydoo", "T1218.010"],
    [/bitsadmin(\.exe)?\s+.*(\/transfer|\/addfile)/i, "bitsadmin download", "T1197"],
    [/wmic(\.exe)?\s+.*(process\s+call\s+create|\/node:)/i, "wmic remote/process exec", "T1047"],
    [/msiexec(\.exe)?\s+.*(\/q|\/i)\s*.*https?:/i, "msiexec remote package", "T1218.007"],
    [/(installutil|regasm|regsvcs)(\.exe)?\s+.*(\/u|\/logfile)/i, "installutil/regasm proxy", "T1218.004"],
    [/cmstp(\.exe)?\s+.*\/s/i, "cmstp proxy execution", "T1218.003"],
    [/(wscript|cscript)(\.exe)?\s+.*\.(js|jse|vbs|vbe|wsf)\b/i, "script host executing script", "T1059.005"],
    [/forfiles(\.exe)?\s+.*\/c/i, "forfiles indirect exec", "T1202"],
    [/(curl|wget)\s+.*\|\s*(ba|z)?sh\b/i, "curl|sh download and execute", "T1105"],
    [/(curl|wget)\s+.*(-o|-O)\s*\/(tmp|dev\/shm|var\/tmp)\//i, "download to temp dir", "T1105"],
    [/chmod\s+\+x\s+\/(tmp|dev\/shm|var\/tmp)\//i, "make temp file executable", "T1222.002"],
    [/(nc|ncat|netcat)(\.exe)?\s+.*-e\s+\S*(sh|cmd)/i, "netcat reverse shell", "T1059"],
    [/bash\s+-i\s+>&\s*\/dev\/tcp\/|\/dev\/tcp\/\d/i, "bash /dev/tcp reverse shell", "T1059.004"],
    [/python\d?\s+-c\s+.*(socket|pty\.spawn)/i, "python reverse shell", "T1059.006"],
    [/base64\s+(-d|--decode)\s*\|\s*(ba)?sh/i, "base64-decoded shell", "T1140"],
  ];
  detection("AG-EXE-002", "Living-off-the-land binary abuse", "high", ["T1218", "T1105"],
    "Signed system binaries or shell one-liners used to download, decode or proxy-execute payloads.", (evs, th, d, out) => {
      for (const e of evs) {
        const c = cmd(e); if (!c) continue;
        for (const [rx, label, tech] of LOLBINS) if (rx.test(c)) {
          out.push(finding(d, `${label}: ${c.slice(0, 140)}`, [e.i], "", { attack: [tech], entities: { user: one(e.user), host: one(e.host) } }));
          break;
        }
      }
    });

  const OFFICE = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "acrord32.exe", "acrobat.exe"];
  const SHELLS = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"];
  const base = (p) => p.split("\\").pop();
  detection("AG-EXE-003", "Office / PDF reader spawned a shell", "high", ["T1566.001", "T1204.002"],
    "Document application launched a command interpreter: classic malicious attachment behaviour.", (evs, th, d, out) => {
      for (const e of evs) {
        const p = parent(e), i = image(e);
        if (p && OFFICE.some((o) => p.endsWith(o)) && SHELLS.some((s) => i.endsWith(s)))
          out.push(finding(d, `${base(p)} → ${base(i)}`, [e.i], cmd(e).slice(0, 400), { entities: { host: one(e.host), user: one(e.user) } }));
      }
    });

  const ODD_PATH = /(\\users\\public\\|\\appdata\\local\\temp\\|\\windows\\temp\\|\\\$recycle\.bin\\|\\programdata\\[^\\]+\.exe|\\downloads\\[^\\]+\.(exe|scr|bat|cmd|ps1|vbs|js|hta)|^\/tmp\/|^\/dev\/shm\/|^\/var\/tmp\/)/i;
  detection("AG-EXE-004", "Execution from a suspicious path", "medium", ["T1036.005", "T1204"], "Processes started from temp, downloads, public or recycle-bin folders.", (evs, th, d, out) => {
    const by = group();
    for (const e of evs) if (e.action === "proc") { const img = image(e); if (ODD_PATH.test(img)) push(by, img, e.i); }
    for (const [img, idx] of by) out.push(finding(d, img, idx, "", { entities: {} }));
  });

  // ------------------------------------------------------------------ discovery / credential access / impact
  const RECON = /\b(whoami(\.exe)?\s*\/(all|priv|groups)|net(1)?(\.exe)?\s+(user|group|localgroup|accounts|view|share)\b|nltest(\.exe)?\s+\/(domain_trusts|dclist)|systeminfo|ipconfig\s+\/all|quser|qwinsta|arp\s+-a|route\s+print|netstat\s+-an|tasklist\s*\/v|dsquery|adfind|Get-AD(User|Computer|Group)|uname\s+-a|cat\s+\/etc\/(passwd|shadow|group)|id\s*$|getent\s+passwd|ps\s+aux|ss\s+-tulpn|crontab\s+-l)/i;
  detection("AG-DIS-001", "Discovery burst", "medium", ["T1087", "T1082", "T1016"], "Several reconnaissance commands run by one account in quick succession.", (evs, th, d, out) => {
    const by = group();
    for (const e of evs) { const c = cmd(e); const m = c && RECON.exec(c); if (m) push(by, JSON.stringify([e.host, e.user]), [ms(e), e.i, m[0]]); }
    for (const [k, items] of by) {
      const [h, u] = JSON.parse(k);
      items.sort(byTime);
      const timed = items.filter((x) => x[0] != null);
      const win = timed.length ? byWindow(timed, 600) : items;
      if (new Set(win.map((x) => x[2].toLowerCase())).size >= 3)
        out.push(finding(d, `${u || "?"}@${h || "?"}: ${win.length} recon commands in 10 min`, items.map((x) => x[1]),
          "Commands: " + [...new Set(win.map((x) => x[2]))].sort().slice(0, 12).join(", "), { entities: { user: one(u), host: one(h) } }));
    }
  });

  const CRED = /(sekurlsa|mimikatz|lsadump|procdump(64)?(\.exe)?\s+.*lsass|comsvcs(\.dll)?[, ]+#?\s*(24|minidump)|reg(\.exe)?\s+save\s+hklm\\(sam|security|system)|ntdsutil.*(ifm|snapshot)|vssadmin.*create\s+shadow|\\windows\\ntds\\ntds\.dit|lazagne|rubeus|kerberoast|secretsdump|\/etc\/shadow|unshadow|Invoke-Mimikatz|Get-GPPPassword|findstr\s+.*(cpassword|password))/i;
  detection("AG-CRD-001", "Credential dumping", "critical", ["T1003"], "LSASS memory dumps, SAM/NTDS extraction or known credential-theft tooling.", (evs, th, d, out) => {
    for (const e of evs) {
      const c = cmd(e), tgt = fget(e, "TargetImage").toLowerCase();
      if ((c && CRED.test(c)) || (e.action === "proc_access" && tgt.endsWith("lsass.exe") && ["0x1010", "0x1fffff", "0x1410", "0x143a"].includes(fget(e, "GrantedAccess").toLowerCase())))
        out.push(finding(d, (c || `LSASS access by ${image(e) || fget(e, "SourceImage")}`).slice(0, 160), [e.i], "", { entities: { host: one(e.host), user: one(e.user) } }));
    }
  });

  const IMPACT = /(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|Get-WmiObject\s+Win32_Shadowcopy.*Delete|cipher(\.exe)?\s+\/w|(rm|shred)\s+-[rf]+\s+\/(\s|$|\*)|dd\s+if=\/dev\/(zero|urandom)\s+of=\/dev\/(sd|nvme|xvd))/i;
  detection("AG-IMP-001", "Ransomware precursor: recovery inhibited", "critical", ["T1490", "T1485"], "Shadow copies or backups deleted, boot recovery disabled, or disks wiped.", (evs, th, d, out) => {
    for (const e of evs) { const c = cmd(e); if (c && IMPACT.test(c)) out.push(finding(d, c.slice(0, 160), [e.i], "Isolate the host immediately. This commonly precedes encryption.", { entities: { host: one(e.host), user: one(e.user) } })); }
  });

  // ------------------------------------------------------------------ persistence
  const PERSIST = [
    [/schtasks(\.exe)?\s+\/create/i, "Scheduled task created", "T1053.005"],
    [/reg(\.exe)?\s+add\s+\S*\\(Run|RunOnce|Winlogon|Image File Execution Options)\b/i, "Registry autorun", "T1547.001"],
    [/New-ItemProperty\s+.*\\CurrentVersion\\Run/i, "Registry autorun (PowerShell)", "T1547.001"],
    [/sc(\.exe)?\s+create\s+/i, "Service created", "T1543.003"],
    [/(crontab\s+-[^l\s]*\s|\/etc\/cron\.|>>?\s*\/var\/spool\/cron)/i, "Cron job modified", "T1053.003"],
    [/systemctl\s+enable\s+|\/etc\/systemd\/system\/\S+\.service/i, "systemd unit enabled", "T1543.002"],
    [/>>?\s*\S*\.ssh\/authorized_keys/i, "SSH authorized_keys modified", "T1098.004"],
    [/>>?\s*\S*(\.bashrc|\.profile|\/etc\/profile|\.zshrc)\b/i, "Shell profile modified", "T1546.004"],
    [/(Startup\\|\\Start Menu\\Programs\\Startup)/i, "Startup folder", "T1547.001"],
    [/__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer/i, "WMI event subscription", "T1546.003"],
  ];
  const PERSIST_SUS = /(powershell|cmd\.exe\s*\/c|\\temp\\|\\users\\public|http|mshta|rundll32|%comspec%)/i;
  detection("AG-PER-001", "Persistence mechanism installed", "medium", ["T1053", "T1547", "T1543"],
    "Scheduled tasks, services, autoruns, cron, systemd units or SSH keys added.", (evs, th, d, out) => {
      for (const e of evs) {
        if (e.action === "task_create" || e.action === "service_install") {
          const f = e.fields;
          const nm = f.TaskName || f.ServiceName || "?";
          const fn = String(f.ImagePath || f.ServiceFileName || f.TaskContent || "");
          const task = e.action === "task_create";
          out.push(finding(d, `${task ? "Task" : "Service"} installed: ${nm}`, [e.i], fn.slice(0, 300),
            { severity: PERSIST_SUS.test(fn) ? "high" : "medium", attack: [task ? "T1053.005" : "T1543.003"], entities: { host: one(e.host) } }));
          continue;
        }
        if (e.action === "cron_edit") { out.push(finding(d, `crontab edited by ${e.user || "?"}`, [e.i], e.msg, { attack: ["T1053.003"] })); continue; }
        const c = cmd(e); if (!c) continue;
        for (const [rx, label, tech] of PERSIST) if (rx.test(c)) {
          out.push(finding(d, `${label}: ${c.slice(0, 130)}`, [e.i], "", { attack: [tech], entities: { host: one(e.host), user: one(e.user) } }));
          break;
        }
      }
    });

  // ------------------------------------------------------------------ web
  const WEB_ATTACKS = [
    [/(union(\s|\+|%20|\/\*.*?\*\/)+(all(\s|\+|%20)+)?select|'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d|information_schema|sleep\s*\(\s*\d|benchmark\s*\(|waitfor\s+delay|extractvalue\s*\(|%27(\s|%20|\+)*(or|and)(\s|%20|\+))/i, "SQL injection", "T1190"],
    [/(\.\.\/|\.\.%2f|%2e%2e%2f|\.\.\\|%2e%2e\/|\/etc\/passwd|\/proc\/self\/environ|win\.ini|boot\.ini|php:\/\/(filter|input)|file:\/\/\/|expect:\/\/)/i, "Path traversal / LFI", "T1190"],
    [/(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|%3csvg|<svg\/onload|alert\(|document\.cookie)/i, "Cross-site scripting", "T1189"],
    [/(\$\{jndi:|%24%7bjndi|\$\{(::-|lower:|upper:|env:))/i, "Log4Shell (JNDI)", "T1190"],
    [/\(\)\s*\{\s*:;\s*\}\s*;/i, "Shellshock", "T1190"],
    [/([;|`]\s*(id|whoami|uname|cat\s+\/etc|wget|curl|nc|bash|sh)\b|\$\((id|whoami|curl|wget)|%7c(id|whoami)|cmd(\.exe)?(%20|\+|\s)*\/c)/i, "OS command injection", "T1059"],
    [/(\/wp-login\.php|\/xmlrpc\.php|\/\.env\b|\/\.git\/(config|HEAD)|\/phpmyadmin|\/actuator\/(env|heapdump)|\/cgi-bin\/.*\.(sh|cgi)|\/vendor\/phpunit\/.*eval-stdin|\/solr\/admin|\/console\/login|\/manager\/html|\/owa\/auth\/|\/autodiscover\/autodiscover\.json|\/\.aws\/credentials|\/server-status)/i, "Sensitive path probe", "T1595.002"],
  ];
  const SCANNER_UA = /(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb\/|wpscan|nuclei|ffuf|feroxbuster|acunetix|nessus|openvas|qualys|burp|wfuzz|hydra|python-requests|go-http-client|curl\/|wget\/|libwww-perl|censysinspect|zmeu|morfeus|jorgee|l9explore|httpx)/i;
  const WEBSHELL = /((c99|r57|wso|b374k|alfa|shell|cmd|webshell|backdoor|up|uploader)\.(php|aspx?|jspx?)|\.(php|aspx?|jspx?)\?(cmd|exec|command|c|e|run)=)/i;

  detection("AG-WEB-001", "Web application attack", "high", ["T1190"], "Injection, traversal, XSS, Log4Shell or Shellshock patterns in request URLs / user agents.", (evs, th, d, out) => {
    const by = new Map();
    for (const e of evs) {
      if ((e.fmt !== "web" && e.fmt !== "json") || e.action !== "http") continue;
      const u = fget(e, "cs-uri") + " " + fget(e, "cs-user-agent");
      for (const [rx, label, tech] of WEB_ATTACKS.slice(0, -1)) if (rx.test(u)) {
        const k = JSON.stringify([e.ip, label, tech]);
        let g = by.get(k); if (!g) by.set(k, (g = { all: [], ok: [] }));
        g.all.push(e.i);
        if (fget(e, "sc-status").startsWith("2")) g.ok.push(e.i);
        break;
      }
    }
    for (const [k, g] of by) {
      const [ip, label, tech] = JSON.parse(k), ok = g.ok.length;
      out.push(finding(d, `${label} from ${ip}: ${g.all.length} request(s)`, g.all, ok ? `${ok} returned HTTP 2xx - review those responses.` : "No 2xx responses observed.",
        { severity: ok && (label === "Log4Shell (JNDI)" || label === "OS command injection") ? "critical" : ok ? "high" : "medium", attack: [tech], entities: { ip: one(ip) } }));
    }
  });

  detection("AG-WEB-002", "Scanner / content discovery", "medium", ["T1595.002", "T1595.003"], "Known scanner user agents, sensitive-path probes, or bursts of 404s from one client.", (evs, th, d, out) => {
    const ua = group(), nf = group(), probe = group();
    for (const e of evs) {
      if (e.action !== "http") continue;
      const m = SCANNER_UA.exec(fget(e, "cs-user-agent"));
      if (m) push(ua, JSON.stringify([e.ip, m[1].toLowerCase()]), e.i);
      if (fget(e, "sc-status") === "404") push(nf, e.ip, e.i);
      if (WEB_ATTACKS[WEB_ATTACKS.length - 1][0].test(fget(e, "cs-uri"))) push(probe, e.ip, e.i);
    }
    for (const [k, idx] of ua) {
      const [ip, tool] = JSON.parse(k);
      out.push(finding(d, `${ip} using ${tool}`, idx, `${idx.length} requests`, { entities: { ip: one(ip) },
        severity: ["curl/", "wget/", "python-requests", "go-http-client"].includes(tool) ? "low" : "medium" }));
    }
    for (const [ip, idx] of nf) if (idx.length >= th.scan_404)
      out.push(finding(d, `${ip}: ${idx.length} × 404`, idx, "Directory / file brute forcing.", { entities: { ip: one(ip) }, attack: ["T1595.003"] }));
    for (const [ip, idx] of probe)
      out.push(finding(d, `${ip} probed ${idx.length} sensitive path(s)`, idx, "", { entities: { ip: one(ip) }, attack: ["T1595.002"], severity: idx.length < 3 ? "low" : "medium" }));
  });

  detection("AG-WEB-003", "Possible web shell", "critical", ["T1505.003"], "Requests to known web-shell names or script files taking a command parameter.", (evs, th, d, out) => {
    const by = group();
    for (const e of evs) if (e.action === "http" && WEBSHELL.test(fget(e, "cs-uri"))) push(by, JSON.stringify([e.ip, fget(e, "cs-uri").split("?")[0]]), e.i);
    for (const [k, idx] of by) {
      const [ip, path] = JSON.parse(k);
      const ok = idx.filter((i) => fget(evs[i], "sc-status").startsWith("2"));
      out.push(finding(d, `${path} from ${ip}`, idx, `${ok.length} successful request(s).`, { severity: ok.length ? "critical" : "medium", entities: { ip: one(ip) } }));
    }
  });

  // ------------------------------------------------------------------ cloud (AWS CloudTrail)
  const CLOUD = {
    StopLogging: ["high", "CloudTrail logging stopped", "T1562.008"], DeleteTrail: ["high", "CloudTrail trail deleted", "T1562.008"],
    UpdateTrail: ["medium", "CloudTrail trail modified", "T1562.008"], DeleteDetector: ["high", "GuardDuty detector deleted", "T1562.001"],
    DisableSecurityHub: ["high", "Security Hub disabled", "T1562.001"], CreateAccessKey: ["medium", "Access key created", "T1098.001"],
    CreateLoginProfile: ["medium", "Console password set for user", "T1098"], UpdateLoginProfile: ["medium", "Console password changed for user", "T1098"],
    AttachUserPolicy: ["medium", "Policy attached to user", "T1098"], PutUserPolicy: ["medium", "Inline policy put on user", "T1098"],
    CreateUser: ["medium", "IAM user created", "T1136.003"], PutBucketPolicy: ["medium", "S3 bucket policy changed", "T1530"],
    PutBucketAcl: ["medium", "S3 bucket ACL changed", "T1530"], DeletePublicAccessBlock: ["high", "S3 public access block removed", "T1530"],
    AuthorizeSecurityGroupIngress: ["medium", "Security group ingress opened", "T1562.007"], ScheduleKeyDeletion: ["high", "KMS key scheduled for deletion", "T1485"],
    DisableKey: ["high", "KMS key disabled", "T1485"], GetSecretValue: ["low", "Secret read", "T1555"],
    CreateInstanceExportTask: ["high", "Instance export task", "T1537"], ModifySnapshotAttribute: ["medium", "Snapshot sharing changed", "T1537"],
  };
  detection("AG-CLD-001", "Risky cloud control-plane activity", "medium", ["T1562.008", "T1098", "T1530"],
    "Logging/guardrails disabled, credentials created, resources exposed (AWS CloudTrail).", (evs, th, d, out) => {
      for (const e of evs) {
        if (e.fmt !== "cloudtrail") continue;
        const f = e.fields, name = e.eid;
        if (Object.prototype.hasOwnProperty.call(CLOUD, name)) {
          let [sev, label, tech] = CLOUD[name], det = "";
          if (name === "AttachUserPolicy" && fget(e, "requestParameters.policyArn").includes("AdministratorAccess")) { sev = "high"; det = "AdministratorAccess attached"; }
          if (name === "AuthorizeSecurityGroupIngress" && JSON.stringify(f).includes("0.0.0.0/0")) { sev = "high"; det = "Ingress from 0.0.0.0/0"; }
          if (f.denied) { sev = "low"; det = "Denied: " + fget(e, "errorCode"); }
          out.push(finding(d, `${label} by ${e.user}`, [e.i], det || `from ${e.ip}`, { severity: sev, attack: [tech], entities: { user: one(e.user), ip: one(e.ip) } }));
        } else if (name === "ConsoleLogin") {
          const mfa = fget(e, "additionalEventData.MFAUsed").toLowerCase();
          if (f["userIdentity.type"] === "Root")
            out.push(finding(d, `Root account console logon from ${e.ip}`, [e.i], `MFA: ${mfa || "?"}`, { severity: "high", attack: ["T1078.004"], entities: { ip: one(e.ip) } }));
          else if (mfa === "no" && e.action === "auth_ok")
            out.push(finding(d, `Console logon without MFA: ${e.user}`, [e.i], `from ${e.ip}`, { severity: "medium", attack: ["T1078.004"], entities: { user: one(e.user), ip: one(e.ip) } }));
        }
      }
      const den = group();
      for (const e of evs) if (e.fmt === "cloudtrail" && e.fields.denied) push(den, e.user, e.i);
      for (const [u, idx] of den) if (idx.length >= 10)
        out.push(finding(d, `${u}: ${idx.length} AccessDenied errors`, idx, "Permission enumeration with a stolen credential?", { severity: "high", attack: ["T1580", "T1526"], entities: { user: one(u) } }));
    });

  // ------------------------------------------------------------------ runner
  const sortFindings = (arr) => arr.sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0) || b.count - a.count);

  /** run(events, thresholds?, disabled?, only?) → findings. A broken detector yields an "info" error finding instead of throwing. */
  function run(events, thresholds, disabled, only) {
    const th = Object.assign({}, DEFAULTS);
    for (const [k, v] of Object.entries(thresholds || {})) if (Number.isFinite(+v) && v !== "" && v != null) th[k] = +v;
    const off = new Set(disabled || []), want = only ? new Set(only) : null;
    const out = [];
    for (const d of DETECTIONS) {
      if ((want && !want.has(d.id)) || off.has(d.id)) continue;
      const got = [];
      try { d.fn(events || [], th, d, got); out.push(...got); }
      catch (e) { out.push({ rule: d.id, name: d.name, severity: "info", attack: [], title: "Detector error", detail: `${e.name}: ${e.message}`, events: [], count: 0, entities: {} }); }
    }
    return sortFindings(out);
  }
  const catalog = () => DETECTIONS.map(({ id, name, severity, attack, desc }) => ({ id, name, severity, attack: attack.slice(), desc }));

  W.eng.detect = { run, catalog, DEFAULTS, THRESHOLDS: DEFAULTS, THRESHOLD_HELP, SEV_ORDER, decodePs, sortFindings };
})(typeof window !== "undefined" ? window.W : globalThis.W);
