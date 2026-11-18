/* Yoroi log ingestion — W.eng.logs. Port of Katana's defense/logs.py.
 *
 * Auto-detects the format and normalises every record into one event shape:
 *   {i, ts, fmt, host, src, eid, user, ip, action, msg, fields}
 *   - ts      ISO-8601 string ("…Z" when the source gives a zone, naive otherwise) or null
 *   - src     program / provider / eventSource
 *   - eid     Windows event id or CloudTrail eventName
 *   - action  normalised verb: auth_fail, auth_ok, http, proc, user_add, group_add, log_clear, …
 *   - fields  flat object of the original fields (dotted keys for nested JSON)
 *
 * Formats: syslog / auth.log (BSD + ISO stamps), web access (common / combined), Windows Event XML
 * (wevtutil / Event Viewer "Save as XML"), JSON + JSON lines (Get-WinEvent, Winlogbeat/ECS, Sysmon,
 * CloudTrail, generic), CSV with a header (Event Viewer export or generic), plain text.
 *
 * Also exposes small IP helpers (parseIp, inCidr, isPublic) used lazily by detect/sigma/synth.
 */
(function (W) {
  "use strict";

  const MAX_EVENTS = 100000;
  const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
  const RE_IP = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/;
  const RE_IP_G = new RegExp(RE_IP.source, "g");
  const p2 = (n) => String(n).padStart(2, "0");
  const obj = () => Object.create(null);

  // ------------------------------------------------------------------ time
  /** Build an ISO string from parts. off = zone offset in minutes (null → naive, no "Z"). */
  function isoFrom(y, mo, d, h, mi, s, off) {
    if ([y, mo, d, h, mi, s].some((x) => !Number.isFinite(x))) return null;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return null;
    if (off == null) return `${String(y).padStart(4, "0")}-${p2(mo)}-${p2(d)}T${p2(h)}:${p2(mi)}:${p2(Math.min(s, 59))}`;
    const t = Date.UTC(y, mo - 1, d, h, mi, Math.min(s, 59)) - off * 60000;
    return fromMs(t);
  }
  function fromMs(t) {
    const d = new Date(t);
    if (isNaN(d)) return null;
    return d.toISOString().replace(/\.\d+Z$/, "Z");
  }
  const zoneMin = (z) => {
    if (!z) return null;
    if (z === "Z" || /^UTC$|^GMT$/i.test(z)) return 0;
    const m = /^([+-])(\d\d):?(\d\d)$/.exec(z);
    return m ? (m[1] === "-" ? -1 : 1) * (+m[2] * 60 + +m[3]) : null;
  };

  /** Best-effort timestamp parser for the formats logs actually use → ISO string or null. */
  function parseTime(s) {
    if (s == null || s === "") return null;
    if (typeof s === "number") {
      let v = s;
      if (v > 1e14) v /= 1e6; else if (v > 1e11) v /= 1e3;
      return fromMs(v * 1000);
    }
    if (typeof s !== "string") s = String(s);
    s = s.trim();
    let m = /^\/Date\((\d+)/.exec(s);
    if (m) return parseTime(+m[1]);
    if (/^\d{10}(?:\.\d+)?$|^\d{13}$/.test(s)) return parseTime(parseFloat(s));
    // ISO 8601 / RFC 3339 (with "T" or a space), optional fraction and zone
    m = /^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,]\d+)?)?)?\s*(Z|UTC|GMT|[+-]\d\d:?\d\d)?$/i.exec(s);
    if (m) return isoFrom(+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), zoneMin(m[7] && m[7].toUpperCase()));
    // Apache / nginx: 14/Nov/2026:10:01:00 +0000
    m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d\d):(\d\d):(\d\d)(?:\s+([+-]\d{4}))?$/.exec(s);
    if (m && MONTHS[m[2].toLowerCase()]) return isoFrom(+m[3], MONTHS[m[2].toLowerCase()], +m[1], +m[4], +m[5], +m[6], zoneMin(m[7]));
    // 11/14/2026 10:01:00 PM  |  11/14/2026 22:01:00  |  14/11/2026 22:01:00
    m = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d\d):(\d\d)(?:\s*([AaPp][Mm]))?$/.exec(s);
    if (m) {
      let a = +m[1], b = +m[2], h = +m[4];
      if (m[7]) { const pm = /p/i.test(m[7]); if (h < 1 || h > 12) return null; h = (h % 12) + (pm ? 12 : 0); }
      else if (a > 12 && b <= 12) [a, b] = [b, a];      // d/m/Y
      return isoFrom(+m[3], a, b, h, +m[5], +m[6], null);
    }
    // 2026/11/14 10:01:00
    m = /^(\d{4})\/(\d{1,2})\/(\d{1,2}) (\d\d):(\d\d):(\d\d)$/.exec(s);
    if (m) return isoFrom(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6], null);
    // Sat Nov 14 10:01:00 2026
    m = /^[A-Za-z]{3} ([A-Za-z]{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (\d{4})$/.exec(s);
    if (m && MONTHS[m[1].toLowerCase()]) return isoFrom(+m[6], MONTHS[m[1].toLowerCase()], +m[2], +m[3], +m[4], +m[5], null);
    // Nov 14 2026 10:01:00
    m = /^([A-Za-z]{3}) +(\d{1,2}) (\d{4}) (\d\d):(\d\d):(\d\d)$/.exec(s);
    if (m && MONTHS[m[1].toLowerCase()]) return isoFrom(+m[3], MONTHS[m[1].toLowerCase()], +m[2], +m[4], +m[5], +m[6], null);
    return null;
  }

  /** BSD syslog stamps carry no year: assume this year, or last year if that lands > 2 days in the future. */
  function bsdTime(mon, day, hms, now) {
    const mo = MONTHS[String(mon).slice(0, 3).toLowerCase()];
    const t = hms.split(":").map(Number);
    if (!mo || t.length !== 3) return null;
    const n = now || new Date();
    let y = n.getFullYear();
    const local = new Date(y, mo - 1, +day, t[0], t[1], t[2]);
    if (local.getTime() > n.getTime() + 2 * 86400000) y -= 1;
    return isoFrom(y, mo, +day, t[0], t[1], t[2], null);
  }

  /** ISO string → epoch ms. Naive stamps are treated as UTC so arithmetic and hour-of-day agree. */
  function toMs(iso) {
    if (!iso) return null;
    const s = /[zZ]$|[+-]\d\d:?\d\d$/.test(iso) ? iso : iso + "Z";
    const t = Date.parse(s);
    return isNaN(t) ? null : t;
  }

  // ------------------------------------------------------------------ IP helpers (shared)
  /** → {v:4|6, b:[bytes]} or null */
  function parseIp(s) {
    s = String(s == null ? "" : s).trim().replace(/^\[|\]$/g, "");
    if (!s) return null;
    let m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (m) { const b = m.slice(1).map(Number); return b.every((x) => x <= 255) ? { v: 4, b } : null; }
    if (!s.includes(":") || !/^[0-9a-f:.%]+$/i.test(s.replace(/%.*$/, ""))) return null;
    s = s.replace(/%.*$/, "");
    let tail = [];
    m = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
    if (m) { const v4 = parseIp(m[2]); if (!v4) return null; tail = v4.b; s = m[1] + "0:0"; }
    const parts = s.split("::");
    if (parts.length > 2) return null;
    const hx = (x) => (x ? x.split(":") : []);
    const head = hx(parts[0]), rest = parts.length === 2 ? hx(parts[1]) : [];
    if (parts.length === 1 && head.length !== 8) return null;
    const fill = 8 - head.length - rest.length;
    if (fill < 0 || (parts.length === 2 && fill < 1 && head.length + rest.length === 8)) { if (fill < 0) return null; }
    const words = head.concat(Array(Math.max(0, fill)).fill("0"), rest);
    if (words.length !== 8 || words.some((w) => !/^[0-9a-f]{1,4}$/i.test(w))) return null;
    const b = [];
    for (const w of words) { const n = parseInt(w, 16); b.push(n >> 8, n & 255); }
    if (tail.length) b.splice(12, 4, ...tail);
    return { v: 6, b };
  }
  /** Parse "a.b.c.d/nn" (or v6) → {v, b, bits}; throws on garbage (strict=False semantics: host bits ignored). */
  function parseCidr(s) {
    const str = String(s).trim();
    const [a, n] = str.split("/");
    const ip = parseIp(a);
    if (!ip) throw new Error(`'${str}' does not appear to be an IPv4 or IPv6 network`);
    const max = ip.v === 4 ? 32 : 128;
    const bits = n === undefined ? max : /^\d{1,3}$/.test(n) ? +n : NaN;
    if (!(bits >= 0 && bits <= max)) throw new Error(`invalid prefix length in '${str}'`);
    return { v: ip.v, b: ip.b, bits };
  }
  function inCidr(ip, net) {
    const a = typeof ip === "string" ? parseIp(ip) : ip;
    if (!a || !net || a.v !== net.v) return false;
    let bits = net.bits;
    for (let i = 0; bits > 0; i++, bits -= 8) {
      const mask = bits >= 8 ? 255 : (0xff << (8 - bits)) & 255;
      if ((a.b[i] & mask) !== (net.b[i] & mask)) return false;
    }
    return true;
  }
  const NON_PUBLIC = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];
  let NP = null;
  /** Routable on the internet. Deliberately counts the RFC 5737 / RFC 3849 documentation ranges as public,
   *  so samples and training logs behave like real attacker traffic. */
  function isPublic(ip) {
    const a = typeof ip === "string" ? parseIp(ip) : ip;
    if (!a) return false;
    NP = NP || NON_PUBLIC.map(parseCidr);
    if (a.v === 6 && a.b.slice(0, 10).every((x) => x === 0) && a.b[10] === 255 && a.b[11] === 255) return isPublic({ v: 4, b: a.b.slice(12) });
    return !NP.some((n) => inCidr(a, n));
  }

  // ------------------------------------------------------------------ helpers
  function flatten(o, prefix = "", out = obj(), depth = 0) {
    if (o && typeof o === "object" && !Array.isArray(o) && depth < 6) {
      for (const k of Object.keys(o)) flatten(o[k], `${prefix}${k}.`, out, depth + 1);
    } else if (Array.isArray(o) && depth < 6) {
      if (o.every((x) => !(x && typeof x === "object"))) out[prefix.replace(/\.$/, "")] = o;
      else o.slice(0, 50).forEach((v, i) => flatten(v, `${prefix}${i}.`, out, depth + 1));
    } else out[prefix.replace(/\.$/, "")] = o;
    return out;
  }
  const blank = (v) => v == null || v === "" || v === "-";
  /** Case-insensitive lookup that also matches the last segment of dotted keys. */
  function get(fields, ...names) {
    if (!fields) return null;
    const keys = Object.keys(fields);
    const low = new Map();
    for (const k of keys) { const l = k.toLowerCase(); if (!low.has(l)) low.set(l, fields[k]); }
    for (const n of names) { const v = low.get(n.toLowerCase()); if (!blank(v)) return v; }
    for (let n of names) {
      n = "." + n.toLowerCase();
      for (const [k, v] of low) if (k.endsWith(n) && !blank(v)) return v;
    }
    return null;
  }
  function ev(kw) {
    const e = { i: 0, ts: null, fmt: "text", host: null, src: null, eid: null, user: null, ip: null, action: null, msg: "", fields: obj() };
    for (const k of Object.keys(kw)) if (kw[k] !== undefined) e[k] = kw[k];
    return e;
  }
  const str = (v) => (v == null ? "" : typeof v === "string" ? v : typeof v === "object" ? JSON.stringify(v) : String(v));
  const strOrNull = (v) => (v == null ? null : typeof v === "string" ? v : typeof v === "object" ? null : String(v));

  // ------------------------------------------------------------------ syslog / auth.log
  const RE_SYSLOG_BSD = /^(?:<\d+>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+(\S+)\s+([^:[\s]+)(?:\[(\d+)\])?:\s?(.*)$/;
  const RE_SYSLOG_ISO = /^(?:<\d+>\d?\s?)?(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(\S+)\s+([^:[\s]+)(?:\[(\d+)\])?:\s?(.*)$/;
  const SSH_PATTERNS = [
    [/Failed (?:password|publickey|keyboard-interactive\/pam|none) for (?:invalid user )?(\S+) from (\S+)/, "auth_fail"],
    [/Invalid user (\S*) from (\S+)/, "auth_fail"],
    [/authentication failure;.*?rhost=(\S*)(?:\s+user=(\S+))?/, "auth_fail_pam"],
    [/Accepted (?:password|publickey|keyboard-interactive\/pam|gssapi-with-mic) for (\S+) from (\S+)/, "auth_ok"],
    [/Disconnected from (?:invalid |authenticating )?user (\S+) (\S+) port/, "disconnect"],
    [/Connection closed by (?:invalid |authenticating )?user (\S+) (\S+) port/, "disconnect"],
  ];
  const RE_SUDO = /^\s*(\S+)\s*:\s*(?:.*?;\s*)?(?:TTY=\S+\s*;\s*)?PWD=(\S*)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)$/;
  const RE_USERADD = /new user: name=([^,\s]+)/;
  const RE_GROUPADD = /(?:add '?(\S+?)'? to (?:shadow )?group '?(\S+?)'?$|adding user '?(\S+?)'? to group '?(\S+?)'?)/i;
  const RE_PASSWD = /password changed for (\S+)/;

  function syslogLine(line, now) {
    let m = RE_SYSLOG_BSD.exec(line), ts, host, prog, pid, msg;
    if (m) { [, , , , host, prog, pid, msg] = m; ts = bsdTime(m[1], m[2], m[3], now); }
    else {
      m = RE_SYSLOG_ISO.exec(line);
      if (!m) return null;
      [, , host, prog, pid, msg] = m; ts = parseTime(m[1]);
    }
    const fields = obj();
    Object.assign(fields, { program: prog, pid: pid || null, host, message: msg });
    const e = ev({ ts, fmt: "syslog", host, src: prog, msg, fields });
    const pl = prog.toLowerCase();
    if (pl.startsWith("sshd") || msg.slice(0, 40).toLowerCase().includes("pam")) {
      for (const [rx, act] of SSH_PATTERNS) {
        const mm = rx.exec(msg);
        if (!mm) continue;
        if (act === "auth_fail_pam") { e.action = "auth_fail"; e.ip = mm[1] || null; e.user = mm[2] || null; }
        else { e.action = act; e.user = mm[1]; e.ip = mm[2]; }
        fields.service = pl.startsWith("sshd") ? "ssh" : pl;
        break;
      }
    }
    if (pl === "sudo") {
      const mm = RE_SUDO.exec(msg);
      if (mm) { e.action = "sudo"; e.user = mm[1]; Object.assign(fields, { runas: mm[3], CommandLine: mm[4].trim(), cwd: mm[2] }); }
      else if (msg.includes("authentication failure") || msg.includes("incorrect password")) e.action = "auth_fail";
    } else if (pl === "useradd" || pl === "adduser") {
      const mm = RE_USERADD.exec(msg);
      if (mm) { e.action = "user_add"; e.user = mm[1]; }
      else if (pl === "adduser") groupAdd(e, msg);
    } else if (["usermod", "gpasswd", "groupmems"].includes(pl)) groupAdd(e, msg);
    else if (pl === "passwd") {
      const mm = RE_PASSWD.exec(msg);
      if (mm) { e.action = "passwd"; e.user = mm[1]; }
    } else if ((pl === "cron" || pl === "crond") && msg.includes("CMD")) {
      const mm = /\((\S+)\) CMD \((.*)\)\s*$/.exec(msg);
      if (mm) { e.action = "cron"; e.user = mm[1]; fields.CommandLine = mm[2]; }
    } else if (pl === "crontab" && /\b(REPLACE|BEGIN EDIT|END EDIT)\b/.test(msg)) e.action = "cron_edit";
    else if ((pl === "systemd" || pl === "systemctl") && /(Created symlink|Reloading)/.test(msg)) e.action = "service_change";
    if (!e.ip) { const ip = RE_IP.exec(msg); e.ip = ip ? ip[0] : null; }
    if (msg.includes("session opened for user")) {
      const mm = /session opened for user (\S+?)(?:\(uid=\d+\))?\s/.exec(msg + " ");
      if (mm) { e.action = e.action || "session"; e.user = e.user || mm[1]; }
    }
    return e;
  }
  function groupAdd(e, msg) {
    const mm = RE_GROUPADD.exec(msg);
    if (!mm) return;
    const [u, g] = mm[1] ? [mm[1], mm[2]] : [mm[3], mm[4]];
    e.action = "group_add"; e.user = u; e.fields.group = g;
  }

  // ------------------------------------------------------------------ web access logs
  const RE_ACCESS = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: (\S+))?" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/;
  function accessLine(line) {
    const m = RE_ACCESS.exec(line);
    if (!m) return null;
    const [, ip, user, t, method, url, proto, status, size, ref, ua] = m;
    const fields = obj();
    Object.assign(fields, { "c-ip": ip, "cs-method": method, "cs-uri": url, "sc-status": +status,
      "sc-bytes": size === "-" ? 0 : /^\d+$/.test(size) ? +size : size, "cs-referer": ref == null ? null : ref,
      "cs-user-agent": ua == null ? null : ua, protocol: proto == null ? null : proto });
    return ev({ ts: parseTime(t), fmt: "web", src: "httpd", ip, user: user === "-" ? null : user, action: "http",
      msg: `${method} ${url} ${status}`, fields });
  }

  // ------------------------------------------------------------------ Windows
  const WIN_ACTION = {
    4625: "auth_fail", 4771: "auth_fail", 4776: "ntlm_auth", 4624: "auth_ok", 4648: "explicit_cred",
    4720: "user_add", 4722: "user_enable", 4724: "passwd_reset", 4726: "user_del", 4738: "user_change",
    4728: "group_add", 4732: "group_add", 4756: "group_add", 4672: "special_priv",
    1102: "log_clear", 104: "log_clear", 4688: "proc", 1: "proc", 4698: "task_create", 4702: "task_change",
    7045: "service_install", 4697: "service_install", 4769: "kerb_tgs", 4768: "kerb_tgt",
    5140: "share_access", 5145: "share_access", 4104: "ps_script", 3: "net_conn", 11: "file_create",
    13: "reg_set", 12: "reg_create", 22: "dns_query", 8: "remote_thread", 10: "proc_access",
    4740: "lockout", 4719: "audit_policy", 5001: "av_disabled", 1116: "av_detect", 4657: "reg_set",
  };
  const WIN_USER_FIELDS = ["TargetUserName", "SubjectUserName", "User", "AccountName", "user.name", "UserName", "SamAccountName"];
  const WIN_IP_FIELDS = ["IpAddress", "SourceAddress", "SourceIp", "ClientAddress", "source.ip", "DestinationIp"];
  const MSG_KEYS = new Set(["TargetUserName", "IpAddress", "LogonType", "CommandLine", "ServiceName", "TaskName", "Image", "GroupName",
    "TargetDomainName", "Status", "ScriptBlockText"]);

  function winEvent(fields, eid, ts, host, provider, msg) {
    eid = eid != null && eid !== "" ? String(eid) : null;
    let user = get(fields, ...WIN_USER_FIELDS);
    if (eid === "4728" || eid === "4732" || eid === "4756") user = get(fields, "MemberName", "MemberSid") || user;
    let ip = get(fields, ...WIN_IP_FIELDS);
    if (typeof ip === "string" && ip.startsWith("::ffff:") && ip !== "::ffff:127.0.0.1") ip = ip.slice(7);
    let action = Object.prototype.hasOwnProperty.call(WIN_ACTION, eid) ? WIN_ACTION[eid] : null;
    if (eid === "1" && provider && !String(provider).toLowerCase().includes("sysmon")) action = null;
    const cmd = get(fields, "CommandLine", "process.command_line", "ProcessCommandLine");
    const img = get(fields, "Image", "NewProcessName", "process.executable", "ProcessName");
    const setd = (k, v) => { if (!(k in fields)) fields[k] = v; };
    if (cmd || img) {
      setd("CommandLine", cmd || ""); setd("Image", img || "");
      const par = get(fields, "ParentImage", "ParentProcessName", "process.parent.executable");
      if (par) setd("ParentImage", par);
    }
    if (eid === "4104") { const sb = get(fields, "ScriptBlockText"); if (sb) setd("CommandLine", sb); }
    if (!msg) msg = Object.keys(fields).filter((k) => MSG_KEYS.has(k)).map((k) => `${k}=${str(fields[k])}`.slice(0, 300)).join(" ");
    return ev({ ts, fmt: "windows", host: strOrNull(host), src: strOrNull(provider), eid, user: strOrNull(user), ip: strOrNull(ip), action,
      msg: str(msg).slice(0, 2000), fields });
  }

  // Minimal, non-validating XML reader: no DTDs, no external entities — only the five predefined + numeric refs.
  const ENT = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };
  const unent = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (all, k) => {
    if (k[0] === "#") { const n = k[1] === "x" || k[1] === "X" ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10); try { return String.fromCodePoint(n); } catch { return all; } }
    return ENT[k.toLowerCase()] != null ? ENT[k.toLowerCase()] : all;
  });
  const local = (n) => n.slice(n.indexOf(":") + 1);
  function xmlTree(text) {
    const root = { tag: "#root", attrs: {}, kids: [], text: "" };
    const stack = [root];
    const re = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^[>]*(?:\[[\s\S]*?\])?\s*>|<!(?:ENTITY|ELEMENT|ATTLIST)[^>]*>|<(\/?)([A-Za-z_][\w:.-]*)((?:\s+[^\s=/>]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)|</gi;
    let m;
    while ((m = re.exec(text))) {
      const top = stack[stack.length - 1];
      if (m[1] != null) { top.text += m[1]; continue; }
      if (m[6] != null) { top.text += unent(m[6]); continue; }
      if (!m[3]) continue;
      const tag = local(m[3]);
      if (m[2]) {   // closing tag: pop to the matching open element (lenient)
        for (let i = stack.length - 1; i > 0; i--) if (stack[i].tag === tag) { stack.length = i; break; }
        continue;
      }
      const attrs = {};
      const ar = /([^\s=/>]+)\s*=\s*("([^"]*)"|'([^']*)')/g; let a;
      while ((a = ar.exec(m[4] || ""))) attrs[local(a[1])] = unent(a[3] != null ? a[3] : a[4]);
      const node = { tag, attrs, kids: [], text: "" };
      top.kids.push(node);
      if (!m[5]) stack.push(node);
    }
    return root;
  }
  const child = (n, tag) => (n ? n.kids.find((k) => k.tag === tag) : null) || null;
  const childText = (n, tag) => { const c = child(n, tag); return c ? c.text : null; };
  function* walk(n) { for (const k of n.kids) { yield k; yield* walk(k); } }

  function parseWinXml(text) {
    const root = xmlTree(text);
    const out = [];
    for (const evn of walk(root)) {
      if (evn.tag !== "Event") continue;
      const sys = child(evn, "System");
      if (!sys) continue;
      const eid = (childText(sys, "EventID") || "").trim();
      const tc = child(sys, "TimeCreated");
      const ts = tc ? parseTime(tc.attrs.SystemTime) : null;
      const prov = child(sys, "Provider");
      const provider = prov ? prov.attrs.Name || null : null;
      const fields = obj();
      const computer = childText(sys, "Computer");
      Object.assign(fields, { EventID: eid, Channel: childText(sys, "Channel"), Computer: computer, Provider: provider });
      for (const sect of ["EventData", "UserData"]) {
        const node = child(evn, sect);
        if (!node) continue;
        for (const d of walk(node)) {
          const name = d.attrs.Name || d.tag;
          if (d.text && d.text.trim()) fields[name] = d.text.trim();
        }
      }
      const rd = child(evn, "RenderingInfo");
      const msg = rd ? childText(rd, "Message") || "" : "";
      out.push(winEvent(fields, eid, ts, computer, provider, msg));
      if (out.length >= MAX_EVENTS) break;
    }
    return out;
  }

  // ------------------------------------------------------------------ JSON
  const CT_ACT = { ConsoleLogin: "auth_ok", CreateUser: "user_add", AddUserToGroup: "group_add", StopLogging: "log_clear", DeleteTrail: "log_clear" };
  function jsonRecord(rec) {
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) {
      const f = obj(); f.value = rec;
      return ev({ fmt: "json", msg: str(rec).slice(0, 2000), fields: f });
    }
    const f = flatten(rec);
    if (rec.eventSource != null && "eventName" in rec) {      // AWS CloudTrail
      const ui = rec.userIdentity || {};
      const issuer = ((ui.sessionContext || {}).sessionIssuer) || {};
      const user = ui.userName || issuer.userName || ui.arn || ui.type || null;
      const name = rec.eventName;
      let act = CT_ACT[name] || "api";
      if (name === "ConsoleLogin" && String((rec.responseElements || {}).ConsoleLogin) === "Failure") act = "auth_fail";
      if (["AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"].includes(rec.errorCode)) f.denied = true;
      return ev({ ts: parseTime(rec.eventTime), fmt: "cloudtrail", host: strOrNull(rec.awsRegion), src: strOrNull(rec.eventSource), eid: strOrNull(name),
        user: strOrNull(user), ip: strOrNull(rec.sourceIPAddress), action: act,
        msg: `${name} by ${user}` + (rec.errorCode ? ` (${rec.errorCode})` : ""), fields: f });
    }
    const eid = get(f, "EventID", "Id", "event_id", "winlog.event_id", "event.code", "EventId", "System.EventID");
    if (eid != null && /^\d{1,5}$/.test(String(eid))) {      // Windows: Get-WinEvent JSON, Winlogbeat/ECS, Sysmon JSON, EVTX dumps
      const provider = get(f, "ProviderName", "Provider", "winlog.provider_name", "SourceName", "Provider.Name", "System.Provider.Name", "Channel");
      const ts = parseTime(get(f, "TimeCreated", "@timestamp", "TimeGenerated", "UtcTime", "System.TimeCreated.SystemTime", "timestamp", "EventTime"));
      const host = get(f, "MachineName", "Computer", "host.name", "Hostname", "winlog.computer_name");
      for (const k of Object.keys(f)) {
        for (const pre of ["EventData.", "winlog.event_data.", "event_data.", "Event.EventData."]) {
          if (k.startsWith(pre) && !(k.slice(pre.length) in f)) f[k.slice(pre.length)] = f[k];
        }
      }
      const msg = get(f, "Message", "message") || "";
      return winEvent(f, eid, ts, host, typeof provider === "object" ? null : provider, str(msg).split("\n")[0]);
    }
    const ts = parseTime(get(f, "@timestamp", "timestamp", "time", "ts", "date", "datetime", "eventTime"));
    const ip = get(f, "source.ip", "src_ip", "client_ip", "remote_addr", "ip", "clientip", "client.ip", "srcip");
    const user = get(f, "user.name", "user", "username", "usr", "account");
    const msg = get(f, "message", "msg", "log", "event.original") || JSON.stringify(rec).slice(0, 400);
    let act = null;
    const url = get(f, "url.original", "request", "uri", "url", "path");
    const status = get(f, "status", "http.response.status_code", "response", "status_code");
    if (url && status) {
      act = "http";
      if (!("cs-uri" in f)) f["cs-uri"] = url;
      if (!("sc-status" in f)) f["sc-status"] = status;
      const ua = get(f, "user_agent.original", "http_user_agent", "user_agent", "agent", "ua");
      if (ua && !("cs-user-agent" in f)) f["cs-user-agent"] = ua;
      const meth = get(f, "http.request.method", "method", "verb");
      if (meth && !("cs-method" in f)) f["cs-method"] = meth;
    }
    return ev({ ts, fmt: "json", host: strOrNull(get(f, "host.name", "hostname", "host")), src: strOrNull(get(f, "program", "app", "service.name")),
      ip: typeof ip === "string" ? ip : null, user: typeof user === "string" ? user : null, action: act, msg: str(msg).slice(0, 2000), fields: f });
  }
  function parseJson(text, cap) {
    text = text.trim();
    let recs;
    try {
      const data = JSON.parse(text);
      recs = data && typeof data === "object" && !Array.isArray(data) && Array.isArray(data.Records) ? data.Records : Array.isArray(data) ? data : [data];
    } catch {
      recs = [];
      for (let line of text.split("\n")) {
        line = line.trim().replace(/,$/, "");
        if (!line.startsWith("{")) continue;
        try { recs.push(JSON.parse(line)); } catch { /* skip */ }
        if (recs.length >= cap) break;
      }
    }
    return recs.slice(0, cap).map(jsonRecord);
  }

  // ------------------------------------------------------------------ CSV
  /** Count delimiter occurrences outside quotes in one line. */
  function countOutside(line, d) { let n = 0, q = false; for (const c of line) { if (c === '"') q = !q; else if (c === d && !q) n++; } return n; }
  function sniffDelim(sample) {
    const lines = sample.split("\n").filter((l) => l.trim()).slice(0, 12);
    let best = ",", score = -1;
    for (const d of [",", ";", "\t", "|"]) {
      const counts = lines.map((l) => countOutside(l, d));
      if (!counts.length || !counts[0]) continue;
      const consistent = counts.filter((c) => c === counts[0]).length;
      const sc = consistent * 100 + counts[0];
      if (sc > score) { score = sc; best = d; }
    }
    return best;
  }
  /** RFC 4180-ish reader (quoted fields, doubled quotes, embedded newlines). */
  function* csvRows(text, d) {
    let row = [], cell = "", q = false, i = 0;
    const n = text.length;
    while (i < n) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i += 2; continue; } q = false; i++; continue; }
        cell += c; i++; continue;
      }
      if (c === '"' && cell === "") { q = true; i++; continue; }
      if (c === d) { row.push(cell); cell = ""; i++; continue; }
      if (c === "\n") { row.push(cell); yield row; row = []; cell = ""; i++; continue; }
      cell += c; i++;
    }
    if (cell !== "" || row.length) { row.push(cell); yield row; }
  }
  const EVT_KEYS = { "Account Name": "TargetUserName", "Source Network Address": "IpAddress", "Process Command Line": "CommandLine",
    "New Process Name": "NewProcessName", "Logon Type": "LogonType", "Service Name": "ServiceName", "Task Name": "TaskName",
    "Group Name": "GroupName", "Failure Reason": "FailureReason" };
  const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  function parseCsv(text, cap) {
    const d = sniffDelim(text.slice(0, 8192));
    const rows = csvRows(text, d);
    const first = rows.next();
    if (first.done) return [];
    const header = first.value.map((h) => h.trim().replace(/^\ufeff/, ""));
    const lowh = header.map((h) => h.toLowerCase());
    const evtviewer = lowh.includes("event id") && (lowh.includes("date and time") || lowh.includes("level"));
    const out = [];
    for (const row of rows) {
      if (out.length >= cap) break;
      if (!row.length || (row.length === 1 && !row[0].trim())) continue;
      const f = obj();
      header.forEach((h, i) => { if (i < row.length) f[h] = row[i]; });
      if (row.length > header.length) f.Message = row.slice(header.length).join(",");
      if (evtviewer || get(f, "EventID", "Event ID", "EventCode")) {
        const eid = get(f, "Event ID", "EventID", "EventCode", "Id");
        const msg = str(get(f, "Message", "Task Category") || "");
        for (const [k, key] of Object.entries(EVT_KEYS)) {
          const mm = new RegExp(reEsc(k) + ":\\s*([^\\r\\n\\t]+)").exec(msg);
          if (mm && !(key in f)) f[key] = mm[1].trim();
        }
        const ts = parseTime(get(f, "Date and Time", "TimeCreated", "TimeGenerated", "Time", "Date"));
        out.push(winEvent(f, eid, ts, get(f, "Computer", "MachineName", "Host"), get(f, "Source", "Provider"), msg.split("\n")[0].slice(0, 500)));
      } else {
        const ts = parseTime(get(f, "timestamp", "time", "date", "@timestamp", "datetime", "_time"));
        const ip = get(f, "src_ip", "source_ip", "ip", "client_ip", "src", "c-ip", "srcaddr");
        out.push(ev({ ts, fmt: "csv", host: strOrNull(get(f, "host", "hostname", "computer")), ip: strOrNull(ip), user: strOrNull(get(f, "user", "username", "account")),
          msg: Object.keys(f).slice(0, 8).map((k) => `${k}=${f[k]}`).join(" ").slice(0, 600), fields: f }));
      }
    }
    return out;
  }

  // ------------------------------------------------------------------ dispatcher
  const FORMATS = [["auto", "auto-detect"], ["syslog", "syslog / auth.log"], ["web", "web access log"], ["winxml", "Windows Event XML"],
    ["json", "JSON / JSON lines"], ["csv", "CSV"], ["text", "plain text"]];

  function sniff(text) {
    const head = text.replace(/^\s+/, "").slice(0, 4000);
    if (head.startsWith("<") && /<Event[\s>]/.test(head)) return "winxml";
    if (head.startsWith("{") || head.startsWith("[")) return "json";
    const lines = head.split("\n").filter((l) => l.trim()).slice(0, 20);
    if (!lines.length) return "text";
    const half = Math.max(1, Math.floor(lines.length / 2));
    if (lines.filter((l) => RE_ACCESS.test(l)).length >= half) return "web";
    if (lines.filter((l) => RE_SYSLOG_BSD.test(l) || RE_SYSLOG_ISO.test(l)).length >= half) return "syslog";
    const first = lines[0];
    const cnt = (ch) => first.split(ch).length - 1;
    if ((cnt(",") >= 2 || cnt("\t") >= 2 || cnt(";") >= 2) && !new RegExp("^" + RE_IP.source).test(first) && lines.length > 1) return "csv";
    return "text";
  }

  /** parse(text, fmt="auto", {max}) → {fmt, events, truncated} */
  function parse(text, fmt = "auto", opts = {}) {
    text = String(text == null ? "" : text).replace(/\r\n?/g, "\n");
    const cap = opts.max || MAX_EVENTS;
    fmt = !fmt || fmt === "auto" ? sniff(text) : fmt;
    let evs, truncated = false;
    if (fmt === "winxml") evs = parseWinXml(text);
    else if (fmt === "json") evs = parseJson(text, cap + 1);
    else if (fmt === "csv") evs = parseCsv(text, cap + 1);
    else {
      evs = [];
      const now = opts.now ? new Date(opts.now) : new Date();
      let start = 0;
      while (start <= text.length) {
        let end = text.indexOf("\n", start);
        if (end < 0) end = text.length;
        const line = text.slice(start, end);
        start = end + 1;
        if (!line.trim()) { if (end >= text.length) break; continue; }
        if (evs.length >= cap) { truncated = true; break; }
        let e = null;
        if (fmt === "web" || fmt === "syslog" || fmt === "text") {
          e = fmt !== "syslog" ? accessLine(line) : null;
          e = e || syslogLine(line, now);
        }
        if (!e) {
          const ip = RE_IP.exec(line);
          const f = obj(); f.message = line.slice(0, 4000);
          e = ev({ fmt: "text", ip: ip ? ip[0] : null, msg: line.slice(0, 2000), fields: f });
          const tm = /^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d\S*)/.exec(line);
          if (tm) e.ts = parseTime(tm[1]);
        }
        evs.push(e);
        if (end >= text.length) break;
      }
    }
    if (evs.length > cap) { evs = evs.slice(0, cap); truncated = true; }
    evs.forEach((e, i) => { e.i = i; });
    return { fmt, events: evs, truncated };
  }

  W.eng.logs = { parse, sniff, parseTime, toMs, flatten, get, _get: get, FORMATS, MAX_EVENTS, RE_IP, RE_IP_G,
    parseIp, parseCidr, inCidr, isPublic };
})(typeof window !== "undefined" ? window.W : globalThis.W);
