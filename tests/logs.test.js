// Yoroi log parser (W.eng.logs) — port of Katana defense/logs.py.
const LP = (t, f) => W.eng.logs.parse(t, f);
const SHAPE = ["i", "ts", "fmt", "host", "src", "eid", "user", "ip", "action", "msg", "fields"];

test("logs: auth.log (BSD syslog) normalisation", () => {
  const r = LP(fixture("yoroi-auth.log"));
  assert.equal(r.fmt, "syslog");
  assert.equal(r.events.length, 27);
  r.events.forEach((e, i) => { assert.deepEqual(Object.keys(e).sort(), SHAPE.slice().sort()); assert.equal(e.i, i); });
  assert.equal(r.events.filter((e) => e.action === "auth_fail").length, 18);
  const ok = r.events[18];
  assert.equal(ok.action, "auth_ok"); assert.equal(ok.user, "deploy"); assert.equal(ok.ip, "203.0.113.50"); assert.equal(ok.fields.service, "ssh");
  assert.match(ok.ts, /^\d{4}-11-14T03:14:02$/);      // BSD stamps carry no year/zone
  assert.equal(r.events[19].action, "session");
  assert.equal(r.events[20].action, "sudo"); assert.equal(r.events[20].fields.CommandLine, "/bin/bash"); assert.equal(r.events[20].fields.runas, "root");
  assert.equal(r.events[21].action, "user_add"); assert.equal(r.events[21].user, "sysupd");
  assert.equal(r.events[22].action, "group_add"); assert.equal(r.events[22].fields.group, "sudo");
  assert.equal(r.events[24].action, "cron"); assert.equal(r.events[24].user, "root"); assert.match(r.events[24].fields.CommandLine, /\/tmp\/\.x\/upd/);
});

test("logs: ISO syslog, PAM failures, passwd", () => {
  const r = LP([
    "2026-11-14T10:00:00+02:00 db01 sshd[9]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.4  user=oracle",
    "<34>1 2026-11-14T10:00:01Z db01 passwd[10]: pam_unix(passwd:chauthtok): password changed for bob",
  ].join("\n"));
  assert.equal(r.fmt, "syslog");
  assert.equal(r.events[0].ts, "2026-11-14T08:00:00Z");
  assert.equal(r.events[0].action, "auth_fail"); assert.equal(r.events[0].ip, "198.51.100.4"); assert.equal(r.events[0].user, "oracle");
  assert.equal(r.events[1].action, "passwd"); assert.equal(r.events[1].user, "bob");
});

test("logs: web access (combined)", () => {
  const r = LP(fixture("yoroi-access.log"));
  assert.equal(r.fmt, "web");
  const e = r.events[0];
  assert.equal(e.ts, "2026-11-14T10:01:00Z"); assert.equal(e.ip, "198.51.100.77"); assert.equal(e.action, "http");
  assert.equal(e.fields["sc-status"], 200); assert.equal(e.fields["cs-user-agent"], "sqlmap/1.8"); assert.equal(e.fields["cs-method"], "GET");
  assert.equal(e.msg.split(" ")[0], "GET");
});

test("logs: Windows Event XML (Sysmon + Security), namespaces, entities", () => {
  const r = LP(fixture("yoroi-sysmon.xml"));
  assert.equal(r.fmt, "winxml");
  assert.equal(r.events.length, 17);
  const ps = r.events[6];
  assert.equal(ps.eid, "1"); assert.equal(ps.action, "proc"); assert.equal(ps.host, "FIN-WS07.corp.local"); assert.equal(ps.ts, "2026-11-14T09:12:01Z");
  assert.match(ps.fields.ParentImage, /WINWORD\.EXE$/); assert.equal(ps.user, "CORP\\jsmith");
  assert.equal(r.events[0].action, "auth_fail"); assert.equal(r.events[0].ip, "203.0.113.80"); assert.equal(r.events[0].user, "svc_backup");
  assert.equal(r.events[16].action, "log_clear");
  // DOCTYPE / entity declarations are stripped, never expanded
  const evil = LP('<!DOCTYPE x [<!ENTITY a "b">]><Event><System><EventID>1</EventID></System><EventData><Data Name="x">&a; &lt;ok&gt;</Data></EventData></Event>');
  assert.equal(evil.events.length, 1);
  assert.equal(evil.events[0].fields.x, "&a; <ok>");
  // 7-digit fractions
  assert.equal(LP('<Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-11-14T09:00:00.1234567Z"/></System></Event>').events[0].ts, "2026-11-14T09:00:00Z");
});

test("logs: JSON — CloudTrail, Get-WinEvent, ECS lines", () => {
  const ct = LP(fixture("yoroi-cloudtrail.json"));
  assert.equal(ct.fmt, "json");
  assert.equal(ct.events[0].fmt, "cloudtrail"); assert.equal(ct.events[0].eid, "ConsoleLogin"); assert.equal(ct.events[0].action, "auth_ok");
  assert.equal(ct.events[0].fields["userIdentity.type"], "Root");
  assert.equal(ct.events[3].action, "log_clear"); assert.equal(ct.events[3].user, "mallory");
  assert.equal(ct.events[5].fields.denied, true);
  const we = LP(fixture("yoroi-winevent.json"));
  assert.equal(we.events[0].action, "auth_fail"); assert.ok(we.events[0].ts.startsWith("2024-11-14"));
  assert.equal(we.events[0].user, "bob"); assert.equal(we.events[0].ip, "203.0.113.9"); assert.equal(we.events[0].msg, "An account failed to log on.");
  assert.equal(we.events[1].fields.TicketEncryptionType, "0x17");      // EventData.* promoted
  const ecs = LP(fixture("yoroi-ecs.jsonl"));
  assert.equal(ecs.events.length, 3);
  assert.equal(ecs.events[0].eid, "4104"); assert.equal(ecs.events[0].host, "ws9"); assert.match(ecs.events[0].fields.CommandLine, /DownloadString/);
  assert.equal(ecs.events[1].action, "http"); assert.equal(ecs.events[1].ip, "203.0.113.7"); assert.equal(ecs.events[1].fields["cs-uri"], "/wp-login.php");
  assert.equal(ecs.events[2].user, "carol");
});

test("logs: CSV — generic + Event Viewer export", () => {
  const g = LP(fixture("yoroi-generic.csv"));
  assert.equal(g.fmt, "csv"); assert.equal(g.events.length, 2);
  assert.equal(g.events[0].ip, "203.0.113.5"); assert.equal(g.events[0].user, "bob"); assert.equal(g.events[0].ts, "2026-11-14T10:00:00");
  assert.equal(g.events[1].fields.message, "login, failed again");
  const ev = LP(fixture("yoroi-evtviewer.csv"));
  assert.equal(ev.events[0].eid, "4720"); assert.equal(ev.events[0].action, "user_add"); assert.equal(ev.events[0].user, "backdoor");
  assert.equal(ev.events[0].ip, "203.0.113.66"); assert.equal(ev.events[0].ts, "2026-11-14T09:40:00");
  assert.equal(ev.events[1].fields.CommandLine, "vssadmin delete shadows /all /quiet");
});

test("logs: plain text fallback, forced format, cap", () => {
  const t = LP("2026-11-14 10:00:00 something odd from 192.0.2.9\nno stamp here");
  assert.equal(t.fmt, "text");
  assert.equal(t.events[0].ip, "192.0.2.9"); assert.equal(t.events[0].ts, "2026-11-14T10:00:00"); assert.equal(t.events[1].ts, null);
  const f = LP("Nov 14 03:10:01 web01 sshd[1]: Failed password for root from 203.0.113.1 port 1 ssh2", "text");
  assert.equal(f.fmt, "text"); assert.equal(f.events[0].action, "auth_fail");
  const big = W.eng.logs.parse(Array.from({ length: 50 }, (_, i) => "line " + i).join("\n"), "auto", { max: 10 });
  assert.equal(big.events.length, 10); assert.equal(big.truncated, true);
  assert.deepEqual(LP("").events.length, 0);
});

test("logs: parseTime formats", () => {
  const p = W.eng.logs.parseTime;
  assert.equal(p("14/Nov/2026:10:01:00 -0500"), "2026-11-14T15:01:00Z");
  assert.equal(p("11/14/2026 9:40:00 PM"), "2026-11-14T21:40:00");
  assert.equal(p("1731571200"), "2024-11-14T08:00:00Z");
  assert.equal(p(1731571200000), "2024-11-14T08:00:00Z");
  assert.equal(p("Sat Nov 14 10:01:00 2026"), "2026-11-14T10:01:00");
  assert.equal(p("2026-11-14 10:00:00 UTC"), "2026-11-14T10:00:00Z");
  assert.equal(p("garbage"), null);
});

test("logs: IP helpers", () => {
  const L = W.eng.logs;
  assert.ok(L.inCidr("10.20.30.40", L.parseCidr("10.0.0.0/8")));
  assert.ok(!L.inCidr("11.0.0.1", L.parseCidr("10.0.0.0/8")));
  assert.ok(L.inCidr("2001:db8::5", L.parseCidr("2001:db8::/32")));
  assert.ok(L.isPublic("203.0.113.5") && L.isPublic("8.8.8.8"));
  assert.ok(!L.isPublic("192.168.1.1") && !L.isPublic("127.0.0.1") && !L.isPublic("fe80::1") && !L.isPublic("nope"));
  assert.throws(() => L.parseCidr("10.0.0.0/99"));
});
