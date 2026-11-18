// Yoroi rule-from-logs synthesizer (W.eng.synth) — port of Katana defense/synth.py.
const WEB = [
  '198.51.100.77 - - [14/Nov/2026:10:01:00 +0000] "GET /i.php?id=1%27%20UNION%20SELECT%20pass-- HTTP/1.1" 200 5120 "-" "sqlmap/1.8"',
  '198.51.100.77 - - [14/Nov/2026:10:02:00 +0000] "GET /d.php?file=../../../../etc/passwd HTTP/1.1" 200 1820 "-" "sqlmap/1.8"',
  '198.51.100.77 - - [14/Nov/2026:10:04:00 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 64 "-" "sqlmap/1.8"',
  '192.0.2.15 - - [14/Nov/2026:10:05:00 +0000] "GET / HTTP/1.1" 200 9000 "-" "Mozilla/5.0"',
  '192.0.2.16 - - [14/Nov/2026:10:06:00 +0000] "GET /about HTTP/1.1" 200 4000 "-" "Mozilla/5.0"',
  '192.0.2.17 - - [14/Nov/2026:10:07:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0"',
  '10.0.0.4 - - [14/Nov/2026:10:08:00 +0000] "GET /i.php?id=42 HTTP/1.1" 200 5000 "-" "Mozilla/5.0"',
].join("\n");
const SSH = Array.from({ length: 6 }, (_, i) => `Nov 14 03:1${i}:0${i} web01 sshd[21${i}0]: Failed password for invalid user root from 203.0.113.37 port 4${i}000 ssh2`)
  .concat(["Nov 14 09:02:11 web01 sshd[3100]: Accepted publickey for alice from 203.0.113.9 port 51234 ssh2",
    "Nov 14 09:05:40 web01 sshd[3140]: Accepted password for deploy from 198.51.100.4 port 40188 ssh2",
    "Nov 14 09:10:33 web01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"]).join("\n");
const syn = (b) => W.eng.synth.synthesize(b);

test("synth: web — exact rule from the sqlmap user agent", () => {
  const r = syn({ text: WEB, indices: [0, 1, 2] });
  assert.equal(r.positives, 3); assert.equal(r.negatives, 4); assert.ok(r.candidates.length);
  assert.equal(r.recommended, 0);
  const g = r.candidates[0].grade;
  assert.ok(g.valid, g.errors);
  assert.equal(g.verdict, "exact"); assert.equal(g.fp, 0); assert.equal(g.fn, 0); assert.equal(g.tp, 3);
  assert.equal(g.precision, 1); assert.equal(g.recall, 1); assert.equal(g.f1, 1);
  assert.deepEqual(r.block_ips, ["198.51.100.77"]);
  assert.deepEqual(r.marked, [0, 1, 2]);
});

test("synth: emitted Sigma is real — compiles and re-matches exactly the marked events", () => {
  const r = syn({ text: WEB, indices: [0, 1, 2], title: "SQLi: sqlmap 'scan'" });
  assert.equal(r.title, "SQLi: sqlmap 'scan'");
  for (const c of r.candidates) {
    const { rules, errors } = W.eng.sigma.compile(c.rule);
    assert.deepEqual(errors, []); assert.equal(rules[0].title, "SQLi: sqlmap 'scan'");
    const evs = W.eng.logs.parse(WEB).events;
    const got = new Set(W.eng.sigma.run(rules, evs).flatMap((h) => h.events));
    assert.deepEqual([...got].sort(), c.grade.matched);
  }
});

test("synth: ssh — IP rule + attacker IP handed to block", () => {
  const r = syn({ text: SSH, indices: [0, 1, 2, 3, 4, 5] });
  assert.equal(r.positives, 6);
  assert.ok(r.block_ips.includes("203.0.113.37"));
  assert.equal(r.candidates[0].grade.verdict, "exact");
});

test("synth: windows — command-line token discriminator", () => {
  const evs = W.eng.logs.parse(fixture("yoroi-sysmon.xml")).events;
  const recon = evs.filter((e) => /cmd\.exe \/c/.test(e.fields.CommandLine || "")).map((e) => e.i);
  assert.equal(recon.length, 4);
  const r = syn({ text: fixture("yoroi-sysmon.xml"), indices: recon });
  const best = r.candidates[0];
  assert.ok(best.grade.recall >= 0.8, JSON.stringify(best.grade));
  assert.ok(["exact", "tight", "good"].includes(best.grade.verdict), best.grade.verdict);
});

test("synth: verdicts — leaky and loose are graded honestly", () => {
  const g = W.eng.synth.grade;
  const evs = W.eng.logs.parse(WEB).events;
  const rule = (v) => `title: t\ndetection:\n    s:\n        cs-uri|contains: '${v}'\n    condition: s\n`;
  const pset = new Set([0, 1, 2]), nset = new Set([3, 4, 5, 6]);
  const leaky = g(rule("UNION"), evs, pset, nset);
  assert.equal(leaky.verdict, "leaky"); assert.equal(leaky.fn, 2);
  const loose = g(rule(".php"), evs, pset, nset);
  assert.equal(loose.verdict, "loose"); assert.equal(loose.fp, 1); assert.deepEqual(loose.fp_events, [6]);
  assert.equal(g("title: t\n", evs, pset, nset).valid, false);
});

test("synth: no negatives warns; baseline adds negatives", () => {
  const r = syn({ text: WEB, indices: [0, 1, 2, 3, 4, 5, 6] });
  assert.equal(r.negatives, 0);
  assert.ok(r.notes.some((n) => /unmeasured|baseline/i.test(n)));
  const benign = Array.from({ length: 5 }, (_, i) => `10.0.0.${i} - - [14/Nov/2026:11:0${i}:00 +0000] "GET /p${i} HTTP/1.1" 200 100 "-" "curl/8"`).join("\n");
  const b = syn({ text: WEB, indices: [0, 1, 2], baseline: benign });
  assert.equal(b.baseline_events, 5); assert.ok(b.negatives >= 9);
});

test("synth: bad input is rejected", () => {
  assert.throws(() => syn({ text: "   ", indices: [0] }));
  assert.throws(() => syn({ text: WEB, indices: [] }));
  assert.throws(() => syn({ text: WEB, indices: [999] }));
  assert.deepEqual(W.eng.synth.parseIndices("0-3, 7 9,7"), [0, 1, 2, 3, 7, 9]);
});
