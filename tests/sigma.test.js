// Yoroi Sigma subset engine (W.eng.sigma) — port of Katana defense/sigma.py.
const S = () => W.eng.sigma;
const mk = (f, extra) => Object.assign({ i: 0, fmt: "windows", eid: null, ip: null, user: null, msg: "", fields: f }, extra || {});
const one = (txt) => { const r = S().compile(txt); assert.deepEqual(r.errors, []); assert.equal(r.rules.length, 1); return r.rules[0]; };
const plain = (x) => JSON.parse(JSON.stringify(x));

test("sigma: mini YAML (maps, lists, flow, block scalars, comments, multi-doc)", () => {
  const d = S().yamlLoad("a: 1\nb:\n    - x\n    - 'y z'\nc: |\n    l1\n    l2\nd:\n    - k: v\n      k2: [1, 2]\n")[0];
  assert.deepEqual(plain(d), { a: 1, b: ["x", "y z"], c: "l1\nl2", d: [{ k: "v", k2: [1, 2] }] });
  const e = S().yamlLoad("x: \"a\\tb\" # comment\ny: 'it''s #not'\nz: >\n  one\n  two\nf: {p: q, n: [1, 2]}\nt: yes\n---\nq: ~\n");
  assert.equal(e.length, 2);
  assert.deepEqual(plain(e[0]), { x: "a\tb", y: "it's #not", z: "one two", f: { p: "q", n: [1, 2] }, t: true });
  assert.equal(e[1].q, null);
});

test("sigma: bundled rules compile", () => {
  const r = S().compile(S().BUILTIN);
  assert.deepEqual(r.errors, []);
  assert.ok(r.rules.length >= 10);
  assert.ok(r.rules.every((x) => x.id.startsWith("yoroi-sig-") && x.attack.length));
  assert.ok(S().BUILTIN.includes("${jndi:"));
});

test("sigma: modifiers and conditions", () => {
  const r = one(String.raw`
title: t
logsource: {product: windows}
detection:
    sel1:
        CommandLine|contains|all: ['a', 'b']
    sel2:
        Image|endswith: '\x.exe'
    net:
        IpAddress|cidr: 10.0.0.0/8
    filt:
        User: 'svc*'
    condition: (1 of sel* and net) and not filt
level: high
`);
  assert.equal(r.level, "high");
  assert.ok(r.match(mk({ CommandLine: "xx a yy b", IpAddress: "10.1.2.3", User: "bob" })));
  assert.ok(!r.match(mk({ CommandLine: "xx a yy b", IpAddress: "10.1.2.3", User: "svc_backup" })));
  assert.ok(!r.match(mk({ CommandLine: "only a", IpAddress: "10.1.2.3", User: "bob" })));
  assert.ok(r.match(mk({ Image: "C:\\X.EXE", IpAddress: "10.9.9.9" })));
  assert.ok(!r.match(mk({ Image: "C:\\X.EXE", IpAddress: "11.9.9.9" })));
});

test("sigma: startswith, re, numeric, exists, cased, windash, null, keywords", () => {
  const r = (det, ev) => one(`title: t\ndetection:\n${det}\n    condition: s\n`).match(ev);
  assert.ok(r("    s:\n        Image|startswith: 'C:\\Users\\'", mk({ Image: "c:\\users\\bob\\a.exe" })));
  assert.ok(r("    s:\n        CommandLine: 'a\\*b'", mk({ CommandLine: "A*B" })));
  assert.ok(!r("    s:\n        CommandLine: 'a\\*b'", mk({ CommandLine: "axxb" })));
  assert.ok(r("    s:\n        CommandLine: 'a*b?'", mk({ CommandLine: "aXXbZ" })));
  assert.ok(r("    s:\n        CommandLine|re: '-e(nc)?\\s+[A-Za-z0-9+/=]{8,}'", mk({ CommandLine: "powershell -enc SQBFAFgAIAAoA" })));
  assert.ok(!r("    s:\n        CommandLine|re: '^POWERSHELL'", mk({ CommandLine: "powershell" })));
  assert.ok(r("    s:\n        CommandLine|re|i: '^POWERSHELL'", mk({ CommandLine: "powershell" })));
  assert.ok(r("    s:\n        sc-bytes|gte: 1000", mk({ "sc-bytes": 5120 })));
  assert.ok(!r("    s:\n        sc-bytes|lt: 1000", mk({ "sc-bytes": 5120 })));
  assert.ok(r("    s:\n        ParentImage|exists: true", mk({ ParentImage: "x" })));
  assert.ok(r("    s:\n        ParentImage|exists: false", mk({})));
  assert.ok(!r("    s:\n        CommandLine|contains|cased: 'IEX'", mk({ CommandLine: "iex (x)" })));
  assert.ok(r("    s:\n        CommandLine|contains|cased: 'IEX'", mk({ CommandLine: "IEX (x)" })));
  assert.ok(r("    s:\n        CommandLine|contains|windash: ' -urlcache '", mk({ CommandLine: "certutil /urlcache /f" })));
  assert.ok(r("    s:\n        CommandLine: null", mk({})));
  assert.ok(r("    s:\n        - 'evil.example'\n        - 'x*z'", mk({ foo: "aaa xyz bbb" })));
  assert.ok(r("    s:\n        '|contains': 'needle'", mk({}, { msg: "hay needle hay" })));
  assert.ok(r("    s:\n        CommandLine|base64: 'whoami'", mk({ CommandLine: W.b64("whoami") })));
});

test("sigma: base64offset matches at every alignment", () => {
  const r = one("title: t\ndetection:\n    s:\n        CommandLine|base64offset|contains: 'http://'\n    condition: s\n");
  for (const pre of ["", "a", "ab"]) assert.ok(r.match(mk({ CommandLine: W.b64(pre + "curl http://evil") }, { fmt: "text" })), JSON.stringify(pre));
});

test("sigma: lists of maps (OR), all of them, any of, condition lists", () => {
  const r = one(`title: t
detection:
    sel:
        - Image|endswith: '\\a.exe'
        - Image|endswith: '\\b.exe'
          CommandLine|contains: go
    other:
        User: bob
    condition:
        - all of them
        - any of sel and User
`.replace("any of sel and User", "1 of sel"));
  assert.ok(r.match(mk({ Image: "c:\\a.exe" })));
  assert.ok(!r.match(mk({ Image: "c:\\b.exe" })));
  assert.ok(r.match(mk({ Image: "c:\\b.exe", CommandLine: "go now" })));
});

test("sigma: field mapping (aliases, eid, ip, cloudtrail eventName, action)", () => {
  const F = S().fieldValue;
  const e = W.eng.logs.parse(fixture("yoroi-access.log")).events[0];
  assert.equal(F(e, "c-uri").startsWith("/index.php"), true);
  assert.equal(F(e, "c-useragent"), "sqlmap/1.8");
  assert.equal(F(e, "SourceIp"), "198.51.100.77");
  assert.equal(F(e, "action"), "http");
  const ct = W.eng.logs.parse(fixture("yoroi-cloudtrail.json")).events[3];
  assert.equal(F(ct, "eventName"), "StopLogging");
  const x = W.eng.logs.parse(fixture("yoroi-sysmon.xml")).events;
  assert.equal(F(x[16], "EventID"), "1102");
  assert.equal(F(x[0], "TargetUserName"), "svc_backup");
});

test("sigma: run over logs honours logsource + reports findings", () => {
  const evs = W.eng.logs.parse(fixture("yoroi-sysmon.xml")).events;
  const hits = S().run(S().builtinRules(), evs);
  const byId = Object.fromEntries(hits.map((h) => [h.rule, h]));
  assert.ok(byId["yoroi-sig-0003"] && byId["yoroi-sig-0003"].severity === "critical");
  assert.ok(byId["yoroi-sig-0008"] && byId["yoroi-sig-0002"] && byId["yoroi-sig-0011"]);
  assert.equal(byId["yoroi-sig-0003"].title, "Sigma: Shadow copy deletion");
  assert.deepEqual(byId["yoroi-sig-0003"].attack, ["T1490"]);
  for (const h of hits) assert.equal(h.count, h.events.length);
  // a linux-only rule never fires on windows events, a webserver rule only on web events
  const web = W.eng.logs.parse(fixture("yoroi-access.log")).events;
  assert.ok(S().run(S().builtinRules(), web).some((h) => h.rule === "yoroi-sig-0007"));
  assert.ok(!S().run(S().builtinRules(), evs).some((h) => h.rule === "yoroi-sig-0007"));
});

test("sigma: custom multi-doc file — one good, one broken", () => {
  const r = S().compile(fixture("yoroi-rules.yml"));
  assert.equal(r.rules.length, 1);
  assert.equal(r.errors.length, 1);
  assert.match(r.errors[0], /rule 2 \(Broken rule\).*unknown item 'nothing'/);
  assert.deepEqual(r.rules[0].attack, ["T1033"]);
  const evs = W.eng.logs.parse(fixture("yoroi-sysmon.xml")).events;
  assert.deepEqual(S().run(r.rules, evs)[0].events, [9]);   // cmd.exe /c whoami /all
});

test("sigma: errors are reported, not thrown", () => {
  const e = (t) => S().compile(t).errors;
  assert.ok(e("title: t\ndetection:\n    s:\n        a: 1\n    condition: s | count() > 5\n").length);
  assert.ok(e("title: t\ndetection:\n    s:\n        a: 1\n    condition: missing\n").length);
  assert.ok(e("title: t\ndetection:\n    s:\n        a: 1\n").length);
  assert.ok(e("title: t\ndetection:\n    s:\n        a|re: '(['\n    condition: s\n").length);
  assert.ok(e("title: t\ndetection:\n    s:\n        a|cidr: 'nope'\n    condition: s\n").length);
  assert.ok(e("title: t\n  bad: indent\n").length);
  assert.ok(e("just a string").length);
  assert.ok(e("title: t\ndetection:\n    s:\n        a: 1\n    condition: (s\n").length);
});
