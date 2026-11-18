// Yumi (CTI) engines: ioc, artifacts, regexgen, yaragen, stix, workbench, triage, transforms, pivot.
const REPORT = `APT29 (Cozy Bear) loader campaign — also tracked as NOBELIUM.
The actor sends a spearphishing link; the user opens a malicious document that runs PowerShell (-enc).
The loader uses rundll32 and performs DLL side-loading, then injects into a process.
It dumps credentials from LSASS with mimikatz and runs whoami and systeminfo for discovery.
C2 is an HTTPS beacon via Cobalt Strike to update-cdn[.]ddns[.]net and 185.220.101.5 (hxxps://185.220.101.5/gate.php).
Exploits CVE-2023-23397. Creates mutex Global\\CozyMutex_v2 and pipe \\\\.\\pipe\\winsvc_44. Maps to T1566.002 and T1059.001.
PDB: C:\\Users\\devbox\\source\\repos\\loader\\Release\\loader.pdb
sha256: 44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f
Finally it deploys ransomware and runs vssadmin to inhibit recovery. Private 10.0.0.5 is internal.`;

test("ioc.extract refangs and types indicators", () => {
  const r = W.eng.ioc.extract(REPORT, { includePrivate: false });
  assert.ok(r.domain.includes("update-cdn.ddns.net"));
  assert.ok(r.ipv4.includes("185.220.101.5"));
  assert.ok(!r.ipv4.includes("10.0.0.5"), "private IPs dropped when asked");
  assert.ok(r.url.includes("https://185.220.101.5/gate.php"));
  assert.deepEqual(r.cve, ["CVE-2023-23397"]);
  assert.ok(r.attack.includes("T1566.002"));
  assert.equal(r.sha256[0], "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f");
  assert.ok(!r.domain.some((d) => d.endsWith(".pdb") || d.endsWith(".php")), "file extensions are not domains");
  assert.ok(W.eng.ioc.extract("10.1.1.1").ipv4.includes("10.1.1.1"), "private kept by default");
});

test("ioc.extract handles IPv6 + MAC + wallets", () => {
  const r = W.eng.ioc.extract("hosts 2001:4860:4860:0:0:0:0:8888 and fe80::1 mac 00:1a:2b:3c:4d:5e eth 0x52908400098527886E0F7030069857D2E4169EE7", { includePrivate: false });
  assert.deepEqual(r.ipv6, ["2001:4860:4860::8888"]);
  assert.deepEqual(r.mac, ["00:1a:2b:3c:4d:5e"]);
  assert.equal(r.eth.length, 1);
});

test("artifacts finds host tradecraft", () => {
  const a = W.eng.ioc.artifacts(REPORT), kinds = Object.fromEntries(a.groups.map((g) => [g.kind, g.items]));
  assert.ok(kinds.pdb[0].endsWith("loader.pdb"));
  assert.ok(kinds.mutex.some((m) => m.includes("CozyMutex_v2")));
  assert.ok(kinds.pipe.some((p) => p.includes("winsvc_44")));
  assert.deepEqual(kinds.username, ["devbox"]);
});

test("regexgen ranks a recommended pattern that matches", () => {
  const r = W.eng.regexgen.generate("Global\\Mutex_1234 x");
  assert.equal(r.options[0].label, "Recommended");
  assert.ok(r.options.every((o) => o.matches));
  assert.ok(r.options[0].regex.includes("\\d{4}"));
  const h = W.eng.regexgen.generate("d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(h.options[0].label, "Exact hash");
  assert.equal(W.eng.regexgen.test("ab\\d+", "x\nab12\nzz").hits[0].n, 2);
});

test("yaragen builds a valid rule from IOCs", () => {
  const r = W.eng.yaragen.fromIocs(REPORT);
  assert.ok(/^rule ioc_set_\d{8} : generated ioc/.test(r.rule));
  assert.ok(r.rule.includes('"update-cdn.ddns.net" ascii wide nocase'));
  assert.ok(r.rule.includes("any of them"));
  if (W.eng.yara) assert.ok(r.valid, (r.errors || []).join("; "));
  const t = W.eng.yaragen.build({ name: "9bad name!", strings: [{ type: "hex", value: "4D 5A ?? 00" }, { type: "regex", value: "a/b" }], condition_mode: "all", mz: true });
  assert.ok(t.startsWith("rule r_9bad_name_"));
  assert.ok(t.includes("{ 4D 5A ?? 00 }") && t.includes("/a\\/b/"));
  assert.ok(t.includes("(all of them) and uint16(0) == 0x5A4D"));
});

test("stix ids are deterministic UUIDv5 (Katana-compatible)", async () => {
  // Katana: uuid5(NS, "indicator:[ipv4-addr:value = '1.2.3.4']") with NS 1b9f0e4a-…; verified against Python's uuid.uuid5
  const a = await W.eng.stix.bundle([{ value: "1.2.3.4", type: "ipv4" }, { value: "CVE-2024-3400" }, { value: "nonsense value" }], { tlp: "green" });
  const b = await W.eng.stix.bundle([{ value: "1.2.3.4" }], {});
  const indA = a.bundle.objects.find((o) => o.type === "indicator"), indB = b.bundle.objects.find((o) => o.type === "indicator");
  assert.equal(indA.id, indB.id);
  assert.match(indA.id, /^indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(indA.pattern, "[ipv4-addr:value = '1.2.3.4']");
  assert.equal(a.stats.vulnerabilities, 1);
  assert.equal(a.stats.skipped, 1);
  assert.equal(await W.eng.stix.uuid5("python.org", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"), "886313e1-3b8a-5372-9b90-0c9aee199e5d");
  // the exact id Katana's Python produces for this indicator (uuid.uuid5(NS, "indicator:[ipv4-addr:value = '1.2.3.4']"))
  assert.equal(indA.id, "indicator--31d015c8-4e77-51f7-871d-6d3c072e04d0");
});

test("workbench: ATT&CK labelled vs inferred + attribution", () => {
  const atk = W.eng.workbench.attack(REPORT), ids = Object.fromEntries(atk.map((t) => [t.id, t]));
  assert.equal(ids["T1566.002"].inferred, false);
  assert.equal(ids["T1059.001"].inferred, false);
  for (const t of ["T1003.001", "T1486", "T1490", "T1574.002", "T1218.011", "T1055"]) assert.ok(ids[t] && ids[t].inferred, t);
  const a = W.eng.workbench.attribution(REPORT);
  assert.ok(a.actors.includes("APT29 (Cozy Bear)"));
  assert.ok(!a.actors.includes("APT29"), "no duplicate designator");
  assert.ok(a.malware.includes("cobalt strike") && a.malware.includes("mimikatz"));
  assert.match(W.eng.workbench.attribution("a commodity loader beacons to 1.2.3.4").note, /unattributed/);
});

test("workbench.enrich builds signatures, STIX and a case", async () => {
  const r = await W.eng.workbench.enrich({ text: REPORT });
  assert.ok(r.sigma.rule.includes("message|contains") && r.sigma.rule.includes("CommandLine|contains"));
  if (W.eng.sigma) assert.ok(r.sigma.valid, r.sigma.errors.join("; "));
  assert.equal(r.sigma.fp.level, "low");
  assert.ok(r.yara.rule.includes("CozyMutex_v2"), "host artifacts folded into YARA");
  const types = r.stix.bundle.objects.reduce((m, o) => ((m[o.type] = (m[o.type] || 0) + 1), m), {});
  assert.equal(types["intrusion-set"], 1);
  assert.ok(types["attack-pattern"] >= 8 && types.relationship >= 8 && types.indicator >= 3);
  assert.ok(r.case.name.startsWith("APT29 (Cozy Bear)"));
  assert.ok(r.case.items.some((i) => i.value === "update-cdn.ddns.net"));
  assert.ok(r.attack.tactics.length >= 5);
});

test("stripHtml keeps article text, drops scripts", () => {
  const t = W.eng.workbench.stripHtml("<html><head><title>x</title></head><body><p>Beacons to evil.com &amp; 1.2.3.4</p><script>evil()</script></body></html>");
  assert.ok(t.includes("Beacons to evil.com & 1.2.3.4"));
  assert.ok(!t.includes("evil()"));
});

// ---- triage over hand-built fixtures
function tinyPE() {
  const b = new Uint8Array(1024), v = new DataView(b.buffer);
  b[0] = 0x4d; b[1] = 0x5a; v.setUint32(0x3c, 0x40, true);
  b.set([0x50, 0x45, 0, 0], 0x40);
  v.setUint16(0x44, 0x14c, true); v.setUint16(0x46, 1, true); v.setUint32(0x48, 1700000000, true);
  v.setUint16(0x54, 224, true); v.setUint16(0x56, 0x0102, true);
  const opt = 0x58; v.setUint16(opt, 0x10b, true); v.setUint32(opt + 16, 0x1000, true); v.setUint16(opt + 68, 2, true); v.setUint32(opt + 92, 16, true);
  const sec = opt + 224; b.set([0x55, 0x50, 0x58, 0x30], sec);                                // "UPX0"
  v.setUint32(sec + 8, 0x1000, true); v.setUint32(sec + 12, 0x1000, true); v.setUint32(sec + 16, 0, true); v.setUint32(sec + 20, 0x200, true);
  v.setUint32(sec + 36, 0xe0000020, true);                                                     // code | exec | read | write
  const s = new TextEncoder().encode("powershell -enc ZQBj VirtualAlloc http://evil-c2.example/gate.php");
  b.set(s, 0x300);
  return b;
}
test("triage parses a PE and scores it", async () => {
  const r = await W.eng.triage.analyze(tinyPE(), "invoice.pdf");
  assert.equal(r.type, "PE / DOS executable");
  assert.equal(r.details.Machine, "x86");
  assert.equal(r.details.Kind, "EXE");
  assert.ok(r.flags.includes("Executable masquerading as .pdf"));
  assert.ok(r.flags.includes("Packer section names present"));
  assert.ok(r.flags.includes("Writable + executable section"));
  assert.ok(r.flags.some((f) => f.startsWith("Entry point in a writable section")));
  assert.ok(r.iocs.domain.includes("evil-c2.example"));
  assert.ok(r.suspicious["Windows execution"].includes("powershell"));
  assert.equal(r.indicators.band, "malicious indicators");
});

function storedZip(files) {   // ZIP with stored (method 0) entries
  const enc = new TextEncoder(), parts = [], cd = []; let off = 0;
  for (const [name, text] of files) {
    const n = enc.encode(name), d = enc.encode(text), lh = new Uint8Array(30 + n.length), lv = new DataView(lh.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint32(18, d.length, true); lv.setUint32(22, d.length, true); lv.setUint16(26, n.length, true); lh.set(n, 30);
    const ch = new Uint8Array(46 + n.length), cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint32(20, d.length, true); cv.setUint32(24, d.length, true); cv.setUint16(28, n.length, true); cv.setUint32(42, off, true); ch.set(n, 46);
    parts.push(lh, d); cd.push(ch); off += lh.length + d.length;
  }
  const cdLen = cd.reduce((n, c) => n + c.length, 0), eocd = new Uint8Array(22), ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, files.length, true); ev.setUint16(10, files.length, true); ev.setUint32(12, cdLen, true); ev.setUint32(16, off, true);
  const all = [...parts, ...cd, eocd], out = new Uint8Array(all.reduce((n, p) => n + p.length, 0)); let p = 0; for (const x of all) { out.set(x, p); p += x.length; }
  return out;
}
test("triage flags macro + remote-template Office docs", async () => {
  const z = storedZip([["[Content_Types].xml", "<Types/>"], ["word/vbaProject.bin", "VBA"],
    ["word/_rels/settings.xml.rels", '<Relationship Target="https://evil.example/t.dotm" TargetMode="External"/>'], ["invoice.pdf.exe", "MZ"]]);
  const r = await W.eng.triage.analyze(z, "invoice.docm");
  assert.equal(r.type, "Office Open XML");
  assert.ok(r.flags.includes("Contains VBA macros (vbaProject.bin)"));
  assert.ok(r.flags.some((f) => f.startsWith("External relationship targets")));
  assert.ok(r.flags.some((f) => f.startsWith("Double-extension")));
  assert.deepEqual(r.details["External targets"], ["https://evil.example/t.dotm"]);
});

test("transforms chain: b64 → xor → hex, gzip round trip, PowerShell -enc", async () => {
  const T = W.eng.transforms;
  let r = await T.run(W.b64("hello"), [{ op: "from_b64" }, { op: "xor", arg: "0x01" }, { op: "to_hex" }]);
  assert.equal(W.utf8(r.output), "69646d6d6e");
  r = await T.run("round trip ✓", [{ op: "gzip" }, { op: "gunzip" }]);
  assert.equal(W.utf8(r.output), "round trip ✓");
  const enc = W.b64(new Uint8Array([...new TextEncoder().encode("whoami")].flatMap((c) => [c, 0])));
  r = await T.run("powershell -enc " + enc, [{ op: "ps_decode" }]);
  assert.equal(W.utf8(r.output), "whoami");
  r = await T.run("x", [{ op: "from_hex" }, { op: "nope" }]);
  assert.equal(r.steps[1].ok, false);
  assert.equal(T.suggest("powershell -enc SQBFAFgA"), "ps_decode");
});

test("pivot builds link groups by type", () => {
  const ip = W.eng.pivot.links("185[.]220[.]101[.]5");
  assert.equal(ip.type, "ipv4");
  assert.ok(ip.groups.reputation.some((l) => l.url === "https://www.abuseipdb.com/check/185.220.101.5"));
  const u = W.eng.pivot.links("@some_handle");
  assert.equal(u.type, "username");
  assert.ok(u.groups.persona.some((l) => l.url === "https://github.com/some_handle"));
  assert.equal(W.eng.pivot.links("T1059.001").groups.intel[0].url, "https://attack.mitre.org/techniques/T1059/001/");
});
