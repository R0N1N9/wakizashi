// BLOCK countermeasure builder — mirrors Katana tests/test_defense.py::TestBlock plus safety cases.
const K = W.eng.block;

test("classify + safety (Katana test_classify_and_safety)", () => {
  const c = K.classify('1.2.3.4 10.0.0.1 evil[.]com hxxps://bad.example/x"; 0.0.0.0/0 d41d8cd98f00b204e9800998ecf8427e');
  assert.deepEqual(c.ipv4, ["1.2.3.4"]);
  assert.deepEqual(c.domain, ["evil.com"]);
  assert.deepEqual(c.md5, ["d41d8cd98f00b204e9800998ecf8427e"]);
  assert.deepEqual(c.url, ["https://bad.example/x"]);              // trailing quote / ; stripped
  assert.deepEqual(K.classify('https://bad.example/a"b\\c').url, []); // embedded quote rejected
  assert.ok(c.rejected.some((r) => r.includes("0.0.0.0/0")));
  assert.ok(c.rejected.some((r) => r.includes("10.0.0.1")));
});

test("all formats produce output (Katana test_all_formats) + STIX bundle", () => {
  for (const f of K.FORMATS) {
    const out = K.generate("1.2.3.4 2001:4860::8888 evil.com https://bad.example/p?q=1 44d88612fea8a8f36de82e1278abb02f", f.id);
    assert.ok(out.output.trim(), f.id);
    assert.equal(out.ext, f.ext);
  }
  const stix = JSON.parse(K.generate("1.2.3.4 evil.com", "stix").output);
  assert.equal(stix.objects.length, 2);
  assert.equal(stix.type, "bundle");
  assert.ok(/^indicator--[0-9a-f-]{36}$/.test(stix.objects[0].id));
});

test("fixture list: refang, dedupe, cidr normalisation, IPv6 canonical form, private toggle", () => {
  const txt = fixture("yoroi-b-indicators.txt");
  const c = K.classify(txt);
  assert.deepEqual(c.ipv4, ["185.220.101.4", "45.9.148.108"]);
  assert.deepEqual(c.cidr, ["91.92.240.0/22"]);
  assert.deepEqual(c.ipv6, ["2001:4860::8888"]);
  assert.deepEqual(c.domain, ["cdn-update.top", "login-micros0ft.com"]);
  assert.deepEqual(c.sha256, ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]);
  assert.ok(c.url_hosts.includes("paypa1-secure.top"));
  assert.ok(c.rejected.some((r) => r.startsWith("192.168.1.10")));
  assert.ok(c.rejected.some((r) => r.startsWith("fe80::1")));
  assert.ok(c.rejected.some((r) => r.startsWith("::/0")));
  assert.ok(c.rejected.some((r) => r.startsWith("not_an_indicator")));
  const p = K.classify(txt, { allowPrivate: true });
  assert.ok(p.ipv4.includes("192.168.1.10"));
  assert.ok(p.ipv6.includes("fe80::1"));
});

test("IPv6 parsing / compression", () => {
  const t = (a) => K._v6str(K._parseV6(a));
  assert.equal(t("2001:0db8:0000:0000:0000:ff00:0042:8329"), "2001:db8::ff00:42:8329");
  assert.equal(t("::1"), "::1");
  assert.equal(t("1:0:0:2:0:0:0:3"), "1:0:0:2::3");
  assert.equal(t("::ffff:1.2.3.4"), "::ffff:102:304");
  assert.equal(K._parseV6("1::2::3"), null);
  assert.equal(K._parseV6("12345::"), null);
  assert.equal(K.classify("1.2.3.4/24").cidr[0], "1.2.3.0/24");      // strict=False
  assert.deepEqual(K.classify("01.2.3.4").ipv4, []);                  // leading zeros refused
});

test("nothing can break out of quoting", () => {
  const evil = ['evil.com";rm -rf /', "https://x.example/'$(id)", "https://x.example/a\\b", "<script>.com", "evil.com\nalert", "bad..com", "-evil.com"];
  for (const f of K.FORMATS) {
    const out = K.generate(evil.join(" "), f.id, 'my"tag;$(x)').output;
    assert.ok(!out.includes('";rm'), f.id);
    assert.ok(!out.includes("$(x)") && !out.includes('my"tag'), f.id + " tag sanitised");
    assert.ok(!out.includes("<script>"), f.id);
  }
  assert.equal(K.cleanTag('a b"c'), "a_b_c");
  // the single quote is legal in a URL; STIX must escape it
  const stix = JSON.parse(K.generate("https://x.example/it's", "stix").output);
  assert.equal(stix.objects[0].pattern, "[url:value = 'https://x.example/it\\'s']");
});

test("format details: iptables, cisco masks, suricata sids, sigma lists, mde expiry", () => {
  const now = new Date("2026-11-18T10:00:00Z");
  const ipt = K.generate("8.8.8.8 2001:4860::8888", "iptables", "op1", { now }).output;
  assert.ok(ipt.includes('iptables -I INPUT -s 8.8.8.8 -j DROP -m comment --comment "wkz:op1"'));
  assert.ok(ipt.includes("ip6tables -I OUTPUT -d 2001:4860::8888"));
  const asa = K.generate("8.8.8.8 91.92.240.0/22", "cisco", "op1").output;
  assert.ok(asa.includes(" network-object host 8.8.8.8") && asa.includes(" network-object 91.92.240.0 255.255.252.0"));
  const sur = K.generate("8.8.8.8 evil.com https://evil.com/a;b", "suricata", "t", { sid: 5000 }).output;
  assert.ok(sur.includes("sid:5000;") && sur.includes("sid:5003;"));
  assert.ok(sur.includes('http.uri; content:"/a";'));            // ';' is a separator, never reaches a rule
  const sig = K.generate("8.8.8.8 evil.com 44d88612fea8a8f36de82e1278abb02f", "sigma").output;
  assert.equal(sig.split("\n---\n").length, 3);
  assert.ok(sig.includes("            - 'evil.com'"));
  const mde = K.generate("evil.com", "mde", "t", { now, days: 30 }).output.split("\n");
  assert.ok(mde[1].startsWith("DomainName,evil.com,2026-12-18T10:00:00.0Z,Block,High"));
  assert.equal(K.generate("evil.com", "windows").output, "# no IP indicators");
  assert.throws(() => K.generate("x", "nope"), /unknown format/);
});

test("Sigma output round-trips through the sigma engine when present", () => {
  const S = W.eng.sigma;
  const fn = S && (S.compile || S.compileRules || S.parse);
  if (!fn) return;   // engine owned by another layer; skip if not loaded
  const out = K.generate("8.8.8.8 evil.com 44d88612fea8a8f36de82e1278abb02f", "sigma").output;
  const r = fn.call(S, out);
  const rules = (r && (r.rules || r[0])) || r;
  if (Array.isArray(rules)) assert.equal(rules.length, 3);
});
