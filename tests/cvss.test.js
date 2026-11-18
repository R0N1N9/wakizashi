// CVSS v3.1: base scores from the FIRST v3.1 specification examples document + well-known CVEs.
{
const CV = W.eng.cvss;
const KNOWN = JSON.parse(fixture("naginata-cvss.json"));

test("cvss: Roundup per spec", () => {
  assert.equal(CV.roundup(4.02), 4.1);
  assert.equal(CV.roundup(4.0), 4.0);
  assert.equal(CV.roundup(4.000000000000001), 4.0);   // float noise must not bump a whole tenth
  assert.equal(CV.roundup(0), 0);
});

test("cvss: published base scores", () => {
  for (const [vec, want, sev] of KNOWN.base) {
    const r = CV.score(vec);
    assert.equal(r.base, want, vec);
    assert.equal(r.baseSeverity, sev, vec);
  }
});

test("cvss: temporal + environmental", () => {
  for (const [vec, t, e] of KNOWN.extended) {
    const r = CV.score(vec);
    assert.equal(r.temporal, t, "temporal " + vec);
    assert.equal(r.environmental, e, "environmental " + vec);
  }
  // environmental with nothing modified equals the temporal score
  const r = CV.score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N/E:F/RL:W/RC:R");
  assert.equal(r.environmental, r.temporal);
  assert.equal(r.overall, r.temporal);
});

test("cvss: parse + vector round-trip and errors", () => {
  const p = CV.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/MAV:L");
  assert.ok(p.ok);
  assert.equal(CV.vector(p.metrics), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:L");
  // order-insensitive input, canonical output
  assert.equal(CV.score("A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N").vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  assert.equal(CV.parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").version, "3.0");
  const bad = CV.parse("CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/ZZ:1/AC:H");
  assert.ok(!bad.ok);
  assert.ok(bad.errors.some((e) => /invalid value/.test(e)));
  assert.ok(bad.errors.some((e) => /unknown metric/.test(e)));
  assert.ok(bad.errors.some((e) => /duplicate/.test(e)));
  assert.ok(bad.errors.some((e) => /missing base metric A/.test(e)) && bad.errors.some((e) => /missing base metric AV/.test(e)));
  assert.ok(!CV.parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N").ok);
  assert.throws(() => CV.score("AV:N"));
  assert.equal(CV.severity(0), "None"); assert.equal(CV.severity(3.9), "Low"); assert.equal(CV.severity(7), "High"); assert.equal(CV.severity(9), "Critical");
});
}
