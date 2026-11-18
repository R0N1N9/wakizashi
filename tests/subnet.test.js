// Subnet engine: IPv4/IPv6 parsing + formatting, CIDR details, split, aggregate, supernet, ranges.
{
const SN = W.eng.subnet;

test("subnet: parse + format IPv4 / IPv6 (RFC 5952)", () => {
  assert.equal(SN.parseIP("192.168.1.10").n, 3232235786n);
  assert.equal(SN.parseIP("256.1.1.1"), null);
  assert.equal(SN.parseIP("01.2.3.4"), null);
  const cases = {
    "2001:0db8:0000:0000:0000:ff00:0042:8329": "2001:db8::ff00:42:8329",
    "2001:db8:0:0:1:0:0:1": "2001:db8::1:0:0:1",           // leftmost of equal runs
    "2001:db8:0:1:1:1:1:1": "2001:db8:0:1:1:1:1:1",          // single zero group not compressed
    "::": "::", "::1": "::1", "FE80::1%eth0": "fe80::1", "[2001:db8::1]": "2001:db8::1",
    "::ffff:192.0.2.128": "::ffff:c000:280", "1:0:0:0:0:0:0:0": "1::",
  };
  for (const [i, o] of Object.entries(cases)) { const p = SN.parseIP(i); assert.ok(p, i); assert.equal(p.v, 6); assert.equal(SN.formatIPv6(p.n), o, i); }
  for (const bad of ["1::2::3", "12345::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", ":::", "g::1", "1.2.3.4::"]) assert.equal(SN.parseIP(bad), null, bad);
  assert.equal(SN.formatIPv6(SN.parseIP("2001:db8::1").n, true), "2001:0db8:0000:0000:0000:0000:0000:0001");
});

test("subnet: IPv4 details", () => {
  const i = SN.info("192.168.10.77/26");
  assert.equal(i.network, "192.168.10.64");
  assert.equal(i.broadcast, "192.168.10.127");
  assert.equal(i.first, "192.168.10.65");
  assert.equal(i.lastHost, "192.168.10.126");
  assert.equal(i.hosts, 62n);
  assert.equal(i.total, 64n);
  assert.equal(i.netmask, "255.255.255.192");
  assert.equal(i.wildcard, "0.0.0.63");
  assert.equal(i.type, "Private (RFC 1918)");
  assert.equal(i.cls, "C");
  assert.equal(i.hostBits, true);
  assert.equal(i.binary.netmask, "11111111.11111111.11111111.11000000");
  assert.equal(i.arpa, "77.10.168.192.in-addr.arpa");
  const p2p = SN.info("10.0.0.0/31");
  assert.equal(p2p.hosts, 2n); assert.equal(p2p.broadcast, null); assert.equal(p2p.first, "10.0.0.0"); assert.equal(p2p.lastHost, "10.0.0.1");
  const one = SN.info("8.8.8.8");
  assert.equal(one.bits, 32); assert.equal(one.hosts, 1n); assert.equal(one.type, "Public");
  assert.equal(SN.info("0.0.0.0/0").total, 4294967296n);
  assert.throws(() => SN.info("10.0.0.0/33"));
  assert.throws(() => SN.info("nope"));
});

test("subnet: IPv6 details", () => {
  const i = SN.info("2001:db8:abcd:12::1/48");
  assert.equal(i.network, "2001:db8:abcd::");
  assert.equal(i.last, "2001:db8:abcd:ffff:ffff:ffff:ffff:ffff");
  assert.equal(i.total, 1n << 80n);
  assert.equal(i.slash64s, 65536n);
  assert.equal(i.type, "Documentation");
  assert.equal(i.netmask, "ffff:ffff:ffff::");
  assert.equal(SN.info("fe80::1/64").type, "Link-local");
  assert.equal(SN.info("fd12:3456::/48").type, "Unique local (ULA)");
  assert.equal(SN.info("2606:4700::1111").type, "Global unicast");
  assert.ok(SN.info("2001:db8::1").arpa.startsWith("1.0.0.0."));
  assert.ok(SN.info("2001:db8::1").arpa.endsWith("8.b.d.0.1.0.0.2.ip6.arpa"));
});

test("subnet: split by prefix and by count", () => {
  const s = SN.split("10.0.0.0/24", 26);
  assert.equal(s.count, 4n);
  assert.deepEqual(s.list.map((x) => x.cidr), ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"]);
  assert.equal(s.list[3].last, "10.0.0.255");
  const c = SN.splitCount("172.16.0.0/16", 5);          // needs 3 extra bits → 8 subnets
  assert.equal(c.bits, 19); assert.equal(c.count, 8n);
  const big = SN.split("10.0.0.0/8", 30);
  assert.equal(big.count, 4194304n); assert.equal(big.truncated, true); assert.equal(big.list.length, SN.LIST_MAX);
  const v6 = SN.split("2001:db8::/32", 34);
  assert.deepEqual(v6.list.map((x) => x.cidr), ["2001:db8::/34", "2001:db8:4000::/34", "2001:db8:8000::/34", "2001:db8:c000::/34"]);
  assert.throws(() => SN.split("10.0.0.0/24", 23));
});

test("subnet: range ↔ CIDR", () => {
  assert.deepEqual(SN.rangeToCidrs("192.168.1.0", "192.168.1.255"), ["192.168.1.0/24"]);
  assert.deepEqual(SN.rangeToCidrs("10.0.0.5", "10.0.0.20"), ["10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/29", "10.0.0.16/30", "10.0.0.20/32"]);
  assert.deepEqual(SN.rangeToCidrs("0.0.0.0", "255.255.255.255"), ["0.0.0.0/0"]);
  assert.deepEqual(SN.rangeToCidrs("2001:db8::", "2001:db8::ff"), ["2001:db8::/120"]);
  assert.throws(() => SN.rangeToCidrs("10.0.0.1", "::1"));
  assert.deepEqual(SN.cidrToRange("10.1.2.0/23"), { v: 4, start: "10.1.2.0", end: "10.1.3.255", size: 512n });
  const r = SN.parseRange("10.0.0.5-40");
  assert.equal(SN.formatIP(4, r.end), "10.0.0.40");
  assert.ok(SN.parseRange("2001:db8::1 - 2001:db8::9"));
});

test("subnet: aggregate + supernet", () => {
  const a = SN.aggregate(["10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24", "10.0.3.0/24", "10.0.3.7", "bogus", "2001:db8::/33", "2001:db8:8000::/33"]);
  assert.deepEqual(a.cidrs, ["10.0.0.0/23", "10.0.3.0/24", "2001:db8::/32"]);
  assert.deepEqual(a.invalid, ["bogus"]);
  const s = SN.supernet(["192.168.0.0/24", "192.168.3.0/24"]);
  assert.equal(s.supernets[0].cidr, "192.168.0.0/22");
  assert.equal(s.supernets[0].extra, 512n);
  assert.equal(SN.supernet(["10.0.0.1", "10.0.0.1"]).supernets[0].cidr, "10.0.0.1/32");
});
}
