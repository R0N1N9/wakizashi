/* Subnet engine — IPv4 + IPv6 address math on BigInt.
 *   parseIP("10.0.0.1") → {v:4, n:BigInt}      parseCidr("2001:db8::/32") → {v, bits, net, start, end, size}
 *   info(cidr)  split(cidr, prefix)  splitCount(cidr, n)  rangeToCidrs(a, b)  aggregate([...])  supernet([...])
 * Also the shared address primitives for W.eng.scope (formatIP, contains, overlaps). */
(function (W) {
  "use strict";
  const B = (x) => BigInt(x);
  const WIDTH = { 4: 32, 6: 128 };
  const ALL = { 4: (1n << 32n) - 1n, 6: (1n << 128n) - 1n };
  const LIST_MAX = 4096;

  // ------------------------------------------------------------------ parse / format
  function parseIPv4(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return null;
    let n = 0n;
    for (let i = 1; i <= 4; i++) {
      if (m[i].length > 1 && m[i][0] === "0") return null;          // no octal-looking octets
      const o = +m[i]; if (o > 255) return null;
      n = (n << 8n) | B(o);
    }
    return n;
  }
  function parseIPv6(s) {
    s = s.replace(/^\[|\]$/g, "").replace(/%[\w.-]+$/, "");            // brackets, zone id
    if (!/^[0-9a-f:.]+$/i.test(s) || !s.includes(":")) return null;
    let tail = [];
    const v4 = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
    if (v4) {
      const n = parseIPv4(v4[1]); if (n == null) return null;
      tail = [Number(n >> 16n), Number(n & 0xffffn)];
      s = s.slice(0, -v4[1].length);
      if (s.endsWith("::")) s += ""; else if (s.endsWith(":")) s = s.slice(0, -1); else return null;
      if (s === "") return null;
    }
    const dbl = s.split("::");
    if (dbl.length > 2) return null;
    const part = (x) => (x === "" ? [] : x.split(":"));
    const head = part(dbl[0]), rest = dbl.length === 2 ? part(dbl[1]) : [];
    for (const g of head.concat(rest)) if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    const groups = head.map((g) => parseInt(g, 16)), back = rest.map((g) => parseInt(g, 16)).concat(tail);
    const fill = 8 - groups.length - back.length;
    if (dbl.length === 2 ? fill < 1 : fill !== 0) return null;
    const all = groups.concat(new Array(dbl.length === 2 ? fill : 0).fill(0), back);
    let n = 0n; for (const g of all) n = (n << 16n) | B(g);
    return n;
  }
  /** {v, n} or null. Accepts IPv4, IPv6 (compressed, embedded v4, [brackets], %zone). */
  function parseIP(s) {
    s = String(s == null ? "" : s).trim();
    const n4 = parseIPv4(s); if (n4 != null) return { v: 4, n: n4 };
    const n6 = parseIPv6(s); if (n6 != null) return { v: 6, n: n6 };
    return null;
  }
  function formatIPv4(n) { return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join("."); }
  /** RFC 5952: lowercase, drop leading zeros, compress the longest (leftmost) run of ≥2 zero groups. */
  function formatIPv6(n, expanded) {
    const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> B(i * 16)) & 0xffffn));
    if (expanded) return g.map((x) => x.toString(16).padStart(4, "0")).join(":");
    let bs = -1, bl = 0;
    for (let i = 0; i < 8;) { if (g[i]) { i++; continue; } let j = i; while (j < 8 && !g[j]) j++; if (j - i > bl && j - i >= 2) { bs = i; bl = j - i; } i = j; }
    const hx = g.map((x) => x.toString(16));
    if (bs < 0) return hx.join(":");
    return hx.slice(0, bs).join(":") + "::" + hx.slice(bs + bl).join(":");
  }
  const formatIP = (v, n, expanded) => (v === 4 ? formatIPv4(n) : formatIPv6(n, expanded));

  const maskOf = (v, bits) => (bits === 0 ? 0n : (ALL[v] >> B(WIDTH[v] - bits)) << B(WIDTH[v] - bits));
  /** "a.b.c.d/nn" | "v6/nn" | bare address (→ /32 or /128). strict: host bits must be zero. */
  function parseCidr(s, strict) {
    s = String(s == null ? "" : s).trim();
    const m = /^(.+?)\/(\d{1,3})$/.exec(s);
    const ip = parseIP(m ? m[1] : s); if (!ip) return null;
    const bits = m ? +m[2] : WIDTH[ip.v];
    if (bits > WIDTH[ip.v]) return null;
    const mask = maskOf(ip.v, bits), net = ip.n & mask;
    if (strict && net !== ip.n) return null;
    const end = net | (ALL[ip.v] ^ mask);
    return { v: ip.v, bits, addr: ip.n, net, start: net, end, size: end - net + 1n, hostBits: ip.n !== net };
  }
  const cidrStr = (v, net, bits) => formatIP(v, net) + "/" + bits;

  // ------------------------------------------------------------------ classification
  const SPECIAL4 = [
    ["0.0.0.0/8", "This network"], ["10.0.0.0/8", "Private (RFC 1918)"], ["100.64.0.0/10", "Shared / CGNAT (RFC 6598)"],
    ["127.0.0.0/8", "Loopback"], ["169.254.0.0/16", "Link-local"], ["172.16.0.0/12", "Private (RFC 1918)"],
    ["192.0.0.0/24", "IETF protocol assignments"], ["192.0.2.0/24", "Documentation (TEST-NET-1)"], ["192.88.99.0/24", "6to4 relay (deprecated)"],
    ["192.168.0.0/16", "Private (RFC 1918)"], ["198.18.0.0/15", "Benchmarking"], ["198.51.100.0/24", "Documentation (TEST-NET-2)"],
    ["203.0.113.0/24", "Documentation (TEST-NET-3)"], ["224.0.0.0/4", "Multicast"], ["240.0.0.0/4", "Reserved"], ["255.255.255.255/32", "Limited broadcast"],
  ];
  const SPECIAL6 = [
    ["::/128", "Unspecified"], ["::1/128", "Loopback"], ["::ffff:0:0/96", "IPv4-mapped"], ["64:ff9b::/96", "NAT64"], ["100::/64", "Discard-only"],
    ["2001::/32", "Teredo"], ["2001:db8::/32", "Documentation"], ["2002::/16", "6to4"], ["fc00::/7", "Unique local (ULA)"],
    ["fe80::/10", "Link-local"], ["ff00::/8", "Multicast"], ["2000::/3", "Global unicast"],
  ];
  let special;
  function classify(v, n) {
    special = special || { 4: SPECIAL4.map(([c, l]) => [parseCidr(c), l]), 6: SPECIAL6.map(([c, l]) => [parseCidr(c), l]) };
    for (const [c, l] of special[v]) if (n >= c.start && n <= c.end) return l;
    return v === 4 ? "Public" : "Reserved / unassigned";
  }
  function ipv4Class(n) {
    const o = Number(n >> 24n);
    return o < 128 ? "A" : o < 192 ? "B" : o < 224 ? "C" : o < 240 ? "D (multicast)" : "E (reserved)";
  }
  const bin = (v, n) => {
    const s = n.toString(2).padStart(WIDTH[v], "0");
    return (s.match(v === 4 ? /.{8}/g : /.{16}/g)).join(v === 4 ? "." : ":");
  };

  // ------------------------------------------------------------------ details
  /** Full details of a CIDR (or bare address). Throws on invalid input. */
  function info(input) {
    const c = parseCidr(input);
    if (!c) throw new Error(`not an IPv4/IPv6 address or CIDR: ${String(input).slice(0, 80)}`);
    const { v, bits, net, end } = c;
    const mask = maskOf(v, bits), wild = ALL[v] ^ mask;
    const o = {
      v, bits, input: String(input).trim(), cidr: cidrStr(v, net, bits), address: formatIP(v, c.addr), hostBits: c.hostBits,
      network: formatIP(v, net), last: formatIP(v, end), total: c.size, type: classify(v, c.addr),
    };
    if (v === 4) {
      // RFC 3021: /31 has two usable hosts and no broadcast; /32 is a single host.
      const p2p = bits >= 31;
      Object.assign(o, {
        netmask: formatIPv4(mask), wildcard: formatIPv4(wild), broadcast: p2p ? null : formatIPv4(end),
        first: formatIPv4(p2p ? net : net + 1n), lastHost: formatIPv4(p2p ? end : end - 1n),
        hosts: bits === 32 ? 1n : bits === 31 ? 2n : c.size - 2n, cls: ipv4Class(c.addr),
        hex: "0x" + c.addr.toString(16).padStart(8, "0"), int: c.addr.toString(),
        binary: { address: bin(4, c.addr), netmask: bin(4, mask), network: bin(4, net), broadcast: bin(4, end) },
        arpa: formatIPv4(c.addr).split(".").reverse().join(".") + ".in-addr.arpa",
      });
    } else {
      Object.assign(o, {
        expanded: formatIPv6(c.addr, true), networkExpanded: formatIPv6(net, true), lastExpanded: formatIPv6(end, true),
        netmask: formatIPv6(mask), first: formatIPv6(net), lastHost: formatIPv6(end), hosts: c.size,
        binary: { address: bin(6, c.addr), netmask: bin(6, mask) },
        arpa: formatIPv6(c.addr, true).replace(/:/g, "").split("").reverse().join(".") + ".ip6.arpa",
        slash64s: bits <= 64 ? 1n << B(64 - bits) : 0n,
      });
    }
    return o;
  }

  // ------------------------------------------------------------------ split / aggregate / ranges
  /** Split a CIDR into subnets of newBits. Returns {count, list (≤ LIST_MAX), truncated}. */
  function split(input, newBits, max = LIST_MAX) {
    const c = parseCidr(input); if (!c) throw new Error("invalid CIDR");
    newBits = +newBits;
    if (!Number.isInteger(newBits) || newBits < c.bits || newBits > WIDTH[c.v]) throw new Error(`new prefix must be between /${c.bits} and /${WIDTH[c.v]}`);
    const count = 1n << B(newBits - c.bits), step = 1n << B(WIDTH[c.v] - newBits);
    const list = [];
    for (let i = 0n; i < count && list.length < max; i++) {
      const s = c.net + i * step;
      list.push({ cidr: cidrStr(c.v, s, newBits), first: formatIP(c.v, s), last: formatIP(c.v, s + step - 1n) });
    }
    return { v: c.v, parent: cidrStr(c.v, c.net, c.bits), bits: newBits, count, size: step, list, truncated: count > B(list.length) };
  }
  /** Split into at least n equal subnets. */
  function splitCount(input, n, max) {
    const c = parseCidr(input); if (!c) throw new Error("invalid CIDR");
    n = Math.max(1, Math.floor(+n || 1));
    const add = Math.ceil(Math.log2(n));
    if (c.bits + add > WIDTH[c.v]) throw new Error(`/${c.bits} cannot be split into ${n} subnets`);
    return split(input, c.bits + add, max);
  }
  /** Minimal CIDR list covering exactly [a, b] (inclusive; BigInt or address strings). */
  function rangeToCidrs(a, b) {
    let v;
    if (typeof a !== "bigint") { const p = parseIP(a), q = parseIP(b); if (!p || !q) throw new Error("invalid address in range"); if (p.v !== q.v) throw new Error("range mixes IPv4 and IPv6"); v = p.v; a = p.n; b = q.n; }
    else v = arguments[2] || 4;
    if (a > b) [a, b] = [b, a];
    const out = [], W_ = B(WIDTH[v]);
    while (a <= b) {
      let size = 0n;                                       // largest block aligned at a that fits
      while (size < W_ && ((a >> size) & 1n) === 0n && a + (1n << (size + 1n)) - 1n <= b) size++;
      out.push(cidrStr(v, a, Number(W_ - size)));
      a += 1n << size;
      if (out.length > 100000) throw new Error("range too fragmented");
    }
    return out;
  }
  /** Parse "a - b", "a-b", or IPv4 shorthand "10.0.0.5-40" into {v, start, end}. */
  function parseRange(s) {
    s = String(s || "").trim();
    const m = /^([0-9a-f:.[\]%]+)\s*[-–]\s*([0-9a-f:.[\]%]+)$/i.exec(s);
    if (!m) return null;
    const p = parseIP(m[1]); if (!p) return null;
    let q = parseIP(m[2]);
    if (!q && p.v === 4 && /^\d{1,3}$/.test(m[2]) && +m[2] <= 255) q = { v: 4, n: (p.n & ~255n) | B(+m[2]) };
    if (!q || q.v !== p.v) return null;
    return { v: p.v, start: p.n < q.n ? p.n : q.n, end: p.n < q.n ? q.n : p.n };
  }
  const cidrToRange = (input) => { const c = parseCidr(input); if (!c) throw new Error("invalid CIDR"); return { v: c.v, start: formatIP(c.v, c.start), end: formatIP(c.v, c.end), size: c.size }; };

  function toIntervals(items) {
    const iv = { 4: [], 6: [] }, bad = [];
    for (const raw of items) {
      const s = String(raw).trim(); if (!s) continue;
      const c = parseCidr(s) || parseRange(s);
      if (!c) bad.push(s); else iv[c.v].push([c.start, c.end]);
    }
    for (const v of [4, 6]) {
      iv[v].sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0));
      const m = [];
      for (const [s, e] of iv[v]) { const l = m[m.length - 1]; if (l && s <= l[1] + 1n) { if (e > l[1]) l[1] = e; } else m.push([s, e]); }
      iv[v] = m;
    }
    return { iv, bad };
  }
  /** Summarise CIDRs/ranges/addresses into the minimal set of CIDRs (merges adjacent + overlapping). */
  function aggregate(items) {
    const { iv, bad } = toIntervals(items);
    const out = [];
    for (const v of [4, 6]) for (const [s, e] of iv[v]) out.push(...rangeToCidrs(s, e, v));
    return { cidrs: out, invalid: bad };
  }
  /** Smallest single CIDR that covers every input (per family), with how much extra space it pulls in. */
  function supernet(items) {
    const { iv, bad } = toIntervals(items);
    const res = [];
    for (const v of [4, 6]) {
      if (!iv[v].length) continue;
      const lo = iv[v][0][0], hi = iv[v][iv[v].length - 1][1];
      let bits = WIDTH[v];
      while (bits > 0 && (lo & maskOf(v, bits)) !== (hi & maskOf(v, bits))) bits--;
      const net = lo & maskOf(v, bits), size = 1n << B(WIDTH[v] - bits);
      const covered = iv[v].reduce((n, [s, e]) => n + e - s + 1n, 0n);
      res.push({ v, cidr: cidrStr(v, net, bits), bits, size, covered, extra: size - covered });
    }
    return { supernets: res, invalid: bad };
  }

  const contains = (outer, inner) => outer.v === inner.v && inner.start >= outer.start && inner.end <= outer.end;
  const overlaps = (a, b) => a.v === b.v && a.start <= b.end && b.start <= a.end;

  W.eng.subnet = { parseIP, parseIPv4, parseIPv6, formatIP, formatIPv4, formatIPv6, parseCidr, parseRange, cidrStr, maskOf,
    info, split, splitCount, rangeToCidrs, cidrToRange, aggregate, supernet, classify, contains, overlaps, WIDTH, LIST_MAX };
})(typeof window !== "undefined" ? window.W : globalThis.W);
