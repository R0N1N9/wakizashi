/* BLOCK — turn indicators into ready-to-deploy countermeasures (port of Katana defense/block.py).
 *
 *   W.eng.block.classify(text, {allowPrivate}) → {ipv4, ipv6, cidr, domain, url, md5, sha1, sha256, url_hosts, rejected}
 *   W.eng.block.generate(text, fmt, tag, {allowPrivate, sid, days}) → {format, label, output, ext, counts, rejected}
 *   W.eng.block.FORMATS  [{id, label, group, ext}]
 *
 * Inputs are strictly validated so nothing in a generated rule can break out of its quoting:
 * domains/hashes/IPs must match strict grammars, URLs must be RFC 3986 characters only with no quote
 * or backslash, tags are reduced to [A-Za-z0-9_-]. 0.0.0.0/0 and ::/0 are refused.
 */
(function (W) {
  "use strict";

  const RE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})$/;
  const RE_HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/;
  const RE_SAFE_URL = /^https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/;

  // ------------------------------------------------------------------ IP parsing (ipaddress-like)
  function parseV4(s) {
    const p = String(s).split(".");
    if (p.length !== 4) return null;
    let n = 0;
    for (const x of p) {
      if (!/^\d{1,3}$/.test(x) || (x.length > 1 && x[0] === "0") || +x > 255) return null;   // no octal-looking octets
      n = n * 256 + +x;
    }
    return n >>> 0;
  }
  const v4str = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
  /** IPv6 → array of 8 hextets, or null. Accepts :: compression and trailing dotted IPv4. */
  function parseV6(s) {
    s = String(s).toLowerCase();
    if (!/^[0-9a-f:.]+$/.test(s) || s.length > 45) return null;
    let tail = [];
    const lastColon = s.lastIndexOf(":");
    if (s.includes(".")) {
      const v4 = parseV4(s.slice(lastColon + 1));
      if (v4 == null) return null;
      tail = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
      s = s.slice(0, lastColon + 1);
      if (!s.endsWith("::")) s = s.slice(0, -1);
    }
    const dbl = s.split("::");
    if (dbl.length > 2) return null;
    const part = (x) => (x === "" ? [] : x.split(":"));
    const head = part(dbl[0]), rest = dbl.length === 2 ? part(dbl[1]) : [];
    for (const h of head.concat(rest)) if (!/^[0-9a-f]{1,4}$/.test(h)) return null;
    const total = head.length + rest.length + tail.length;
    let out;
    if (dbl.length === 2) { if (total > 7) return null; out = head.concat(Array(8 - total).fill("0"), rest); }
    else { if (total !== 8) return null; out = head; }
    return out.map((h) => parseInt(h, 16)).concat(tail);
  }
  /** RFC 5952 canonical text (what Python's str(IPv6Address) prints). */
  function v6str(h) {
    let best = -1, bestLen = 0;
    for (let i = 0; i < 8;) {
      if (h[i] !== 0) { i++; continue; }
      let j = i; while (j < 8 && h[j] === 0) j++;
      if (j - i > bestLen) { best = i; bestLen = j - i; }
      i = j;
    }
    const hx = h.map((x) => x.toString(16));
    if (bestLen < 2) return hx.join(":");
    return hx.slice(0, best).join(":") + "::" + hx.slice(best + bestLen).join(":");
  }
  function inV4(n, net, bits) { const mask = bits ? (0xffffffff << (32 - bits)) >>> 0 : 0; return ((n & mask) >>> 0) === ((net & mask) >>> 0); }
  const V4_NONGLOBAL = [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
    ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
    ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]].map(([a, b]) => [parseV4(a), b]);
  const v4Global = (n) => !V4_NONGLOBAL.some(([net, b]) => inV4(n, net, b));
  function inV6(h, net, bits) {
    for (let i = 0; i < 8 && bits > 0; i++, bits -= 16) {
      const m = bits >= 16 ? 0xffff : (0xffff << (16 - bits)) & 0xffff;
      if ((h[i] & m) !== (net[i] & m)) return false;
    }
    return true;
  }
  const V6_NONGLOBAL = [["2001::", 23], ["2001:db8::", 32], ["2002::", 16]].map(([a, b]) => [parseV6(a), b]);
  const v6Global = (h) => inV6(h, parseV6("2000::"), 3) && !V6_NONGLOBAL.some(([n, b]) => inV6(h, n, b));

  /** Parse "addr" or "addr/prefix" (strict=False → host bits are cleared). */
  function parseNet(v) {
    const [a, p, extra] = v.split("/");
    if (extra !== undefined || !/^\d{1,3}$/.test(p)) return null;
    const bits = +p;
    const n4 = parseV4(a);
    if (n4 != null) {
      if (bits > 32) return null;
      const mask = bits ? (0xffffffff << (32 - bits)) >>> 0 : 0;
      return { v: 4, net: (n4 & mask) >>> 0, bits, str: v4str((n4 & mask) >>> 0) + "/" + bits };
    }
    const h = parseV6(a);
    if (h && bits <= 128) {
      const o = h.map((x, i) => { const left = bits - i * 16; return left >= 16 ? x : left <= 0 ? 0 : x & ((0xffff << (16 - left)) & 0xffff); });
      return { v: 6, net: o, bits, str: v6str(o) + "/" + bits };
    }
    return null;
  }
  const v4mask = (bits) => v4str(bits ? (0xffffffff << (32 - bits)) >>> 0 : 0);

  const refang = (t) => W.refang(String(t || "")).replace(/h(?:xx|XX|\*\*)p(s?)(?=\[?:)/g, "http$1").replace(/\[\s*:\s*\/\/\s*\]/g, "://");

  // ------------------------------------------------------------------ classify
  function classify(text, opts) {
    const allowPrivate = !!(opts && (opts.allowPrivate || opts === true));
    const out = { ipv4: [], ipv6: [], cidr: [], domain: [], url: [], md5: [], sha1: [], sha256: [] };
    const rejected = [];
    for (const raw of refang(text).split(/[\s,;]+/)) {
      const v = raw.trim().replace(/^['"<>]+|['"<>]+$/g, "").replace(/\.+$/, "");
      if (!v) continue;
      const lv = v.toLowerCase();
      if (v.includes("/") && !lv.startsWith("http")) {
        const n = parseNet(v);
        if (n) {
          if (n.bits === 0) { rejected.push(v + " (refusing to block everything)"); continue; }
          out.cidr.push(n.str); continue;
        }
      } else {
        const n4 = parseV4(v);
        if (n4 != null) {
          if (!allowPrivate && !v4Global(n4)) { rejected.push(v + " (private/reserved - enable 'allow internal' to include)"); continue; }
          out.ipv4.push(v4str(n4)); continue;
        }
        const h6 = v.includes(":") && !lv.startsWith("http") ? parseV6(v.replace(/^\[|\]$/g, "")) : null;
        if (h6) {
          if (!allowPrivate && !v6Global(h6)) { rejected.push(v + " (private/reserved - enable 'allow internal' to include)"); continue; }
          out.ipv6.push(v6str(h6)); continue;
        }
      }
      if (RE_HASH.test(lv)) out[{ 32: "md5", 40: "sha1", 64: "sha256" }[lv.length]].push(lv);
      else if (lv.startsWith("http://") || lv.startsWith("https://")) {
        if (RE_SAFE_URL.test(v) && !v.includes('"') && !v.includes("\\")) out.url.push(v);
        else rejected.push(v.slice(0, 80) + " (unsafe characters)");
      } else if (RE_DOMAIN.test(lv)) out.domain.push(lv);
      else rejected.push(v.slice(0, 80));
    }
    for (const k of Object.keys(out)) out[k] = [...new Set(out[k])].sort();
    const hosts = new Set(out.url.map((u) => u.replace(/^https?:\/\/(?:[^/@?#]*@)?([^/:?#]+).*$/i, "$1").toLowerCase()));
    out.url_hosts = [...hosts].filter((h) => !out.domain.includes(h)).sort();
    out.rejected = rejected;
    return out;
  }

  // ------------------------------------------------------------------ helpers
  const ips = (c) => c.ipv4.concat(c.ipv6, c.cidr);
  const domains = (c, withUrlHosts = true) => c.domain.concat(withUrlHosts ? c.url_hosts.filter((h) => RE_DOMAIN.test(h)) : []);
  const isV6 = (x) => x.includes(":");
  const pad2 = (n) => String(n).padStart(2, "0");
  const ts = (d) => `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())} UTC`;
  const day = (d) => d.toISOString().slice(0, 10);
  function uuid4() {
    const b = new Uint8Array(16);
    if (globalThis.crypto && globalThis.crypto.getRandomValues) globalThis.crypto.getRandomValues(b); else for (let i = 0; i < 16; i++) b[i] = (Math.random() * 256) | 0;
    b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
    const h = W.hex(b);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  const surEsc = (s) => s.replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/"/g, '\\"');
  const yamlList = (xs, ind = 12) => xs.map((x) => " ".repeat(ind) + `- '${x}'`).join("\n");

  // ------------------------------------------------------------------ generators: (c, o) → text
  const G = {
    iptables(c, o) {
      const L = [`# Wakizashi blocklist '${o.tag}' - ${ts(o.now)}`, "# Apply as root. Inbound + outbound drop."];
      for (const ip of ips(c)) {
        const t = isV6(ip) ? "ip6tables" : "iptables";
        L.push(`${t} -I INPUT -s ${ip} -j DROP -m comment --comment "wkz:${o.tag}"`, `${t} -I OUTPUT -d ${ip} -j DROP -m comment --comment "wkz:${o.tag}"`);
      }
      return L.join("\n");
    },
    ipset(c, o) {
      const s4 = `wkz_${o.tag}_v4`.slice(0, 31), s6 = `wkz_${o.tag}_v6`.slice(0, 31);
      const v4 = ips(c).filter((x) => !isV6(x)), v6 = ips(c).filter(isV6);
      return [`# Wakizashi ipset '${o.tag}' - ${ts(o.now)}`, `ipset create ${s4} hash:net -exist`, `ipset create ${s6} hash:net family inet6 -exist`,
        ...v4.map((x) => `ipset add ${s4} ${x} -exist`), ...v6.map((x) => `ipset add ${s6} ${x} -exist`),
        `iptables -I INPUT -m set --match-set ${s4} src -j DROP`, `iptables -I OUTPUT -m set --match-set ${s4} dst -j DROP`,
        `ip6tables -I INPUT -m set --match-set ${s6} src -j DROP`, `ip6tables -I OUTPUT -m set --match-set ${s6} dst -j DROP`].join("\n");
    },
    nftables(c, o) {
      const v4 = ips(c).filter((x) => !isV6(x)), v6 = ips(c).filter(isV6);
      const el = (xs) => (xs.length ? "elements = { " + xs.join(", ") + " }" : "");
      return `# Wakizashi nftables blocklist '${o.tag}' - ${ts(o.now)}
# nft -f this-file
table inet wkz_${o.tag} {
    set block_v4 { type ipv4_addr; flags interval; ${el(v4)} }
    set block_v6 { type ipv6_addr; flags interval; ${el(v6)} }
    chain input  { type filter hook input priority -10; ip saddr @block_v4 drop; ip6 saddr @block_v6 drop; }
    chain output { type filter hook output priority -10; ip daddr @block_v4 drop; ip6 daddr @block_v6 drop; }
}`;
    },
    windows(c, o) {
      const x = ips(c);
      if (!x.length) return "# no IP indicators";
      const lst = x.map((i) => `"${i}"`).join(","), name = `Wakizashi-${o.tag}`;
      return `# Wakizashi Windows Firewall block '${o.tag}' - ${ts(o.now)} (run in an elevated PowerShell)
$ips = @(${lst})
New-NetFirewallRule -DisplayName "${name}-In"  -Direction Inbound  -Action Block -RemoteAddress $ips -Profile Any
New-NetFirewallRule -DisplayName "${name}-Out" -Direction Outbound -Action Block -RemoteAddress $ips -Profile Any

# netsh equivalent:
netsh advfirewall firewall add rule name="${name}-In" dir=in action=block remoteip=${x.join(",")}
netsh advfirewall firewall add rule name="${name}-Out" dir=out action=block remoteip=${x.join(",")}`;
    },
    pfsense(c) { return "# pfSense / OPNsense URL table alias (host this file, or paste into an alias)\n" + ips(c).join("\n"); },
    cisco(c, o) {
      const g = `WKZ_${o.tag.toUpperCase()}`;
      const L = [`! Wakizashi '${o.tag}' - ${ts(o.now)}`, `object-group network ${g}`];
      for (const x of ips(c)) {
        if (isV6(x)) continue;
        const n = parseNet(x.includes("/") ? x : x + "/32");
        L.push(n.bits === 32 ? ` network-object host ${v4str(n.net)}` : ` network-object ${v4str(n.net)} ${v4mask(n.bits)}`);
      }
      L.push(`access-list OUTSIDE_IN extended deny ip object-group ${g} any`, `access-list INSIDE_OUT extended deny ip any object-group ${g}`);
      return L.join("\n");
    },
    hosts(c, o) { return `# Wakizashi sinkhole '${o.tag}' - append to /etc/hosts or C:\\Windows\\System32\\drivers\\etc\\hosts\n` + domains(c).map((d) => `0.0.0.0 ${d}\n:: ${d}`).join("\n"); },
    rpz(c, o) {
      const d = o.now, serial = `${d.getUTCFullYear()}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}`;
      return `; Wakizashi Response Policy Zone '${o.tag}' - ${ts(o.now)}
$TTL 300
@ IN SOA localhost. hostmaster.localhost. ( ${serial} 3600 600 86400 300 )
@ IN NS localhost.
${domains(c).map((x) => `${x}\tCNAME .\n*.${x}\tCNAME .`).join("\n")}`;
    },
    unbound(c, o) { return `# Wakizashi unbound.conf include '${o.tag}'\nserver:\n` + domains(c).map((d) => `    local-zone: "${d}." always_nxdomain`).join("\n"); },
    dnsmasq(c, o) { return `# Wakizashi dnsmasq '${o.tag}'\n` + domains(c).map((d) => `address=/${d}/0.0.0.0\naddress=/${d}/::`).join("\n"); },
    adblock(c, o) { return `! Wakizashi '${o.tag}' - Pi-hole (adlist) / AdGuard Home\n` + domains(c).map((d) => `||${d}^`).join("\n"); },
    suricata(c, o) {
      let sid = parseInt(o.sid, 10) || 9100000;
      const out = [`# Wakizashi Suricata rules '${o.tag}' - ${ts(o.now)}`], x = ips(c);
      for (let i = 0; i < x.length; i += 100) {
        const grp = x.slice(i, i + 100).join(",");
        out.push(`alert ip $HOME_NET any -> [${grp}] any (msg:"WKZ ${o.tag} traffic to blocklisted IP"; classtype:trojan-activity; sid:${sid++}; rev:1;)`);
        out.push(`alert ip [${grp}] any -> $HOME_NET any (msg:"WKZ ${o.tag} traffic from blocklisted IP"; classtype:misc-attack; sid:${sid++}; rev:1;)`);
      }
      for (const d of domains(c)) {
        out.push(`alert dns $HOME_NET any -> any any (msg:"WKZ ${o.tag} DNS lookup ${d}"; dns.query; dotprefix; content:".${surEsc(d)}"; endswith; nocase; classtype:trojan-activity; sid:${sid++}; rev:1;)`);
        out.push(`alert tls $HOME_NET any -> any any (msg:"WKZ ${o.tag} TLS SNI ${d}"; tls.sni; dotprefix; content:".${surEsc(d)}"; endswith; nocase; classtype:trojan-activity; sid:${sid++}; rev:1;)`);
      }
      for (const u of c.url) {
        const m = /^https?:\/\/(?:[^/@?#]*@)?([^/:?#]+)(?::\d+)?(\/[^?#]*)?/i.exec(u);
        const host = m[1], path = m[2] || "/";
        out.push(`alert http $HOME_NET any -> any any (msg:"WKZ ${o.tag} URL ${surEsc(host)}"; http.host; content:"${surEsc(host)}"; nocase; http.uri; content:"${surEsc(path)}"; classtype:trojan-activity; sid:${sid++}; rev:1;)`);
      }
      if (c.sha256.length || c.md5.length) {
        out.push(`# File hashes: save to wkz-${o.tag}.md5/.sha256 and use filemd5/filesha256 keywords:`);
        if (c.md5.length) out.push(`# alert http any any -> $HOME_NET any (msg:"WKZ ${o.tag} known-bad file"; filemd5:wkz-${o.tag}.md5; sid:${sid++}; rev:1;)`);
        if (c.sha256.length) out.push(`# alert http any any -> $HOME_NET any (msg:"WKZ ${o.tag} known-bad file"; filesha256:wkz-${o.tag}.sha256; sid:${sid++}; rev:1;)`);
      }
      return out.join("\n");
    },
    sigma(c, o) {
      const docs = [], today = day(o.now), x = ips(c), d = domains(c), hs = c.md5.concat(c.sha1, c.sha256);
      if (x.length) docs.push(`title: Wakizashi ${o.tag} - connection to blocklisted IP
id: ${uuid4()}
status: experimental
description: Network connections to indicators from incident/blocklist '${o.tag}'.
date: ${today}
tags: [attack.command_and_control, attack.t1071]
logsource: {category: network_connection, product: windows}
detection:
    selection:
        DestinationIp|cidr:
${yamlList(x)}
    condition: selection
level: high`);
      if (d.length) docs.push(`title: Wakizashi ${o.tag} - DNS query for blocklisted domain
id: ${uuid4()}
status: experimental
description: DNS lookups of domains from '${o.tag}'.
date: ${today}
tags: [attack.command_and_control, attack.t1071.004]
logsource: {category: dns_query, product: windows}
detection:
    selection:
        QueryName|endswith:
${yamlList(d)}
    condition: selection
level: high`);
      if (hs.length) docs.push(`title: Wakizashi ${o.tag} - known-bad file hash executed
id: ${uuid4()}
status: experimental
description: Process creation with a hash from '${o.tag}' (Sysmon Hashes field).
date: ${today}
tags: [attack.execution, attack.t1204.002]
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Hashes|contains:
${yamlList(hs)}
    condition: selection
level: critical`);
      return docs.join("\n---\n") || "# no indicators";
    },
    yara(c, o) {
      const hs = c.md5.concat(c.sha256);
      if (!hs.length) return "// no MD5/SHA256 hashes";
      const conds = c.md5.map((h) => `hash.md5(0, filesize) == "${h}"`).concat(c.sha256.map((h) => `hash.sha256(0, filesize) == "${h}"`));
      return `// Wakizashi '${o.tag}' - requires real YARA (hash module); not runnable in YARA-lite
import "hash"

rule Wkz_${o.tag.replace(/[^A-Za-z0-9_]/g, "_")}_known_bad_hashes
{
    meta:
        description = "Known-bad files from ${o.tag}"
        date = "${day(o.now)}"
    condition:
        ${conds.join(" or\n        ")}
}`;
    },
    kql(c, o) {
      const q = [`// Wakizashi '${o.tag}' hunting queries - Microsoft Defender XDR / Sentinel`], x = c.ipv4.concat(c.ipv6), d = domains(c);
      const lst = (a) => a.map((v) => `"${v}"`).join(", ");
      if (x.length) q.push(`DeviceNetworkEvents\n| where RemoteIP in (${lst(x)})\n| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl`);
      if (c.cidr.length) q.push(`DeviceNetworkEvents\n| where ${c.cidr.map((n) => `ipv${isV6(n) ? "6" : "4"}_is_in_range(RemoteIP, "${n}")`).join(" or ")}\n| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl`);
      if (d.length) q.push(`DeviceNetworkEvents\n| where RemoteUrl has_any (${lst(d)})\n| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP`);
      if (c.sha256.length || c.sha1.length || c.md5.length)
        q.push(`DeviceFileEvents\n| where SHA256 in (${lst(c.sha256)}) or SHA1 in (${lst(c.sha1)}) or MD5 in (${lst(c.md5)})`);
      return q.join("\n\n");
    },
    splunk(c, o) {
      const q = [`\`comment("Wakizashi ${o.tag}")\``], x = ips(c), d = domains(c), hs = c.md5.concat(c.sha1, c.sha256);
      if (x.length) q.push("index=* (" + x.slice(0, 200).map((v) => (v.includes("/") ? `cidrmatch("${v}", dest_ip)` : `dest_ip="${v}" OR src_ip="${v}"`)).join(" OR ") + ")\n| stats count by src_ip, dest_ip, dest_port");
      if (d.length) q.push("index=* (" + d.slice(0, 200).map((v) => `query="*${v}" OR url="*${v}*"`).join(" OR ") + ")\n| stats count by src, query, url");
      if (hs.length) q.push("index=* (" + hs.slice(0, 200).map((h) => `"${h}"`).join(" OR ") + ")\n| stats count by host, file_name, file_hash");
      return q.join("\n\n");
    },
    mde(c, o) {
      const exp = new Date(o.now.getTime() + (parseInt(o.days, 10) || 90) * 86400000).toISOString().replace(/\.\d+Z$/, ".0Z");
      const rows = ["IndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups,Category,MitreTechniques,GenerateAlert"];
      const row = (t, v, act) => rows.push(`${t},${v},${exp},${act},High,Wakizashi ${o.tag},"Imported from Wakizashi (${o.tag})",,,,,TRUE`);
      c.sha256.forEach((x) => row("FileSha256", x, "BlockAndRemediate"));
      c.sha1.forEach((x) => row("FileSha1", x, "BlockAndRemediate"));
      c.md5.forEach((x) => row("FileMd5", x, "BlockAndRemediate"));
      c.ipv4.concat(c.ipv6).forEach((x) => row("IpAddress", x, "Block"));
      c.domain.forEach((x) => row("DomainName", x, "Block"));
      c.url.forEach((x) => row("Url", x.replace(/,/g, "%2C"), "Block"));
      return rows.join("\n");
    },
    stix(c, o) {
      const now = o.now.toISOString().replace(/\.\d+Z$/, ".000Z"), objs = [];
      const ind = (pattern, name) => objs.push({ type: "indicator", spec_version: "2.1", id: `indicator--${uuid4()}`, created: now, modified: now, name, pattern,
        pattern_type: "stix", valid_from: now, indicator_types: ["malicious-activity"], labels: [`wkz:${o.tag}`] });
      c.ipv4.forEach((x) => ind(`[ipv4-addr:value = '${x}']`, x));
      c.ipv6.forEach((x) => ind(`[ipv6-addr:value = '${x}']`, x));
      c.cidr.forEach((x) => ind(`[${isV6(x) ? "ipv6" : "ipv4"}-addr:value = '${x}']`, x));
      c.domain.forEach((x) => ind(`[domain-name:value = '${x}']`, x));
      c.url.forEach((x) => ind("[url:value = '" + x.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "']", x));
      for (const [k, alg] of [["md5", "MD5"], ["sha1", "SHA-1"], ["sha256", "SHA-256"]]) c[k].forEach((x) => ind(`[file:hashes.'${alg}' = '${x}']`, x));
      return JSON.stringify({ type: "bundle", id: `bundle--${uuid4()}`, objects: objs }, null, 2);
    },
  };

  const FORMATS = [
    ["iptables", "iptables / ip6tables", "network", "sh"], ["ipset", "ipset + iptables", "network", "sh"], ["nftables", "nftables", "network", "nft"],
    ["windows", "Windows Firewall (PowerShell/netsh)", "network", "ps1"], ["pfsense", "pfSense / OPNsense alias", "network", "txt"],
    ["cisco", "Cisco ASA object-group", "network", "txt"], ["hosts", "hosts file sinkhole", "dns", "txt"], ["rpz", "BIND RPZ zone", "dns", "zone"],
    ["unbound", "Unbound local-zone", "dns", "conf"], ["dnsmasq", "dnsmasq", "dns", "conf"], ["adblock", "Pi-hole / AdGuard", "dns", "txt"],
    ["suricata", "Suricata / Snort-style IDS", "ids", "rules"], ["sigma", "Sigma rules", "detection", "yml"], ["yara", "YARA (hash module)", "detection", "yar"],
    ["kql", "KQL (Defender / Sentinel)", "detection", "kql"], ["splunk", "Splunk SPL", "detection", "spl"], ["mde", "Microsoft Defender indicators CSV", "edr", "csv"],
    ["stix", "STIX 2.1 bundle", "sharing", "json"],
  ].map(([id, label, group, ext]) => ({ id, label, group, ext }));
  const FMAP = Object.fromEntries(FORMATS.map((f) => [f.id, f]));

  const cleanTag = (tag) => String(tag || "blocklist").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 40) || "blocklist";

  function generate(text, fmt, tag, opts = {}) {
    if (!FMAP[fmt]) throw new Error(`unknown format ${fmt}`);
    const c = classify(text, opts);
    const o = Object.assign({ sid: 9100000, days: 90 }, opts, { tag: cleanTag(tag), now: opts.now instanceof Date ? opts.now : new Date() });
    const counts = {};
    for (const [k, v] of Object.entries(c)) if (k !== "rejected") counts[k] = v.length;
    return { format: fmt, label: FMAP[fmt].label, output: G[fmt](c, o), ext: FMAP[fmt].ext, counts, rejected: c.rejected, classified: c };
  }

  /** true for a globally routable IPv4/IPv6 address (private, loopback, link-local, doc, CGNAT, multicast… → false). */
  function isPublicIp(ip) {
    ip = String(ip || "").trim().replace(/^\[|\]$/g, "");
    const n4 = parseV4(ip); if (n4 != null) return v4Global(n4);
    const h6 = parseV6(ip); if (h6) return v6Global(h6);
    return false;
  }

  W.eng.block = { classify, generate, FORMATS, cleanTag, isPublicIp, _parseV6: parseV6, _v6str: v6str };
})(typeof window !== "undefined" ? window.W : globalThis.W);
