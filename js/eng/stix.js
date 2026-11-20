/* STIX 2.1 bundle builder (port of katana/cti/stix.py). Ids are deterministic UUIDv5 — same namespace as
   Katana — so exporting the same indicator from Katana, Tantō or Wakizashi updates rather than duplicates
   it in OpenCTI. Async because UUIDv5 needs SHA-1 (WebCrypto). */
(function (W) {
  "use strict";
  const NS = "1b9f0e4a-2c3d-5e6f-8a9b-0c1d2e3f4a5b";
  const TLP = {
    clear: "marking-definition--94868c89-83c2-464b-929b-a1811b5e990b", white: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    green: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", amber: "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    red: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
  };
  const CONF = { malicious: 90, suspicious: 60, info: 40, clean: 10 };
  const HASHLEN = { 32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512" };
  const MITRE = "https://attack.mitre.org/techniques/";

  async function uuid5(name, ns = NS) {
    const nsb = W.fromHex(ns.replace(/-/g, ""));
    const nb = W.bytes(name), buf = new Uint8Array(nsb.length + nb.length); buf.set(nsb); buf.set(nb, nsb.length);
    const h = W.fromHex(await W.hash.sha("SHA-1", buf)).slice(0, 16);
    h[6] = (h[6] & 0x0f) | 0x50; h[8] = (h[8] & 0x3f) | 0x80;
    const x = W.hex(h); return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
  }
  const rid = async (kind, seed) => `${kind}--${await uuid5(kind + ":" + seed)}`;
  const v4 = () => { const b = W.randomBytes(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; const x = W.hex(b); return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`; };
  const now = () => new Date().toISOString().replace(/\.\d+Z$/, ".000Z");
  const pesc = (v) => v.replace(/\\/g, "\\\\").replace(/'/g, "\\'");

  function classify(value, type) {
    const v = String(value).trim(), t = String(type || "").toLowerCase();
    if (/^CVE-\d{4}-\d{4,7}$/i.test(v)) return "cve";
    if (["ip", "ipv4", "ip-addr", "ipv4-addr"].includes(t) || W.RE.ipv4.test(v)) return "ipv4";
    if (["ipv6", "ipv6-addr"].includes(t) || (v.includes(":") && /^[0-9A-Fa-f:]+:[0-9A-Fa-f:]+$/.test(v))) return "ipv6";
    if (t === "url" || /^https?:\/\//i.test(v)) return "url";
    if (["email", "email-addr"].includes(t) || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return "email";
    if (["md5", "sha1", "sha256", "sha512", "hash"].includes(t) || (/^[0-9a-fA-F]+$/.test(v) && HASHLEN[v.length])) return HASHLEN[v.length] ? "hash" : null;
    if (["domain", "hostname", "fqdn", "domain-name"].includes(t) || W.RE.domain.test(v)) return "domain";
    return null;
  }
  function pattern(kind, value) {
    const v = pesc(value.trim());
    return ({ ipv4: `[ipv4-addr:value = '${v}']`, ipv6: `[ipv6-addr:value = '${v}']`, url: `[url:value = '${v}']`, email: `[email-addr:value = '${v}']`,
      domain: `[domain-name:value = '${v}']`, hash: `[file:hashes.'${HASHLEN[value.trim().length] || "SHA-256"}' = '${v}']` })[kind] || null;
  }

  /** bundle(items, {producer, tlp}) → {bundle, stats}. items = case items [{value,type,verdict,note,tags}] */
  async function bundle(items, opts = {}) {
    const producer = String(opts.producer || "Wakizashi").slice(0, 120), ts = now();
    const tlpRef = TLP[String(opts.tlp || "amber").toLowerCase().replace("tlp:", "")] || TLP.amber;
    const identId = await rid("identity", producer);
    const objects = [{ type: "identity", spec_version: "2.1", id: identId, created: ts, modified: ts, name: producer, identity_class: "organization" }];
    const seen = new Set(); let nInd = 0, nVuln = 0; const skipped = [];
    for (const it of items || []) {
      const value = String((it && it.value) || "").trim(); if (!value) continue;
      const kind = classify(value, it.type), verdict = it.verdict, note = String(it.note || "").slice(0, 900), tags = (it.tags || []).filter(Boolean).map((t) => String(t).slice(0, 60));
      if (kind === "cve") {
        const id = await rid("vulnerability", value.toUpperCase()); if (seen.has(id)) continue; seen.add(id);
        const o = { type: "vulnerability", spec_version: "2.1", id, created: ts, modified: ts, name: value.toUpperCase(), created_by_ref: identId, object_marking_refs: [tlpRef],
          external_references: [{ source_name: "cve", external_id: value.toUpperCase() }] };
        if (note) o.description = note; if (tags.length) o.labels = tags;
        objects.push(o); nVuln++; continue;
      }
      const pat = kind ? pattern(kind, value) : null;
      if (!pat) { skipped.push(value); continue; }
      const id = await rid("indicator", pat); if (seen.has(id)) continue; seen.add(id);
      const itypes = verdict === "clean" ? ["benign"] : ["malicious", "suspicious"].includes(verdict) ? ["malicious-activity"] : ["anomalous-activity"];
      const o = { type: "indicator", spec_version: "2.1", id, created: ts, modified: ts, name: `${kind}: ${value}`.slice(0, 250), pattern: pat, pattern_type: "stix",
        valid_from: ts, indicator_types: itypes, confidence: CONF[verdict] || 50, created_by_ref: identId, object_marking_refs: [tlpRef] };
      const labels = tags.concat(verdict ? [`verdict:${verdict}`] : []); if (labels.length) o.labels = labels; if (note) o.description = note;
      objects.push(o); nInd++;
    }
    return { bundle: { type: "bundle", id: "bundle--" + v4(), objects }, stats: { indicators: nInd, vulnerabilities: nVuln, skipped: skipped.length, skipped_values: skipped.slice(0, 50), objects: objects.length } };
  }

  /** Indicators + ATT&CK attack-patterns + an intrusion-set + relationships. */
  async function enriched(items, techniques = [], actor = null, opts = {}) {
    const built = await bundle(items, opts), objs = built.bundle.objects, identId = objs[0].id, ts = now();
    const tlpRef = TLP[String(opts.tlp || "amber").toLowerCase()] || TLP.amber;
    const rel = (s, t, r) => ({ type: "relationship", spec_version: "2.1", id: "relationship--" + v4(), created: ts, modified: ts, relationship_type: r, source_ref: s, target_ref: t, created_by_ref: identId });
    const ap = [];
    for (const t of techniques) {
      const tid = String(t.id || "").trim().toUpperCase(); if (!/^T\d{4}(?:\.\d{3})?$/.test(tid)) continue;
      const id = await rid("attack-pattern", tid); if (ap.includes(id)) continue;
      objs.push({ type: "attack-pattern", spec_version: "2.1", id, created: ts, modified: ts, name: t.name || tid, created_by_ref: identId, object_marking_refs: [tlpRef],
        external_references: [{ source_name: "mitre-attack", external_id: tid, url: MITRE + tid.replace(".", "/") }] });
      ap.push(id);
    }
    let isId = null;
    if (actor) {
      isId = await rid("intrusion-set", actor);
      objs.push({ type: "intrusion-set", spec_version: "2.1", id: isId, created: ts, modified: ts, name: String(actor).slice(0, 120), created_by_ref: identId, object_marking_refs: [tlpRef] });
      for (const a of ap) objs.push(rel(isId, a, "uses"));
    }
    const tgt = isId || ap[0];
    if (tgt) for (const o of objs.filter((x) => x.type === "indicator").slice(0, 300)) objs.push(rel(o.id, tgt, "indicates"));
    Object.assign(built.stats, { attack_patterns: ap.length, intrusion_set: !!isId, objects: objs.length });
    return built;
  }

  const filename = (p = "wakizashi-stix") => `${p}-${new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-")}.json`;
  W.eng.stix = { bundle, enriched, classify, pattern, uuid5, TLP, filename };
})(typeof window !== "undefined" ? window.W : globalThis.W);
