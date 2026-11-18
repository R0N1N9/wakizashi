/* SCRUB — metadata inspection and lossless stripping (port of Katana shinobi/scrub.py + Karambit ScrubEngine).
 *
 *   await W.eng.scrub.scan(bytes, name)  → { type, label, leaks[], meta{}, gps, risks[], segments[], counts,
 *                                            summary, canStrip, clean (Uint8Array|null), removed[], note, mime }
 *   await W.eng.scrub.analyze(bytes, name) → scan() without the cleaned bytes
 *   await W.eng.scrub.strip(bytes, name, opts) → { data, removed[], note, name, mime }
 *
 * Stripping never re-encodes pixels: it drops metadata segments/chunks (JPEG APPn/COM, PNG text/eXIf/tIME,
 * WebP EXIF/XMP, GIF comment/XMP extensions, ID3 tags), blanks PDF Info strings in place (same byte length so
 * the xref table stays valid) and rewrites OOXML/ODF property parts inside the ZIP.
 * opts: { keepOrientation = true (JPEG: re-adds a 1-tag EXIF with Orientation), keepIcc = true (colour profile) }
 */
(function (W) {
  "use strict";
  const HIGH = "high", MED = "medium", LOW = "low", INFO = "info";
  const K = () => W.eng.kpack;

  // ------------------------------------------------------------------ EXIF / TIFF
  const EXIF_TAGS = {
    0x010e: ["ImageDescription", MED], 0x010f: ["Make", LOW], 0x0110: ["Model", MED], 0x0112: ["Orientation", INFO],
    0x0131: ["Software", LOW], 0x0132: ["DateTime", MED], 0x013b: ["Artist", HIGH], 0x013c: ["HostComputer", MED],
    0x8298: ["Copyright", MED], 0x829a: ["ExposureTime", INFO], 0x829d: ["FNumber", INFO], 0x8827: ["ISO", INFO],
    0x9003: ["DateTimeOriginal", MED], 0x9004: ["DateTimeDigitized", MED], 0x9010: ["OffsetTime", MED], 0x9011: ["OffsetTimeOriginal", MED],
    0x920a: ["FocalLength", INFO], 0x927c: ["MakerNote", MED], 0x9286: ["UserComment", MED],
    0x9c9b: ["XPTitle", MED], 0x9c9c: ["XPComment", MED], 0x9c9d: ["XPAuthor", HIGH], 0x9c9e: ["XPKeywords", MED], 0x9c9f: ["XPSubject", MED],
    0xa420: ["ImageUniqueID", MED], 0xa430: ["CameraOwnerName", HIGH], 0xa431: ["BodySerialNumber", HIGH], 0xa432: ["LensSpecification", INFO],
    0xa433: ["LensMake", LOW], 0xa434: ["LensModel", LOW], 0xa435: ["LensSerialNumber", HIGH], 0xc614: ["UniqueCameraModel", MED],
  };
  const GPS_TAGS = { 0x0001: "GPSLatitudeRef", 0x0002: "GPSLatitude", 0x0003: "GPSLongitudeRef", 0x0004: "GPSLongitude", 0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude", 0x0007: "GPSTimeStamp", 0x0010: "GPSImgDirectionRef", 0x0011: "GPSImgDirection", 0x0012: "GPSMapDatum", 0x001d: "GPSDateStamp" };
  const TYPE_SZ = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };

  function decodeTiffValue(t, typ, cnt, off, le, tag) {
    const sz = TYPE_SZ[typ] || 1, n = Math.min(cnt, 4096);
    const u16 = (o) => le ? t[o] | (t[o + 1] << 8) : (t[o] << 8) | t[o + 1];
    const u32 = (o) => (le ? (t[o] | (t[o + 1] << 8) | (t[o + 2] << 16) | (t[o + 3] << 24)) : ((t[o] << 24) | (t[o + 1] << 16) | (t[o + 2] << 8) | t[o + 3])) >>> 0;
    if (off < 0 || off + sz * n > t.length) return null;
    if (typ === 2) { let s = ""; for (let i = 0; i < n; i++) { const c = t[off + i]; if (!c) break; s += String.fromCharCode(c); } try { s = decodeURIComponent(escape(s)); } catch { /* latin1 */ } return s.trim(); }
    if (tag >= 0x9c9b && tag <= 0x9c9f) { // XP* tags: UCS-2 LE in BYTE arrays
      let s = ""; for (let i = 0; i + 1 < n; i += 2) { const c = t[off + i] | (t[off + i + 1] << 8); if (!c) break; s += String.fromCharCode(c); } return s.trim();
    }
    if (tag === 0x9286) { // UserComment: 8-byte charset id + text
      const id = K().ascii(t, off, 8).replace(/\0/g, ""), body = t.subarray(off + 8, off + n);
      if (/^UNICODE/.test(id)) { let s = ""; for (let i = 0; i + 1 < body.length; i += 2) { const c = le ? body[i] | (body[i + 1] << 8) : (body[i] << 8) | body[i + 1]; if (c) s += String.fromCharCode(c); } return s.trim(); }
      return W.utf8(body).replace(/\0+/g, "").trim();
    }
    const vals = [];
    for (let i = 0; i < n; i++) {
      const o = off + i * sz;
      if (typ === 3) vals.push(u16(o));
      else if (typ === 8) { const v = u16(o); vals.push(v > 32767 ? v - 65536 : v); }
      else if (typ === 4) vals.push(u32(o));
      else if (typ === 9) vals.push(u32(o) | 0);
      else if (typ === 5) { const a = u32(o), b = u32(o + 4); vals.push(b ? a / b : 0); }
      else if (typ === 10) { const a = u32(o) | 0, b = u32(o + 4) | 0; vals.push(b ? a / b : 0); }
      else if (typ === 1 || typ === 6) vals.push(t[o]);
      else if (typ === 7) { if (tag === 0x927c) return `${cnt} bytes vendor data`; vals.push(t[o]); }
      else return null;
    }
    if (typ === 7 && tag !== 0x927c) return cnt > 16 ? `${cnt} bytes` : W.hex(t.subarray(off, off + n));
    return vals.length === 1 ? vals[0] : vals;
  }

  /** Parse a TIFF/EXIF block → { tags: {name: value}, gps: {name: value}, ifd1: bool, orientation } */
  function parseTiff(tiff) {
    const t = W.bytes(tiff);
    const res = { tags: {}, gps: {}, thumbnail: null, orientation: null, order: null };
    if (t.length < 8) return res;
    const le = t[0] === 0x49 && t[1] === 0x49; const be = t[0] === 0x4d && t[1] === 0x4d;
    if (!le && !be) return res;
    res.order = le ? "II" : "MM";
    const u16 = (o) => le ? t[o] | (t[o + 1] << 8) : (t[o] << 8) | t[o + 1];
    const u32 = (o) => (le ? (t[o] | (t[o + 1] << 8) | (t[o + 2] << 16) | (t[o + 3] << 24)) : ((t[o] << 24) | (t[o + 1] << 16) | (t[o + 2] << 8) | t[o + 3])) >>> 0;
    const seen = new Set();
    function ifd(off, kind) {
      if (!off || off + 2 > t.length || seen.has(off) || seen.size > 16) return 0;
      seen.add(off);
      const n = u16(off);
      for (let i = 0; i < n && i < 512; i++) {
        const o = off + 2 + i * 12; if (o + 12 > t.length) break;
        const tag = u16(o), typ = u16(o + 2), cnt = u32(o + 4);
        const size = (TYPE_SZ[typ] || 0) * cnt;
        const voff = size <= 4 ? o + 8 : u32(o + 8);
        if (kind !== "gps" && tag === 0x8769) { ifd(u32(o + 8), "exif"); continue; }
        if (kind !== "gps" && tag === 0x8825) { ifd(u32(o + 8), "gps"); continue; }
        if (tag === 0xa005) continue; // interop pointer
        if (kind === "ifd1") { if (tag === 0x0201) res.thumbnail = res.thumbnail || {}; if (tag === 0x0201) res.thumbnail.offset = u32(o + 8); if (tag === 0x0202) { res.thumbnail = res.thumbnail || {}; res.thumbnail.length = u32(o + 8); } continue; }
        if (kind === "gps") { if (GPS_TAGS[tag]) res.gps[GPS_TAGS[tag]] = decodeTiffValue(t, typ, cnt, voff, le, tag); continue; }
        const def = EXIF_TAGS[tag]; if (!def) continue;
        const v = decodeTiffValue(t, typ, cnt, voff, le, tag);
        if (v == null || v === "" || (Array.isArray(v) && !v.length)) continue;
        if (tag === 0x0112) res.orientation = +v;
        res.tags[def[0]] = v;
      }
      const nextPtr = off + 2 + n * 12;
      return nextPtr + 4 <= t.length ? u32(nextPtr) : 0;
    }
    try {
      const next = ifd(u32(4), "ifd0");
      if (next) ifd(next, "ifd1");
    } catch { /* tolerate garbage */ }
    return res;
  }

  function dms(v, ref) {
    const a = Array.isArray(v) ? v : [v];
    const [d, m, s] = [a[0] || 0, a[1] || 0, a[2] || 0];
    let dd = +d + m / 60 + s / 3600;
    if (/^[SW]/i.test(String(ref || ""))) dd = -dd;
    return isFinite(dd) ? Math.round(dd * 1e6) / 1e6 : null;
  }
  const fmtVal = (v) => Array.isArray(v) ? v.map((x) => typeof x === "number" ? +x.toFixed(4) : x).join(", ") : typeof v === "number" ? String(+v.toFixed(6)) : String(v);

  /** EXIF block → leaks/meta/gps. src labels where it came from. */
  function exifLeaks(tiff, src) {
    const p = parseTiff(tiff), leaks = [], meta = {};
    let gps = null;
    for (const [name, v] of Object.entries(p.tags)) {
      const sev = (Object.values(EXIF_TAGS).find((d) => d[0] === name) || [0, LOW])[1];
      meta[name] = fmtVal(v);
      leaks.push({ field: name, value: fmtVal(v).slice(0, 200), severity: sev, src });
    }
    const g = p.gps;
    if (g.GPSLatitude != null && g.GPSLongitude != null) {
      const lat = dms(g.GPSLatitude, g.GPSLatitudeRef), lon = dms(g.GPSLongitude, g.GPSLongitudeRef);
      if (lat != null && lon != null && !(lat === 0 && lon === 0)) {
        gps = { lat, lon };
        if (typeof g.GPSAltitude === "number") gps.alt = Math.round((g.GPSAltitudeRef === 1 || (Array.isArray(g.GPSAltitudeRef) && g.GPSAltitudeRef[0] === 1) ? -1 : 1) * g.GPSAltitude * 10) / 10;
        if (g.GPSDateStamp) gps.time = `${g.GPSDateStamp}${Array.isArray(g.GPSTimeStamp) ? " " + g.GPSTimeStamp.map((x) => String(Math.floor(x)).padStart(2, "0")).join(":") + "Z" : ""}`;
        meta.GPSPosition = `${lat}, ${lon}`;
        leaks.push({ field: "GPS coordinates", value: `${lat}, ${lon}${gps.alt != null ? ` · alt ${gps.alt} m` : ""}`, severity: HIGH, src, gps: true });
        if (gps.time) leaks.push({ field: "GPS timestamp", value: gps.time, severity: MED, src });
        if (g.GPSImgDirection != null) leaks.push({ field: "GPS direction", value: `${fmtVal(g.GPSImgDirection)}°`, severity: LOW, src });
      }
    } else if (Object.keys(g).length) leaks.push({ field: "GPS block", value: Object.keys(g).join(", "), severity: MED, src });
    if (p.thumbnail) leaks.push({ field: "Embedded thumbnail", value: `${p.thumbnail.length || "?"} bytes — may show the original, uncropped/unedited picture`, severity: MED, src });
    return { leaks, meta, gps, orientation: p.orientation };
  }

  // ------------------------------------------------------------------ XMP / IPTC
  const XMP_FIELDS = [
    ["dc:creator", HIGH], ["dc:rights", MED], ["dc:title", LOW], ["dc:description", MED], ["dc:subject", LOW],
    ["xmp:CreatorTool", LOW], ["xmp:CreateDate", MED], ["xmp:ModifyDate", LOW], ["xmp:MetadataDate", LOW],
    ["photoshop:AuthorsPosition", MED], ["photoshop:City", HIGH], ["photoshop:State", MED], ["photoshop:Country", MED], ["photoshop:Credit", MED],
    ["Iptc4xmpCore:Location", HIGH], ["Iptc4xmpCore:CreatorContactInfo", HIGH], ["Iptc4xmpCore:CiEmailWork", HIGH], ["Iptc4xmpCore:CiAdrCity", HIGH],
    ["exif:GPSLatitude", HIGH], ["exif:GPSLongitude", HIGH], ["tiff:Make", LOW], ["tiff:Model", MED], ["aux:SerialNumber", HIGH], ["exifEX:BodySerialNumber", HIGH],
    ["aux:LensSerialNumber", HIGH], ["aux:OwnerName", HIGH], ["xmpMM:DocumentID", MED], ["xmpMM:OriginalDocumentID", MED], ["xmpMM:InstanceID", LOW],
    ["pdf:Producer", LOW], ["pdf:Author", HIGH], ["pdf:Keywords", MED], ["GCamera:MotionPhoto", MED], ["xmpRights:Owner", HIGH],
  ];
  function xmpGps(s) {
    const m = String(s).match(/^(\d+),(\d+(?:\.\d+)?)(?:,(\d+(?:\.\d+)?))?([NSEW])$/i);
    if (!m) return null;
    let v = +m[1] + +m[2] / 60 + (m[3] ? +m[3] / 3600 : 0);
    if (/[SW]/i.test(m[4])) v = -v;
    return Math.round(v * 1e6) / 1e6;
  }
  function xmpLeaks(xml, src) {
    const leaks = [], meta = {}; let gps = null;
    const clean = (s) => s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').trim();
    for (const [key, sev] of XMP_FIELDS) {
      const k = key.replace(/[.]/g, "\\.");
      const m = xml.match(new RegExp(`\\b${k}="([^"]*)"`)) || xml.match(new RegExp(`<${k}\\b[^>]*>([\\s\\S]*?)</${k}>`));
      if (!m) continue;
      const v = clean(m[1]); if (!v) continue;
      meta[key] = v; leaks.push({ field: "XMP " + key, value: v.slice(0, 200), severity: sev, src });
    }
    const softs = W.uniq((xml.match(/stEvt:softwareAgent="([^"]+)"/g) || []).map((x) => x.split('"')[1]));
    if (softs.length) leaks.push({ field: "XMP edit history", value: `${(xml.match(/stEvt:action=/g) || []).length} event(s) · ${softs.slice(0, 4).join("; ")}`, severity: MED, src });
    if (meta["exif:GPSLatitude"] && meta["exif:GPSLongitude"]) {
      const lat = xmpGps(meta["exif:GPSLatitude"]), lon = xmpGps(meta["exif:GPSLongitude"]);
      if (lat != null && lon != null) { gps = { lat, lon }; leaks.push({ field: "GPS coordinates (XMP)", value: `${lat}, ${lon}`, severity: HIGH, src, gps: true }); }
    }
    if (!leaks.length && xml.trim()) leaks.push({ field: "XMP packet", value: `${xml.length} bytes of Adobe XMP metadata`, severity: LOW, src });
    return { leaks, meta, gps };
  }
  const IPTC = { 5: ["ObjectName", LOW], 25: ["Keywords", LOW], 80: ["By-line (author)", HIGH], 85: ["By-line title", MED], 90: ["City", HIGH], 92: ["Sub-location", HIGH],
    95: ["Province/State", MED], 101: ["Country", MED], 105: ["Headline", LOW], 110: ["Credit", MED], 115: ["Source", LOW], 116: ["Copyright notice", MED],
    118: ["Contact", HIGH], 120: ["Caption", MED], 122: ["Caption writer", HIGH], 55: ["Date created", MED], 60: ["Time created", MED] };
  /** Photoshop APP13 IRB → IPTC IIM datasets. */
  function iptcLeaks(seg, src) {
    const leaks = [], meta = {}, b = W.bytes(seg);
    const k = K();
    let i = 14; // after "Photoshop 3.0\0"
    while (i + 12 <= b.length && k.ascii(b, i, 4) === "8BIM") {
      const id = k.u16be(b, i + 4); let nl = b[i + 6]; let p = i + 7 + nl; if ((nl + 1) % 2) p++;
      const size = k.u32be(b, p); const data = b.subarray(p + 4, p + 4 + size);
      if (id === 0x0404) {
        let j = 0;
        while (j + 5 <= data.length && data[j] === 0x1c) {
          const rec = data[j + 1], ds = data[j + 2], len = k.u16be(data, j + 3);
          const val = W.utf8(data.subarray(j + 5, j + 5 + len)).trim();
          if (rec === 2 && IPTC[ds] && val) {
            const [name, sev] = IPTC[ds];
            meta[name] = meta[name] ? meta[name] + "; " + val : val;
          }
          j += 5 + len;
        }
      }
      i = p + 4 + size + (size % 2);
    }
    for (const [name, v] of Object.entries(meta)) leaks.push({ field: "IPTC " + name, value: v.slice(0, 200), severity: (Object.values(IPTC).find((d) => d[0] === name) || [0, LOW])[1], src });
    if (!leaks.length) leaks.push({ field: "Photoshop/IPTC block", value: `${b.length} bytes`, severity: LOW, src });
    return { leaks, meta };
  }

  // ------------------------------------------------------------------ result builder
  function Rec(type, label) {
    return { type, label, leaks: [], meta: {}, gps: null, segments: [], removed: [], notes: [], canStrip: false, clean: null };
  }
  function merge(rec, part) {
    if (!part) return;
    rec.leaks.push(...(part.leaks || []));
    Object.assign(rec.meta, part.meta || {});
    if (part.gps && !rec.gps) rec.gps = part.gps;
  }

  // ------------------------------------------------------------------ JPEG
  const APP_NAME = (m) => m === 0xfe ? "COM" : m >= 0xe0 && m <= 0xef ? "APP" + (m - 0xe0) : "0x" + m.toString(16);
  function minimalExif(orientation) {
    // "Exif\0\0" + big-endian TIFF with one IFD0 entry: Orientation (SHORT)
    const body = Uint8Array.of(0x45, 0x78, 0x69, 0x66, 0, 0, 0x4d, 0x4d, 0, 0x2a, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, orientation & 255, 0, 0, 0, 0, 0, 0);
    const len = body.length + 2;
    return K().concat([Uint8Array.of(0xff, 0xe1, len >> 8, len & 255), body]);
  }
  function jpeg(b, opts) {
    const rec = Rec("jpeg", "JPEG image"), k = K(), out = [b.subarray(0, 2)];
    let i = 2, orientation = null, eoi = -1;
    const keep = (s, e) => out.push(b.subarray(s, e));
    while (i + 1 < b.length) {
      if (b[i] !== 0xff) { keep(i, b.length); rec.notes.push("Unexpected bytes between segments — copied through unchanged."); i = b.length; break; }
      while (b[i + 1] === 0xff && i + 2 < b.length) i++; // fill bytes
      const m = b[i + 1];
      if (m === 0xd9) { keep(i, i + 2); eoi = i + 2; break; }
      if ((m >= 0xd0 && m <= 0xd7) || m === 0x01) { keep(i, i + 2); i += 2; continue; }
      if (i + 4 > b.length) { keep(i, b.length); break; }
      const len = k.u16be(b, i + 2), end = i + 2 + len, seg = b.subarray(i + 4, Math.min(end, b.length));
      if (m === 0xda) { // start of scan: copy header + entropy-coded data up to the next real marker
        let j = end;
        while (j + 1 < b.length && !(b[j] === 0xff && b[j + 1] !== 0 && !(b[j + 1] >= 0xd0 && b[j + 1] <= 0xd7))) j++;
        keep(i, j); i = j; continue;
      }
      const id = k.ascii(seg, 0, 40);
      let drop = false, what = APP_NAME(m), sev = LOW;
      if (m === 0xe1 && id.startsWith("Exif\0")) {
        const r = exifLeaks(seg.subarray(6), "EXIF"); merge(rec, r); orientation = r.orientation; drop = true; what = "APP1 EXIF"; sev = r.gps ? HIGH : MED;
      } else if (m === 0xe1 && id.startsWith("http://ns.adobe.com/xap/1.0/")) {
        const xml = W.utf8(seg.subarray(29)); merge(rec, xmpLeaks(xml, "XMP")); drop = true; what = "APP1 XMP"; sev = MED;
      } else if (m === 0xe1 && id.startsWith("http://ns.adobe.com/xmp/extension/")) {
        rec.leaks.push({ field: "Extended XMP", value: `${len} bytes`, severity: MED, src: "XMP" }); drop = true; what = "APP1 Extended XMP";
      } else if (m === 0xed) {
        merge(rec, iptcLeaks(seg, "IPTC")); drop = true; what = "APP13 Photoshop/IPTC"; sev = MED;
      } else if (m === 0xe2 && id.startsWith("ICC_PROFILE")) {
        const desc = iccDesc(seg.subarray(14)); what = "APP2 ICC colour profile";
        rec.leaks.push({ field: "ICC profile", value: desc || `${len} bytes`, severity: INFO, src: "ICC", note: "Kept by default — removing it can shift colours." });
        drop = opts.keepIcc === false;
      } else if (m === 0xe2 && id.startsWith("MPF")) {
        rec.leaks.push({ field: "Multi-Picture (MPF) index", value: "extra images (depth map / preview) are appended after the main picture", severity: MED, src: "MPF" }); drop = true; what = "APP2 MPF";
      } else if (m === 0xe0 && id.startsWith("JFIF")) { what = "APP0 JFIF header";
      } else if (m === 0xe0 && id.startsWith("JFXX")) { rec.leaks.push({ field: "JFIF thumbnail", value: `${len} bytes`, severity: MED, src: "JFIF" }); drop = true; what = "APP0 JFXX thumbnail";
      } else if (m === 0xee && id.startsWith("Adobe")) { what = "APP14 Adobe (colour transform)";
      } else if (m === 0xeb && (id.includes("JP") || id.includes("jumb") || id.includes("c2pa"))) {
        rec.leaks.push({ field: "Content Credentials (C2PA/JUMBF)", value: `${len} bytes — provenance manifest, may name the creator/tool`, severity: MED, src: "C2PA" }); drop = true; what = "APP11 JUMBF";
      } else if (m === 0xfe) {
        rec.leaks.push({ field: "JPEG comment", value: W.utf8(seg).replace(/\0+$/, "").slice(0, 200), severity: MED, src: "COM" }); drop = true; sev = MED;
      } else if (m >= 0xe0 && m <= 0xef) {
        const tagName = id.replace(/[^\x20-\x7e].*$/s, "").slice(0, 24);
        rec.leaks.push({ field: `${APP_NAME(m)} segment`, value: `${tagName ? tagName + " · " : ""}${len} bytes vendor metadata`, severity: LOW, src: APP_NAME(m) }); drop = true;
      }
      rec.segments.push({ name: what, size: len + 2, action: drop ? "remove" : "keep", severity: drop ? sev : null });
      if (drop) rec.removed.push(`${what} (${W.fmt.bytes(len + 2)})`); else keep(i, end);
      i = end;
    }
    if (eoi > 0 && eoi < b.length) {
      const extra = b.length - eoi;
      const tail = k.ascii(b, eoi, 64);
      const isVideo = /ftyp(mp4|isom|qt)/.test(k.ascii(b, eoi, 4096)) ;
      rec.leaks.push({ field: "Data after end of image", value: `${W.fmt.bytes(extra)}${isVideo ? " — looks like an embedded motion-photo video" : /\xff\xd8/.test(tail) ? " — another JPEG (preview/depth map)" : ""}`, severity: MED, src: "trailer" });
      rec.segments.push({ name: "Trailer after EOI", size: extra, action: "remove", severity: MED });
      rec.removed.push(`trailing data (${W.fmt.bytes(extra)})`);
    }
    if (opts.keepOrientation !== false && orientation && orientation !== 1) {
      const afterJfif = out[1] && out[1][0] === 0xff && out[1][1] === 0xe0 ? 2 : 1;
      out.splice(afterJfif, 0, minimalExif(orientation));
      rec.notes.push(`Orientation (${orientation}) re-added as a one-tag EXIF block so the photo isn't shown rotated.`);
    }
    rec.clean = k.concat(out); rec.canStrip = true; rec.mime = "image/jpeg";
    return rec;
  }
  function iccDesc(icc) {
    // find the 'desc' tag (v2 'desc' textDescription or v4 'mluc')
    const k = K(); if (icc.length < 132) return "";
    const n = k.u32be(icc, 128);
    for (let i = 0; i < n && i < 64; i++) {
      const o = 132 + i * 12; if (o + 12 > icc.length) break;
      if (k.ascii(icc, o, 4) !== "desc") continue;
      const off = k.u32be(icc, o + 4), t = k.ascii(icc, off, 4);
      if (t === "desc") { const l = k.u32be(icc, off + 8); return k.ascii(icc, off + 12, Math.min(l, 80)).replace(/\0.*$/s, ""); }
      if (t === "mluc") { const so = k.u32be(icc, off + 20), sl = k.u32be(icc, off + 16); let s = ""; for (let j = 0; j + 1 < sl && j < 160; j += 2) s += String.fromCharCode(k.u16be(icc, off + so + j)); return s.replace(/\0.*$/s, ""); }
    }
    return "";
  }

  // ------------------------------------------------------------------ PNG
  async function png(b, opts) {
    const rec = Rec("png", "PNG image"), k = K(), chunks = k.pngChunks(b), out = [k.PNG_SIG];
    for (const c of chunks) {
      let drop = false, sev = LOW;
      try {
        if (c.type === "tEXt" || c.type === "zTXt" || c.type === "iTXt") {
          const z = c.data.indexOf(0), key = k.ascii(c.data, 0, z);
          let val = "";
          if (c.type === "tEXt") val = W.latin1(c.data.subarray(z + 1));
          else if (c.type === "zTXt") val = W.latin1(await k.inflate(c.data.subarray(z + 2)));
          else {
            const comp = c.data[z + 1]; let p = z + 3;
            p = c.data.indexOf(0, p) + 1; p = c.data.indexOf(0, p) + 1; // lang, translated keyword
            const body = c.data.subarray(p);
            val = W.utf8(comp ? await k.inflate(body) : body);
          }
          if (key === "XML:com.adobe.xmp") { merge(rec, xmpLeaks(val, "XMP")); sev = MED; }
          else {
            sev = /^(author|artist|copyright|owner|e-?mail|contact)$/i.test(key) ? HIGH : /^(parameters|prompt|workflow|comment|description|source|creation time|location)$/i.test(key) ? MED : LOW;
            const label = /^(parameters|prompt|workflow)$/i.test(key) ? `PNG ${key} (AI generation settings)` : `PNG ${key}`;
            rec.meta[key] = val.slice(0, 300);
            rec.leaks.push({ field: label, value: val.slice(0, 200), severity: sev, src: c.type });
          }
          drop = true;
        } else if (c.type === "eXIf") {
          const r = exifLeaks(c.data, "eXIf"); merge(rec, r); drop = true; sev = r.gps ? HIGH : MED;
        } else if (c.type === "tIME") {
          const d = c.data; const ts = `${k.u16be(d, 0)}-${String(d[2]).padStart(2, "0")}-${String(d[3]).padStart(2, "0")} ${String(d[4]).padStart(2, "0")}:${String(d[5]).padStart(2, "0")}:${String(d[6]).padStart(2, "0")}Z`;
          rec.leaks.push({ field: "PNG last-modified (tIME)", value: ts, severity: LOW, src: "tIME" }); drop = true;
        } else if (c.type === "iCCP") {
          const z = c.data.indexOf(0);
          rec.leaks.push({ field: "ICC profile", value: k.ascii(c.data, 0, z), severity: INFO, src: "iCCP", note: "Kept by default — removing it can shift colours." });
          drop = opts.keepIcc === false;
        } else if (c.type === "caBX" || c.type === "dSIG") {
          rec.leaks.push({ field: c.type === "caBX" ? "Content Credentials (C2PA)" : "Digital signature (dSIG)", value: `${c.data.length} bytes`, severity: MED, src: c.type }); drop = true;
        }
      } catch (e) { rec.leaks.push({ field: `PNG ${c.type}`, value: "unreadable chunk", severity: LOW, src: c.type }); drop = /^(tEXt|zTXt|iTXt|eXIf)$/.test(c.type); }
      if (drop || ["tEXt", "zTXt", "iTXt", "eXIf", "tIME", "iCCP"].includes(c.type) || c.type === "IEND" || c.type === "IHDR")
        rec.segments.push({ name: c.type, size: c.end - c.start, action: drop ? "remove" : "keep", severity: drop ? sev : null });
      if (drop) rec.removed.push(`${c.type} chunk (${W.fmt.bytes(c.end - c.start)})`); else out.push(b.subarray(c.start, c.end));
    }
    if (chunks.trailer) {
      rec.leaks.push({ field: "Data after IEND", value: `${W.fmt.bytes(chunks.trailer)} appended to the image`, severity: MED, src: "trailer" });
      rec.segments.push({ name: "Trailer after IEND", size: chunks.trailer, action: "remove", severity: MED });
      rec.removed.push(`trailing data (${W.fmt.bytes(chunks.trailer)})`);
    }
    rec.clean = k.concat(out); rec.canStrip = true; rec.mime = "image/png";
    return rec;
  }

  // ------------------------------------------------------------------ WebP (RIFF)
  function webp(b, opts) {
    const rec = Rec("webp", "WebP image"), k = K(), out = []; let i = 12, vp8x = -1;
    while (i + 8 <= b.length) {
      const id = k.ascii(b, i, 4), len = k.u32le(b, i + 4), end = Math.min(b.length, i + 8 + len + (len & 1));
      const data = b.subarray(i + 8, i + 8 + len);
      let drop = false, sev = LOW;
      if (id === "EXIF") { const r = exifLeaks(k.ascii(data, 0, 6) === "Exif\0\0" ? data.subarray(6) : data, "EXIF"); merge(rec, r); drop = true; sev = r.gps ? HIGH : MED; }
      else if (id === "XMP ") { merge(rec, xmpLeaks(W.utf8(data), "XMP")); drop = true; sev = MED; }
      else if (id === "ICCP") { rec.leaks.push({ field: "ICC profile", value: iccDesc(data) || `${len} bytes`, severity: INFO, src: "ICCP", note: "Kept by default — removing it can shift colours." }); drop = opts.keepIcc === false; }
      if (id === "VP8X") vp8x = out.length;
      rec.segments.push({ name: id.trim(), size: end - i, action: drop ? "remove" : "keep", severity: drop ? sev : null });
      if (drop) rec.removed.push(`${id.trim()} chunk (${W.fmt.bytes(end - i)})`); else out.push(b.slice(i, end));
      i = end;
    }
    if (vp8x >= 0) { // clear the EXIF (0x08) / XMP (0x04) [/ ICC (0x20)] feature flags
      const c = out[vp8x]; c[8] &= ~(0x08 | 0x04 | (opts.keepIcc === false ? 0x20 : 0));
    }
    const body = k.concat(out);
    rec.clean = k.concat([k.ascii(b, 0, 4) === "RIFF" ? Uint8Array.of(0x52, 0x49, 0x46, 0x46) : b.subarray(0, 4), k.w32le(body.length + 4), Uint8Array.of(0x57, 0x45, 0x42, 0x50), body]);
    rec.canStrip = true; rec.mime = "image/webp";
    return rec;
  }

  // ------------------------------------------------------------------ GIF
  function gif(b) {
    const rec = Rec("gif", "GIF image"), out = [];
    let i = 13; const flags = b[10];
    if (flags & 0x80) i += 3 * (1 << ((flags & 7) + 1));
    out.push(b.subarray(0, i));
    const skipSub = (j) => { while (j < b.length && b[j]) j += 1 + b[j]; return j + 1; };
    while (i < b.length) {
      const c = b[i];
      if (c === 0x3b) { out.push(b.subarray(i, i + 1)); i++; break; }
      if (c === 0x2c) { // image descriptor (+ optional local colour table) + LZW data
        let j = i + 10; const f = b[i + 9]; if (f & 0x80) j += 3 * (1 << ((f & 7) + 1));
        j = skipSub(j + 1); out.push(b.subarray(i, j)); i = j; continue;
      }
      if (c === 0x21) {
        const label = b[i + 1], end = skipSub(i + 2);
        let drop = false;
        if (label === 0xfe) {
          let s = "", j = i + 2; while (j < end - 1 && b[j]) { s += W.latin1(b.subarray(j + 1, j + 1 + b[j])); j += 1 + b[j]; }
          rec.leaks.push({ field: "GIF comment", value: s.slice(0, 200), severity: MED, src: "comment" }); drop = true;
        } else if (label === 0xff) {
          const app = K().ascii(b, i + 3, 11);
          if (/^(NETSCAPE2\.0|ANIMEXTS1\.0|ICCRGBG1012)/.test(app)) { /* animation loop / colour — keep */ }
          else { rec.leaks.push({ field: `GIF application block ${app.replace(/[^\x20-\x7e]/g, "")}`, value: `${end - i} bytes${/XMP/.test(app) ? " — XMP metadata" : ""}`, severity: /XMP/.test(app) ? MED : LOW, src: "app" }); drop = true; }
        }
        rec.segments.push({ name: `ext 0x${label.toString(16)}`, size: end - i, action: drop ? "remove" : "keep" });
        if (drop) rec.removed.push(`GIF extension 0x${label.toString(16)} (${W.fmt.bytes(end - i)})`); else out.push(b.subarray(i, end));
        i = end; continue;
      }
      out.push(b.subarray(i)); rec.notes.push("Unknown GIF block — rest of file copied unchanged."); i = b.length;
    }
    if (i < b.length) { rec.leaks.push({ field: "Data after GIF trailer", value: W.fmt.bytes(b.length - i), severity: MED, src: "trailer" }); rec.removed.push(`trailing data (${W.fmt.bytes(b.length - i)})`); }
    rec.clean = K().concat(out); rec.canStrip = true; rec.mime = "image/gif";
    return rec;
  }

  // ------------------------------------------------------------------ PDF
  const PDF_KEYS = { Author: HIGH, Creator: MED, Producer: LOW, Title: LOW, Subject: LOW, Keywords: MED, CreationDate: MED, ModDate: LOW, Company: MED, SourceModified: LOW, Manager: MED };
  function pdfString(b, i) {
    // b[i] is "(" or "<"; returns {end (exclusive), raw bytes, text}
    if (b[i] === 0x3c) {
      const e = b.indexOf(0x3e, i); if (e < 0) return null;
      const hex = W.latin1(b.subarray(i + 1, e)).replace(/\s/g, "");
      return { end: e + 1, bytes: W.fromHex(hex.length % 2 ? hex + "0" : hex) };
    }
    const out = []; let depth = 0, j = i;
    for (; j < b.length && j < i + 20000; j++) {
      const c = b[j];
      if (c === 0x5c) { // escape
        const n = b[++j];
        const map = { 0x6e: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12, 0x28: 0x28, 0x29: 0x29, 0x5c: 0x5c };
        if (map[n] != null) out.push(map[n]);
        else if (n >= 0x30 && n <= 0x37) { let v = n - 0x30, c2 = 0; while (c2 < 2 && b[j + 1] >= 0x30 && b[j + 1] <= 0x37) { v = v * 8 + b[++j] - 0x30; c2++; } out.push(v & 255); }
        continue;
      }
      if (c === 0x28) { depth++; if (depth === 1) continue; }
      if (c === 0x29) { depth--; if (depth === 0) return { end: j + 1, bytes: Uint8Array.from(out) }; }
      out.push(c);
    }
    return null;
  }
  function pdfText(bytes) {
    if (bytes[0] === 0xfe && bytes[1] === 0xff) { let s = ""; for (let i = 2; i + 1 < bytes.length; i += 2) s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]); return s; }
    if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return W.utf8(bytes.subarray(3));
    return W.latin1(bytes);
  }
  const pdfDate = (s) => { const m = String(s).match(/^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Z+-])?(\d{2})?'?(\d{2})?/); return m ? `${m[1]}-${m[2] || "01"}-${m[3] || "01"} ${m[4] || "00"}:${m[5] || "00"}:${m[6] || "00"}${m[7] === "Z" ? "Z" : m[7] ? ` ${m[7]}${m[8]}:${m[9] || "00"}` : ""}` : s; };
  function pdf(b) {
    const rec = Rec("pdf", "PDF document"), clean = b.slice(), s = W.latin1(b);
    const re = /\/(Author|Creator|Producer|Title|Subject|Keywords|CreationDate|ModDate|Company|SourceModified|Manager)\s*([(<])/g;
    let m, blanked = 0; const seen = new Set();
    while ((m = re.exec(s))) {
      const start = m.index + m[0].length - 1;
      if (m[2] === "<" && s[start + 1] === "<") continue; // a dictionary, not a hex string
      const str = pdfString(b, start); if (!str) continue;
      const key = m[1]; let val = pdfText(str.bytes).replace(/\0/g, "").trim();
      if (/Date$/.test(key)) val = pdfDate(val);
      if (val && !seen.has(key + "\0" + val)) {
        seen.add(key + "\0" + val);
        rec.meta[key] = val; rec.leaks.push({ field: `PDF /${key}`, value: val.slice(0, 200), severity: PDF_KEYS[key], src: "Info" });
      }
      // blank in place: "()" followed by spaces — identical byte length so xref offsets stay valid
      if (str.end - start >= 2) { clean[start] = 0x28; clean[start + 1] = 0x29; for (let j = start + 2; j < str.end; j++) clean[j] = 0x20; blanked++; }
      re.lastIndex = str.end;
    }
    let xmpCount = 0;
    const xre = /<\?xpacket begin=[^>]*\?>([\s\S]*?)<\?xpacket end=[^>]*\?>/g;
    while ((m = xre.exec(s))) {
      xmpCount++;
      merge(rec, xmpLeaks(m[1], "XMP"));
      const a = m.index + m[0].indexOf("?>") + 2, e = m.index + m[0].lastIndexOf("<?xpacket end");
      for (let j = a; j < e; j++) if (clean[j] !== 0x0a && clean[j] !== 0x0d) clean[j] = 0x20;
    }
    if (/\/Type\s*\/Metadata\b[^>]*\/Filter/.test(s) || /\/Filter[^>]*\/Type\s*\/Metadata\b/.test(s)) rec.notes.push("A compressed XMP stream exists — it can't be inspected or blanked without decompressing; use print-to-PDF for a full rebuild.");
    if (/\/ObjStm\b/.test(s)) rec.notes.push("This PDF uses compressed object streams — an Info dictionary inside one is invisible to this scan.");
    const revisions = (s.match(/%%EOF/g) || []).length;
    if (revisions > 1) rec.leaks.push({ field: "Incremental updates", value: `${revisions} saved revisions — earlier versions of the content may still be inside`, severity: MED, src: "structure" });
    if (/\/EmbeddedFile\b/.test(s)) rec.leaks.push({ field: "Embedded files", value: "the PDF carries attachments", severity: MED, src: "structure" });
    if (/\/JavaScript\b|\/JS\s*[(<]/.test(s)) rec.leaks.push({ field: "JavaScript", value: "document contains scripts (can phone home when opened)", severity: MED, src: "structure" });
    if (blanked) rec.removed.push(`${blanked} Info string(s) blanked in place`);
    if (xmpCount) rec.removed.push(`${xmpCount} XMP packet(s) whitespaced`);
    rec.notes.push("PDF: metadata strings are blanked in place (same length, xref stays valid). Page content, fonts and annotations are untouched.");
    rec.clean = clean; rec.canStrip = true; rec.mime = "application/pdf";
    return rec;
  }

  // ------------------------------------------------------------------ OOXML / ODF (ZIP)
  const xmlUnesc = (s) => s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
  const CORE = [["dc:creator", HIGH], ["cp:lastModifiedBy", HIGH], ["dc:title", LOW], ["dc:subject", LOW], ["dc:description", MED], ["cp:keywords", MED],
    ["cp:category", LOW], ["cp:contentStatus", LOW], ["dcterms:created", MED], ["dcterms:modified", LOW], ["cp:lastPrinted", LOW], ["cp:revision", LOW]];
  const APPX = [["Company", MED], ["Manager", MED], ["Template", LOW], ["HyperlinkBase", MED], ["Application", LOW], ["AppVersion", INFO], ["TotalTime", LOW]];
  const ODF = [["meta:initial-creator", HIGH], ["dc:creator", HIGH], ["meta:printed-by", HIGH], ["dc:title", LOW], ["dc:description", MED], ["meta:keyword", MED],
    ["meta:creation-date", MED], ["dc:date", LOW], ["meta:print-date", LOW], ["meta:generator", LOW], ["meta:editing-duration", LOW], ["meta:editing-cycles", LOW]];
  const BLANK_DATE = "1980-01-01T00:00:00Z";
  function xmlField(xml, tag) {
    const m = xml.match(new RegExp(`<${tag}\\b[^>]*>([^<]*)</${tag}>`)); const v = m ? xmlUnesc(m[1]).trim() : "";
    return v === BLANK_DATE || (tag === "TotalTime" && v === "0") || (tag === "cp:revision" && v === "1") || (tag === "meta:editing-duration" && v === "PT0S") ? "" : v;
  }
  function blankXml(xml, tags, dateTags) {
    for (const t of tags) xml = xml.replace(new RegExp(`(<${t}\\b[^>]*>)[^<]*(</${t}>)`, "g"), (_, a, z) => a + (dateTags.includes(t) ? BLANK_DATE : t === "TotalTime" ? "0" : t === "cp:revision" ? "1" : "") + z);
    return xml;
  }
  async function office(b, name, opts) {
    const k = K(), files = await k.unzip(b);
    const names = files.map((f) => f.name);
    const isOdf = names.includes("meta.xml") || (files[0] && files[0].name === "mimetype");
    const ext = (name.match(/\.(\w+)$/) || [])[1] || "";
    const rec = Rec(isOdf ? "odf" : "ooxml", isOdf ? `OpenDocument (${ext || "odf"})` : `Office document (${ext || "ooxml"})`);
    const authors = new Map(); // name → count
    const addAuthor = (a) => { a = xmlUnesc(a).trim(); if (a && !/^(author|a)$/i.test(a)) authors.set(a, (authors.get(a) || 0) + 1); };
    const enc = (s) => W.bytes(s);
    let thumbs = [];
    for (const f of files) {
      const nm = f.name;
      if (/\.xml$|\.rels$/.test(nm)) {
        let xml = W.utf8(f.data), changed = false;
        if (nm === "docProps/core.xml") {
          for (const [t, sev] of CORE) { const v = xmlField(xml, t); if (v) { rec.meta[t.split(":")[1]] = v; rec.leaks.push({ field: t, value: v.slice(0, 200), severity: sev, src: "core.xml" }); } }
          xml = blankXml(xml, ["dc:creator", "cp:lastModifiedBy", "dc:title", "dc:subject", "dc:description", "cp:keywords", "cp:category", "cp:contentStatus", "dcterms:created", "dcterms:modified", "cp:lastPrinted", "cp:revision"], ["dcterms:created", "dcterms:modified", "cp:lastPrinted"]);
          changed = true;
        } else if (nm === "docProps/app.xml") {
          for (const [t, sev] of APPX) { const v = xmlField(xml, t); if (v) { rec.meta[t] = v; rec.leaks.push({ field: "app:" + t, value: v.slice(0, 200), severity: sev, src: "app.xml" }); } }
          xml = blankXml(xml, ["Company", "Manager", "Template", "HyperlinkBase", "TotalTime"], []); changed = true;
        } else if (nm === "docProps/custom.xml") {
          const props = [...xml.matchAll(/<property\b[^>]*\bname="([^"]*)"[^>]*>\s*<vt:\w+>([^<]*)<\/vt:\w+>/g)];
          for (const p of props) rec.leaks.push({ field: `custom: ${xmlUnesc(p[1])}`, value: xmlUnesc(p[2]).slice(0, 200), severity: MED, src: "custom.xml" });
          xml = xml.replace(/(<vt:\w+>)[^<]*(<\/vt:\w+>)/g, "$1$2"); changed = true;
        } else if (nm === "meta.xml" && isOdf) {
          for (const [t, sev] of ODF) { const v = xmlField(xml, t); if (v) { rec.meta[t] = v; rec.leaks.push({ field: t, value: v.slice(0, 200), severity: sev, src: "meta.xml" }); } }
          for (const p of xml.matchAll(/<meta:user-defined\b[^>]*meta:name="([^"]*)"[^>]*>([^<]*)</g)) rec.leaks.push({ field: `user-defined: ${xmlUnesc(p[1])}`, value: xmlUnesc(p[2]).slice(0, 200), severity: MED, src: "meta.xml" });
          xml = blankXml(xml, ["meta:initial-creator", "dc:creator", "meta:printed-by", "dc:title", "dc:description", "meta:keyword", "meta:creation-date", "dc:date", "meta:print-date", "meta:generator"], ["meta:creation-date", "dc:date", "meta:print-date"])
            .replace(/(<meta:user-defined\b[^>]*>)[^<]*(<)/g, "$1$2").replace(/(<meta:editing-duration>)[^<]*(<)/, "$1PT0S$2"); changed = true;
        } else {
          // revision / comment authors in document parts
          const before = xml;
          xml = xml.replace(/\b(w:author|w15:author|w:initials|author|initials)="([^"]*)"/g, (all, attr, v) => { if (/initials/.test(attr)) return `${attr}="A"`; addAuthor(v); return `${attr}="Author"`; });
          xml = xml.replace(/<(author|dc:creator)>([^<]+)<\/(author|dc:creator)>/g, (all, t, v) => { addAuthor(v); return `<${t}>Author</${t}>`; });
          if (/commentAuthors\.xml$|people\.xml$/.test(nm)) xml = xml.replace(/\bname="([^"]*)"/g, (all, v) => { addAuthor(v); return 'name="Author"'; });
          xml = xml.replace(/\b(w15:userId|userId|providerId)="[^"]*"/g, '$1="None"');
          if (nm === "_rels/.rels") xml = xml.replace(/<Relationship\b[^>]*Target="\/?docProps\/thumbnail\.\w+"[^>]*\/>/g, "");
          changed = xml !== before;
        }
        if (changed) f.data = enc(xml);
      } else if (/^docProps\/thumbnail\.\w+$|^Thumbnails\/thumbnail\.png$/.test(nm)) {
        thumbs.push(nm);
      } else if (/\.(jpe?g|png|webp|gif)$/i.test(nm)) {
        // pictures embedded in the document carry their own EXIF/GPS
        try {
          const sub = await scan(f.data, nm, opts);
          for (const l of sub.leaks.filter((x) => x.severity !== INFO)) rec.leaks.push(Object.assign({}, l, { field: `${nm.split("/").pop()}: ${l.field}`, src: nm }));
          if (sub.gps && !rec.gps) rec.gps = sub.gps;
          if (sub.clean && sub.removed.length) { f.data = sub.clean; rec.removed.push(`${nm}: ${sub.removed.length} metadata block(s)`); }
        } catch { /* leave picture as-is */ }
      }
    }
    for (const [a, n] of authors) rec.leaks.push({ field: "Comment / revision author", value: `${a}${n > 1 ? ` (×${n})` : ""}`, severity: HIGH, src: "document" });
    let outFiles = files;
    if (thumbs.length) {
      rec.leaks.push({ field: "Document thumbnail", value: thumbs.join(", ") + " — a picture of the first page", severity: MED, src: "thumbnail" });
      if (!isOdf) { outFiles = files.filter((f) => !thumbs.includes(f.name)); rec.removed.push("document thumbnail"); }
      else rec.notes.push("ODF thumbnail kept (it is listed in the manifest); re-save without preview to drop it.");
    }
    rec.removed.unshift("document properties blanked", ...(authors.size ? [`${authors.size} author name(s) → "Author"`] : []), "ZIP entry timestamps reset to 1980-01-01");
    rec.clean = await k.zip(outFiles.map((f) => ({ name: f.name, data: f.data, method: f.method })));
    rec.canStrip = true;
    rec.mime = isOdf ? "application/vnd.oasis.opendocument." + (ext === "ods" ? "spreadsheet" : ext === "odp" ? "presentation" : "text") : "application/vnd.openxmlformats-officedocument." + ({ xlsx: "spreadsheetml.sheet", pptx: "presentationml.presentation" }[ext] || "wordprocessingml.document");
    return rec;
  }

  // ------------------------------------------------------------------ MP3 / ID3
  const ID3 = { TPE1: ["Artist", HIGH], TPE2: ["Album artist", MED], TCOM: ["Composer", MED], TENC: ["Encoded by", MED], TOWN: ["Owner", HIGH], WXXX: ["URL", MED], COMM: ["Comment", MED],
    TPUB: ["Publisher", LOW], TSSE: ["Encoder software", LOW], TXXX: ["User text", MED], GEOB: ["Embedded object", MED], TIT2: ["Title", LOW], TALB: ["Album", LOW], TYER: ["Year", LOW], TDRC: ["Recording date", LOW], APIC: ["Cover picture", LOW], PRIV: ["Private frame", MED] };
  function id3Text(d) {
    const e = d[0], body = d.subarray(1);
    if (e === 1 || e === 2) { let s = "", le = e === 1 && body[0] === 0xff; for (let i = e === 1 ? 2 : 0; i + 1 < body.length; i += 2) { const c = le ? body[i] | (body[i + 1] << 8) : (body[i] << 8) | body[i + 1]; s += c ? String.fromCharCode(c) : " "; } return s.trim(); }
    return (e === 3 ? W.utf8(body) : W.latin1(body)).replace(/\0/g, " ").trim();
  }
  function mp3(b) {
    const rec = Rec("mp3", "MP3 audio"), k = K(); let start = 0, end = b.length;
    if (k.ascii(b, 0, 3) === "ID3") {
      const ver = b[3], flags = b[5];
      const size = ((b[6] & 0x7f) << 21) | ((b[7] & 0x7f) << 14) | ((b[8] & 0x7f) << 7) | (b[9] & 0x7f);
      const tag = b.subarray(10, 10 + size);
      let j = 0;
      while (j + 10 < tag.length) {
        const fid = k.ascii(tag, j, 4); if (!/^[A-Z0-9]{4}$/.test(fid)) break;
        const fsz = ver >= 4 ? ((tag[j + 4] & 0x7f) << 21) | ((tag[j + 5] & 0x7f) << 14) | ((tag[j + 6] & 0x7f) << 7) | (tag[j + 7] & 0x7f) : k.u32be(tag, j + 4);
        if (!fsz || j + 10 + fsz > tag.length) break;
        const d = tag.subarray(j + 10, j + 10 + fsz);
        if (ID3[fid]) {
          const [nm, sev] = ID3[fid];
          const v = fid === "APIC" || fid === "GEOB" || fid === "PRIV" ? `${fsz} bytes` : fid === "COMM" ? id3Text(Uint8Array.of(d[0], ...d.subarray(4))) : id3Text(d);
          if (v) { rec.meta[nm] = v.slice(0, 200); rec.leaks.push({ field: `ID3 ${nm}`, value: v.slice(0, 200), severity: sev, src: "ID3v2" }); }
        }
        j += 10 + fsz;
      }
      start = 10 + size + (flags & 0x10 ? 10 : 0);
      rec.removed.push(`ID3v2 tag (${W.fmt.bytes(start)})`);
    }
    if (end - start >= 128 && k.ascii(b, end - 128, 3) === "TAG") {
      const t = (o, n) => W.latin1(b.subarray(end - 128 + o, end - 128 + o + n)).replace(/\0.*$/s, "").trim();
      const v1 = [t(3, 30), t(33, 30), t(63, 30)].filter(Boolean).join(" · ");
      rec.leaks.push({ field: "ID3v1 trailer", value: v1 || "128-byte legacy tag", severity: LOW, src: "ID3v1" });
      end -= 128; rec.removed.push("ID3v1 trailer");
    }
    rec.clean = b.slice(start, end); rec.canStrip = true; rec.mime = "audio/mpeg";
    return rec;
  }

  // ------------------------------------------------------------------ inspect-only: HEIC / MP4 / MOV
  function isobmff(b, kind) {
    const rec = Rec(kind, kind === "heic" ? "HEIC/AVIF image" : "MP4/MOV video"), s = W.latin1(b.length > 64 << 20 ? b.subarray(0, 64 << 20) : b);
    const ei = s.indexOf("Exif\0\0");
    if (ei >= 0) merge(rec, exifLeaks(b.subarray(ei + 6), "EXIF"));
    const xi = s.indexOf("<x:xmpmeta"); if (xi >= 0) { const xe = s.indexOf("</x:xmpmeta>", xi); merge(rec, xmpLeaks(s.slice(xi, xe > 0 ? xe + 12 : xi + 20000), "XMP")); }
    const iso = s.match(/([+-]\d{1,2}\.\d{3,})([+-]\d{1,3}\.\d{3,})([+-]\d+(?:\.\d+)?)?\//); // ©xyz / ISO 6709
    if (iso) { const lat = +iso[1], lon = +iso[2]; if (!rec.gps) rec.gps = { lat, lon }; rec.leaks.push({ field: "GPS (ISO 6709 location atom)", value: `${lat}, ${lon}`, severity: HIGH, src: "©xyz", gps: true }); }
    for (const [atom, nm] of [["\xa9mak", "Make"], ["\xa9mod", "Model"], ["\xa9swr", "Software"], ["\xa9day", "Date"]]) {
      const i = s.indexOf(atom); if (i < 0) continue;
      const m = s.slice(i + 4, i + 80).match(/data\0{4,8}([\x20-\x7e]{2,60})/) || s.slice(i + 4, i + 80).match(/^\0.\0.([\x20-\x7e]{2,60})/s);
      if (m) rec.leaks.push({ field: nm, value: m[1], severity: nm === "Model" || nm === "Date" ? MED : LOW, src: "udta" });
    }
    rec.notes.push(kind === "heic" ? "HEIC can't be stripped losslessly here. Convert to JPEG (or share with “remove location” on your phone), then scrub." : "Video containers can't be rewritten here. Use your phone's share-without-location option, or remux with ffmpeg -map_metadata -1.");
    return rec;
  }

  // ------------------------------------------------------------------ dispatch
  function kindOf(b, name) {
    const k = K(), n = String(name || "").toLowerCase();
    if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
    if (k.isPng(b)) return "png";
    if (k.ascii(b, 0, 4) === "RIFF" && k.ascii(b, 8, 4) === "WEBP") return "webp";
    if (/^GIF8[79]a/.test(k.ascii(b, 0, 6))) return "gif";
    if (k.ascii(b, 0, 5) === "%PDF-" || (k.ascii(b, 0, 1024).includes("%PDF-"))) return "pdf";
    if (k.ascii(b, 0, 2) === "PK" && (/\.(docx|xlsx|pptx|docm|xlsm|pptm|dotx|odt|ods|odp)$/.test(n) || /\[Content_Types\]\.xml|mimetypeapplication\/vnd\.oasis/.test(k.ascii(b, 0, 2048)))) return "office";
    if (k.ascii(b, 0, 3) === "ID3" || (/\.mp3$/.test(n) && b[0] === 0xff && (b[1] & 0xe0) === 0xe0)) return "mp3";
    const ft = k.ascii(b, 4, 8);
    if (/^ftyp(heic|heix|mif1|msf1|heim|hevc|avif)/.test(ft)) return "heic";
    if (/^ftyp/.test(ft) || /^(moov|mdat|wide)/.test(ft)) return "video";
    return "unknown";
  }
  const ORDER = { high: 0, medium: 1, low: 2, info: 3 };

  async function scan(buf, name = "file", opts = {}) {
    const b = W.bytes(buf), kind = kindOf(b, name);
    let rec;
    try {
      if (kind === "jpeg") rec = jpeg(b, opts);
      else if (kind === "png") rec = await png(b, opts);
      else if (kind === "webp") rec = webp(b, opts);
      else if (kind === "gif") rec = gif(b);
      else if (kind === "pdf") rec = pdf(b);
      else if (kind === "office") rec = await office(b, name, opts);
      else if (kind === "mp3") rec = mp3(b);
      else if (kind === "heic" || kind === "video") rec = isobmff(b, kind);
      else { rec = Rec("unknown", "Unrecognised file"); rec.notes.push("No metadata parser for this type. Supported: JPEG, PNG, WebP, GIF, PDF, DOCX/XLSX/PPTX, ODT/ODS/ODP, MP3 (HEIC/MP4/MOV inspect-only)."); }
    } catch (e) {
      rec = Rec(kind, kind.toUpperCase()); rec.notes.push("Could not fully parse: " + (e && e.message || e)); rec.clean = null; rec.canStrip = false;
    }
    rec.name = name; rec.size = b.length;
    rec.leaks.sort((a, z) => (ORDER[a.severity] - ORDER[z.severity]));
    const c = { high: 0, medium: 0, low: 0, info: 0 }; for (const l of rec.leaks) c[l.severity] = (c[l.severity] || 0) + 1;
    rec.counts = c;
    rec.risks = risks(rec);
    const real = rec.leaks.filter((l) => l.severity !== INFO).length;
    rec.summary = real ? `${real} metadata item(s): ${c.high} high, ${c.medium} medium, ${c.low} low.` : rec.type === "unknown" ? "Unsupported file type." : "No identifying metadata found — clean.";
    rec.level = c.high ? "high" : c.medium ? "medium" : c.low ? "low" : "ok";
    if (rec.clean && !rec.removed.length && rec.type !== "pdf" && rec.type !== "ooxml" && rec.type !== "odf") rec.notes.push("Nothing to remove — the cleaned copy is identical.");
    return rec;
  }
  function risks(rec) {
    const r = [], f = (re) => rec.leaks.some((l) => re.test(l.field));
    if (rec.gps) r.push({ level: "critical", text: `GPS location present! (${rec.gps.lat}, ${rec.gps.lon}) — this pins where the file was made.` });
    if (f(/Serial|ImageUniqueID|DocumentID/)) r.push({ level: "high", text: "Device serial / unique IDs — link this file to your camera or other files you've shared." });
    if (f(/Artist|Author|creator|Owner|By-line|lastModifiedBy|printed-by|Caption writer|Contact|custom:|user-defined/i)) r.push({ level: "high", text: "A person's name or account is embedded." });
    if (f(/Make|Model|HostComputer|Software|Application|Producer|CreatorTool|generator|Encoder/i)) r.push({ level: "medium", text: "Device / software fingerprint (make, model, app versions)." });
    if (f(/Date|Time|tIME|created|modified/i)) r.push({ level: "medium", text: "Timestamps reveal when (and in which time zone) it was made." });
    if (f(/thumbnail|after end|after IEND|after GIF|Multi-Picture|Incremental/i)) r.push({ level: "medium", text: "Hidden extra content (thumbnail, appended data or old revisions) can show more than the visible file." });
    if (f(/AI generation/)) r.push({ level: "medium", text: "AI-generation prompt/settings are embedded." });
    return r;
  }
  async function analyze(buf, name, opts) { const r = await scan(buf, name, opts); delete r.clean; return r; }
  async function strip(buf, name = "file", opts = {}) {
    const r = await scan(buf, name, opts);
    if (!r.canStrip || !r.clean) throw new Error(r.notes[0] || "No lossless stripper for this file type");
    return { data: r.clean, removed: r.removed, note: r.notes.join(" "), mime: r.mime, name: cleanName(name) };
  }
  const cleanName = (n) => { const m = String(n || "file").match(/^(.*?)(\.[^.]+)?$/); return `${m[1] || "file"}.clean${m[2] || ""}`; };

  W.eng.scrub = { scan, analyze, strip, kindOf, parseTiff, exifLeaks, xmpLeaks, cleanName, minimalExif };
})(typeof window !== "undefined" ? window.W : globalThis.W);
