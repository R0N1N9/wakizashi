/* Kemuridama byte toolkit — CRC-32, zlib/deflate via (De)CompressionStream, a small ZIP reader/writer and
 * PNG chunk helpers. Shared by scrub (OOXML/ODF, PNG text), stego (PNG pixels) and decoy (canary .docx).
 * Pure: no DOM. ZIP64, encryption and multi-disk archives are refused with a clear error. */
(function (W) {
  "use strict";

  // ------------------------------------------------------------------ CRC-32 (IEEE, as used by ZIP + PNG)
  let T = null;
  function crc32(bytes, crc) {
    if (!T) { T = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; T[n] = c >>> 0; } }
    let c = (crc == null ? 0 : crc) ^ 0xffffffff;
    for (let i = 0; i < bytes.length; i++) c = T[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  // ------------------------------------------------------------------ streams
  async function through(bytes, stream) {
    const S = globalThis.Response;
    const blob = new Blob([W.bytes(bytes)]);
    const out = await new S(blob.stream().pipeThrough(stream)).arrayBuffer();
    return new Uint8Array(out);
  }
  const need = (name) => { if (typeof globalThis[name] !== "function") throw new Error(name + " is not supported by this browser"); return globalThis[name]; };
  /** fmt: "deflate" (zlib, RFC 1950) | "deflate-raw" (RFC 1951) | "gzip" */
  const inflate = (bytes, fmt = "deflate") => through(bytes, new (need("DecompressionStream"))(fmt));
  const deflate = (bytes, fmt = "deflate") => through(bytes, new (need("CompressionStream"))(fmt));

  // ------------------------------------------------------------------ little readers
  const u16le = (b, o) => b[o] | (b[o + 1] << 8);
  const u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const u16be = (b, o) => (b[o] << 8) | b[o + 1];
  const u32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  const ascii = (b, o, n) => { let s = ""; for (let i = 0; i < n && o + i < b.length; i++) s += String.fromCharCode(b[o + i]); return s; };
  function concat(parts) {
    let n = 0; for (const p of parts) n += p.length;
    const out = new Uint8Array(n); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const w16le = (v) => Uint8Array.of(v & 255, (v >>> 8) & 255);
  const w32le = (v) => Uint8Array.of(v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255);
  const w32be = (v) => Uint8Array.of((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);

  // ------------------------------------------------------------------ ZIP
  /** Parse the central directory. Returns [{name, method, crc, csize, usize, time, date, offset, dataStart, flags, extraLen}] */
  function zipEntries(buf) {
    const b = W.bytes(buf);
    let eocd = -1;
    for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) if (u32le(b, i) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error("Not a ZIP archive (no end-of-central-directory record)");
    const count = u16le(b, eocd + 10), cdOff = u32le(b, eocd + 16);
    if (count === 0xffff || cdOff === 0xffffffff) throw new Error("ZIP64 archives are not supported");
    const out = []; let p = cdOff;
    for (let i = 0; i < count; i++) {
      if (u32le(b, p) !== 0x02014b50) throw new Error("Corrupt ZIP central directory");
      const flags = u16le(b, p + 8), method = u16le(b, p + 10), time = u16le(b, p + 12), date = u16le(b, p + 14);
      const crc = u32le(b, p + 16), csize = u32le(b, p + 20), usize = u32le(b, p + 24);
      const nlen = u16le(b, p + 28), xlen = u16le(b, p + 30), clen = u16le(b, p + 32), offset = u32le(b, p + 42);
      const name = W.utf8(b.subarray(p + 46, p + 46 + nlen));
      if (u32le(b, offset) !== 0x04034b50) throw new Error("Corrupt ZIP local header for " + name);
      const dataStart = offset + 30 + u16le(b, offset + 26) + u16le(b, offset + 28);
      out.push({ name, method, crc, csize, usize, time, date, offset, dataStart, flags, extraLen: xlen, commentLen: clen });
      p += 46 + nlen + xlen + clen;
    }
    return out;
  }
  async function zipRead(buf, entry) {
    const b = W.bytes(buf);
    if (entry.flags & 1) throw new Error("Encrypted ZIP entries are not supported");
    const raw = b.subarray(entry.dataStart, entry.dataStart + entry.csize);
    if (entry.method === 0) return raw.slice();
    if (entry.method === 8) return inflate(raw, "deflate-raw");
    throw new Error(`Unsupported ZIP compression method ${entry.method} (${entry.name})`);
  }
  /** Read every entry → [{name, data, method}] in archive order. */
  async function unzip(buf) {
    const ents = zipEntries(buf);
    const out = [];
    for (const e of ents) out.push({ name: e.name, method: e.method, data: e.name.endsWith("/") ? new Uint8Array(0) : await zipRead(buf, e), time: e.time, date: e.date });
    return out;
  }
  /** Build a ZIP from [{name, data, method?(0|8), time?, date?}]. Defaults: deflate, DOS time 1980-01-01 00:00
   *  (so the archive itself doesn't leak when it was made), no extra fields, no comments. */
  async function zip(files) {
    const locals = [], central = []; let off = 0;
    for (const f of files) {
      const name = W.bytes(f.name), data = W.bytes(f.data);
      const method = f.method === 0 || data.length === 0 ? 0 : 8;
      const comp = method === 8 ? await deflate(data, "deflate-raw") : data;
      const crc = crc32(data), time = f.time || 0, date = f.date || 0x21; // 0x21 = 1980-01-01
      const flags = 0x0800; // UTF-8 names
      const lh = concat([w32le(0x04034b50), w16le(20), w16le(flags), w16le(method), w16le(time), w16le(date), w32le(crc), w32le(comp.length), w32le(data.length), w16le(name.length), w16le(0), name]);
      locals.push(lh, comp);
      central.push(concat([w32le(0x02014b50), w16le(20), w16le(20), w16le(flags), w16le(method), w16le(time), w16le(date), w32le(crc), w32le(comp.length), w32le(data.length),
        w16le(name.length), w16le(0), w16le(0), w16le(0), w16le(0), w32le(0), w32le(off), name]));
      off += lh.length + comp.length;
    }
    const cd = concat(central);
    const eocd = concat([w32le(0x06054b50), w16le(0), w16le(0), w16le(files.length), w16le(files.length), w32le(cd.length), w32le(off), w16le(0)]);
    return concat([...locals, cd, eocd]);
  }

  // ------------------------------------------------------------------ PNG chunks
  const PNG_SIG = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);
  const isPng = (b) => b.length > 8 && PNG_SIG.every((x, i) => b[i] === x);
  /** [{type, data, start, end}] (end = after CRC). Stops after IEND; `trailer` = bytes after IEND. */
  function pngChunks(buf) {
    const b = W.bytes(buf);
    if (!isPng(b)) throw new Error("Not a PNG file");
    const out = []; let i = 8, trailer = 0;
    while (i + 12 <= b.length) {
      const len = u32be(b, i), type = ascii(b, i + 4, 4);
      if (i + 12 + len > b.length) { out.push({ type, data: b.subarray(i + 8, b.length), start: i, end: b.length, truncated: true }); i = b.length; break; }
      out.push({ type, data: b.subarray(i + 8, i + 8 + len), start: i, end: i + 12 + len });
      i += 12 + len;
      if (type === "IEND") break;
    }
    trailer = Math.max(0, b.length - i);
    out.trailer = trailer;
    return out;
  }
  function pngChunk(type, data) {
    const t = W.bytes(type), d = W.bytes(data);
    return concat([w32be(d.length), t, d, w32be(crc32(concat([t, d])))]);
  }

  W.eng.kpack = { crc32, inflate, deflate, zipEntries, zipRead, unzip, zip, pngChunks, pngChunk, isPng, PNG_SIG, concat, u16le, u32le, u16be, u32be, ascii, w32be, w32le, w16le };
})(typeof window !== "undefined" ? window.W : globalThis.W);
