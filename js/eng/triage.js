/* Static file triage (port of katana/cti/triage.py): type, hashes, entropy, PE (sections, imports, imphash,
   flags), ELF, PDF keywords, ZIP/Office/APK/JAR listing, suspicious strings, embedded IOCs and a scored,
   severity-sorted indicator list. Files never leave the device. analyze() is async (hashing + zip inflate). */
(function (W) {
  "use strict";
  const MAGIC = [
    [[0x4d, 0x5a], "PE / DOS executable"], [[0x7f, 0x45, 0x4c, 0x46], "ELF executable"], [[0x25, 0x50, 0x44, 0x46], "PDF document"],
    [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], "OLE2 (legacy Office / MSI)"], [[0x50, 0x4b, 0x03, 0x04], "ZIP container"],
    [[0x1f, 0x8b], "GZIP"], [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], "7-Zip"], [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], "RAR"],
    [[0x89, 0x50, 0x4e, 0x47], "PNG image"], [[0xff, 0xd8, 0xff], "JPEG image"], [[0x47, 0x49, 0x46, 0x38], "GIF image"],
    [[0xca, 0xfe, 0xba, 0xbe], "Mach-O fat / Java class"], [[0xcf, 0xfa, 0xed, 0xfe], "Mach-O 64"], [[0xfe, 0xed, 0xfa, 0xce], "Mach-O"],
    [[0x64, 0x65, 0x78, 0x0a], "Android DEX"], [[0x7b, 0x5c, 0x72, 0x74, 0x66], "RTF document"], [[0x4c, 0, 0, 0, 1, 0x14, 2, 0], "Windows shortcut (LNK)"],
    [[0x4d, 0x53, 0x43, 0x46], "Microsoft CAB"], [[0x23, 0x21], "Script (shebang)"], [[0x3c, 0x3f, 0x78, 0x6d, 0x6c], "XML"],
    [[0x3c, 0x68, 0x74, 0x6d, 0x6c], "HTML"], [[0x3c, 0x21, 0x44, 0x4f, 0x43, 0x54, 0x59, 0x50, 0x45], "HTML"], [[0, 0, 1, 0], "ICO"],
  ];
  const SUSPICIOUS = {
    "Windows execution": ["powershell", "cmd.exe /c", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "schtasks", "wmic", "-encodedcommand", "-enc ", "invoke-expression", "iex(", "frombase64string", "downloadstring", "downloadfile", "start-process", "bypass"],
    "Process injection / evasion": ["virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread", "ntunmapviewofsection", "queueuserapc", "setwindowshookex", "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "loadlibrary", "getprocaddress", "amsiscanbuffer", "etweventwrite"],
    "Network": ["urldownloadtofile", "internetopen", "internetreadfile", "winhttp", "wsastartup", "httpsendrequest", "user-agent:", "socket(", "connect(", "/gate.php", "pastebin.com", "discord.com/api/webhooks", "api.telegram.org", "ngrok", ".onion"],
    "Persistence": ["currentversion\\run", "currentversion\\runonce", "\\startup\\", "crontab", "/etc/init.d", "systemctl enable", ".bashrc", "launchagents", "services\\"],
    "Credential / data theft": ["lsass", "mimikatz", "sekurlsa", "login data", "cookies.sqlite", "wallet.dat", "keychain", "/etc/shadow", "getasynckeystate", "clipboard"],
    "Ransomware": ["vssadmin delete shadows", "wbadmin delete", "bcdedit /set", "recoveryenabled no", "your files have been encrypted", ".onion", "bitcoin", "decrypt"],
    "Linux / IoT": ["/bin/sh", "/bin/busybox", "chmod 777", "chmod +x", "wget http", "curl http", "/dev/tcp/", "nc -e", "base64 -d", "/tmp/.", "iptables -f"],
    "Android": ["dexclassloader", "runtime.exec", "getdeviceid", "smsmanager", "sendtextmessage", "accessibilityservice", "device_admin", "bind_accessibility_service", "read_sms", "getinstalledpackages", "requestinstallpackages"],
  };
  const IMPORT_CAPS = [
    ["Process injection", "high", "T1055", ["virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection", "queueuserapc", "setthreadcontext", "rtlcreateuserthread", "ntmapviewofsection", "ntwritevirtualmemory", "mapviewofsection", "ntcreatethreadex"]],
    ["Dynamic API resolution", "medium", "T1027", ["loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress"]],
    ["Process / command execution", "high", "T1106", ["winexec", "createprocess", "shellexecute", "ntcreateprocess"]],
    ["Network / C2", "high", "T1071", ["urldownloadtofile", "internetopen", "internetconnect", "internetreadfile", "httpopenrequest", "httpsendrequest", "winhttp", "wsastartup", "wsasocket", "gethostbyname", "getaddrinfo"]],
    ["Persistence (registry)", "medium", "T1547", ["regsetvalue", "regcreatekey", "regsetkeyvalue"]],
    ["Service control", "medium", "T1543", ["openscmanager", "createservice", "startservice", "changeserviceconfig"]],
    ["Keylogging / input capture", "high", "T1056", ["setwindowshookex", "getasynckeystate", "getkeystate", "getrawinputdata", "registerrawinputdevices", "attachthreadinput"]],
    ["Anti-debugging", "medium", "T1622", ["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring", "ntsetinformationthread"]],
    ["Privilege / token manipulation", "medium", "T1134", ["adjusttokenprivileges", "lookupprivilegevalue", "openprocesstoken", "duplicatetokenex", "impersonateloggedonuser", "setthreadtoken"]],
    ["Credential access", "high", "T1003", ["lsaenumerate", "samiconnect", "credenumerate", "credread", "cryptunprotectdata", "lsaretrieveprivatedata"]],
    ["Cryptography", "medium", "T1486", ["cryptencrypt", "cryptdecrypt", "cryptacquirecontext", "cryptgenkey", "bcryptencrypt", "bcryptgeneratesymmetrickey", "cryptderivekey"]],
    ["Screen / clipboard capture", "medium", "T1113", ["bitblt", "createcompatibledc", "getwindowdc", "getclipboarddata", "openclipboard"]],
    ["Anti-analysis (sleep / timing)", "low", "T1497", ["queryperformancecounter", "ntdelayexecution"]],
    ["System / host discovery", "low", "T1082", ["getcomputername", "getvolumeinformation", "getsysteminfo", "gethostname", "getusername"]],
  ];
  const PE_MACHINE = { 0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64" };
  const ELF_MACHINE = { 3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS", 20: "PowerPC", 243: "RISC-V" };

  const startsWith = (b, sig) => sig.every((x, i) => b[i] === x);
  function magic(bytes) {
    const b = W.bytes(bytes);
    for (const [sig, d] of MAGIC) if (b.length >= sig.length && startsWith(b, sig)) return d;
    if (b.length > 262 && W.latin1(b.subarray(257, 262)) === "ustar") return "TAR";
    try { new TextDecoder("utf-8", { fatal: true }).decode(b.subarray(0, 4096)); return "Text / script"; } catch { return "Unknown binary"; }
  }
  const dv = (b) => new DataView(b.buffer, b.byteOffset, b.byteLength);
  const cstr = (b, off, lim = 256) => { if (off == null || off < 0 || off >= b.length) return ""; let e = off; while (e < b.length && e < off + lim && b[e]) e++; return W.latin1(b.subarray(off, e)); };
  const indexOfBytes = (b, needle, from = 0) => { const n = W.bytes(needle); outer: for (let i = from; i <= b.length - n.length; i++) { for (let j = 0; j < n.length; j++) if (b[i + j] !== n[j]) continue outer; return i; } return -1; };
  const countBytes = (b, needle) => { let c = 0, i = 0; while ((i = indexOfBytes(b, needle, i)) >= 0) { c++; i++; } return c; };

  function pe(b) {
    try {
      const v = dv(b), off = v.getUint32(0x3c, true);
      if (off + 24 > b.length || W.latin1(b.subarray(off, off + 4)) !== "PE\0\0") return null;
      const machine = v.getUint16(off + 4, true), nsec = v.getUint16(off + 6, true), ts = v.getUint32(off + 8, true);
      const optSize = v.getUint16(off + 20, true), chars = v.getUint16(off + 22, true), opt = off + 24;
      const mg = v.getUint16(opt, true), is64 = mg === 0x20b, sub = v.getUint16(opt + 68, true), aoe = v.getUint32(opt + 16, true);
      const secOff = opt + optSize, secs = [], raw = []; let endRaw = 0;
      for (let i = 0; i < Math.min(nsec, 40); i++) {
        const s = secOff + i * 40; if (s + 40 > b.length) break;
        const name = W.latin1(b.subarray(s, s + 8)).replace(/\0+$/, "");
        const vsize = v.getUint32(s + 8, true), vaddr = v.getUint32(s + 12, true), rsize = v.getUint32(s + 16, true), rptr = v.getUint32(s + 20, true), sch = v.getUint32(s + 36, true);
        raw.push([vaddr, vsize, rptr, rsize]); endRaw = Math.max(endRaw, rptr + rsize);
        secs.push({ name, vsize, rsize, vaddr, entropy: +W.entropy(b.subarray(rptr, Math.min(b.length, rptr + rsize))).toFixed(2), exec: !!(sch & 0x20000000), write: !!(sch & 0x80000000) });
      }
      const rva2off = (rva) => { for (const [va, vs, rp, rs] of raw) if (rva >= va && rva < va + Math.max(vs, rs)) return rp + (rva - va); return null; };
      const ndd = v.getUint32(opt + (is64 ? 108 : 92), true), dd = opt + (is64 ? 112 : 96);
      const ddir = (i) => (i < ndd && dd + i * 8 + 8 <= b.length ? [v.getUint32(dd + i * 8, true), v.getUint32(dd + i * 8 + 4, true)] : [0, 0]);
      const imports = [], parts = [];
      let d = rva2off(ddir(1)[0]), guardD = 0;
      while (d != null && d + 20 <= b.length && guardD++ < 200) {
        const ilt = v.getUint32(d, true), nameRva = v.getUint32(d + 12, true), iat = v.getUint32(d + 16, true);
        if (!ilt && !nameRva && !iat) break;
        const dll = cstr(b, rva2off(nameRva), 64) || "?", funcs = [];
        let t = rva2off(ilt || iat), g = 0; const step = is64 ? 8 : 4;
        while (t != null && t + step <= b.length && g++ < 5000) {
          const lo = v.getUint32(t, true), hi = is64 ? v.getUint32(t + 4, true) : 0;
          if (!lo && !hi) break;
          const ord = is64 ? (hi & 0x80000000) : (lo & 0x80000000);
          if (ord) funcs.push("ord" + (lo & 0xffff)); else { const fn = cstr(b, rva2off((lo & 0x7fffffff) + 2), 128); if (fn) funcs.push(fn); }
          t += step;
        }
        if (dll !== "?" || funcs.length) {
          imports.push({ dll, funcs });
          const base = dll.toLowerCase().replace(/\.(dll|ocx|sys)$/, "");
          for (const f of funcs) parts.push(`${base}.${f.toLowerCase()}`);
        }
        d += 20;
      }
      const imphash = parts.length ? W.hash.md5(parts.join(",")) : null;
      let exports = 0; const eo = rva2off(ddir(0)[0]); if (eo != null && eo + 28 <= b.length) exports = v.getUint32(eo + 24, true);
      const tls = !!ddir(9)[0];
      const ep = secs.find((s) => aoe >= s.vaddr && aoe < s.vaddr + Math.max(s.vsize, s.rsize));
      const overlay = endRaw && b.length > endRaw ? b.length - endRaw : 0;
      const flags = [], names = secs.map((s) => s.name.toLowerCase());
      if (names.some((n) => /^(upx|\.aspack|\.themida|\.vmp|\.mpress|petite|\.enigma|\.nsp)/.test(n))) flags.push("Packer section names present");
      if (secs.some((s) => s.entropy > 7.2)) flags.push("High-entropy section (packed / encrypted)");
      if (secs.some((s) => s.exec && s.write)) flags.push("Writable + executable section");
      if (secs.some((s) => s.rsize === 0 && s.vsize > 0 && s.exec)) flags.push("Executable section empty on disk (unpacks at runtime)");
      if (ep && ep.write) flags.push(`Entry point in a writable section (${ep.name})`);
      if (imports.length && imports.length <= 2 && imports.reduce((n, i) => n + i.funcs.length, 0) <= 5) flags.push("Very small import table (likely packed - APIs resolved at runtime)");
      if (tls) flags.push("TLS callbacks present (code can run before main/entry)");
      if (overlay > 4096) flags.push(`Overlay: ${overlay.toLocaleString("en-US")} bytes appended after the last section`);
      const compiled = ts > 0 && ts < 4102444800 ? new Date(ts * 1000) : null;
      if (!compiled || compiled.getUTCFullYear() < 2000 || compiled > new Date()) flags.push("Compile timestamp is implausible (likely forged)");
      return { Format: is64 ? "PE32+" : "PE32", Machine: PE_MACHINE[machine] || "0x" + machine.toString(16), Kind: chars & 0x2000 ? "DLL" : sub === 1 ? "Driver" : "EXE",
        Subsystem: { 2: "GUI", 3: "Console", 1: "Native/Driver" }[sub] || sub, Compiled: compiled ? compiled.toISOString().slice(0, 16).replace("T", " ") + " UTC" : "invalid",
        ImpHash: imphash, "Imported DLLs": imports.length, Exports: exports, "Entry section": ep ? ep.name : null, "Overlay bytes": overlay || null,
        Sections: secs.map(({ vaddr, ...s }) => s), imports, Flags: flags };
    } catch { return null; }
  }
  function elf(b) {
    try {
      const le = b[5] === 1, v = dv(b);
      const et = v.getUint16(16, le), m = v.getUint16(18, le);
      return { Class: { 1: "32-bit", 2: "64-bit" }[b[4]], Endian: le ? "little" : "big", Type: { 1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core" }[et] || et,
        Machine: ELF_MACHINE[m] || m, Stripped: indexOfBytes(b, ".symtab") < 0, "Statically linked": indexOfBytes(b, ".interp") < 0 };
    } catch { return null; }
  }
  function pdf(b) {
    const keys = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/URI", "/AcroForm", "/XFA", "/ObjStm", "/RichMedia", "/Encrypt"];
    const counts = {}; for (const k of keys) { const n = countBytes(b, k); if (n) counts[k] = n; }
    const risky = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/XFA"].filter((k) => counts[k]);
    return { Keywords: counts, Pages: countBytes(b, "/Type /Page") || countBytes(b, "/Type/Page"), Flags: risky.map((k) => `Contains ${k}`) };
  }

  /** Minimal ZIP central-directory reader: [{name, method, csize, size, flags, off}] + read(entry) → Uint8Array (async). */
  function zipEntries(b) {
    const v = dv(b); let eocd = -1;
    for (let i = b.length - 22; i >= Math.max(0, b.length - 65557); i--) if (v.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) return null;
    const n = v.getUint16(eocd + 10, true), cdOff = v.getUint32(eocd + 16, true), out = [];
    let p = cdOff;
    for (let i = 0; i < n && p + 46 <= b.length; i++) {
      if (v.getUint32(p, true) !== 0x02014b50) break;
      const flags = v.getUint16(p + 8, true), method = v.getUint16(p + 10, true), csize = v.getUint32(p + 20, true), size = v.getUint32(p + 24, true);
      const nl = v.getUint16(p + 28, true), xl = v.getUint16(p + 30, true), cl = v.getUint16(p + 32, true), off = v.getUint32(p + 42, true);
      out.push({ name: W.utf8(b.subarray(p + 46, p + 46 + nl)), flags, method, csize, size, off });
      p += 46 + nl + xl + cl;
    }
    return out;
  }
  async function zipRead(b, e) {
    const v = dv(b); if (v.getUint32(e.off, true) !== 0x04034b50) throw new Error("bad local header");
    const start = e.off + 30 + v.getUint16(e.off + 26, true) + v.getUint16(e.off + 28, true), data = b.subarray(start, start + e.csize);
    if (e.method === 0) return data;
    if (e.method !== 8 || typeof DecompressionStream === "undefined") throw new Error("unsupported compression");
    const ds = new DecompressionStream("deflate-raw");
    const buf = await new Response(new Blob([data]).stream().pipeThrough(ds)).arrayBuffer();
    return new Uint8Array(buf);
  }
  async function zip(b) {
    const ents = zipEntries(b); if (!ents) return [null, null];
    const names = ents.map((e) => e.name), low = names.map((n) => n.toLowerCase()), flags = [];
    let kind = "ZIP archive", info = {};
    if (low.includes("androidmanifest.xml")) {
      kind = "Android APK";
      const dex = names.filter((n) => n.endsWith(".dex")), libs = [...new Set(names.filter((n) => n.startsWith("lib/") && n.split("/").length >= 3).map((n) => n.split("/")[1]))].sort();
      if (dex.length > 1) flags.push(`Multidex (${dex.length} dex files)`);
      if (low.some((n) => n.startsWith("assets/") && /\.(dex|jar|apk|so)$/.test(n))) flags.push("Code hidden in assets/ (dropper / dynamic loading)");
      info = { "DEX files": dex, "Native ABIs": libs, Signed: low.some((n) => n.startsWith("meta-inf/") && /\.(rsa|dsa|ec)$/.test(n)) };
    } else if (low.includes("[content_types].xml")) {
      kind = "Office Open XML";
      if (low.some((n) => n.includes("vbaproject.bin"))) flags.push("Contains VBA macros (vbaProject.bin)");
      if (low.some((n) => n.includes("activex"))) flags.push("Contains ActiveX objects");
      let rels = "";
      for (const e of ents.filter((x) => x.name.endsWith(".rels")).slice(0, 40)) { try { rels += W.utf8(await zipRead(b, e)); } catch { /* skip */ } }
      const ext = [...rels.matchAll(/Target="(https?:\/\/[^"]+)"[^>]*TargetMode="External"/g)].map((m) => m[1]);
      if (ext.length) flags.push("External relationship targets (remote template injection?)");
      info = { "External targets": ext.slice(0, 10) };
    } else if (low.includes("meta-inf/manifest.mf")) kind = "Java JAR";
    if (ents.some((e) => e.flags & 1)) flags.push("Password-protected entries");
    const dbl = names.filter((n) => /\.(pdf|docx?|jpg|png|txt)\.(exe|scr|js|vbs|lnk|bat|cmd|hta)$/i.test(n));
    if (dbl.length) flags.push("Double-extension filenames: " + dbl.slice(0, 5).join(", "));
    const exe = names.filter((n) => /\.(exe|scr|js|vbs|lnk|bat|cmd|hta|ps1|iso|msi|dll)$/i.test(n));
    if (exe.length && kind === "ZIP archive") flags.push(`Archive contains executable/script content (${exe.length})`);
    return [kind, Object.assign(info, { Entries: names.length, Listing: names.slice(0, 80), Flags: flags })];
  }

  const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
  const HIGH_FLAG = ["writable + executable", "masquerad", "empty on disk", "entry point in a writable", "double-extension", "remote template", "hidden in assets"];
  const MED_FLAG = ["packer", "high-entropy", "overlay", "tls callback", "timestamp", "macro", "password-protect", "small import", "activex", "multidex", "/javascript", "/openaction", "/launch"];
  const flagSev = (t) => { t = t.toLowerCase(); return HIGH_FLAG.some((k) => t.includes(k)) ? "high" : MED_FLAG.some((k) => t.includes(k)) ? "medium" : "low"; };

  function indicators(out) {
    const ind = [], imports = (out.details && out.details.imports) || [];
    const funcs = [...new Set(imports.flatMap((i) => i.funcs.map((f) => f.toLowerCase())))].sort(), apis = new Set();
    for (const [cap, sev, tech, needles] of IMPORT_CAPS) {
      const m = funcs.filter((f) => needles.some((n) => f.includes(n)));
      if (m.length) { m.forEach((x) => apis.add(x)); ind.push({ severity: sev, title: cap, tech, detail: "APIs: " + m.slice(0, 8).join(", ") + (m.length > 8 ? " …" : "") }); }
    }
    for (const f of out.flags) ind.push({ severity: flagSev(f), title: f, detail: "", tech: null });
    const HI = new Set(["Process injection / evasion", "Credential / data theft", "Ransomware"]);
    for (const [cat, found] of Object.entries(out.suspicious || {})) ind.push({ severity: HI.has(cat) ? "high" : "medium", tech: null, title: `Strings → ${cat}`, detail: found.slice(0, 10).join(", ") });
    const best = {};
    for (const i of ind) if (!best[i.title] || SEV[i.severity] < SEV[best[i.title].severity]) best[i.title] = i;
    const items = Object.values(best).sort((a, b) => (SEV[a.severity] - SEV[b.severity]) || a.title.localeCompare(b.title));
    const counts = { high: 0, medium: 0, low: 0 }; items.forEach((i) => counts[i.severity]++);
    const score = Math.min(100, counts.high * 20 + counts.medium * 8 + counts.low * 2);
    const band = score >= 60 || counts.high >= 2 ? "malicious indicators" : score >= 25 || counts.high ? "suspicious" : "low signal";
    return { items, counts, score, band, apis: [...apis].sort() };
  }

  async function analyze(bytes, filename = "") {
    const b = W.bytes(bytes);
    if (!b.length) throw new Error("empty file");
    let type = magic(b);
    const out = { name: filename, size: b.length, type, hashes: await W.hash.all(b), entropy: +W.entropy(b).toFixed(3), details: null, flags: [] };
    if (out.entropy > 7.5) out.flags.push("Very high overall entropy: compressed, packed or encrypted");
    const ext = filename.includes(".") ? filename.toLowerCase().split(".").pop() : "";
    if (type.startsWith("PE") && ["pdf", "doc", "docx", "jpg", "png", "txt", "xls", "xlsx"].includes(ext)) out.flags.push(`Executable masquerading as .${ext}`);
    if (type.startsWith("PE")) out.details = pe(b);
    else if (type.startsWith("ELF")) out.details = elf(b);
    else if (type.startsWith("PDF")) out.details = pdf(b);
    else if (type.startsWith("ZIP")) { const [k, info] = await zip(b); if (k) { out.type = k; out.details = info; } }
    else if (type.startsWith("OLE2")) out.details = { Flags: indexOfBytes(b, "_VBA_PROJECT") >= 0 || (indexOfBytes(b, "VBA") >= 0 && indexOfBytes(b, "Attribute VB_") >= 0) ? ["VBA macro streams present"] : [] };
    if (out.details && out.details.Flags) { out.flags.push(...out.details.Flags); delete out.details.Flags; }
    const strs = W.eng.yaragen.strings(b, 6, 4000), blob = strs.join("\n"), low = blob.toLowerCase(), hits = {};
    for (const [cat, words] of Object.entries(SUSPICIOUS)) { const f = [...new Set(words.filter((w) => low.includes(w)))].sort(); if (f.length) hits[cat] = f; }
    out.suspicious = hits; out.strings_count = strs.length; out.strings_sample = strs.filter((s) => s.length >= 8).slice(0, 300);
    const iocs = W.eng.ioc.extract(blob, { includePrivate: false, refang: false });
    if ((iocs.filepath || []).length > 200) delete iocs.filepath;
    for (const h of ["md5", "sha1", "sha256", "sha512"]) if (iocs[h]) { iocs[h] = iocs[h].filter((x) => x !== out.hashes[h]); if (!iocs[h].length) delete iocs[h]; }
    out.iocs = Object.fromEntries(Object.entries(iocs).map(([k, v]) => [k, v.slice(0, 200)]));
    out.indicators = indicators(out);
    return out;
  }

  W.eng.triage = { analyze, magic, pe, elf, pdf, zipEntries, zipRead };
})(typeof window !== "undefined" ? window.W : globalThis.W);
