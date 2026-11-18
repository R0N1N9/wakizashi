(function () {
  "use strict";
  const { $, esc, ui } = W;
  const ACCEPT = "image/*,.jpg,.jpeg,.png,.webp,.gif,.heic,.pdf,.docx,.xlsx,.pptx,.odt,.ods,.odp,.mp3,.mp4,.mov";

  // ---- sample: a real JPEG from a canvas with a hand-built EXIF block (fictitious values) ----
  function tiff(ifds) {
    // ifds: {ifd0:[[tag,type,value]], exif:[...], gps:[...]} → big-endian TIFF with pointers wired up
    const enc = (s) => Array.from(new TextEncoder().encode(s + "\0"));
    const order = ["ifd0", "exif", "gps"], size = { 2: 1, 3: 2, 4: 4, 5: 8 };
    const ent = { ifd0: ifds.ifd0.slice(), exif: ifds.exif, gps: ifds.gps };
    ent.ifd0.push([0x8769, 4, 0], [0x8825, 4, 0]);
    let off = 8; const start = {};
    for (const k of order) { start[k] = off; off += 2 + ent[k].length * 12 + 4; }
    const data = []; let dOff = off; const out = [];
    const u16 = (v) => [(v >> 8) & 255, v & 255], u32 = (v) => [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
    for (const k of order) {
      ent[k].sort((a, b) => a[0] - b[0]);
      out.push(...u16(ent[k].length));
      for (const [tag, type, val] of ent[k]) {
        let bytes = type === 2 ? enc(val) : type === 3 ? u16(val) : type === 4 ? u32(tag === 0x8769 ? start.exif : tag === 0x8825 ? start.gps : val)
          : val.flatMap((r) => [...u32(Math.round(r * 100)), ...u32(100)]);
        const cnt = type === 2 ? bytes.length : type === 5 ? val.length : 1;
        out.push(...u16(tag), ...u16(type), ...u32(cnt));
        if (bytes.length <= 4) { while (bytes.length < 4) bytes.push(0); out.push(...bytes); }
        else { out.push(...u32(dOff)); data.push(...bytes); if (bytes.length % 2) data.push(0); dOff = off + data.length; }
        void size;
      }
      out.push(0, 0, 0, 0);
    }
    return Uint8Array.from([0x4d, 0x4d, 0, 42, 0, 0, 0, 8, ...out, ...data]);
  }
  async function sampleJpeg() {
    const c = document.createElement("canvas"); c.width = 320; c.height = 200;
    const g = c.getContext("2d"); const gr = g.createLinearGradient(0, 0, 320, 200); gr.addColorStop(0, "#3b1d6e"); gr.addColorStop(1, "#ff9b54");
    g.fillStyle = gr; g.fillRect(0, 0, 320, 200); g.fillStyle = "#fff"; g.font = "bold 22px sans-serif"; g.fillText("holiday.jpg (sample)", 20, 105);
    const jpg = new Uint8Array(await (await new Promise((r) => c.toBlob(r, "image/jpeg", 0.85))).arrayBuffer());
    const t = tiff({
      ifd0: [[0x010f, 2, "FictionCam"], [0x0110, 2, "FC-100 Mk II"], [0x0131, 2, "FictionOS 17.2"], [0x0132, 2, "2026:07:14 18:22:05"], [0x013b, 2, "Jane Example"]],
      exif: [[0x9003, 2, "2026:07:14 18:22:05"], [0xa431, 2, "SN-0042-TEST"], [0x9010, 2, "+02:00"]],
      gps: [[0x0001, 2, "N"], [0x0002, 5, [48, 51, 30.24]], [0x0003, 2, "E"], [0x0004, 5, [2, 17, 40.2]], [0x0006, 5, [35.5]]],
    });
    const body = W.eng.kpack.concat([Uint8Array.of(0x45, 0x78, 0x69, 0x66, 0, 0), t]), len = body.length + 2;
    return W.eng.kpack.concat([jpg.subarray(0, 2), Uint8Array.of(0xff, 0xe1, len >> 8, len & 255), body, jpg.subarray(2)]);
  }

  W.tool("kemuridama", "scrub", {
    name: "Scrub", order: 10,
    desc: "See the hidden metadata in photos and documents — GPS, camera serials, authors — and download a losslessly cleaned copy.",
    icon: '<path d="M4 20h16"/><path d="M7 16l9-9 3 3-9 9H7z"/><path d="M14 9l3 3"/><path d="M5 5l2 2M9 3v2M3 9h2"/>',
    render(el) {
      const files = []; // {id, name, bytes, rec}
      el.innerHTML = ui.head("Scrub", "Metadata scrubber", "Photos, PDFs and Office files carry who, where and with-what they were made. Drop them here to see it and get a cleaned copy. Files are read in this tab only — nothing is uploaded.") + `
        <div class="grid g2">
          <div class="panel">${ui.drop("sc-drop", "Drop files (or tap to choose) — JPEG · PNG · WebP · GIF · PDF · DOCX/XLSX/PPTX · ODT · MP3", ACCEPT)}
            <div class="spacer"></div>
            <div class="row"><button class="btn ghost" id="sc-sample">${W.icon(W.I.play)} Try a sample photo</button>
              <button class="btn" id="sc-all" disabled>${W.icon(W.I.dl)} Download all cleaned (.zip)</button>
              <button class="btn ghost" id="sc-clear" disabled>${W.icon(W.I.trash)} Clear</button></div></div>
          <div class="panel"><h2>How it cleans</h2>
            <p class="small muted" style="margin-top:0">Pixels are never re-encoded: metadata blocks are cut out (JPEG APPn/COM, PNG text/eXIf/tIME chunks, WebP EXIF/XMP, GIF comments, ID3 tags), PDF info strings are blanked in place, and Office/ODF property files are rewritten inside the zip (embedded photos get scrubbed too).</p>
            <label class="check"><input type="checkbox" id="sc-orient" checked> keep image orientation (re-adds a one-tag EXIF)</label><br>
            <label class="check"><input type="checkbox" id="sc-icc" checked> keep colour profile (ICC)</label></div>
        </div>
        <div id="sc-sum"></div><div id="sc-list"></div>`;
      W.kmz.wireCopy(el);
      const opts = () => ({ keepOrientation: $("#sc-orient").checked, keepIcc: $("#sc-icc").checked });
      async function add(name, bytes) {
        const rec = await W.eng.scrub.scan(bytes, name, opts());
        files.unshift({ id: W.uid(), name, bytes, rec });
        paint();
      }
      W.dropZone("sc-drop", async (f) => { try { await add(f.name, await W.kmz.fileBytes(f)); } catch (e) { W.toast(`${f.name}: ${e.message}`, 1); } }, { multiple: true });
      W.act("#sc-sample", async () => add("holiday.jpg", await sampleJpeg()));
      $("#sc-clear").onclick = () => { files.length = 0; paint(); };
      const rescan = async () => { for (const f of files) f.rec = await W.eng.scrub.scan(f.bytes, f.name, opts()); paint(); };
      $("#sc-orient").onchange = rescan; $("#sc-icc").onchange = rescan;
      W.act("#sc-all", async () => {
        const ok = files.filter((f) => f.rec.canStrip && f.rec.clean);
        if (!ok.length) throw new Error("Nothing that can be cleaned");
        const names = new Set();
        const entries = ok.map((f) => { let n = W.eng.scrub.cleanName(f.name); while (names.has(n)) n = "1-" + n; names.add(n); return { name: n, data: f.rec.clean, method: 0 }; });
        W.kmz.save("scrubbed-files.zip", await W.eng.kpack.zip(entries), "application/zip");
      });
      el.addEventListener("click", (e) => {
        const b = e.target.closest("[data-scdl]"); if (!b) return;
        const f = files.find((x) => x.id === b.dataset.scdl); if (!f || !f.rec.clean) return;
        W.kmz.save(W.eng.scrub.cleanName(f.name), f.rec.clean, f.rec.mime);
        W.toast(`Saved ${W.eng.scrub.cleanName(f.name)}`);
      });
      el.addEventListener("click", (e) => { const b = e.target.closest("[data-scx]"); if (!b) return; const i = files.findIndex((x) => x.id === b.dataset.scx); if (i >= 0) { files.splice(i, 1); paint(); } });

      function paint() {
        $("#sc-all").disabled = !files.some((f) => f.rec.canStrip); $("#sc-clear").disabled = !files.length;
        if (!files.length) { $("#sc-sum").innerHTML = ""; $("#sc-list").innerHTML = ""; return; }
        const tot = { high: 0, medium: 0, low: 0 }, gps = files.filter((f) => f.rec.gps).length;
        for (const f of files) for (const k of Object.keys(tot)) tot[k] += f.rec.counts[k] || 0;
        $("#sc-sum").innerHTML = `<div class="grid g4">${ui.stat(files.length, "file(s)")}${ui.stat(gps, "with GPS", gps > 0)}${ui.stat(tot.high, "high-risk items")}${ui.stat(tot.medium + tot.low, "other items")}</div>`;
        $("#sc-list").innerHTML = files.map(card).join("");
      }
      function card(f) {
        const r = f.rec;
        const lvl = r.gps ? "critical" : r.level;
        const gps = r.gps ? `<div class="km-gps">${W.icon(W.I.warn)}<div><div class="n">${esc(r.gps.lat)}, ${esc(r.gps.lon)}</div><div class="tiny">GPS location present!${r.gps.alt != null ? ` · altitude ${esc(r.gps.alt)} m` : ""}${r.gps.time ? ` · ${esc(r.gps.time)}` : ""}</div></div>
          <span class="grow"></span>${W.kmz.copyBtn(`${r.gps.lat}, ${r.gps.lon}`, "Copy")}${W.kmz.ext(`https://www.openstreetmap.org/?mlat=${r.gps.lat}&mlon=${r.gps.lon}#map=16/${r.gps.lat}/${r.gps.lon}`, "Open map ↗", "btn sm ghost")}</div>` : "";
        const risks = r.risks.filter((x) => !(r.gps && /^GPS/.test(x.text))).map((x) => `<div class="callout ${x.level === "high" || x.level === "critical" ? "bad" : "warn"} small">${esc(x.text)}</div>`).join("");
        const leaks = r.leaks.length ? ui.table(["Field", "Value", "Risk"], r.leaks.map((l) => [`${esc(l.field)}<div class="tiny faint km-wrap">${esc(l.src || "")}</div>`, `<span class="km-wrap">${esc(l.value)}</span>${l.note ? `<div class="tiny faint">${esc(l.note)}</div>` : ""}`, W.kmz.sev(l.severity)]), { raw: true, max: 380 })
          : ui.empty("NO METADATA", r.type === "unknown" ? "Unsupported file type." : "Nothing identifying found.");
        const segs = r.segments.length ? `<div class="spacer"></div><span class="lbl">Structure</span><div class="km-seg">${r.segments.map((s) => `<span class="chip ${s.action === "remove" ? "rm" : ""}" title="${s.action}">${esc(s.name)} · ${esc(W.fmt.bytes(s.size))}</span>`).join("")}</div>` : "";
        const notes = r.notes.map((n) => `<div class="tiny muted">• ${esc(n)}</div>`).join("");
        const cleanInfo = r.canStrip ? `<div class="tiny muted">${r.removed.length ? "Cleaned copy removes: " + esc(r.removed.join(", ")) : "Nothing to remove."} ${r.clean ? `→ ${esc(W.fmt.bytes(r.clean.length))} (was ${esc(W.fmt.bytes(r.size))})` : ""}</div>` : "";
        return `<section class="panel km-file"><header>${W.kmz.sev(lvl, true)}<b>${esc(f.name)}</b><span class="tiny muted">${esc(r.label)} · ${esc(W.fmt.bytes(r.size))}</span>
          ${r.canStrip ? `<button class="btn sm pri" data-scdl="${f.id}">${W.icon(W.I.dl)} Clean copy</button>` : ""}<button class="btn sm ghost" data-scx="${f.id}" aria-label="Remove from list">${W.icon(W.I.x)}</button></header>
          <p class="small" style="margin:0 0 10px">${esc(r.summary)}</p>${gps}<div class="km-risk">${risks}</div>${leaks}${segs}<div class="spacer"></div>${cleanInfo}${notes}</section>`;
      }
    },
  });
})();
