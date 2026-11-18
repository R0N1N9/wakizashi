(function () {
  "use strict";
  const { $, esc, ui } = W;
  const S = () => W.eng.stego;

  /** Any image file → stego image record. PNGs are used as-is; everything else goes through a canvas (RGBA). */
  async function load(file) {
    const bytes = await W.kmz.fileBytes(file);
    if (W.eng.kpack.isPng(bytes)) { try { return { img: await S().decode(bytes), via: "png" }; } catch { /* palette / 16-bit / interlaced → canvas */ } }
    const url = URL.createObjectURL(new Blob([bytes]));
    try {
      const im = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error("Not an image the browser can read")); i.src = url; });
      const c = document.createElement("canvas"); c.width = im.naturalWidth; c.height = im.naturalHeight;
      const g = c.getContext("2d"); g.drawImage(im, 0, 0);
      return { img: S().fromRGBA(c.width, c.height, g.getImageData(0, 0, c.width, c.height).data), via: "canvas" };
    } finally { URL.revokeObjectURL(url); }
  }
  const preview = (png) => URL.createObjectURL(new Blob([png], { type: "image/png" }));

  W.tool("kemuridama", "stego", {
    name: "Stego", order: 80,
    desc: "Privacy demo: hide a short message in a PNG's least-significant bits (optionally AES-encrypted) and reveal it again. Katana-compatible.",
    help: {
      steps: ["Pick a PNG, type a short message (optionally a passphrase to AES-encrypt it) and press Hide & download PNG.", "To read one, load the PNG (and passphrase) and press Reveal."],
      tips: ["Re-compression, resizing and most chat apps destroy hidden bits — share the PNG as a file.", "Katana-compatible."],
    },
    icon: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 16l5-5 4 4 3-3 6 6"/><circle cx="16" cy="9" r="1.5"/>',
    render(el) {
      let tab = W.kmz.store("stego", "tab", "hide"), cover = null, urlNow = null;
      el.innerHTML = ui.head("Stego", "Hide in an image", "Steganography hides that a message exists; encryption hides what it says — use both. Hidden bits are destroyed by re-compression, resizing or most chat apps; share the PNG as a file.") +
        W.kmz.tabs("sg-tabs", [["hide", "Hide"], ["reveal", "Reveal"], ["detect", "Detect"]], tab) + `<div id="sg-body"></div>`;
      W.kmz.wireCopy(el);
      W.tabs($("#sg-tabs"), (t) => { tab = t; W.kmz.put("stego", "tab", t); cover = null; draw(); });
      draw();
      function draw() { ({ hide: drawHide, reveal: drawReveal, detect: drawDetect })[tab](); }

      function drawHide() {
        $("#sg-body").innerHTML = `<div class="grid g2"><div class="panel">${ui.drop("sg-cover", "Drop a cover image (PNG best; JPEG/WebP are converted to PNG)", "image/*")}<div class="spacer"></div><div id="sg-cinfo" class="small muted">No cover yet.</div></div>
          <div class="panel"><label class="lbl" for="sg-msg">Message</label><textarea id="sg-msg" rows="5" placeholder="short text to hide"></textarea><div class="tiny muted" id="sg-cap"></div>
            <div class="spacer"></div>${ui.seg("sg-prot", [["aes", "AES-256 (Cipher)"], ["ks", "Katana keystream"], ["none", "No password"]], W.kmz.store("stego", "prot", "aes"))}
            <div class="spacer"></div><div id="sg-pw-box"><label class="lbl" for="sg-pw">Password</label><input type="password" id="sg-pw" autocomplete="new-password"><div id="sg-str"></div></div>
            <div class="tiny muted" id="sg-prot-note"></div><div class="spacer"></div><button class="btn pri" id="sg-go" disabled>Hide &amp; download PNG</button></div></div><div id="sg-out"></div>`;
        const prot = W.seg("sg-prot", (v) => { W.kmz.put("stego", "prot", v); sync(); });
        const notes = { aes: "Message is encrypted with AES-256-GCM (PBKDF2 600k) before hiding. Only Wakizashi can reveal it.", ks: "Katana's SHA-256 keystream XOR — opens in Katana's CIPHER too, but it is obfuscation, not authenticated encryption.", none: "Anyone who knows to look can read it (e.g. Katana / Wakizashi Reveal)." };
        const sync = () => { $("#sg-pw-box").hidden = prot() === "none"; $("#sg-prot-note").textContent = notes[prot()]; cap(); };
        const cap = () => { if (!cover) { $("#sg-cap").textContent = ""; return; } const n = W.bytes($("#sg-msg").value).length + (prot() === "aes" ? 56 : 0), c = S().capacity(cover.img); $("#sg-cap").innerHTML = `${n} / ${c} bytes${n > c ? ' — <span class="c-crit">too long for this image</span>' : ""}`; $("#sg-go").disabled = !$("#sg-msg").value || n > c; };
        $("#sg-msg").addEventListener("input", cap);
        $("#sg-pw").addEventListener("input", W.debounce(() => ($("#sg-str").innerHTML = W.kmz.strengthHtml($("#sg-pw").value)), 120));
        sync();
        W.dropZone("sg-cover", async (f) => {
          try { cover = await load(f); cover.name = f.name; $("#sg-cinfo").innerHTML = `<b>${esc(f.name)}</b> · ${cover.img.w}×${cover.img.h} · capacity ${S().capacity(cover.img).toLocaleString()} bytes${cover.via === "canvas" ? " · converted to RGBA PNG" : ""}`; cap(); }
          catch (e) { W.toast(e.message, 1); }
        });
        W.act("#sg-go", async () => {
          let msg = W.bytes($("#sg-msg").value), pw = $("#sg-pw").value, p = prot();
          if (p !== "none" && !pw) throw new Error("Enter a password");
          if (p === "aes") { msg = await W.eng.cipher.encrypt(msg, { passphrase: pw }); pw = ""; }
          const r = await S().embed(cover.img, msg, p === "ks" ? pw : "");
          const name = (cover.name || "image").replace(/\.[^.]+$/, "") + ".stego.png";
          W.kmz.save(name, r.png, "image/png");
          if (urlNow) URL.revokeObjectURL(urlNow); urlNow = preview(r.png);
          $("#sg-out").innerHTML = ui.panel("Done", `<div class="row" style="align-items:flex-start"><img class="km-prev" src="${urlNow}" alt="Image with hidden message"><div class="small">Saved <b>${esc(name)}</b> (${esc(W.fmt.bytes(r.png.length))}).<br>${r.used} of ${r.capacity} bytes used · ${p === "aes" ? "AES-encrypted" : p === "ks" ? "keystream-obfuscated" : "plain"}.<br><span class="muted">Send it as a file/attachment — re-encoded copies lose the message.</span></div></div>`);
        });
      }

      function drawReveal() {
        $("#sg-body").innerHTML = `<div class="grid g2"><div class="panel">${ui.drop("sg-rf", "Drop a PNG to reveal", "image/png,.png")}<div class="spacer"></div><div id="sg-rinfo" class="small muted"></div></div>
          <div class="panel"><label class="lbl" for="sg-rpw">Password (if one was used)</label><input type="password" id="sg-rpw" autocomplete="off"><div class="spacer"></div><button class="btn pri" id="sg-rgo" disabled>Reveal</button><div class="spacer"></div><div id="sg-rout"></div></div></div>`;
        W.dropZone("sg-rf", async (f) => { try { cover = await load(f); $("#sg-rinfo").innerHTML = `<b>${esc(f.name)}</b> · ${cover.img.w}×${cover.img.h}`; $("#sg-rgo").disabled = false; } catch (e) { W.toast(e.message, 1); } });
        W.act("#sg-rgo", async () => {
          const pw = $("#sg-rpw").value, out = $("#sg-rout");
          let r = await S().extract(cover.img, "");
          let how = "plain";
          const isWkz = r.bytes.length > 40 && W.latin1(r.bytes.subarray(0, 4)) === "WKZC";
          if (isWkz) { if (!pw) throw new Error("This message is AES-encrypted — enter the password"); const d = await W.eng.cipher.decrypt(r.bytes, { passphrase: pw }); r = { message: W.utf8(d.data), bytes: d.data }; how = "AES-256-GCM, authenticated"; }
          else if (pw) { r = await S().extract(cover.img, pw); how = "Katana keystream"; }
          const text = r.message;
          out.innerHTML = text != null ? `<div class="callout ok small">${W.icon(W.I.check)} Message found (${esc(how)}).</div><div class="spacer"></div><pre class="out">${esc(text)}</pre><div class="spacer"></div>${W.kmz.copyBtn(text, "Copy")}`
            : `<div class="callout warn small">A payload is there but it isn't text — wrong password? (${r.bytes.length} bytes)</div>`;
        });
      }

      function drawDetect() {
        $("#sg-body").innerHTML = `<div class="panel">${ui.drop("sg-df", "Drop a PNG to test for LSB hiding", "image/png,.png")}</div><div id="sg-dout"></div>`;
        W.dropZone("sg-df", async (f) => {
          try {
            const { img } = await load(f), r = await S().detect(img);
            const lvl = r.ks1_header ? "critical" : /likely/.test(r.verdict) ? "medium" : "ok";
            $("#sg-dout").innerHTML = ui.panel(f.name, `<div class="row">${W.kmz.sev(lvl, true)}<b>${esc(r.verdict)}</b></div><div class="spacer"></div>${ui.kv([["LSB ones ratio", String(r.lsb_ones_ratio)], ["Chi-square (pairs)", String(r.chi_square)], ["KS1 header", r.ks1_header ? "present" : "absent"], ["Capacity", r.capacity_bytes.toLocaleString() + " bytes"]])}<p class="tiny muted">${esc(r.note)}</p>`);
          } catch (e) { W.toast(e.message, 1); }
        });
      }
    },
  });
})();
