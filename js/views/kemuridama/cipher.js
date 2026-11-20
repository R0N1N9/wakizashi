(function () {
  "use strict";
  const { $, esc, ui } = W;
  const C = () => W.eng.cipher;

  W.tool("kemuridama", "cipher", {
    name: "Cipher", order: 20,
    desc: "Encrypt text and files with AES-256-GCM (passphrase or generated key); one-time pads and Shamir secret sharing.",
    help: {
      steps: ["Encrypt: enter text (or a file) and a passphrase — or generate a key — and press Encrypt.", "Decrypt: paste the ciphertext, enter the same passphrase/key and press Decrypt.", "Other tabs: generate one-time pads, or Split a secret into Shamir shares and Combine them back."],
      tips: ["AES-256-GCM with PBKDF2-SHA256 (600,000+ iterations). Lose the passphrase and the data is gone."],
    },
    icon: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><path d="M12 15v2"/>',
    render(el) {
      let tab = W.kmz.store("cipher", "tab", "text");
      el.innerHTML = ui.head("Cipher", "Encrypt & decrypt", "AES-256-GCM with a key derived from your passphrase (PBKDF2-SHA256, 600,000+ iterations) or a random 256-bit key. Runs entirely in this browser; passphrases and keys are never stored.") + `
        <div class="panel"><div class="grid g2">
          <div><span class="lbl">Key</span>${ui.seg("ci-mode", [["pass", "Passphrase"], ["key", "Generated key"]], W.kmz.store("cipher", "mode", "pass"))}
            <div class="spacer"></div>
            <div id="ci-pass-box"><label class="lbl" for="ci-pass">Passphrase</label>
              <div class="row" style="flex-wrap:nowrap"><input type="password" id="ci-pass" autocomplete="new-password" spellcheck="false" autocapitalize="off" placeholder="a long passphrase — 5+ random words is ideal"><button class="btn ghost" id="ci-show" aria-label="Show passphrase">Show</button></div>
              <div id="ci-str"></div></div>
            <div id="ci-key-box" hidden><label class="lbl" for="ci-key">Key (wkzk1.…)</label>
              <div class="row" style="flex-wrap:nowrap"><input type="text" id="ci-key" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="paste a key, or generate one"><button class="btn" id="ci-gen">Generate</button></div>
              <div class="tiny muted" style="margin-top:6px">Anyone with the key can decrypt. Share it over a different channel than the ciphertext; it can't be recovered if lost.</div></div>
          </div>
          <div><label class="lbl" for="ci-iter">PBKDF2 iterations (encrypting)</label><select id="ci-iter"><option value="600000">600,000 (OWASP 2023 minimum)</option><option value="1000000">1,000,000</option><option value="2000000">2,000,000 (slower, stronger)</option></select>
            <div class="spacer"></div><div class="tiny muted">Format: <code>WKZC</code> v1 header (mode, iterations, 16-byte salt, 12-byte IV — all authenticated) + ciphertext + 128-bit GCM tag. Tampering with any byte makes decryption fail.</div></div>
        </div></div>
        ${W.kmz.tabs("ci-tabs", [["text", "Text"], ["file", "Files"], ["otp", "One-time pad"], ["shamir", "Secret sharing"]], tab)}
        <div id="ci-body"></div>`;
      W.kmz.wireCopy(el);
      const mode = W.seg("ci-mode", (v) => { W.kmz.put("cipher", "mode", v); syncMode(); });
      const syncMode = () => { $("#ci-pass-box").hidden = mode() !== "pass"; $("#ci-key-box").hidden = mode() !== "key"; };
      syncMode();
      const pass = $("#ci-pass");
      const str = () => ($("#ci-str").innerHTML = W.kmz.strengthHtml(pass.value));
      pass.addEventListener("input", W.debounce(str, 120)); str();
      $("#ci-show").onclick = () => { pass.type = pass.type === "password" ? "text" : "password"; $("#ci-show").textContent = pass.type === "password" ? "Show" : "Hide"; };
      $("#ci-gen").onclick = () => { $("#ci-key").value = C().genKey(); W.toast("New key generated — copy it somewhere safe"); };
      const creds = (forMode) => {
        const m = forMode || (mode() === "key" ? "key" : "passphrase");
        if (m === "key") { const k = $("#ci-key").value.trim(); if (!k) throw new Error("Paste or generate a key"); C().parseKey(k); return { key: k }; }
        if (!pass.value) throw new Error("Enter the passphrase");
        return { passphrase: pass.value, iterations: +$("#ci-iter").value };
      };
      W.tabs($("#ci-tabs"), (t) => { tab = t; W.kmz.put("cipher", "tab", t); draw(); });
      draw();

      function draw() {
        const body = $("#ci-body");
        if (tab === "text") {
          body.innerHTML = `<div class="grid g2"><div class="panel"><label class="lbl" for="ci-in">Message or armored ciphertext</label>
              <textarea id="ci-in" rows="9" spellcheck="false" placeholder="Type a message to encrypt — or paste a -----BEGIN WAKIZASHI MESSAGE----- block to decrypt"></textarea>
              <div class="spacer"></div><div class="row"><button class="btn pri" id="ci-enc">${W.icon('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>')} Encrypt</button><button class="btn" id="ci-dec">Decrypt</button><span class="tiny muted" id="ci-hint"></span></div></div>
            <div class="panel"><h2>Output</h2><div id="ci-out">${ui.empty("NOTHING YET", "Encrypted output is self-describing: it records how it was encrypted, never the key.")}</div></div></div>`;
          const inp = $("#ci-in");
          inp.addEventListener("input", () => { const a = C().isArmored(inp.value); $("#ci-hint").textContent = a ? (() => { try { const h = C().inspect(C().dearmor(inp.value)); return `Armored message · ${h.mode === "key" ? "needs the generated key" : `passphrase · ${h.iterations.toLocaleString()} iterations`}`; } catch (e) { return e.message; } })() : ""; });
          W.act("#ci-enc", async () => {
            if (!inp.value) throw new Error("Nothing to encrypt");
            const arm = await C().encryptText(inp.value, creds());
            $("#ci-out").innerHTML = `<pre class="out" id="ci-arm">${esc(arm)}</pre><div class="spacer"></div><div class="row">${W.kmz.copyBtn(arm, "Copy")}<button class="btn sm ghost" id="ci-save">${W.icon(W.I.dl)} .txt</button></div>`;
            $("#ci-save").onclick = () => W.download("message.wkz.txt", arm);
          });
          W.act("#ci-dec", async () => {
            const raw = C().dearmor(inp.value), h = C().inspect(raw);
            const r = await C().decrypt(raw, creds(h.mode === "key" ? "key" : "passphrase"));
            const text = W.utf8(r.data);
            $("#ci-out").innerHTML = `<div class="callout ok small">${W.icon(W.I.check)} Decrypted and authenticated (${esc(h.mode)}${h.iterations ? `, ${h.iterations.toLocaleString()} iterations` : ""}).</div><div class="spacer"></div><pre class="out">${esc(text)}</pre><div class="spacer"></div>${W.kmz.copyBtn(text, "Copy")}`;
          });
        } else if (tab === "file") {
          body.innerHTML = `<div class="grid g2"><div class="panel"><h2>Encrypt files</h2>${ui.drop("ci-fenc", "Drop files to encrypt → .wkz")}<div class="tiny muted" style="margin-top:8px">The original file name and type are stored inside the encrypted part.</div></div>
            <div class="panel"><h2>Decrypt .wkz</h2>${ui.drop("ci-fdec", "Drop a .wkz file to decrypt", ".wkz,application/octet-stream")}</div></div><div id="ci-flog"></div>`;
          const log = (html) => $("#ci-flog").insertAdjacentHTML("afterbegin", `<div class="finding ok"><header>${html}</header></div>`);
          const fail = (name, e) => $("#ci-flog").insertAdjacentHTML("afterbegin", `<div class="finding high"><header><h3>${esc(name)}</h3>${W.kmz.sev("high")}</header><div class="det">${esc(e.message)}</div></div>`);
          W.dropZone("ci-fenc", async (f) => {
            try { const b = await W.kmz.fileBytes(f); const ct = await C().encrypt(b, Object.assign(creds(), { name: f.name, type: f.type }));
              W.kmz.save(f.name + ".wkz", ct); log(`<h3>${esc(f.name)} → ${esc(f.name)}.wkz</h3><span class="tiny muted">${esc(W.fmt.bytes(b.length))} → ${esc(W.fmt.bytes(ct.length))}</span>${W.kmz.sev("ok")}`); }
            catch (e) { fail(f.name, e); }
          }, { multiple: true });
          W.dropZone("ci-fdec", async (f) => {
            try { const b = await W.kmz.fileBytes(f); const h = C().inspect(b); const r = await C().decrypt(b, creds(h.mode === "key" ? "key" : "passphrase"));
              const name = r.name || f.name.replace(/\.wkz$/i, "") || "decrypted.bin";
              W.kmz.save(name, r.data, r.type || undefined); log(`<h3>${esc(f.name)} → ${esc(name)}</h3><span class="tiny muted">${esc(W.fmt.bytes(r.data.length))} · authenticated</span>${W.kmz.sev("ok")}`); }
            catch (e) { fail(f.name, e); }
          }, { multiple: true });
        } else if (tab === "otp") {
          body.innerHTML = `<div class="panel"><p class="small muted" style="margin-top:0">A one-time pad is unbreakable only if the pad is truly random, at least as long as the message, kept secret and <b>never reused</b>. Same format as Katana / Tantō (base64 pad, base64 ciphertext).</p>
            <div class="grid g2"><div><label class="lbl" for="ci-otxt">Message / ciphertext</label><textarea id="ci-otxt" rows="5" spellcheck="false"></textarea></div>
            <div><label class="lbl" for="ci-opad">Pad (base64)</label><textarea id="ci-opad" rows="5" spellcheck="false"></textarea>
              <div class="row" style="margin-top:8px"><input type="number" id="ci-olen" value="256" min="1" max="65536" style="max-width:120px" aria-label="Pad length in bytes"><button class="btn sm" id="ci-ogen">New pad (bytes)</button></div></div></div>
            <div class="spacer"></div><div class="row"><button class="btn pri" id="ci-oenc">Encrypt</button><button class="btn" id="ci-odec">Decrypt</button></div><div class="spacer"></div><div id="ci-oout"></div></div>`;
          $("#ci-ogen").onclick = () => ($("#ci-opad").value = C().otpPad(W.clamp(+$("#ci-olen").value || 256, 1, 65536)));
          const run = (m) => { try { const r = C().otp($("#ci-otxt").value, $("#ci-opad").value, m); $("#ci-oout").innerHTML = `<pre class="out">${esc(r.result)}</pre><div class="spacer"></div>${W.kmz.copyBtn(r.result, "Copy")} <span class="tiny muted">${r.bytes} byte(s)</span>`; } catch (e) { $("#ci-oout").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; } };
          $("#ci-oenc").onclick = () => run("encrypt"); $("#ci-odec").onclick = () => run("decrypt");
        } else {
          body.innerHTML = `<div class="grid g2"><div class="panel"><h2>Split a secret</h2><label class="lbl" for="ci-ssec">Secret (a passphrase, recovery code…)</label><input type="password" id="ci-ssec" autocomplete="off">
              <div class="row" style="margin-top:10px"><label class="small muted">Shares <input type="number" id="ci-sn" value="5" min="2" max="255" style="width:80px"></label><label class="small muted">Needed <input type="number" id="ci-sk" value="3" min="2" max="255" style="width:80px"></label><button class="btn pri" id="ci-ssplit">Split</button></div>
              <div class="spacer"></div><div id="ci-sout"></div></div>
            <div class="panel"><h2>Combine shares</h2><label class="lbl" for="ci-sin">Shares (one per line)</label><textarea id="ci-sin" rows="6" spellcheck="false"></textarea>
              <div class="spacer"></div><button class="btn" id="ci-scomb">Combine</button><div class="spacer"></div><div id="ci-cout"></div></div></div>
            <p class="tiny muted">Shamir's scheme over GF(256): any <i>k</i> of <i>n</i> shares rebuild the secret; fewer reveal nothing. Shares are compatible with Katana and Tantō.</p>`;
          $("#ci-ssplit").onclick = () => { try { const s = C().shamirSplit($("#ci-ssec").value, $("#ci-sn").value, $("#ci-sk").value); $("#ci-sout").innerHTML = `<pre class="out">${esc(s.join("\n"))}</pre><div class="spacer"></div>${W.kmz.copyBtn(s.join("\n"), "Copy all")}`; } catch (e) { $("#ci-sout").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; } };
          $("#ci-scomb").onclick = () => { try { const v = C().shamirCombine($("#ci-sin").value.split(/\s+/)); $("#ci-cout").innerHTML = `<div class="km-out sm">${esc(v)}</div><div class="tiny muted" style="margin-top:6px">With too few shares this is garbage, not an error — that's by design.</div>`; } catch (e) { $("#ci-cout").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; } };
        }
      }
    },
  });
})();
