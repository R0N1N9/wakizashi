(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const KEY = "yumi.toolkit.chain";

  W.tool("yumi", "toolkit", {
    name: "Toolkit", order: 60,
    desc: "CyberChef-style transform chain: Base64, hex, XOR, gzip, URL, PowerShell -enc, hashes, refang…",
    help: {
      steps: ["Type or paste input (or Load file).", "Stack operations — Base64, hex, XOR, gzip, URL, PowerShell -enc, hashes, refang… — output updates live.", "Copy or save the result; use Output → input to keep peeling layers."],
      tips: ["Everything runs in the browser; nothing is sent anywhere."],
    },
    icon: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4z"/>',
    render(el, arg) {
      const ops = W.eng.transforms.OPS;
      let chain = W.store.get(KEY, []);
      el.innerHTML = ui.head("Toolkit", "Transform chain", "Stack operations to decode, deobfuscate and hash. Runs live as you type; nothing leaves the browser.") + `
        <div class="grid g2">
          <div>${ui.panel("Input", `<textarea id="tk-in" rows="9" spellcheck="false" placeholder="Paste data — base64, hex, URL-encoded, PowerShell -enc …"></textarea>
            <div class="spacer"></div><div class="row"><label class="btn sm ghost">${W.icon(W.I.up)} Load file<input type="file" id="tk-file"></label><span class="small muted" id="tk-hint"></span></div>`)}
            ${ui.panel("Recipe", `<div class="row"><select id="tk-add" style="flex:1;min-width:180px"><option value="">＋ Add an operation…</option>${Object.entries(ops).map(([k, o]) => `<option value="${k}">${esc(o.name)}</option>`).join("")}</select><button class="btn sm ghost" id="tk-clear">Clear</button></div>
              <div class="spacer"></div><div id="tk-chain"></div>`)}</div>
          <div>${ui.panel("Output", `<div class="row" style="justify-content:space-between"><span class="small muted" id="tk-meta"></span><span class="row"><button class="btn sm" id="tk-copy">${W.icon(W.I.copy)} Copy</button><button class="btn sm" id="tk-dl">${W.icon(W.I.dl)} Save</button><button class="btn sm" id="tk-use">↺ Output → input</button></span></div>
            <div class="spacer"></div><pre class="out" id="tk-out" style="min-height:200px"></pre><div id="tk-steps" class="spacer"></div>`)}</div>
        </div>`;
      let input = new Uint8Array(0), out = new Uint8Array(0);
      const ta = $("#tk-in");
      if (arg) ta.value = String(arg);
      const drawChain = () => {
        W.store.set(KEY, chain);
        $("#tk-chain").innerHTML = chain.length ? chain.map((s, i) => `<div class="row" style="padding:7px 0;border-bottom:1px solid var(--line)"><b class="mono small" style="flex:1">${i + 1}. ${esc(ops[s.op] ? ops[s.op].name : s.op)}</b>
          ${ops[s.op] && ops[s.op].arg ? `<input data-arg="${i}" value="${esc(s.arg != null ? s.arg : ops[s.op].arg)}" style="width:130px;min-height:34px">` : ""}
          <button class="btn sm ghost" data-up="${i}" aria-label="Move up" ${i ? "" : "disabled"}>↑</button><button class="btn sm ghost" data-rm="${i}" aria-label="Remove">${W.icon(W.I.x)}</button></div>`).join("")
          : '<span class="muted small">No operations — the output mirrors the input. Add one above.</span>';
      };
      const run = W.debounce(async () => {
        input = W.bytes(ta.value);
        const s = W.eng.transforms.suggest(ta.value);
        $("#tk-hint").textContent = s && !chain.length ? `Looks like it wants: ${ops[s].name}` : "";
        const r = await W.eng.transforms.run(input, chain.map((c) => ({ op: c.op, arg: c.arg != null ? c.arg : (ops[c.op] || {}).arg })));
        out = r.output;
        const text = W.eng.transforms.printable(out);
        $("#tk-out").textContent = text ? W.utf8(out).slice(0, 200000) : W.eng.transforms.hexdump(out);
        $("#tk-meta").textContent = `${out.length} bytes · ${text ? "text" : "binary (hex view)"} · entropy ${W.entropy(out).toFixed(2)}`;
        const bad = r.steps.find((x) => !x.ok);
        $("#tk-steps").innerHTML = bad ? `<div class="callout bad small">Step “${esc(ops[bad.op] ? ops[bad.op].name : bad.op)}” failed: ${esc(bad.error)}</div>` : "";
      }, 120);
      ta.addEventListener("input", run);
      $("#tk-file").onchange = async (e) => { const f = e.target.files[0]; if (!f) return; const b = await W.readFile(f, "buffer"); ta.value = W.eng.transforms.printable(b) ? W.utf8(b) : W.b64(b); if (!W.eng.transforms.printable(b)) W.toast("Binary file loaded as Base64 — add “From Base64” first"); run(); };
      $("#tk-add").onchange = (e) => { if (!e.target.value) return; chain.push({ op: e.target.value }); e.target.value = ""; drawChain(); run(); };
      $("#tk-clear").onclick = () => { chain = []; drawChain(); run(); };
      $("#tk-chain").addEventListener("click", (e) => {
        const up = e.target.closest("[data-up]"), rm = e.target.closest("[data-rm]");
        if (up) { const i = +up.dataset.up; [chain[i - 1], chain[i]] = [chain[i], chain[i - 1]]; }
        else if (rm) chain.splice(+rm.dataset.rm, 1); else return;
        drawChain(); run();
      });
      $("#tk-chain").addEventListener("input", (e) => { const a = e.target.closest("[data-arg]"); if (!a) return; chain[+a.dataset.arg].arg = a.value; W.store.set(KEY, chain); run(); });
      $("#tk-copy").onclick = () => W.copy(W.eng.transforms.printable(out) ? W.utf8(out) : W.hex(out));
      $("#tk-dl").onclick = () => W.download("output.bin", out, "application/octet-stream");
      $("#tk-use").onclick = () => { ta.value = W.eng.transforms.printable(out) ? W.utf8(out) : W.b64(out); chain = []; drawChain(); run(); };
      drawChain(); run();
    },
  });
})();
