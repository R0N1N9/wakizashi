(function () {
  "use strict";
  const { $, esc, ui } = W;
  const FP = { none: "ok", low: "ok", medium: "warn", high: "bad" };

  W.tool("yumi", "regex", {
    name: "Regex", order: 70,
    desc: "Turn an example (mutex, UA, path, C2 URI) into ranked regexes for YARA and hunt queries.",
    icon: '<path d="M4 7h6M7 4v6M5 5l4 4M9 5 5 9"/><circle cx="16" cy="17" r="3"/><path d="M14 7l6 0"/>',
    render(el, arg) {
      el.innerHTML = ui.head("Regex", "Pattern builder", "Give it one literal example; get candidate regexes ranked best-first, each checked against your input with a false-positive rating — then test against your own lines.") + `
        <div class="panel"><label class="lbl" for="rx-in">Example string</label><div class="row"><input id="rx-in" type="text" spellcheck="false" autocapitalize="off" placeholder="Global\\MyBotMutex_1234 · Mozilla/5.0 (compatible; Bot/2.1) · /api/v2/gate.php?id=88" style="flex:1;min-width:200px"><button class="btn pri" id="rx-go">Build</button></div></div>
        <div id="rx-out"></div>
        ${ui.panel("Test", `<div class="row"><input id="rx-pat" type="text" spellcheck="false" placeholder="regex to test" style="flex:1;min-width:200px"><label class="check"><input type="checkbox" id="rx-i"> case-insensitive</label></div>
          <div class="spacer"></div><textarea id="rx-lines" rows="6" spellcheck="false" placeholder="Lines to test against…"></textarea><div class="spacer"></div><div id="rx-tres" class="small"></div>`)}`;
      const go = () => {
        let r; try { r = W.eng.regexgen.generate($("#rx-in").value); } catch (e) { return W.toast(e.message, 1); }
        $("#rx-out").innerHTML = r.options.map((o, i) => `<div class="finding ${i === 0 ? "ok" : "info"}"><header>${i === 0 ? ui.badge("best", "ok", true) : ""}<h3>${esc(o.label)}</h3>${ui.badge("FP " + o.fp, FP[o.fp])}${o.matches ? "" : ui.badge("does not match input", "bad")}</header>
            <div class="det">${esc(o.desc)}</div><div class="spacer"></div><pre class="out">${esc(o.regex)}</pre><div class="spacer"></div>
            <div class="row"><button class="btn sm" data-c="${i}" data-k="regex">${W.icon(W.I.copy)} Regex</button><button class="btn sm" data-c="${i}" data-k="yara">${W.icon(W.I.copy)} YARA string</button><button class="btn sm" data-c="${i}" data-k="test">Test it ↓</button></div></div>`).join("");
        $("#rx-out").onclick = (e) => {
          const b = e.target.closest("[data-c]"); if (!b) return; const o = r.options[+b.dataset.c];
          if (b.dataset.k === "regex") W.copy(o.regex); else if (b.dataset.k === "yara") W.copy("$s = " + o.yara);
          else { $("#rx-pat").value = o.regex; $("#rx-i").checked = o.nocase; if (!$("#rx-lines").value) $("#rx-lines").value = r.input; test(); $("#rx-pat").scrollIntoView({ behavior: "smooth", block: "center" }); }
        };
      };
      const test = W.debounce(() => {
        const p = $("#rx-pat").value; if (!p) return ($("#rx-tres").innerHTML = "");
        const r = W.eng.regexgen.test(p, $("#rx-lines").value, $("#rx-i").checked ? "i" : "");
        $("#rx-tres").innerHTML = !r.ok ? `<span class="c-crit">${esc(r.error)}</span>` : `${ui.badge(r.hits.length + " matching line(s)", r.hits.length ? "ok" : "")}<div class="spacer"></div>` +
          r.hits.slice(0, 200).map((h) => `<div class="mono tiny"><span class="faint">${h.n}:</span> ${esc(h.line.slice(0, h.index))}<b class="c-acc">${esc(h.match)}</b>${esc(h.line.slice(h.index + h.match.length))}</div>`).join("");
      }, 150);
      $("#rx-go").onclick = go;
      $("#rx-in").addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
      ["#rx-pat", "#rx-lines"].forEach((s) => $(s).addEventListener("input", test));
      $("#rx-i").onchange = test;
      if (arg) { $("#rx-in").value = String(arg); go(); }
    },
  });
})();
