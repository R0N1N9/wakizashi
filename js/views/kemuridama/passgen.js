(function () {
  "use strict";
  const { $, esc, ui } = W;
  const P = () => W.eng.passgen;
  const crackFromBits = (bits) => { const g = Math.pow(2, bits); return { online: P().duration(g / 10 / 2), slow: P().duration(g / 1e4 / 2), fast: P().duration(g / 1e10 / 2) }; };

  W.tool("kemuridama", "passgen", {
    name: "Passwords", order: 50,
    desc: "Generate strong random passwords and word passphrases, and check how fast a password you type would fall to real attacks.",
    icon: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3M14 9l2 2"/>',
    render(el) {
      let tab = W.kmz.store("passgen", "tab", "gen");
      el.innerHTML = ui.head("Passwords", "Generator & strength check", "Randomness comes from the browser's cryptographic RNG. Nothing you generate or type is stored or sent anywhere.") +
        W.kmz.tabs("pg-tabs", [["gen", "Generate"], ["check", "Check a password"]], tab) + `<div id="pg-body"></div>`;
      W.kmz.wireCopy(el);
      W.tabs($("#pg-tabs"), (t) => { tab = t; W.kmz.put("passgen", "tab", t); draw(); });
      draw();
      function draw() { (tab === "gen" ? drawGen : drawCheck)(); }

      function drawGen() {
        const o = W.kmz.store("passgen", "opts", { mode: "phrase", length: 20, lower: true, upper: true, digits: true, symbols: true, ambiguous: true, words: 6, sep: "-", caps: false, number: false });
        $("#pg-body").innerHTML = `<div class="grid g2"><div class="panel">${ui.seg("pg-mode", [["phrase", "Passphrase"], ["pw", "Random password"]], o.mode)}<div class="spacer"></div>
            <div id="pg-pw-opts"><label class="lbl" for="pg-len">Length: <b id="pg-lenv">${o.length}</b></label><input type="range" id="pg-len" min="8" max="64" value="${o.length}">
              <div class="row">${[["lower", "a–z"], ["upper", "A–Z"], ["digits", "0–9"], ["symbols", "!@#"]].map(([k, l]) => `<label class="check"><input type="checkbox" data-pgo="${k}" ${o[k] ? "checked" : ""}> ${l}</label>`).join("")}
              <label class="check"><input type="checkbox" data-pgo="ambiguous" ${o.ambiguous ? "" : "checked"}> avoid look-alikes (l 1 O 0)</label></div></div>
            <div id="pg-ph-opts"><label class="lbl" for="pg-words">Words: <b id="pg-wv">${o.words}</b></label><input type="range" id="pg-words" min="3" max="12" value="${o.words}">
              <div class="row"><label class="small muted">Separator <select id="pg-sep" style="width:auto;min-height:36px">${[["-", "hyphen -"], [" ", "space"], [".", "dot ."], ["_", "underscore _"], ["", "none"]].map(([v, l]) => `<option value="${esc(v)}" ${v === o.sep ? "selected" : ""}>${l}</option>`).join("")}</select></label>
              <label class="check"><input type="checkbox" data-pgo="caps" ${o.caps ? "checked" : ""}> Capitalise</label><label class="check"><input type="checkbox" data-pgo="number" ${o.number ? "checked" : ""}> add a digit</label></div>
              <div class="tiny muted">Word list: ${W.eng.words.size.toLocaleString()} words → ${Math.log2(W.eng.words.size).toFixed(2)} bits per word.</div></div>
          </div>
          <div class="panel"><h2>Result</h2><div class="row" style="flex-wrap:nowrap;align-items:stretch"><div class="km-out" id="pg-out" style="flex:1"></div></div>
            <div class="spacer"></div><div class="row"><button class="btn pri" id="pg-new">${W.icon(W.I.refresh)} New</button><span id="pg-copy"></span><button class="btn ghost" id="pg-five">5 more</button></div>
            <div class="spacer"></div><div id="pg-info"></div><div id="pg-more"></div></div></div>`;
        const mode = W.seg("pg-mode", () => { save(); gen(); });
        const read = () => { const r = { mode: mode(), length: +$("#pg-len").value, words: +$("#pg-words").value, sep: $("#pg-sep").value }; el.querySelectorAll("[data-pgo]").forEach((c) => (r[c.dataset.pgo] = c.dataset.pgo === "ambiguous" ? !c.checked : c.checked)); return r; };
        const save = () => { const r = read(); W.kmz.put("passgen", "opts", r); $("#pg-pw-opts").hidden = r.mode !== "pw"; $("#pg-ph-opts").hidden = r.mode !== "phrase"; $("#pg-lenv").textContent = r.length; $("#pg-wv").textContent = r.words; return r; };
        const one = (r) => (r.mode === "pw" ? P().password(r) : P().passphrase(r));
        const gen = () => {
          let r = save(), v;
          try { v = one(r); } catch (e) { $("#pg-out").textContent = "—"; $("#pg-info").innerHTML = `<div class="callout bad small">${esc(e.message)}</div>`; return; }
          $("#pg-out").textContent = v.value; $("#pg-copy").innerHTML = W.kmz.copyBtn(v.value, "Copy"); $("#pg-more").innerHTML = "";
          const t = crackFromBits(v.bits), lvl = v.bits >= 80 ? "ok" : v.bits >= 60 ? "medium" : "high";
          $("#pg-info").innerHTML = `${W.kmz.meter(v.bits / 128, lvl)}<div class="spacer"></div>${ui.kv([["Entropy", `${v.bits} bits (exact — chosen uniformly at random)`], ["10 guesses/s (online)", t.online], ["10k/s (bcrypt, offline)", t.slow], ["10¹⁰/s (fast hash on GPUs)", t.fast]])}
            <p class="tiny muted">${v.bits >= 80 ? "Strong enough for anything, including a password-manager master password." : v.bits >= 60 ? "Fine for site passwords behind rate limits; use more for a master password or disk encryption." : "Weak against offline cracking — add length."}</p>`;
        };
        el.querySelectorAll("#pg-body input, #pg-body select").forEach((x) => x.addEventListener("input", gen));
        $("#pg-new").onclick = gen;
        $("#pg-five").onclick = () => { const r = read(); const list = Array.from({ length: 5 }, () => one(r).value); $("#pg-more").innerHTML = `<div class="spacer"></div>${list.map((v) => `<div class="row" style="flex-wrap:nowrap;margin-bottom:6px"><div class="km-out sm" style="flex:1">${esc(v)}</div>${W.kmz.copyBtn(v)}</div>`).join("")}`; };
        gen();
      }

      function drawCheck() {
        $("#pg-body").innerHTML = `<div class="panel"><label class="lbl" for="pg-in">Password to check</label>
            <div class="row" style="flex-wrap:nowrap"><input type="password" id="pg-in" autocomplete="off" spellcheck="false" autocapitalize="off" placeholder="type a password — it never leaves this page"><button class="btn ghost" id="pg-show">Show</button></div>
            <div class="spacer"></div><label class="lbl" for="pg-user">Words about you (optional: name, pet, birthday, team — they're tried first)</label><input type="text" id="pg-user" autocomplete="off" spellcheck="false" placeholder="jane, rex, 1987, arsenal">
            <p class="tiny muted">zxcvbn-style estimate: dictionary words and common passwords (incl. reversed and l33t), keyboard walks, sequences, repeats and dates are matched and priced like an attacker's cracking rules would.</p></div>
          <div id="pg-res"></div>`;
        const inp = $("#pg-in");
        $("#pg-show").onclick = () => { inp.type = inp.type === "password" ? "text" : "password"; $("#pg-show").textContent = inp.type === "password" ? "Show" : "Hide"; };
        const run = () => {
          const pw = inp.value; if (!pw) { $("#pg-res").innerHTML = ""; return; }
          const user = $("#pg-user").value.split(/[,\s]+/).filter(Boolean);
          const r = P().estimate(pw, user), lvl = ["critical", "high", "medium", "ok", "ok"][r.score];
          const pat = (m) => m.pattern === "dictionary" ? `${m.dict}${m.l33t ? ", l33t" : ""}${m.reversed ? ", reversed" : ""} (rank ${m.rank})` : m.pattern === "keyboard" ? `keyboard walk, ${m.turns} turn(s)` : m.pattern === "repeat" ? `“${m.unit}” × ${m.count}` : m.pattern === "bruteforce" ? "no pattern (brute force)" : m.pattern;
          $("#pg-res").innerHTML = `<div class="grid g3"><div class="panel stat"><div class="n km-s${r.score} km-big">${esc(r.label)}</div><div class="l">score ${r.score}/4</div></div>
              <div class="panel stat"><div class="n">10<sup>${esc(r.log10.toFixed(1))}</sup></div><div class="l">guesses needed (~${esc(r.bits)} bits)</div></div>
              <div class="panel stat"><div class="n">${esc(P().poolBits(pw))}</div><div class="l">naïve "charset" bits — what simple meters show</div></div></div>
            <div class="panel">${W.kmz.meter((r.score + 1) / 5, lvl)}<div class="spacer"></div>
              ${r.warning ? `<div class="callout bad small">${esc(r.warning)}</div><div class="spacer"></div>` : ""}${r.suggestions.map((s) => `<div class="small muted">• ${esc(s)}</div>`).join("")}
              <div class="spacer"></div>${ui.table(["Attack", "Time to crack (average)"], Object.values(r.crack).map((c) => [esc(c.label), `<b>${esc(c.text)}</b>`]), { raw: true })}
              <div class="spacer"></div><span class="lbl">How an attacker sees it</span>${ui.table(["Piece", "Pattern", "Guesses"], r.sequence.map((m) => [`<code>${esc(m.token)}</code>`, esc(pat(m)), `<span class="mono">${esc(m.guesses < 1e6 ? Math.round(m.guesses) : m.guesses.toExponential(1))}</span>`]), { raw: true })}</div>`;
        };
        inp.addEventListener("input", W.debounce(run, 150)); $("#pg-user").addEventListener("input", W.debounce(run, 250));
      }
    },
  });
})();
