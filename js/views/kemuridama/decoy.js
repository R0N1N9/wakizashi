(function () {
  "use strict";
  const { $, esc, ui } = W;
  const D = () => W.eng.decoy;

  W.tool("kemuridama", "decoy", {
    name: "Decoy", order: 40,
    desc: "Generate a clearly fictitious cover identity from a seed (name, address, fiction-range phone, aliases), plus canary tokens and honeytokens.",
    help: {
      steps: ["Enter a seed and press Generate for a clearly fictitious cover identity (name, address, fiction-range phone, aliases).", "Save personas you use; export them as JSON.", "Use the canary/honeytoken tab to create tripwires."],
      tips: ["Use decoys for sign-ups, loyalty cards and forums you don't trust."],
    },
    icon: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/><path d="M3 4l3 3M21 4l-3 3"/>',
    render(el) {
      let tab = W.kmz.store("decoy", "tab", "persona");
      el.innerHTML = ui.head("Decoy", "Cover identity", "Keep your real name, address and number out of sign-ups, loyalty cards and forums you don't trust. Everything is generated on this device.") +
        W.kmz.tabs("de-tabs", [["persona", "Persona"], ["saved", "Saved"], ["canary", "Canary tokens"]], tab) + `<div id="de-body"></div>`;
      W.kmz.wireCopy(el);
      W.tabs($("#de-tabs"), (t) => { tab = t; W.kmz.put("decoy", "tab", t); draw(); });
      draw();
      function draw() { ({ persona: drawPersona, saved: drawSaved, canary: drawCanary })[tab](); }

      function personaCard(p) {
        const row = (k, v, copy) => [k, `<span>${esc(v)}</span>${copy === false || !v ? "" : W.kmz.copyBtn(v)}`, true];
        const ph = p.phone.number ? `${p.phone.number}` : "";
        return `<section class="panel km-persona"><div class="row" style="justify-content:space-between;margin-bottom:12px"><span class="km-fict">FICTITIOUS · ${esc(p.countryName.toUpperCase())}</span><span class="tiny muted">seed <code>${esc(p.seed)}</code></span></div>
          <div class="grid g2"><div>${ui.kv([row("Name", p.name.full), row("Middle", p.name.middle), row("Born", `${p.birthdate} (age ${p.age})`), row("Occupation", p.occupation, false),
            row("Street", p.address.lines[0]), row("City", p.address.lines.slice(1).join(", ")), row("Country", p.address.country, false)])}
            <div class="spacer"></div>${ui.kv([row("Phone", ph || "—", !!ph)])}<div class="tiny muted" style="margin-top:4px">${esc(p.phone.note)}</div>
            <div class="spacer"></div><div class="row">${W.kmz.copyBtn(p.address.lines.join("\n"), "Copy address")}</div></div>
          <div><span class="lbl">Usernames</span><div>${p.handles.map((h) => `<button type="button" class="chip" data-kcopy="${(() => { const id = "c" + W.uid(); W.kmz.copies.set(id, h); return id; })()}" title="Copy">${esc(h)}</button>`).join("")}</div>
            <div class="spacer"></div><span class="lbl">Email aliases</span>${p.emails.map((e) => `<div class="finding info"><header><h3 class="mono break">${esc(e.value)}</h3>${W.kmz.copyBtn(e.value)}</header><div class="det">${esc(e.kind)} — ${esc(e.note)}</div></div>`).join("")}
            <span class="lbl">Security answers (random — store them with the account)</span>${ui.kv(p.answers.map((a) => row(a.q, a.a)))}
            <div class="spacer"></div><span class="lbl">Password (crypto-random, not from the seed)</span>${p.password ? `<div class="row" style="flex-wrap:nowrap"><div class="km-out sm" style="flex:1">${esc(p.password)}</div>${W.kmz.copyBtn(p.password)}</div>` : "—"}</div></div>
          <div class="spacer"></div><div class="callout warn small">${esc(p.note)} Any generated address could coincide with a real one — never have goods or mail sent to it.</div></section>`;
      }

      function drawPersona() {
        const prefs = W.kmz.store("decoy", "prefs", { country: "us", sex: "any", minAge: 25, maxAge: 55 });
        $("#de-body").innerHTML = `<div class="panel"><div class="grid g4">
            <div><label class="lbl" for="de-c">Country</label><select id="de-c">${D().COUNTRIES.map((c) => `<option value="${c.id}" ${c.id === prefs.country ? "selected" : ""}>${esc(c.name)}${c.reservedPhones ? "" : " (no fiction phone range)"}</option>`).join("")}</select></div>
            <div><span class="lbl">Sex</span>${ui.seg("de-sex", [["any", "Any"], ["f", "F"], ["m", "M"]], prefs.sex)}</div>
            <div><label class="lbl" for="de-min">Age range</label><div class="row" style="flex-wrap:nowrap"><input type="number" id="de-min" min="16" max="90" value="${prefs.minAge}" aria-label="Minimum age"><span class="muted">–</span><input type="number" id="de-max" min="16" max="95" value="${prefs.maxAge}" aria-label="Maximum age"></div></div>
            <div><label class="lbl" for="de-base">Your base email (optional)</label><input type="email" id="de-base" placeholder="you@example.com" autocapitalize="off" spellcheck="false" value="${esc(W.kmz.store("decoy", "base", ""))}"></div>
          </div><div class="spacer"></div>
          <label class="lbl" for="de-seed">Seed — the same seed and settings always give the same persona</label>
          <div class="row" style="flex-wrap:nowrap"><input type="text" id="de-seed" spellcheck="false" autocapitalize="off" value="${esc(D().seedPhrase())}"><button class="btn ghost" id="de-rnd" aria-label="New random seed">${W.icon(W.I.refresh)}</button></div>
          <div class="spacer"></div><div class="row"><button class="btn pri" id="de-go">Generate</button><button class="btn" id="de-save">${W.icon(W.I.plus)} Save persona</button><span class="tiny muted">Keep the seed private — anyone with it can regenerate this persona (but not its password).</span></div></div>
          <div id="de-out"></div>`;
        const sex = W.seg("de-sex", () => gen());
        let cur = null;
        const gen = () => {
          const o = { seed: $("#de-seed").value.trim() || D().seedPhrase(), country: $("#de-c").value, sex: sex(), minAge: +$("#de-min").value, maxAge: +$("#de-max").value, baseEmail: $("#de-base").value.trim() };
          W.kmz.put("decoy", "prefs", { country: o.country, sex: o.sex, minAge: o.minAge, maxAge: o.maxAge });
          if (o.baseEmail) W.kmz.put("decoy", "base", o.baseEmail); else W.store.del("kemuridama.decoy.base");
          cur = D().persona(o); $("#de-out").innerHTML = personaCard(cur);
        };
        $("#de-go").onclick = gen; $("#de-c").onchange = gen;
        $("#de-rnd").onclick = () => { $("#de-seed").value = D().seedPhrase(); gen(); };
        $("#de-save").onclick = () => {
          if (!cur) gen();
          const saved = W.kmz.store("decoy", "saved", []);
          const keep = Object.assign({}, cur, { password: null, saved: W.nowIso() });
          W.kmz.put("decoy", "saved", [keep].concat(saved.filter((x) => !(x.seed === keep.seed && x.country === keep.country))).slice(0, 100));
          W.toast(`Saved ${cur.name.full} (password not stored — put it in your password manager)`);
        };
        gen();
      }

      function drawSaved() {
        const saved = W.kmz.store("decoy", "saved", []);
        $("#de-body").innerHTML = saved.length ? `<div class="panel"><div class="row" style="justify-content:space-between"><span class="small muted">${saved.length} saved persona(s) · stored in <code>kemuridama.decoy.saved</code> on this device</span>
            <div class="row"><button class="btn sm" id="de-exp">${W.icon(W.I.dl)} Export JSON</button><button class="btn sm danger" id="de-wipe">${W.icon(W.I.trash)} Delete all</button></div></div><div class="spacer"></div>
            ${ui.table(["Name", "Country", "Seed", "Saved", ""], saved.map((p, i) => [`<b>${esc(p.name.full)}</b><div class="tiny muted">${esc(p.handles[0])}</div>`, esc(p.countryName), `<code class="break">${esc(p.seed)}</code>`, esc(W.fmt.ago(p.saved)),
              `<div class="row" style="flex-wrap:nowrap"><button class="btn sm" data-deo="${i}">Open</button><button class="btn sm ghost" data-dex="${i}" aria-label="Delete">${W.icon(W.I.trash)}</button></div>`]), { raw: true })}</div><div id="de-sv"></div>`
          : ui.panel("", ui.empty("NO SAVED PERSONAS", "Generate one in the Persona tab and press Save."));
        if (!saved.length) return;
        $("#de-exp").onclick = () => W.download("decoy-personas.json", JSON.stringify(saved, null, 2), "application/json");
        $("#de-wipe").onclick = () => { if (confirm("Delete every saved persona?")) { W.store.del("kemuridama.decoy.saved"); drawSaved(); } };
        $("#de-body").querySelectorAll("[data-deo]").forEach((b) => (b.onclick = () => {
          const p = saved[+b.dataset.deo];
          $("#de-sv").innerHTML = personaCard(Object.assign({}, p, { password: W.eng.passgen.password({ length: 20 }).value }));
        }));
        $("#de-body").querySelectorAll("[data-dex]").forEach((b) => (b.onclick = () => { saved.splice(+b.dataset.dex, 1); W.kmz.put("decoy", "saved", saved); drawSaved(); }));
      }

      function drawCanary() {
        $("#de-body").innerHTML = `<div class="panel"><p class="small muted" style="margin-top:0">Tripwires (port of Katana's DECOY): a resource nobody should ever touch, so any access tells you someone is in your inbox, files or repo. Wakizashi only makes the artifacts — the alert comes from a callback host <b>you</b> control (your own web server log, a webhook, or a canary-token service). Nothing is registered anywhere.</p>
          ${ui.seg("de-k", [["webbug", "Web bug"], ["docx", "Canary .docx"], ["honeycred", "Honey credential"], ["alias", "Tracking alias"]], W.kmz.store("decoy", "kind", "webbug"))}
          <div class="spacer"></div><div class="grid g2">
            <div id="de-cb-box"><label class="lbl" for="de-cb">Callback host you control</label><input type="text" id="de-cb" placeholder="canary.your-domain.example" value="${esc(W.kmz.store("decoy", "cb", ""))}" spellcheck="false" autocapitalize="off"></div>
            <div id="de-fl-box"><label class="lbl" for="de-fl">Credential flavour</label><select id="de-fl"><option value="aws">AWS access key</option><option value="github">GitHub token</option><option value="slack">Slack bot token</option><option value="stripe">Stripe secret key</option><option value="generic">Generic API key</option></select></div>
            <div id="de-al-box"><label class="lbl" for="de-ae">Your email</label><input type="email" id="de-ae" placeholder="you@example.com" spellcheck="false" autocapitalize="off"><label class="lbl" for="de-as" style="margin-top:8px">Service you're giving it to</label><input type="text" id="de-as" placeholder="shop-name"></div>
            <div><label class="lbl" for="de-lb">Label</label><input type="text" id="de-lb" placeholder="where you'll plant it"></div>
          </div><div class="spacer"></div><button class="btn pri" id="de-mk">Generate</button></div><div id="de-cout"></div>`;
        const kind = W.seg("de-k", (v) => { W.kmz.put("decoy", "kind", v); vis(); });
        const vis = () => { const k = kind(); $("#de-cb-box").hidden = !(k === "webbug" || k === "docx"); $("#de-fl-box").hidden = k !== "honeycred"; $("#de-al-box").hidden = k !== "alias"; };
        vis();
        W.act("#de-mk", async () => {
          const k = kind(), cb = $("#de-cb").value.trim(), label = $("#de-lb").value.trim();
          if (cb) W.kmz.put("decoy", "cb", cb);
          const out = $("#de-cout");
          const line = (n, v) => `<div class="finding info"><header><h3>${esc(n)}</h3>${W.kmz.copyBtn(v)}</header><div class="det mono break">${esc(v)}</div></div>`;
          if (k === "webbug") { const r = D().webbug(cb, label || "webbug"); out.innerHTML = ui.panel("Web bug", `${line("Beacon URL", r.url)}${Object.entries(r.snippets).map(([n, v]) => line(n.replace("_", " "), v)).join("")}<p class="tiny muted">Fires when ${esc(r.fires_when)}.${cb ? "" : " (Using canary.example.com — set your own callback host for real alerts.)"}</p>`); }
          else if (k === "docx") { const r = await D().canaryDocx(cb, label || "canary.docx"); W.kmz.save(r.filename, r.data, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"); out.innerHTML = ui.panel("Canary document", `${line("Beacon URL", r.url)}<p class="small">Saved <b>${esc(r.filename)}</b>. Fires when ${esc(r.fires_when)}. ${esc(r.note)}</p>`); }
          else if (k === "honeycred") { const r = D().honeycred($("#de-fl").value, label || "honeytoken"); out.innerHTML = ui.panel("Honey credential", `${Object.entries(r.token).filter(([n]) => n !== "hint").map(([n, v]) => line(n, v)).join("")}<p class="small muted">${esc(r.token.hint)}</p><div class="callout warn small">${esc(r.warning)}</div>`); }
          else { const r = D().alias($("#de-ae").value.trim(), $("#de-as").value.trim()); if (r.error) throw new Error(r.error); out.innerHTML = ui.panel("Tracking alias", `${line("Plus-address", r.plus)}<p class="small muted">If mail to it arrives from anyone but ${esc(r.service || "that service")}, ${esc(r.fires_when.split("→")[1] || "they leaked it")}. ${esc(r.dot_hint)}</p>`); }
        });
      }
    },
  });
})();
