(function () {
  "use strict";
  const { $, esc, ui } = W;
  const T = () => W.eng.trace;
  const SAMPLE = [
    "https://www.google.com/url?sa=t&q=https%3A%2F%2Fnews.example.com%2Fstory%3Futm_source%3Dnewsletter%26utm_medium%3Demail%26id%3D42&ved=2ahUKEw",
    "https://shop.example/item/123?color=blue&fbclid=IwAR2xYz&gclid=Cj0KCQjw&mc_eid=8f3a2b",
    "https://youtu.be/dQw4w9WgXcQ?si=Xy12ab34Cd&t=30",
    "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.example.org%2Flogin%3Fref_src%3Dtwsrc&data=05%7C01",
    "https://t.co/AbCdEf123",
    "https://xn--pple-43d.com/account",
  ].join("\n");

  W.tool("kemuridama", "trace", {
    name: "Trace", order: 60,
    desc: "Strip tracking parameters, unwrap redirect wrappers (Google, Facebook, Outlook Safe Links…), flag shorteners and look-alike domains.",
    icon: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/><path d="M3 3l18 18"/>',
    render(el, arg) {
      el.innerHTML = ui.head("Trace", "Link cleaner", "Paste links, a message, or an email's HTML source. Tracking IDs (utm_*, fbclid, gclid, si…) tie a click to you and your account; redirect wrappers log where you go. Everything is checked offline — nothing is fetched.") + `
        <div class="panel"><label class="lbl" for="tr-in">Links, text or HTML</label>
          <textarea id="tr-in" rows="7" spellcheck="false" autocapitalize="off" placeholder="https://example.com/?utm_source=…  — one or many, or a whole message"></textarea>
          <div class="spacer"></div><div class="row"><button class="btn pri" id="tr-go">${W.icon(W.I.search)} Clean</button><button class="btn ghost" id="tr-sample">Sample</button><button class="btn ghost" id="tr-clear">Clear</button>
            <label class="check"><input type="checkbox" id="tr-auto" checked> clean as I type</label></div></div>
        <div id="tr-out"></div>`;
      W.kmz.wireCopy(el);
      const inp = $("#tr-in");
      if (typeof arg === "string") inp.value = arg;
      const run = () => {
        const v = inp.value.trim(); if (!v) { $("#tr-out").innerHTML = ""; return; }
        const r = T().analyze(v), out = $("#tr-out");
        const total = r.links.reduce((n, l) => n + l.removed.length, 0);
        const cleanedAll = r.mode === "url" ? r.cleanedText : r.sanitized.join("\n");
        out.innerHTML = `<div class="grid g4">${ui.stat(r.links.length, "link(s)")}${ui.stat(total, "trackers stripped", total > 0)}${ui.stat(r.links.reduce((n, l) => n + l.unwrapped.length, 0), "redirects unwrapped")}${ui.stat(r.links.reduce((n, l) => n + l.flags.filter((f) => f.level === "high").length, 0) + r.beacons.length, "high-risk")}</div>
          <div class="panel"><h2>Cleaned</h2><pre class="out" id="tr-clean">${esc(cleanedAll)}</pre><div class="spacer"></div><div class="row">${W.kmz.copyBtn(cleanedAll, "Copy cleaned")}<span class="tiny muted">${esc(r.summary)}</span></div></div>
          ${r.beacons.length ? `<div class="panel"><h2>Tracking pixels / beacons</h2>${ui.table(["Host", "Tracker", "URL"], r.beacons.map((b) => [esc(b.host), `${W.kmz.sev(b.level)} ${esc(b.tracker)}`, `<span class="km-url">${esc(b.url)}</span>`]), { raw: true })}</div>` : ""}
          ${r.links.map(card).join("")}`;
      };
      function card(l) {
        const worst = l.flags.find((f) => f.level === "high") ? "high" : l.flags.find((f) => f.level === "medium") ? "medium" : l.changed ? "low" : "ok";
        const chain = l.unwrapped.map((u, i) => i === 0 && u.from === l.input ? `<div class="tiny muted">unwrapped <b>${esc(u.via)}</b></div>` : `<div class="tiny muted">via <b>${esc(u.via)}</b>: <span class="km-url"><del>${esc(u.from.slice(0, 160))}${u.from.length > 160 ? "…" : ""}</del></span></div>`).join("");
        const host = l.idn ? `<div class="tiny">Host shown as <b>${esc(l.idn.unicode)}</b> · really <code>${esc(l.idn.ascii)}</code>${l.idn.lookalike ? ` · imitates <b class="c-crit">${esc(l.idn.lookalike)}</b>` : ""}</div>` : "";
        return `<section class="finding ${worst}"><header><h3 class="km-url"><ins>${esc(l.clean)}</ins></h3>${W.kmz.sev(worst)}${W.kmz.copyBtn(l.clean)}</header>
          <div class="det">${l.changed ? `<div class="km-url"><del>${esc(l.input.slice(0, 300))}${l.input.length > 300 ? "…" : ""}</del></div>` : ""}${chain}${host}
          ${l.flags.length ? `<div style="margin-top:6px">${l.flags.map((f) => `<div>${W.kmz.sev(f.level)} <span class="small">${esc(f.text)}</span></div>`).join("")}</div>` : ""}
          ${l.removed.length ? `<div style="margin-top:8px">${ui.table(["Removed", "Value", "What it does"], l.removed.map((x) => [`<code>${esc(x.param)}</code>`, `<span class="break tiny">${esc(x.value)}</span>`, esc(x.what)]), { raw: true })}</div>` : ""}</div></section>`;
      }
      $("#tr-go").onclick = run;
      $("#tr-sample").onclick = () => { inp.value = SAMPLE; run(); };
      $("#tr-clear").onclick = () => { inp.value = ""; run(); inp.focus(); };
      inp.addEventListener("input", W.debounce(() => { if ($("#tr-auto").checked) run(); }, 300));
      if (inp.value) run();
    },
  });
})();
