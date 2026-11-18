/* Yoroi · BLOCK — countermeasure builder. Indicators (from HUNT, PHISH, RESPOND, the case, or pasted) →
 * firewall, DNS sinkhole, IDS, detection, EDR and sharing formats. Everything is strictly validated by
 * W.eng.block so nothing can break out of a rule's quoting. */
(function () {
  "use strict";
  const { $, $$, esc, ui } = W;
  const FMT = "yoroi.block.fmt", TAG = "yoroi.block.tag", PRIV = "yoroi.block.private";
  const GROUPS = { network: "Firewall", dns: "DNS sinkhole", ids: "IDS", detection: "Detection / hunting", edr: "EDR", sharing: "Sharing" };
  const ICON = '<path d="M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z"/><path d="M8.5 8.5l7 7"/>';

  W.tool("yoroi", "block", {
    name: "Block", order: 60, icon: ICON,
    desc: "Turn IPs, domains, URLs and hashes into firewall, DNS, IDS, Sigma, KQL, EDR and STIX countermeasures.",
    render(el, arg) {
      const B = W.eng.block;
      let cur = B.FORMATS.some((f) => f.id === W.store.get(FMT)) ? W.store.get(FMT) : "iptables", res = null;
      const c = W.Case.active();
      el.innerHTML = ui.head("BLOCK", "Countermeasure builder", "Paste indicators in any shape — defanged, comma/space/newline separated. They are refanged and strictly validated; private ranges and catch-alls like 0.0.0.0/0 are refused unless you allow internal addresses.") +
        `<div class="grid g2 yb-split"><div>${ui.panel("Indicators", `
          <textarea id="bk-t" rows="11" spellcheck="false" autocapitalize="off" placeholder="185.220.101[.]4&#10;evil-domain[.]com&#10;hxxps://bad.example/payload&#10;44d88612fea8a8f36de82e1278abb02f"></textarea>
          <div class="spacer"></div><div class="grid g2"><div><label class="lbl" for="bk-tag">Tag / rule name</label><input type="text" id="bk-tag" maxlength="40" value="${esc(W.store.get(TAG, "blocklist"))}"></div>
            <div><label class="lbl" for="bk-sid">Suricata start SID · MDE expiry (days)</label><div class="row" style="flex-wrap:nowrap"><input type="number" id="bk-sid" value="9100000" min="1"><input type="number" id="bk-days" value="90" min="1" max="3650"></div></div></div>
          <div class="spacer"></div><label class="check"><input type="checkbox" id="bk-priv" ${W.store.get(PRIV) ? "checked" : ""}> allow internal / reserved addresses (RFC 1918, loopback, link-local…)</label>
          <div class="spacer"></div><div class="row">${c.items.length ? ui.btn(W.icon(W.I.case) + `Load case “${esc(c.name.slice(0, 24))}” (${c.items.length})`, 'id="bk-case"', "sm") : ""}${ui.btn("Clear", 'id="bk-clr"', "sm ghost")}</div>`)}
          <div id="bk-counts"></div></div>
        <div>${ui.panel("Format", Object.entries(GROUPS).map(([g, gl]) => `<div class="lbl" style="margin-top:8px">${esc(gl)}</div><div class="row yb-fmts">${B.FORMATS.filter((f) => f.group === g).map((f) => `<button type="button" class="btn sm ${f.id === cur ? "pri" : ""}" data-f="${esc(f.id)}">${esc(f.label)}</button>`).join("")}</div>`).join(""))}
          <section class="panel"><div class="row"><h2 style="margin:0" id="bk-lbl">Output</h2><span class="grow"></span>${ui.btn(W.icon(W.I.copy) + "Copy", 'id="bk-cp"', "sm")}${ui.btn(W.icon(W.I.dl) + "Download", 'id="bk-dl"', "sm")}</div>
            <div class="spacer"></div><pre class="out" id="bk-out">// add indicators to generate rules</pre></section></div></div>`;
      const gen = () => {
        const text = $("#bk-t").value;
        if (!text.trim()) { res = null; $("#bk-out").textContent = "// add indicators to generate rules"; $("#bk-counts").innerHTML = ""; $("#bk-lbl").textContent = "Output"; return; }
        W.store.set(TAG, $("#bk-tag").value);
        res = B.generate(text, cur, $("#bk-tag").value, { allowPrivate: $("#bk-priv").checked, sid: +$("#bk-sid").value || 9100000, days: +$("#bk-days").value || 90 });
        $("#bk-lbl").textContent = res.label;
        $("#bk-out").textContent = res.output;
        const counts = Object.entries(res.counts).filter(([k, n]) => n && k !== "url_hosts");
        const total = counts.reduce((a, [, n]) => a + n, 0);
        $("#bk-counts").innerHTML = ui.panel(`Accepted (${total})${res.rejected.length ? ` · rejected (${res.rejected.length})` : ""}`, `
          <div class="row">${counts.length ? counts.map(([k, n]) => `<span class="chip">${esc(k)} <b>${n}</b></span>`).join("") : `<span class="muted small">nothing valid yet</span>`}
          ${res.counts.url_hosts ? `<span class="chip" title="Hosts taken from URLs for DNS/network formats">url hosts <b>${res.counts.url_hosts}</b></span>` : ""}</div>
          ${res.rejected.length ? `<div class="spacer"></div><div class="lbl">Rejected — not included in any output</div><div class="yb-rej">${res.rejected.map((x) => `<div class="mono tiny break">✕ ${esc(x)}</div>`).join("")}</div>` : ""}
          ${total ? `<div class="spacer"></div>${ui.btn(W.icon(W.I.case) + "Add accepted to case", 'id="bk-tocase"', "sm ghost")}` : ""}`);
        const tc = $("#bk-tocase");
        if (tc) tc.onclick = () => { const k = res.classified; W.Case.add(["ipv4", "ipv6", "cidr", "domain", "url", "md5", "sha1", "sha256"].flatMap((t) => k[t].map((v) => ({ value: v, type: t === "cidr" ? "cidr" : t, tags: ["blocklist", $("#bk-tag").value].filter(Boolean) })))); };
      };
      const deb = W.debounce(gen, 250);
      el.addEventListener("click", (e) => {
        const b = e.target.closest("button[data-f]"); if (!b) return;
        cur = b.dataset.f; W.store.set(FMT, cur);
        $$("button[data-f]", el).forEach((x) => x.classList.toggle("pri", x === b));
        gen();
      });
      $("#bk-t").addEventListener("input", deb);
      ["#bk-tag", "#bk-sid", "#bk-days"].forEach((s) => $(s).addEventListener("input", deb));
      $("#bk-priv").addEventListener("change", (e) => { W.store.set(PRIV, e.target.checked); gen(); });
      const lc = $("#bk-case"); if (lc) lc.onclick = () => { $("#bk-t").value = W.Case.active().items.map((x) => x.value).join("\n"); gen(); };
      $("#bk-clr").onclick = () => { $("#bk-t").value = ""; gen(); };
      $("#bk-cp").onclick = () => (res ? W.copy(res.output, "Rules copied") : W.toast("Nothing to copy yet", 1));
      $("#bk-dl").onclick = () => (res ? W.download(`wkz_${B.cleanTag($("#bk-tag").value)}_${cur}.${res.ext}`, res.output) : W.toast("Nothing to download yet", 1));
      if (arg != null && String(arg).trim()) { $("#bk-t").value = Array.isArray(arg) ? arg.join("\n") : String(arg); gen(); }
    },
  });
})();
