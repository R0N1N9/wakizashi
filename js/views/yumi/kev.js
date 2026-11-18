(function () {
  "use strict";
  const { $, esc, ui } = W;
  // CISA's own URL doesn't allow cross-origin reads; CISA publishes the same catalog to GitHub, which does.
  const SOURCES = [
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  ];
  const CACHE = "wkz-data";
  let mem = null;

  async function load(force) {
    if (mem && !force) return mem;
    const cache = typeof caches !== "undefined" ? await caches.open(CACHE).catch(() => null) : null;
    if (!force && cache) { const hit = await cache.match("kev.json"); if (hit) return (mem = await hit.json()); }
    let lastErr;
    for (const url of SOURCES) {
      try {
        const r = await fetch(url, { credentials: "omit", referrerPolicy: "no-referrer" });
        if (!r.ok) throw new Error("HTTP " + r.status);
        const j = await r.json();
        if (!Array.isArray(j.vulnerabilities)) throw new Error("unexpected format");
        if (cache) await cache.put("kev.json", new Response(JSON.stringify(j), { headers: { "content-type": "application/json", "x-fetched": new Date().toISOString() } }));
        W.store.set("yumi.kev.fetched", W.nowIso());
        return (mem = j);
      } catch (e) { lastErr = e; }
    }
    throw new Error("couldn't download the KEV catalog (" + (lastErr && lastErr.message) + ") — check your connection");
  }

  W.tool("yumi", "kev", {
    name: "KEV", order: 80,
    desc: "Search CISA's Known Exploited Vulnerabilities catalog — cached for offline use.",
    help: {
      steps: ["Download the CISA Known Exploited Vulnerabilities catalog (one press — it's then cached for offline use).", "Search by CVE, vendor, product or keyword.", "Export the results as CSV."],
      tips: ["Refresh the catalog every so often to pick up newly added CVEs."],
    },
    icon: '<path d="M12 2 4 5v6c0 5 3.4 9 8 10 4.6-1 8-5 8-10V5z"/><path d="M12 8v5M12 16v.5"/>',
    render(el, arg) {
      const fetched = W.store.get("yumi.kev.fetched");
      el.innerHTML = ui.head("KEV", "Known exploited vulnerabilities", "CISA's catalog of CVEs exploited in the wild. Downloaded only when you ask, then cached on this device for offline searching.") + `
        <div class="panel"><div class="row"><input type="search" id="kv-q" placeholder="Search CVE, vendor, product, keyword…" style="flex:1;min-width:200px" value="${esc(arg || "")}">
          <button class="btn pri" id="kv-load">${fetched ? "Refresh" : "Download catalog"}</button></div>
          <div class="tiny faint" style="margin-top:6px" id="kv-meta">${fetched ? "Cached " + esc(W.fmt.ago(fetched)) : "Not downloaded yet (~1 MB from github.com/cisagov)."}</div>
          <div class="spacer"></div><div class="row"><label class="check"><input type="checkbox" id="kv-ransom"> used in ransomware</label><label class="check"><input type="checkbox" id="kv-recent"> added in the last 30 days</label></div></div>
        <div id="kv-out"></div>`;
      const draw = () => {
        if (!mem) return;
        const q = $("#kv-q").value.trim().toLowerCase(), rans = $("#kv-ransom").checked, recent = $("#kv-recent").checked, cutoff = Date.now() - 30 * 864e5;
        let v = mem.vulnerabilities.filter((x) => (!q || (x.cveID + " " + x.vendorProject + " " + x.product + " " + x.vulnerabilityName + " " + x.shortDescription).toLowerCase().includes(q))
          && (!rans || x.knownRansomwareCampaignUse === "Known") && (!recent || Date.parse(x.dateAdded) >= cutoff));
        v = v.sort((a, b) => b.dateAdded.localeCompare(a.dateAdded));
        const vendors = {}; v.forEach((x) => (vendors[x.vendorProject] = (vendors[x.vendorProject] || 0) + 1));
        $("#kv-meta").textContent = `Catalog ${mem.catalogVersion || ""} · ${mem.count || mem.vulnerabilities.length} entries · released ${mem.dateReleased ? mem.dateReleased.slice(0, 10) : "?"}`;
        $("#kv-out").innerHTML = `<div class="grid g2">${ui.panel(`Matches (${v.length})`, v.length ? ui.bars(Object.entries(vendors).sort((a, b) => b[1] - a[1]).slice(0, 8)) : ui.empty("NO MATCHES"))}
          ${ui.panel("Actions", `<div class="row"><button class="btn sm" id="kv-case" ${v.length ? "" : "disabled"}>${W.icon(W.I.case)} Add ${Math.min(v.length, 200)} CVE(s) to case</button><button class="btn sm" id="kv-csv" ${v.length ? "" : "disabled"}>${W.icon(W.I.dl)} CSV</button></div>`)}</div>` +
          v.slice(0, 150).map((x) => `<div class="finding ${x.knownRansomwareCampaignUse === "Known" ? "critical" : "high"}"><header><button class="chip" data-cve="${esc(x.cveID)}">${esc(x.cveID)}</button><h3>${esc(x.vulnerabilityName)}</h3>
            ${x.knownRansomwareCampaignUse === "Known" ? ui.badge("ransomware", "crit") : ""}<span class="tiny muted">added ${esc(x.dateAdded)} · due ${esc(x.dueDate)}</span></header>
            <div class="det"><b>${esc(x.vendorProject)}</b> · ${esc(x.product)} — ${esc(x.shortDescription)}</div><div class="det small"><b>Action:</b> ${esc(x.requiredAction)}</div></div>`).join("")
          + (v.length > 150 ? `<p class="muted small">Showing 150 of ${v.length} — refine the search.</p>` : "");
        $("#kv-out").onclick = (e) => { const c = e.target.closest("[data-cve]"); if (c) W.go("yumi", "pivot", c.dataset.cve); };
        const b1 = $("#kv-case"); if (b1) b1.onclick = () => W.Case.add(v.slice(0, 200).map((x) => ({ value: x.cveID, type: "cve", verdict: "suspicious", tags: ["kev"], note: `${x.vendorProject} ${x.product}` })));
        const b2 = $("#kv-csv"); if (b2) b2.onclick = () => W.download("kev.csv", "cve,vendor,product,name,added,due,ransomware\n" + v.map((x) => [x.cveID, x.vendorProject, x.product, x.vulnerabilityName, x.dateAdded, x.dueDate, x.knownRansomwareCampaignUse].map((s) => `"${String(s).replace(/"/g, '""')}"`).join(",")).join("\n"), "text/csv");
      };
      W.act("#kv-load", async () => { $("#kv-out").innerHTML = ui.panel("", ui.loader("DOWNLOADING KEV")); await load(true); W.toast("KEV catalog updated"); draw(); });
      ["#kv-ransom", "#kv-recent"].forEach((s) => ($(s).onchange = draw));
      $("#kv-q").addEventListener("input", W.debounce(draw, 200));
      if (fetched) load(false).then(draw).catch((e) => ($("#kv-out").innerHTML = `<div class="callout warn">${esc(e.message)}</div>`));
    },
  });
})();
