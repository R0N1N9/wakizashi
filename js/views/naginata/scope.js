(function () {
  "use strict";
  const { $, esc, ui } = W;
  const K = (k) => "naginata.scope." + k;
  const STATUS = [["untested", "Untested"], ["in-progress", "In progress"], ["tested", "Tested"], ["finding", "Finding"], ["blocked", "Blocked"]];
  const VERDICT = { in: ["IN SCOPE", "ok"], out: ["OUT OF SCOPE", "crit"], partial: ["PARTIAL", "med"], unlisted: ["NOT LISTED", "high"], unresolved: ["RESOLVE FIRST", "info"], invalid: ["INVALID", ""] };
  const SAMPLE_IN = "10.0.0.0/16          # internal corp\n198.51.100.10-20     # DMZ\n2001:db8:1::/48\nexample.com\n*.example.com";
  const SAMPLE_OUT = "10.0.99.0/24         # payments VLAN\nvpn.example.com\n*.payments.example.com";

  /** Shared: the stored scope as {in, out} text (used by the report tool too). */
  W.naginataScope = () => ({ in: W.store.get(K("in"), ""), out: W.store.get(K("out"), "") });
  const verdictBadge = (v) => ui.badge(VERDICT[v][0], VERDICT[v][1]);

  W.tool("naginata", "scope", {
    name: "Scope", order: 10,
    desc: "Engagement details, in/out-of-scope lists (CIDR, ranges, wildcards), an is-it-in-scope checker and an asset tracker.",
    icon: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.5"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/>',
    render(el, arg) {
      W.roeGate(el, () => {
        const eng = W.store.get(K("engagement"), { name: "", client: "", start: "", end: "", notes: "" });
        el.innerHTML = ui.head("Scope", "Engagement & scope board", "Record what you're authorised to test. Out-of-scope entries always win over in-scope ones. Everything stays in this browser.") + `
          <div class="panel"><h2>Engagement</h2>
            <div class="grid g2">
              <div><label class="lbl" for="sc-name">Engagement</label><input id="sc-name" type="text" maxlength="160" placeholder="Q4 external + internal assessment"></div>
              <div><label class="lbl" for="sc-client">Client</label><input id="sc-client" type="text" maxlength="160" placeholder="Acme Corp"></div>
              <div><label class="lbl" for="sc-start">Start</label><input id="sc-start" type="date"></div>
              <div><label class="lbl" for="sc-end">End</label><input id="sc-end" type="date"></div>
            </div>
            <div class="spacer"></div>
            <label class="lbl" for="sc-notes">Notes — contacts, testing windows, authorisation reference</label>
            <textarea id="sc-notes" rows="3" spellcheck="true" placeholder="Authorisation letter ref, emergency contact, permitted hours, rate limits…"></textarea>
            <div class="spacer"></div><div class="row small muted" id="sc-window"></div>
          </div>
          <div class="grid g2">
            <div class="panel"><h2>In scope</h2>
              <textarea id="sc-in" rows="8" spellcheck="false" autocapitalize="off" placeholder="One per line: 10.0.0.0/24, 10.0.1.5-40, 2001:db8::/48, example.com, *.example.com — add # notes"></textarea>
              <div id="sc-in-sum"></div></div>
            <div class="panel"><h2>Out of scope</h2>
              <textarea id="sc-out" rows="8" spellcheck="false" autocapitalize="off" placeholder="Exclusions override in-scope entries: 10.0.0.1, vpn.example.com, *.prod.example.com"></textarea>
              <div id="sc-out-sum"></div></div>
          </div>
          <div class="row"><button class="btn ghost sm" id="sc-sample">Load example scope</button>
            <button class="btn ghost sm" id="sc-export">${W.icon(W.I.dl)} Export JSON</button>
            <label class="btn ghost sm">${W.icon(W.I.up)} Import JSON<input type="file" id="sc-import" accept=".json,application/json"></label>
            <button class="btn ghost sm" id="sc-md">${W.icon(W.I.copy)} Copy as Markdown</button></div>
          <div class="spacer"></div>
          <div class="panel"><h2>Is this in scope?</h2>
            <textarea id="sc-q" rows="3" spellcheck="false" autocapitalize="off" placeholder="IP, CIDR, range, hostname or URL — one per line"></textarea>
            <div class="spacer"></div>
            <div class="row"><button class="btn pri" id="sc-check">${W.icon(W.I.search)} Check</button><button class="btn ghost" id="sc-addq">${W.icon(W.I.plus)} Add to assets</button></div>
            <div class="spacer"></div><div id="sc-res"></div>
          </div>
          <div class="panel"><h2>Assets</h2>
            <div class="grid g3">
              <div><label class="lbl" for="sc-a-val">Asset</label><input id="sc-a-val" type="text" placeholder="app.example.com or 10.0.4.12" autocapitalize="off" spellcheck="false"></div>
              <div><label class="lbl" for="sc-a-st">Status</label><select id="sc-a-st">${STATUS.map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select></div>
              <div><label class="lbl" for="sc-a-note">Notes</label><input id="sc-a-note" type="text" placeholder="ports, owner, creds used…"></div>
            </div>
            <div class="spacer"></div>
            <div class="row"><button class="btn" id="sc-a-add">${W.icon(W.I.plus)} Add asset</button>
              <select id="sc-a-filter" style="width:auto;min-width:150px" aria-label="Filter assets"><option value="">All statuses</option>${STATUS.map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}<option value="!in">Not in scope</option></select>
              <button class="btn ghost sm" id="sc-a-csv">${W.icon(W.I.dl)} CSV</button></div>
            <div class="spacer"></div><div id="sc-assets"></div>
          </div>`;

        // ---- engagement
        const f = { name: $("#sc-name"), client: $("#sc-client"), start: $("#sc-start"), end: $("#sc-end"), notes: $("#sc-notes") };
        for (const [k, inp] of Object.entries(f)) { inp.value = eng[k] || ""; inp.addEventListener("input", saveEng); }
        function saveEng() {
          const o = {}; for (const [k, inp] of Object.entries(f)) o[k] = inp.value;
          W.store.set(K("engagement"), o); drawWindow(o);
        }
        function drawWindow(o) {
          const today = new Date().toISOString().slice(0, 10);
          let s = "";
          if (o.start && o.end && o.end < o.start) s = ui.badge("end before start", "crit");
          else if (o.start && today < o.start) s = ui.badge("not started", "info") + ` <span>starts ${esc(o.start)}</span>`;
          else if (o.end && today > o.end) s = ui.badge("window closed", "crit") + ` <span>ended ${esc(o.end)} — stop testing unless extended in writing</span>`;
          else if (o.start || o.end) { const left = o.end ? Math.round((Date.parse(o.end) - Date.parse(today)) / 86400000) : null; s = ui.badge("active", "ok") + (left != null ? ` <span>${left} day(s) left</span>` : ""); }
          else s = `<span>Set the dates to track the testing window.</span>`;
          $("#sc-window").innerHTML = s;
        }
        drawWindow(eng);

        // ---- scope lists
        const tin = $("#sc-in"), tout = $("#sc-out");
        tin.value = W.store.get(K("in"), ""); tout.value = W.store.get(K("out"), "");
        const sumHtml = (text) => {
          const s = W.eng.scope.summarise(text), bad = W.eng.scope.parseList(text).invalid;
          return `<div class="ng-sum"><span><b>${s.entries}</b> entries</span><span><b>${W.fmt.num(Number(s.v4))}</b> IPv4 addr</span>${s.v6 ? `<span><b>${s.v6 > 2n ** 53n ? "2^" + (s.v6.toString(2).length - 1) + "+" : W.fmt.num(Number(s.v6))}</b> IPv6 addr</span>` : ""}<span><b>${s.domains}</b> hosts</span><span><b>${s.wildcards}</b> wildcards</span></div>`
            + (bad.length ? `<div class="ng-bad">${bad.map((b) => `✕ ${esc(b.raw)} — ${esc(b.error)}`).join("<br>")}</div>` : "");
        };
        const saveScope = W.debounce(() => { W.store.set(K("in"), tin.value); W.store.set(K("out"), tout.value); drawSums(); drawAssets(); if ($("#sc-q").value.trim()) check(); }, 250);
        const drawSums = () => { $("#sc-in-sum").innerHTML = sumHtml(tin.value); $("#sc-out-sum").innerHTML = sumHtml(tout.value); };
        tin.addEventListener("input", saveScope); tout.addEventListener("input", saveScope);
        drawSums();
        $("#sc-sample").onclick = () => {
          if ((tin.value.trim() || tout.value.trim()) && !confirm("Replace the current scope lists with the example?")) return;
          tin.value = SAMPLE_IN; tout.value = SAMPLE_OUT; saveScope();
          if (!$("#sc-q").value.trim()) $("#sc-q").value = "10.0.4.12\n10.0.99.7\nshop.example.com\nvpn.example.com\nhttps://api.payments.example.com/v1\n198.51.100.0/24\n8.8.8.8";
          setTimeout(check, 300);
        };

        // ---- checker
        function check() {
          const q = $("#sc-q").value;
          if (!q.trim()) { $("#sc-res").innerHTML = ""; return; }
          const rs = W.eng.scope.checkMany(q.split(/\r?\n/), W.naginataScope());
          $("#sc-res").innerHTML = ui.table(["Target", "Verdict", "Why"], rs.map((r) => [`<span class="mono break">${esc(r.input)}</span>`, verdictBadge(r.verdict), esc(r.reason)]), { raw: true });
          return rs;
        }
        $("#sc-check").onclick = () => { if (!$("#sc-q").value.trim()) return W.toast("Enter a target to check", 1); check(); };
        $("#sc-q").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) check(); });
        $("#sc-addq").onclick = () => {
          const vals = $("#sc-q").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
          if (!vals.length) return W.toast("Nothing to add", 1);
          const n = addAssets(vals.map((v) => ({ value: v })));
          W.toast(`${n} asset(s) added`);
        };
        if (arg) { $("#sc-q").value = String(arg); check(); }

        // ---- assets
        const assets = () => W.store.get(K("assets"), []);
        const saveAssets = (a) => W.store.set(K("assets"), a);
        function addAssets(list) {
          const a = assets(); let n = 0;
          for (const it of list) {
            const v = String(it.value || "").trim().slice(0, 300); if (!v) continue;
            if (a.some((x) => x.value.toLowerCase() === v.toLowerCase())) continue;
            a.push({ id: W.uid(), value: v, status: it.status || "untested", notes: String(it.notes || "").slice(0, 2000), added: W.nowIso() }); n++;
          }
          saveAssets(a); drawAssets(); return n;
        }
        $("#sc-a-add").onclick = () => {
          const v = $("#sc-a-val").value.trim(); if (!v) return W.toast("Enter an asset", 1);
          if (!addAssets([{ value: v, status: $("#sc-a-st").value, notes: $("#sc-a-note").value }])) return W.toast("Already listed", 1);
          $("#sc-a-val").value = ""; $("#sc-a-note").value = "";
          const r = W.eng.scope.check(v, W.naginataScope());
          if (r.verdict !== "in") W.toast(`Heads up: ${v} is ${VERDICT[r.verdict][0].toLowerCase()}`, 1);
        };
        $("#sc-a-val").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#sc-a-add").click(); });
        $("#sc-a-filter").onchange = drawAssets;
        function drawAssets() {
          const a = assets(), sc = W.naginataScope(), flt = $("#sc-a-filter").value;
          const rows = a.map((x) => Object.assign({}, x, { r: W.eng.scope.check(x.value, sc) }))
            .filter((x) => !flt || (flt === "!in" ? x.r.verdict !== "in" : x.status === flt));
          const counts = {}; for (const x of a) counts[x.status] = (counts[x.status] || 0) + 1;
          const box = $("#sc-assets");
          if (!a.length) { box.innerHTML = ui.empty("NO ASSETS", "Add hosts as you discover them — each is checked against the scope lists."); return; }
          box.innerHTML = `<div class="ng-sum" style="margin:0 0 8px">${STATUS.map(([v, l]) => `<span>${l}: <b>${counts[v] || 0}</b></span>`).join("")}</div>`
            + `<div class="tablewrap ng-tbl-in"><table class="tbl"><thead><tr><th>Asset</th><th>Scope</th><th>Status</th><th>Notes</th><th></th></tr></thead><tbody>${rows.map((x) => `<tr data-id="${esc(x.id)}">
              <td class="mono break" style="min-width:140px">${esc(x.value)}</td>
              <td title="${esc(x.r.reason)}">${verdictBadge(x.r.verdict)}</td>
              <td><select data-f="status" aria-label="Status">${STATUS.map(([v, l]) => `<option value="${v}" ${v === x.status ? "selected" : ""}>${l}</option>`).join("")}</select></td>
              <td style="min-width:180px"><input type="text" data-f="notes" value="${esc(x.notes)}" aria-label="Notes"></td>
              <td><button class="btn ghost sm" data-del="1" aria-label="Delete">${W.icon(W.I.trash)}</button></td></tr>`).join("") || `<tr><td colspan="5">${ui.empty("NONE MATCH")}</td></tr>`}</tbody></table></div>`;
        }
        $("#sc-assets").addEventListener("change", (e) => {
          const tr = e.target.closest("tr[data-id]"), fld = e.target.dataset.f; if (!tr || !fld) return;
          const a = assets(), it = a.find((x) => x.id === tr.dataset.id); if (!it) return;
          it[fld] = String(e.target.value).slice(0, 2000); saveAssets(a);
          if (fld === "status") drawAssets();
        });
        $("#sc-assets").addEventListener("click", (e) => {
          const b = e.target.closest("button[data-del]"); if (!b) return;
          const id = b.closest("tr").dataset.id; saveAssets(assets().filter((x) => x.id !== id)); drawAssets();
        });
        drawAssets();
        $("#sc-a-csv").onclick = () => {
          const q = (s) => `"${String(s == null ? "" : s).replace(/"/g, '""')}"`;
          const sc = W.naginataScope();
          const csv = ["asset,scope,status,notes,added"].concat(assets().map((x) => [x.value, W.eng.scope.check(x.value, sc).verdict, x.status, x.notes, x.added].map(q).join(","))).join("\n");
          W.download(`assets-${slug()}.csv`, csv, "text/csv");
        };

        // ---- export / import
        const slug = () => (W.store.get(K("engagement"), {}).name || "engagement").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "engagement";
        $("#sc-export").onclick = () => W.download(`scope-${slug()}.json`, JSON.stringify({ app: "wakizashi", kind: "naginata.scope", exported: W.nowIso(),
          engagement: W.store.get(K("engagement"), {}), in: W.store.get(K("in"), ""), out: W.store.get(K("out"), ""), assets: assets() }, null, 2), "application/json");
        $("#sc-import").onchange = async (e) => {
          const file = e.target.files[0]; e.target.value = ""; if (!file) return;
          try {
            const j = JSON.parse(await W.readFile(file));
            if (!j || j.kind !== "naginata.scope") throw new Error("not a Wakizashi scope export");
            if (!confirm("Replace the current engagement, scope and assets with this file?")) return;
            const e2 = j.engagement || {};
            W.store.set(K("engagement"), { name: String(e2.name || ""), client: String(e2.client || ""), start: String(e2.start || ""), end: String(e2.end || ""), notes: String(e2.notes || "") });
            W.store.set(K("in"), String(j.in || "")); W.store.set(K("out"), String(j.out || ""));
            W.store.set(K("assets"), (Array.isArray(j.assets) ? j.assets : []).filter((x) => x && x.value).map((x) => ({ id: String(x.id || W.uid()), value: String(x.value), status: STATUS.some(([v]) => v === x.status) ? x.status : "untested", notes: String(x.notes || ""), added: String(x.added || W.nowIso()) })));
            W.toast("Scope imported"); W.go("naginata", "scope");
          } catch (err) { W.toast(err.message, 1); }
        };
        $("#sc-md").onclick = () => {
          const e2 = W.store.get(K("engagement"), {}), lines = (t) => W.eng.scope.parseList(t).entries.map((x) => `- \`${x.label}\`${x.note ? " — " + x.note : ""}`).join("\n") || "- _none_";
          W.copy(`# Scope — ${e2.name || "Engagement"}${e2.client ? " (" + e2.client + ")" : ""}\n\n${e2.start || e2.end ? `Window: ${e2.start || "?"} → ${e2.end || "?"}\n\n` : ""}## In scope\n${lines(tin.value)}\n\n## Out of scope\n${lines(tout.value)}\n`, "Scope copied as Markdown");
        };
      });
    },
  });
})();
