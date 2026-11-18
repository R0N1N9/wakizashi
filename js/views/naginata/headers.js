(function () {
  "use strict";
  const { $, esc, ui } = W;
  const K = (k) => "naginata.headers." + k;
  const SAMPLE = `HTTP/1.1 200 OK
Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1k
X-Powered-By: PHP/7.4.3
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src *
Strict-Transport-Security: max-age=86400
X-Frame-Options: SAMEORIGIN
Referrer-Policy: no-referrer-when-downgrade
X-XSS-Protection: 1; mode=block
Access-Control-Allow-Origin: *
Set-Cookie: PHPSESSID=8f3c2a; path=/
Set-Cookie: prefs=dark; Secure; SameSite=Lax`;
  const SEVK = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info", ok: "ok" };

  W.tool("naginata", "headers", {
    name: "Headers", order: 40,
    desc: "Review pasted HTTP response headers — CSP, HSTS, framing, CORS, cookies, disclosure — with an A–F grade and fixes.",
    icon: '<path d="M4 5h16M4 10h10M4 15h13M4 20h7"/><path d="M18 14l2 2 3-4" transform="translate(-2 2)"/>',
    render(el, arg) {
      W.roeGate(el, () => {
        el.innerHTML = ui.head("Headers", "Security-header review", "Paste the response headers of a site you're assessing (<code>curl -sI https://…</code>, DevTools → Network → Response headers, or Burp). If a redirect chain is pasted, the last response is graded. Nothing is fetched.") + `
          <div class="panel">
            <textarea id="hd-in" rows="9" spellcheck="false" autocapitalize="off" placeholder="HTTP/2 200&#10;content-security-policy: default-src 'self'&#10;strict-transport-security: max-age=31536000; includeSubDomains&#10;…"></textarea>
            <div class="spacer"></div>
            <div class="row"><button class="btn pri" id="hd-go">${W.icon(W.I.search)} Analyse</button>
              <button class="btn ghost" id="hd-sample">Sample</button>
              <label class="check"><input type="checkbox" id="hd-https" checked> served over HTTPS</label>
              <input id="hd-label" type="text" style="flex:1;min-width:160px;max-width:320px" placeholder="Label (e.g. https://app.example.com)" aria-label="Label for the report"></div>
          </div>
          <div id="hd-out"></div>`;
        const ta = $("#hd-in");
        ta.value = typeof arg === "string" && arg ? arg : W.store.get(K("last"), "");
        $("#hd-label").value = W.store.get(K("label"), "");
        $("#hd-https").checked = W.store.get(K("https"), true);
        $("#hd-sample").onclick = () => { ta.value = SAMPLE; $("#hd-label").value = "sample"; run(); };
        $("#hd-go").onclick = () => { if (!ta.value.trim()) return W.toast("Paste some response headers first", 1); run(); };
        $("#hd-https").onchange = () => { W.store.set(K("https"), $("#hd-https").checked); if (ta.value.trim()) run(); };
        let res, filter = "issues";

        function run() {
          W.store.set(K("last"), ta.value.slice(0, 64000)); W.store.set(K("label"), $("#hd-label").value);
          res = W.eng.headers.analyse(ta.value, { https: $("#hd-https").checked });
          if (res.empty) { $("#hd-out").innerHTML = ui.panel("", ui.empty("NO HEADERS FOUND", "Expected lines like “Name: value”.")); return; }
          const c = res.counts, issues = res.findings.filter((f) => f.sev !== "ok" && f.sev !== "info").length;
          $("#hd-out").innerHTML = `<div class="panel"><div class="ng-score">
              <div class="ng-grade g-${res.grade}" aria-label="Grade ${res.grade}">${res.grade}</div>
              <div class="col"><b>Score ${res.score}/100</b><span class="small muted">${res.status ? esc(res.status) + " · " : ""}${res.order.length} header(s)${res.blocks > 1 ? ` · last of ${res.blocks} responses` : ""}</span>
                <div class="row">${["critical", "high", "medium", "low", "info", "ok"].filter((s) => c[s]).map((s) => ui.badge(`${c[s]} ${s === "ok" ? "passing" : s}`, SEVK[s])).join("")}</div></div>
              <div class="row"><button class="btn sm" id="hd-md">${W.icon(W.I.copy)} Copy Markdown</button><button class="btn sm" id="hd-rep">${W.icon(W.I.plus)} Send to report</button></div>
            </div></div>
            <div class="tabs" id="hd-tabs"><button data-tab="issues" class="${filter === "issues" ? "on" : ""}">Issues (${issues})</button><button data-tab="all" class="${filter === "all" ? "on" : ""}">All checks (${res.findings.length})</button><button data-tab="csp" class="${filter === "csp" ? "on" : ""}">CSP</button><button data-tab="cookies" class="${filter === "cookies" ? "on" : ""}">Cookies (${res.cookies.length})</button><button data-tab="raw" class="${filter === "raw" ? "on" : ""}">Parsed headers</button></div>
            <div id="hd-body"></div>`;
          W.tabs($("#hd-tabs"), (t) => { filter = t; body(); });
          $("#hd-md").onclick = () => W.copy(W.eng.headers.toMarkdown(res, $("#hd-label").value.trim()), "Markdown copied");
          $("#hd-rep").onclick = () => {
            const bad = res.findings.filter((f) => !["ok", "info"].includes(f.sev));
            const top = bad[0] ? bad[0].sev : "info";
            W.go("naginata", "report", {
              title: "Missing or weak HTTP security headers", severity: top === "critical" ? "high" : top,
              assets: $("#hd-label").value.trim(), description: `The HTTP response headers were reviewed and graded ${res.grade} (${res.score}/100). ${bad.length} issue(s) were identified.`,
              evidence: bad.map((f) => `[${f.sev.toUpperCase()}] ${f.title}`).join("\n"),
              remediation: W.uniq(bad.map((f) => f.fix).filter(Boolean)).map((f) => "- " + f).join("\n"),
              references: "https://owasp.org/www-project-secure-headers/\nhttps://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            });
          };
          body();
        }
        function body() {
          const b = $("#hd-body");
          if (filter === "issues" || filter === "all") {
            const list = filter === "issues" ? res.findings.filter((f) => f.sev !== "ok" && f.sev !== "info") : res.findings;
            b.innerHTML = list.length ? list.map(fHtml).join("") : ui.panel("", ui.empty("NO ISSUES", "Nothing above informational — check the All tab for details."));
          } else if (filter === "csp") {
            const csp = res.csp;
            if (!csp) { b.innerHTML = ui.panel("", ui.empty("NO CSP", "No Content-Security-Policy (or report-only) header in the response.")); return; }
            b.innerHTML = (csp.reportOnly ? `<div class="callout warn">Report-only policy — browsers log violations but enforce nothing.</div><div class="spacer"></div>` : "")
              + ui.table(["Directive", "Sources"], csp.order.map((n) => [`<span class="mono">${esc(n)}</span>`, csp.directives[n].length ? csp.directives[n].map((s) => `<span class="chip${/unsafe|^\*$|^(https?|data):$/i.test(s) ? " c-crit" : ""}">${esc(s)}</span>`).join("") : '<span class="faint">(no value)</span>']), { raw: true })
              + `<div class="spacer"></div>` + res.findings.filter((f) => /^Content-Security-Policy/.test(f.header)).map(fHtml).join("");
          } else if (filter === "cookies") {
            b.innerHTML = res.cookies.length ? ui.table(["Cookie", "Secure", "HttpOnly", "SameSite", "Path / Domain", "Issues"], res.cookies.map((c) => [
              `<span class="mono break">${esc(c.name || "(unnamed)")}</span>`, yn(c.attrs.secure), yn(c.attrs.httponly), c.attrs.samesite ? esc(c.attrs.samesite) : '<span class="c-med">—</span>',
              `<span class="mono">${esc(c.attrs.path || "")}${c.attrs.domain ? " · " + esc(c.attrs.domain) : ""}</span>`,
              c.issues.map((i) => ui.badge(i.title, SEVK[i.sev])).join(" ")]), { raw: true }) : ui.panel("", ui.empty("NO COOKIES", "No Set-Cookie headers in this response."));
          } else {
            b.innerHTML = ui.table(["Header", "Value"], res.order.flatMap((k) => res.headers[k].map((v) => [`<span class="mono">${esc(k)}</span>`, `<span class="mono break">${esc(v)}</span>`])), { raw: true });
          }
        }
        const yn = (v) => (v ? '<span class="c-ok">yes</span>' : '<span class="c-crit">no</span>');
        const fHtml = (f) => `<div class="finding ${SEVK[f.sev]}"><header>${ui.sev(SEVK[f.sev])}<h3>${esc(f.title)}</h3><span class="tiny faint mono">${esc(f.header)}</span></header>
          ${f.detail ? `<div class="det break-word">${esc(f.detail)}</div>` : ""}${f.fix ? `<div class="det"><b class="c-acc">Fix:</b> <span class="mono">${esc(f.fix)}</span></div>` : ""}</div>`;
        if (ta.value.trim()) run();
      });
    },
  });
})();
