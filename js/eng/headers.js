/* Security-header review engine. Paste raw HTTP response headers (curl -I / DevTools / Burp) → findings + A–F grade.
 *   parse(text)            → {status, headers: Map-like {name: [values]}, order, blocks}
 *   parseCSP(value)        → {directives: {name: [sources]}, order, dupes}
 *   parseCookie(line)      → {name, value, attrs}
 *   analyse(text, {https}) → {grade, score, findings[], csp, cookies[], headers}
 * Severity weights drive the score: critical 30, high 20, medium 10, low 4, info/ok 0. */
(function (W) {
  "use strict";
  const WEIGHT = { critical: 30, high: 20, medium: 10, low: 4, info: 0, ok: 0 };
  const GRADES = [[90, "A"], [75, "B"], [60, "C"], [45, "D"], [0, "F"]];

  // ------------------------------------------------------------------ parsing
  /** Parse raw headers. If several responses are pasted (redirect chain), the LAST one is analysed. */
  function parse(text) {
    const lines = String(text == null ? "" : text).replace(/\r/g, "").split("\n");
    const blocks = []; let cur = null;
    const start = () => { cur = { status: null, headers: {}, order: [] }; blocks.push(cur); };
    for (let raw of lines) {
      if (/^[>*}{] ?/.test(raw)) continue;                                 // curl -v: request lines + info
      const line = raw.replace(/^< ?/, "");                                 // curl -v response prefix
      if (/^HTTP\/\d(\.\d)?\s+\d{3}/i.test(line.trim())) { start(); cur.status = line.trim(); continue; }
      if (!line.trim()) continue;
      if (/^\s/.test(line) && cur && cur.order.length) {                    // obsolete line folding
        const k = cur.order[cur.order.length - 1], a = cur.headers[k]; a[a.length - 1] += " " + line.trim(); continue;
      }
      const m = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+)\s*:\s?(.*)$/.exec(line.trim());
      if (!m) continue;
      if (!cur) start();
      const k = m[1].toLowerCase();
      if (!cur.headers[k]) { cur.headers[k] = []; cur.order.push(k); }
      cur.headers[k].push(m[2].trim());
    }
    const last = blocks.filter((b) => b.order.length).pop() || { status: null, headers: {}, order: [] };
    return { status: last.status, headers: last.headers, order: last.order, blocks: blocks.length };
  }
  const one = (h, k) => (h[k] ? h[k].join(", ") : null);

  function parseCSP(value) {
    const directives = {}, order = [], dupes = [];
    for (const part of String(value || "").split(";")) {
      const toks = part.trim().split(/\s+/).filter(Boolean);
      if (!toks.length) continue;
      const name = toks[0].toLowerCase();
      if (name in directives) { dupes.push(name); continue; }            // browsers ignore repeats
      directives[name] = toks.slice(1);
      order.push(name);
    }
    return { directives, order, dupes };
  }
  function parseCookie(line) {
    const parts = String(line).split(";").map((s) => s.trim());
    const nv = parts.shift() || "", eq = nv.indexOf("=");
    const attrs = {};
    for (const p of parts) { if (!p) continue; const i = p.indexOf("="); attrs[(i < 0 ? p : p.slice(0, i)).trim().toLowerCase()] = i < 0 ? true : p.slice(i + 1).trim(); }
    return { name: eq < 0 ? "" : nv.slice(0, eq).trim(), value: eq < 0 ? nv : nv.slice(eq + 1).trim(), attrs, raw: line };
  }

  // ------------------------------------------------------------------ CSP evaluation
  const FETCH_FALLBACK = { "script-src-elem": "script-src", "script-src-attr": "script-src", "style-src-elem": "style-src", "style-src-attr": "style-src", "worker-src": "script-src" };
  const KNOWN_DIRECTIVES = ["default-src", "script-src", "script-src-elem", "script-src-attr", "style-src", "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src",
    "media-src", "object-src", "frame-src", "child-src", "worker-src", "manifest-src", "base-uri", "form-action", "frame-ancestors", "sandbox", "report-uri", "report-to",
    "upgrade-insecure-requests", "require-trusted-types-for", "trusted-types", "fenced-frame-src", "webrtc"];
  const DEPRECATED = { "block-all-mixed-content": "superseded by upgrade-insecure-requests", "plugin-types": "removed from CSP3", "referrer": "use the Referrer-Policy header", "reflected-xss": "removed", "prefetch-src": "removed from CSP3", "navigate-to": "never shipped", "require-sri-for": "never shipped" };
  function effective(d, name) {
    if (d[name]) return { from: name, list: d[name] };
    if (FETCH_FALLBACK[name] && d[FETCH_FALLBACK[name]]) return { from: FETCH_FALLBACK[name], list: d[FETCH_FALLBACK[name]] };
    if (name !== "base-uri" && name !== "form-action" && name !== "frame-ancestors" && d["default-src"]) return { from: "default-src", list: d["default-src"] };
    return null;
  }
  const isNonceHash = (s) => /^'(nonce-|sha(256|384|512)-)/i.test(s);
  const lc = (a) => a.map((s) => s.toLowerCase());

  function evalCSP(value, F, reportOnly) {
    const csp = parseCSP(value), d = csp.directives;
    const tag = reportOnly ? " (report-only)" : "";
    const H = reportOnly ? "Content-Security-Policy-Report-Only" : "Content-Security-Policy";
    const add = (sev, title, detail, fix, id) => F.push({ header: H, sev: reportOnly && sev !== "ok" && sev !== "info" ? "info" : sev, title: title + tag, detail, fix, id });
    for (const n of csp.dupes) add("low", `Duplicate directive ${n}`, `The second ${n} is ignored by browsers.`, `Merge the ${n} values into one directive.`, "csp-dupe");
    for (const n of csp.order) {
      if (DEPRECATED[n]) add("info", `Deprecated directive ${n}`, DEPRECATED[n] + ".", `Remove ${n}.`, "csp-deprecated");
      else if (!KNOWN_DIRECTIVES.includes(n)) add("info", `Unknown directive ${n}`, "Browsers ignore directives they don't recognise — check the spelling.", "Fix or remove it.", "csp-unknown");
    }
    // ---- scripts
    const sc = effective(d, "script-src");
    if (!sc) add("high", "No script-src or default-src", "Scripts can load from anywhere, so the policy gives no XSS protection.", "Add script-src 'self' (ideally with nonces or hashes and 'strict-dynamic') or default-src 'self'.", "csp-no-script");
    else {
      const s = lc(sc.list), nh = sc.list.some(isNonceHash), sd = s.includes("'strict-dynamic'");
      if (s.includes("'unsafe-inline'") && !nh) add("high", `'unsafe-inline' in ${sc.from}`, "Inline scripts and event handlers run, which defeats CSP's XSS protection.", "Remove 'unsafe-inline'; move inline code to files or allow it with nonces/hashes.", "csp-unsafe-inline");
      else if (s.includes("'unsafe-inline'")) add("info", `'unsafe-inline' alongside nonces/hashes in ${sc.from}`, "CSP2+ browsers ignore 'unsafe-inline' when a nonce or hash is present (it's a fallback for old browsers).", "Fine as a backwards-compat fallback.", "csp-unsafe-inline-fallback");
      if (s.includes("'unsafe-eval'")) add("medium", `'unsafe-eval' in ${sc.from}`, "eval(), new Function() and string timers are allowed, widening DOM-XSS sinks.", "Remove 'unsafe-eval' and refactor code that needs it ('wasm-unsafe-eval' is fine for WebAssembly).", "csp-unsafe-eval");
      if (!sd) {
        const wild = sc.list.filter((x) => x === "*" || /^(https?|data|blob|filesystem):$/i.test(x));
        if (wild.length) add("high", `Wildcard script sources in ${sc.from}: ${wild.join(" ")}`, "Any site (or any data: URL) can serve scripts, so an attacker can host their own.", `Replace ${wild.join(" ")} with specific origins, nonces or hashes.`, "csp-wild-script");
        const sub = sc.list.filter((x) => /^(https?:\/\/)?\*\./i.test(x));
        if (sub.length) add("low", `Wildcard sub-domain script sources: ${sub.join(" ")}`, "Any sub-domain (including user-content or abandoned ones) can serve scripts.", "List the exact hosts you load scripts from.", "csp-subdomain-script");
        const http = sc.list.filter((x) => /^http:\/\//i.test(x));
        if (http.length) add("medium", `Insecure http: script sources: ${http.join(" ")}`, "Scripts over plain HTTP can be modified in transit.", "Load scripts over https only.", "csp-http-script");
        const cdns = sc.list.filter((x) => /(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|ajax\.googleapis\.com|raw\.githubusercontent\.com|storage\.googleapis\.com|\.s3\.amazonaws\.com)/i.test(x));
        if (cdns.length) add("low", `Public CDN allow-listed for scripts: ${cdns.join(" ")}`, "Public CDNs host thousands of libraries, some with known CSP bypass gadgets (e.g. old AngularJS, JSONP endpoints).", "Prefer nonces/hashes with 'strict-dynamic', or pin exact paths.", "csp-cdn");
      } else add("ok", `'strict-dynamic' with ${nh ? "nonces/hashes" : "no nonce or hash"} in ${sc.from}`, nh ? "A strict CSP — host allow-lists are ignored by modern browsers." : "'strict-dynamic' needs a nonce or hash to have any effect.", nh ? "" : "Add a per-response nonce.", "csp-strict");
      if (!s.includes("'unsafe-inline'") && !s.includes("'unsafe-eval'") && !sd && !sc.list.some((x) => x === "*" || /^(https?|data):$/i.test(x)))
        add("ok", `Scripts restricted by ${sc.from}`, sc.list.join(" ") || "(none)", "", "csp-script-ok");
    }
    // ---- objects / base / framing / forms / styles
    const ob = effective(d, "object-src");
    if (!ob || !lc(ob.list).includes("'none'")) add("medium", "object-src is not 'none'", "Plugins (<object>/<embed>) can load content that bypasses script-src in some browsers.", "Add object-src 'none'.", "csp-object");
    if (!d["base-uri"]) add("medium", "Missing base-uri", "An injected <base> tag can redirect every relative script URL to an attacker's host (bypasses nonce-based CSP).", "Add base-uri 'none' (or 'self').", "csp-base");
    else if (lc(d["base-uri"]).some((x) => x === "*" || /^https?:$/.test(x))) add("medium", "base-uri allows any origin", "", "Set base-uri 'none' or 'self'.", "csp-base");
    if (!d["frame-ancestors"]) add(F.__xfo ? "low" : "medium", "Missing frame-ancestors", F.__xfo ? "X-Frame-Options gives legacy protection, but frame-ancestors is the standard control." : "The page can be framed by any site (clickjacking).", "Add frame-ancestors 'none' (or 'self').", "csp-frame");
    else if (lc(d["frame-ancestors"]).some((x) => x === "*" || /^https?:$/.test(x))) add("medium", "frame-ancestors allows any origin", "Any site can frame this page (clickjacking).", "Restrict frame-ancestors to 'none', 'self' or specific origins.", "csp-frame");
    if (!d["form-action"]) add("low", "Missing form-action", "Injected forms can post data to other origins (default-src does not cover form-action).", "Add form-action 'self'.", "csp-form");
    const st = effective(d, "style-src");
    if (st && lc(st.list).includes("'unsafe-inline'") && !st.list.some(isNonceHash)) add("low", `'unsafe-inline' in ${st.from} for styles`, "Inline styles allow CSS injection (UI redress, attribute exfiltration).", "Use nonces/hashes for styles where practical.", "csp-style-inline");
    for (const [n, list] of Object.entries(d)) {
      if (/^(script|object|base|frame-anc)/.test(n)) continue;
      if (list.includes("*") && !/^(img|media|font)-src$/.test(n)) add("low", `Wildcard * in ${n}`, `${n} accepts any origin.`, `Restrict ${n} to the origins you use.`, "csp-wild");
    }
    if (!d["report-uri"] && !d["report-to"]) add("info", "No CSP reporting", "Violations aren't reported, so breakage and attacks go unseen.", "Add report-to (with a Reporting-Endpoints header) or report-uri.", "csp-report");
    if (d["require-trusted-types-for"]) add("ok", "Trusted Types enforced", "DOM-XSS sinks only accept Trusted Types.", "", "csp-tt");
    return csp;
  }

  // ------------------------------------------------------------------ main analysis
  function analyse(text, opts = {}) {
    const https = opts.https !== false;
    const p = parse(text), h = p.headers, F = [];
    const add = (header, sev, title, detail, fix, id) => F.push({ header, sev, title, detail: detail || "", fix: fix || "", id: id || "" });
    if (!p.order.length) return { grade: "—", score: 0, findings: [], csp: null, cookies: [], headers: h, status: p.status, empty: true };

    F.__xfo = !!h["x-frame-options"];
    // ---- CSP
    let csp = null;
    if (h["content-security-policy"]) {
      if (h["content-security-policy"].length > 1) add("Content-Security-Policy", "info", "Multiple CSP headers", "Every policy is enforced; a resource must satisfy all of them. Only the first is analysed in detail.", "Merge into one policy unless the layering is deliberate.", "csp-multi");
      csp = evalCSP(h["content-security-policy"][0], F, false);
    } else {
      add("Content-Security-Policy", "high", "No Content-Security-Policy", "Without CSP there is no browser-side mitigation for XSS or clickjacking via frame-ancestors.", "Start with: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' — then tighten script-src with nonces.", "csp-missing");
      if (h["content-security-policy-report-only"]) add("Content-Security-Policy-Report-Only", "info", "CSP is report-only", "The report-only policy is analysed below but nothing is enforced yet.", "Promote it to Content-Security-Policy once violations are resolved.", "csp-ro");
    }
    if (h["content-security-policy-report-only"]) { const ro = evalCSP(h["content-security-policy-report-only"][0], F, true); csp = csp || Object.assign(ro, { reportOnly: true }); }
    if (h["x-content-security-policy"] || h["x-webkit-csp"]) add("X-Content-Security-Policy", "info", "Legacy X-Content-Security-Policy / X-WebKit-CSP", "Prefixed CSP headers are obsolete.", "Remove them and use Content-Security-Policy.", "csp-legacy");
    delete F.__xfo;

    // ---- HSTS
    const hsts = one(h, "strict-transport-security");
    if (!https) add("Strict-Transport-Security", "high", "Site served over plain HTTP", "Traffic can be read and modified in transit; HSTS only works over HTTPS.", "Serve the site over HTTPS, redirect HTTP→HTTPS and then add HSTS.", "http");
    else if (!hsts) add("Strict-Transport-Security", "high", "No Strict-Transport-Security", "Users can be downgraded to HTTP (SSL-stripping) on first visit or via typed http:// links.", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", "hsts-missing");
    else {
      const v = h["strict-transport-security"][0];
      const ma = /max-age\s*=\s*"?(\d+)"?/i.exec(v), age = ma ? +ma[1] : null;
      const sub = /includesubdomains/i.test(v), pre = /\bpreload\b/i.test(v);
      if (age == null) add("Strict-Transport-Security", "high", "HSTS without max-age", "Browsers ignore an HSTS header with no max-age.", "Add max-age=31536000.", "hsts-noage");
      else if (age === 0) add("Strict-Transport-Security", "high", "HSTS max-age=0", "max-age=0 tells browsers to forget HSTS for this host.", "Set max-age=31536000.", "hsts-zero");
      else if (age < 15768000) add("Strict-Transport-Security", "medium", `HSTS max-age is short (${fmtSecs(age)})`, "A short max-age leaves long gaps where users can be downgraded.", "Use max-age=31536000 (1 year) or more.", "hsts-short");
      else if (age < 31536000) add("Strict-Transport-Security", "low", `HSTS max-age under a year (${fmtSecs(age)})`, "", "Use max-age=31536000 (required for preload).", "hsts-short");
      else add("Strict-Transport-Security", "ok", `HSTS max-age ${fmtSecs(age)}`, v, "", "hsts-ok");
      if (age && !sub) add("Strict-Transport-Security", "low", "HSTS without includeSubDomains", "Sub-domains (and cookies scoped to the parent domain) can still be reached over HTTP.", "Add includeSubDomains once every sub-domain serves HTTPS.", "hsts-sub");
      if (pre && (!sub || (age || 0) < 31536000)) add("Strict-Transport-Security", "low", "preload requested but not eligible", "Preload lists need max-age ≥ 31536000 and includeSubDomains.", "Fix max-age/includeSubDomains or drop preload.", "hsts-preload");
      if (h["strict-transport-security"].length > 1) add("Strict-Transport-Security", "low", "Multiple HSTS headers", "Browsers only process the first one.", "Send exactly one.", "hsts-multi");
    }

    // ---- framing
    const xfo = one(h, "x-frame-options"), fa = csp && !csp.reportOnly && csp.directives["frame-ancestors"];
    if (xfo) {
      const v = xfo.toUpperCase().split(",")[0].trim();
      if (v === "DENY" || v === "SAMEORIGIN") add("X-Frame-Options", "ok", `X-Frame-Options: ${v}`, fa ? "frame-ancestors takes precedence in modern browsers." : "", "", "xfo-ok");
      else if (v.startsWith("ALLOW-FROM")) add("X-Frame-Options", fa ? "low" : "medium", "X-Frame-Options ALLOW-FROM is unsupported", "Modern browsers ignore ALLOW-FROM, so the page is frameable.", "Use CSP frame-ancestors with the allowed origin.", "xfo-allowfrom");
      else add("X-Frame-Options", fa ? "low" : "medium", `Invalid X-Frame-Options value “${xfo}”`, "Browsers ignore unknown values.", "Use DENY or SAMEORIGIN.", "xfo-bad");
    } else if (!fa) add("X-Frame-Options", "medium", "No clickjacking protection", "Neither X-Frame-Options nor CSP frame-ancestors is set, so any site can frame the page.", "Add Content-Security-Policy: frame-ancestors 'none' (and X-Frame-Options: DENY for old browsers).", "xfo-missing");

    // ---- nosniff
    const xcto = one(h, "x-content-type-options");
    if (!xcto) add("X-Content-Type-Options", "low", "No X-Content-Type-Options", "Browsers may MIME-sniff responses (e.g. treat an upload as script or HTML).", "Add: X-Content-Type-Options: nosniff", "xcto-missing");
    else if (xcto.toLowerCase().trim() !== "nosniff") add("X-Content-Type-Options", "low", `Invalid X-Content-Type-Options “${xcto}”`, "The only valid value is nosniff.", "Set X-Content-Type-Options: nosniff", "xcto-bad");
    else add("X-Content-Type-Options", "ok", "X-Content-Type-Options: nosniff", "", "", "xcto-ok");

    // ---- referrer
    const rp = one(h, "referrer-policy");
    const RP_OK = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
    const RP_ALL = RP_OK.concat(["origin", "origin-when-cross-origin", "no-referrer-when-downgrade", "unsafe-url"]);
    if (!rp) add("Referrer-Policy", "low", "No Referrer-Policy", "Browsers default to strict-origin-when-cross-origin, but older ones leak full URLs (with tokens in query strings) to other sites.", "Add: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).", "rp-missing");
    else {
      const vals = rp.toLowerCase().split(",").map((s) => s.trim()).filter((s) => RP_ALL.includes(s));
      const eff = vals[vals.length - 1];                                   // last recognised value wins
      if (!eff) add("Referrer-Policy", "low", `Unrecognised Referrer-Policy “${rp}”`, "", "Use strict-origin-when-cross-origin or no-referrer.", "rp-bad");
      else if (eff === "unsafe-url") add("Referrer-Policy", "medium", "Referrer-Policy: unsafe-url", "Full URLs (path + query) are sent to every site, even over HTTP.", "Use strict-origin-when-cross-origin or no-referrer.", "rp-unsafe");
      else if (!RP_OK.includes(eff)) add("Referrer-Policy", "low", `Referrer-Policy: ${eff}`, eff === "no-referrer-when-downgrade" ? "Full URLs are sent cross-origin over HTTPS." : "Origin leaks cross-origin, and over HTTP for origin*.", "Use strict-origin-when-cross-origin or no-referrer.", "rp-weak");
      else add("Referrer-Policy", "ok", `Referrer-Policy: ${eff}`, "", "", "rp-ok");
    }

    // ---- permissions policy
    const pp = one(h, "permissions-policy");
    if (!pp) {
      if (h["feature-policy"]) add("Permissions-Policy", "low", "Only the legacy Feature-Policy header", "Feature-Policy is superseded and ignored by current browsers.", "Replace with Permissions-Policy, e.g. camera=(), microphone=(), geolocation=().", "pp-legacy");
      else add("Permissions-Policy", "low", "No Permissions-Policy", "Powerful features (camera, microphone, geolocation…) follow browser defaults, including for embedded third-party frames.", "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()", "pp-missing");
    } else {
      const wide = [];
      for (const part of pp.split(",")) {
        const m = /^\s*([a-z0-9-]+)\s*=\s*(.*)$/i.exec(part); if (!m) continue;
        if (/^\*$|\(\s*\*\s*\)/.test(m[2].trim()) && /^(camera|microphone|geolocation|usb|payment|serial|hid|bluetooth|display-capture|screen-wake-lock|clipboard-read)$/i.test(m[1])) wide.push(m[1]);
      }
      if (wide.length) add("Permissions-Policy", "low", `Sensitive features allowed for every origin: ${wide.join(", ")}`, "Any embedded frame can request these features.", `Restrict them, e.g. ${wide[0]}=(self).`, "pp-wide");
      else add("Permissions-Policy", "ok", "Permissions-Policy set", pp.length > 140 ? pp.slice(0, 140) + "…" : pp, "", "pp-ok");
    }

    // ---- cross-origin isolation family
    const coop = one(h, "cross-origin-opener-policy"), coep = one(h, "cross-origin-embedder-policy"), corp = one(h, "cross-origin-resource-policy");
    if (!coop) add("Cross-Origin-Opener-Policy", "low", "No Cross-Origin-Opener-Policy", "Cross-origin windows you open (or that open you) keep a reference to this window — enables XS-Leaks and tab-nabbing style attacks.", "Add: Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if you rely on OAuth/payment pop-ups).", "coop-missing");
    else if (/unsafe-none/i.test(coop)) add("Cross-Origin-Opener-Policy", "low", "COOP: unsafe-none", "Equivalent to not setting COOP.", "Use same-origin or same-origin-allow-popups.", "coop-none");
    else add("Cross-Origin-Opener-Policy", "ok", `COOP: ${coop}`, "", "", "coop-ok");
    if (!corp) add("Cross-Origin-Resource-Policy", "info", "No Cross-Origin-Resource-Policy", "Other sites can embed this response (relevant for APIs and private images).", "Add Cross-Origin-Resource-Policy: same-origin (or same-site) on non-public resources.", "corp-missing");
    else if (/cross-origin/i.test(corp)) add("Cross-Origin-Resource-Policy", "info", "CORP: cross-origin", "Explicitly embeddable by anyone — fine for public assets.", "", "corp-cross");
    else add("Cross-Origin-Resource-Policy", "ok", `CORP: ${corp}`, "", "", "corp-ok");
    if (coep) add("Cross-Origin-Embedder-Policy", /require-corp|credentialless/i.test(coep) ? "ok" : "info", `COEP: ${coep}`, /require-corp|credentialless/i.test(coep) && coop && /^same-origin$/i.test(coop.trim()) ? "Cross-origin isolated (COOP same-origin + COEP)." : "", "", "coep");

    // ---- CORS
    const acao = one(h, "access-control-allow-origin"), acac = (one(h, "access-control-allow-credentials") || "").trim().toLowerCase() === "true";
    if (acao) {
      const v = acao.trim();
      if (h["access-control-allow-origin"].length > 1 || /,/.test(v) && v !== "*") add("Access-Control-Allow-Origin", "medium", "Multiple Access-Control-Allow-Origin values", "Browsers reject a list of origins; this usually means the header is added twice (proxy + app).", "Send exactly one origin (validated against an allow-list) or *.", "cors-multi");
      else if (v === "*" && acac) add("Access-Control-Allow-Origin", "high", "CORS: wildcard origin with credentials", "Browsers refuse this combination, but it shows intent to share credentialed responses with any site — often 'fixed' by reflecting the Origin header, which is exploitable.", "Allow-list specific origins; never reflect Origin when credentials are allowed.", "cors-wild-cred");
      else if (v === "*") add("Access-Control-Allow-Origin", "info", "CORS: Access-Control-Allow-Origin: *", "Any site can read this response (without cookies). Fine for genuinely public data, a leak for anything else.", "Restrict to known origins if the response isn't public.", "cors-wild");
      else if (v.toLowerCase() === "null") add("Access-Control-Allow-Origin", "high", "CORS: Access-Control-Allow-Origin: null", "Sandboxed iframes and data:/file: documents send Origin: null, so any attacker page can match it.", "Never allow the null origin.", "cors-null");
      else {
        if (/^http:\/\//i.test(v) && https) add("Access-Control-Allow-Origin", "medium", `CORS trusts an http:// origin (${v})`, "A network attacker can inject script into that origin and read responses.", "Only trust https:// origins.", "cors-http");
        if (acac) add("Access-Control-Allow-Origin", "info", `CORS with credentials for ${v}`, "Can't tell from one response whether the origin is allow-listed or reflected from the request.", "Re-test with a different Origin header (on an in-scope host) and confirm it isn't echoed back.", "cors-cred");
        if (!/\borigin\b/i.test(one(h, "vary") || "")) add("Vary", "low", "CORS origin without Vary: Origin", "Caches may serve one origin's CORS response to another.", "Add Vary: Origin.", "cors-vary");
      }
      const meth = one(h, "access-control-allow-methods"), hdrs = one(h, "access-control-allow-headers");
      if (meth && /\*/.test(meth) && acac) add("Access-Control-Allow-Methods", "low", "CORS allows every method", "", "List only the methods the API needs.", "cors-methods");
      if (hdrs && /\*/.test(hdrs) && acac) add("Access-Control-Allow-Headers", "low", "CORS allows every request header", "", "List only the headers the API needs.", "cors-headers");
    }

    // ---- information disclosure
    const DISC = [["server", "Server"], ["x-powered-by", "X-Powered-By"], ["x-aspnet-version", "X-AspNet-Version"], ["x-aspnetmvc-version", "X-AspNetMvc-Version"],
      ["x-generator", "X-Generator"], ["x-drupal-cache", "X-Drupal-Cache"], ["x-drupal-dynamic-cache", "X-Drupal-Dynamic-Cache"], ["x-runtime", "X-Runtime"], ["x-version", "X-Version"],
      ["x-backend-server", "X-Backend-Server"], ["x-server", "X-Server"], ["via", "Via"], ["x-debug-token", "X-Debug-Token"], ["x-debug-token-link", "X-Debug-Token-Link"]];
    for (const [k, name] of DISC) {
      const v = one(h, k); if (!v) continue;
      const ver = /\d+\.\d+/.test(v);
      if (k === "server") { if (ver) add(name, "low", `Server version disclosed: ${v}`, "Exact versions make it trivial to match known CVEs.", "Strip the version (e.g. nginx server_tokens off; Apache ServerTokens Prod).", "disc-server"); else add(name, "info", `Server: ${v}`, "Product name only — low value to an attacker.", "Optionally remove it.", "disc-server"); continue; }
      if (k === "via" && !ver) continue;
      if (/debug/.test(k)) { add(name, "medium", `Debug header present: ${name}`, "Debug toolbars/profilers in production can expose internals.", "Disable debug mode in production.", "disc-debug"); continue; }
      add(name, "low", `${name} disclosed${v.length < 60 ? ": " + v : ""}`, "Reveals the technology stack" + (ver ? " and version." : "."), `Remove the ${name} header.`, "disc-" + k);
    }
    // ---- legacy XSS auditor
    const xxp = one(h, "x-xss-protection");
    if (xxp && !/^\s*0\s*$/.test(xxp)) add("X-XSS-Protection", "info", `X-XSS-Protection: ${xxp}`, "The XSS auditor was removed from browsers; where it existed, mode=block could itself be abused for XS-Leaks.", "Set X-XSS-Protection: 0 (or remove it) and rely on CSP.", "xxp");

    // ---- caching of authenticated responses
    const cc = (one(h, "cache-control") || "").toLowerCase();
    if (h["set-cookie"] && !/no-store|private/.test(cc)) add("Cache-Control", "low", "Response sets cookies but may be cached", "Without Cache-Control: no-store/private a shared cache can store the response (and its Set-Cookie) for other users.", "Add Cache-Control: no-store on authenticated or cookie-setting responses.", "cache");

    // ---- cookies
    const cookies = (h["set-cookie"] || []).map(parseCookie).map((c) => Object.assign(c, { issues: cookieIssues(c, https) }));
    for (const c of cookies) for (const i of c.issues) add("Set-Cookie", i.sev, `Cookie ${c.name || "(unnamed)"}: ${i.title}`, i.detail, i.fix, "cookie-" + i.id);

    // ---- score
    let score = 100;
    for (const f of F) score -= WEIGHT[f.sev] || 0;
    score = Math.max(0, score);
    const grade = GRADES.find(([n]) => score >= n)[1];
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, ok: 5 };
    F.sort((a, b) => order[a.sev] - order[b.sev]);
    const counts = {}; for (const f of F) counts[f.sev] = (counts[f.sev] || 0) + 1;
    return { grade, score, findings: F, counts, csp, cookies, headers: h, order: p.order, status: p.status, blocks: p.blocks };
  }

  const SESSIONISH = /sess|sid\b|^sid|token|auth|jwt|login|remember|csrf|xsrf|^id$|user/i;
  function cookieIssues(c, https) {
    const a = c.attrs, out = [];
    const ss = typeof a.samesite === "string" ? a.samesite.toLowerCase() : null;
    const sensitive = SESSIONISH.test(c.name);
    if (!a.secure) out.push({ id: "secure", sev: https ? (sensitive ? "high" : "medium") : "medium", title: "missing Secure", detail: "The cookie is also sent over plain HTTP, where it can be intercepted.", fix: "Add the Secure attribute." });
    if (!a.httponly) out.push({ id: "httponly", sev: sensitive ? "medium" : "low", title: "missing HttpOnly", detail: sensitive ? "Looks like a session/auth cookie — readable by any XSS payload." : "Readable from JavaScript (fine only if the front end genuinely needs it).", fix: "Add HttpOnly unless client-side code must read it." });
    if (!ss) out.push({ id: "samesite", sev: "low", title: "no SameSite", detail: "Browsers default to Lax, but explicit is safer and protects older browsers against CSRF.", fix: "Add SameSite=Lax (or Strict)." });
    else if (ss === "none" && !a.secure) out.push({ id: "samesite-none", sev: "medium", title: "SameSite=None without Secure", detail: "Browsers reject SameSite=None cookies that aren't Secure.", fix: "Add Secure, or use SameSite=Lax." });
    else if (ss === "none") out.push({ id: "samesite-none", sev: sensitive ? "low" : "info", title: "SameSite=None", detail: "Sent on all cross-site requests — needs separate CSRF protection.", fix: "Use Lax/Strict unless cross-site use is required." });
    else if (!["lax", "strict"].includes(ss)) out.push({ id: "samesite-bad", sev: "low", title: `invalid SameSite=${a.samesite}`, detail: "Unknown values are treated as unset.", fix: "Use Lax, Strict or None." });
    if (/^__host-/i.test(c.name)) {
      const bad = [];
      if (!a.secure) bad.push("Secure"); if (a.path !== "/") bad.push("Path=/"); if (a.domain) bad.push("no Domain");
      if (bad.length) out.push({ id: "host-prefix", sev: "medium", title: "__Host- prefix rules broken", detail: `__Host- cookies need ${bad.join(", ")} — browsers will reject this cookie.`, fix: "Set Secure; Path=/ and remove Domain." });
    } else if (/^__secure-/i.test(c.name) && !a.secure) out.push({ id: "secure-prefix", sev: "medium", title: "__Secure- prefix without Secure", detail: "Browsers reject it.", fix: "Add Secure." });
    else if (sensitive && a.secure && !a.domain && a.path === "/") out.push({ id: "prefix", sev: "info", title: "could use the __Host- prefix", detail: "The prefix stops sub-domains and HTTP pages from overwriting the cookie.", fix: `Rename to __Host-${c.name}.` });
    if (a.domain) out.push({ id: "domain", sev: "info", title: `scoped to Domain=${a.domain}`, detail: "Every sub-domain receives (and can overwrite) this cookie.", fix: "Omit Domain to keep it host-only, if sub-domains don't need it." });
    const exp = a.expires ? Date.parse(a.expires) : NaN, max = a["max-age"] != null ? +a["max-age"] : NaN;
    const life = !isNaN(max) ? max : !isNaN(exp) ? (exp - Date.now()) / 1000 : null;
    if (sensitive && life != null && life > 90 * 86400) out.push({ id: "lifetime", sev: "low", title: `long lifetime (${fmtSecs(life)})`, detail: "Long-lived session cookies extend the window for stolen-cookie replay.", fix: "Shorten the lifetime or use a session cookie with server-side expiry." });
    if (!out.some((x) => x.sev !== "info")) out.unshift({ id: "ok", sev: "ok", title: "Secure, HttpOnly, SameSite set", detail: "", fix: "" });
    return out;
  }
  function fmtSecs(s) {
    s = Math.round(s);
    if (s >= 86400 * 365) return (s / (86400 * 365)).toFixed(s % (86400 * 365) ? 1 : 0) + " y";
    if (s >= 86400) return Math.round(s / 86400) + " d";
    if (s >= 3600) return Math.round(s / 3600) + " h";
    return s + " s";
  }

  /** Markdown summary of an analysis. */
  function toMarkdown(r, title) {
    const lines = [`## Security headers${title ? " — " + title : ""}`, "", `**Grade ${r.grade}** (score ${r.score}/100)`, ""];
    for (const f of r.findings.filter((x) => x.sev !== "ok")) lines.push(`- **[${f.sev.toUpperCase()}] ${f.title}** (${f.header})${f.detail ? " — " + f.detail : ""}${f.fix ? `  \n  _Fix:_ ${f.fix}` : ""}`);
    const ok = r.findings.filter((x) => x.sev === "ok");
    if (ok.length) lines.push("", "Passing: " + ok.map((f) => f.title).join("; "));
    return lines.join("\n") + "\n";
  }

  W.eng.headers = { parse, parseCSP, parseCookie, analyse, cookieIssues, toMarkdown, WEIGHT, GRADES };
})(typeof window !== "undefined" ? window.W : globalThis.W);
