(function () {
  "use strict";
  const { $, esc, ui } = W;
  const K = (k) => "naginata.jwt." + k;
  const SEVK = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info", ok: "ok" };
  // Example tokens are built locally (documentation values only) so nothing here is a real credential.
  const b64u = (o) => W.b64(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const SAMPLES = {
    hs: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    weak: () => `${b64u({ alg: "none", typ: "JWT", jku: "https://keys.example.com/jwks.json", kid: "../../keys/k1" })}.${b64u({ sub: "user-42", role: "admin", email: "jane@example.com", password: "Winter2026!", iat: Math.floor(Date.now() / 1000) - 3600 })}.`,
  };

  W.tool("naginata", "jwt", {
    name: "JWT", order: 50,
    desc: "Decode a JSON Web Token, read its claims and times, flag weak configuration and verify the signature with your key.",
    icon: '<path d="M12 3v5M12 16v5M3 12h5M16 12h5M5.6 5.6l3.5 3.5M14.9 14.9l3.5 3.5M5.6 18.4l3.5-3.5M14.9 9.1l3.5-3.5"/>',
    render(el, arg) {
      W.roeGate(el, () => {
        el.innerHTML = ui.head("JWT", "Token inspector", "Decoding happens locally — tokens and keys never leave this browser. Treat tokens from an engagement as credentials: don't paste them into online decoders.") + `
          <div class="panel"><label class="lbl" for="jw-in">Token</label>
            <textarea id="jw-in" rows="4" spellcheck="false" autocapitalize="off" placeholder="eyJhbGciOi… (a leading “Bearer ” is fine)"></textarea>
            <div class="spacer"></div>
            <div class="row"><button class="btn pri" id="jw-go">${W.icon(W.I.search)} Decode</button><button class="btn ghost" id="jw-s1">HS256 example</button><button class="btn ghost" id="jw-s2">Weak example</button>
              <label class="check"><input type="checkbox" id="jw-keep"> remember token on this device</label></div>
          </div>
          <div id="jw-out"></div>`;
        const ta = $("#jw-in");
        const remember = W.store.get(K("keep"), false);
        $("#jw-keep").checked = remember;
        ta.value = typeof arg === "string" && arg ? arg : remember ? W.store.get(K("token"), "") : "";
        $("#jw-keep").onchange = () => { W.store.set(K("keep"), $("#jw-keep").checked); if (!$("#jw-keep").checked) W.store.del(K("token")); else W.store.set(K("token"), ta.value); };
        $("#jw-s1").onclick = () => { ta.value = SAMPLES.hs; run(); };
        $("#jw-s2").onclick = () => { ta.value = SAMPLES.weak(); run(); };
        $("#jw-go").onclick = () => { if (!ta.value.trim()) return W.toast("Paste a token first", 1); run(); };
        ta.addEventListener("input", W.debounce(() => { if (ta.value.trim().split(".").length >= 3) run(); }, 400));

        let d;
        function run() {
          if ($("#jw-keep").checked) W.store.set(K("token"), ta.value);
          try { d = W.eng.jwt.decode(ta.value); }
          catch (e) { $("#jw-out").innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; return; }
          const now = Date.now() / 1000;
          const F = W.eng.jwt.analyse(d, { now });
          const parts = d.parts;
          const colour = d.jwe ? `<span class="h">${esc(parts[0])}</span><i>.</i>${parts.slice(1).map((p) => `<span class="p">${esc(p)}</span>`).join("<i>.</i>")}`
            : `<span class="h">${esc(parts[0])}</span><i>.</i><span class="p">${esc(parts[1])}</span><i>.</i><span class="s">${esc(parts[2])}</span>`;
          const worst = F.find((f) => !["ok", "info"].includes(f.sev));
          const cl = d.jwe ? [] : W.eng.jwt.claims(d.payload, now);
          const val = (v) => (typeof v === "string" ? v : JSON.stringify(v));
          $("#jw-out").innerHTML = `<div class="panel"><h2>Token</h2><div class="ng-tok">${colour}</div>
              <div class="row small muted" style="margin-top:8px">${ui.badge(d.jwe ? "JWE (encrypted)" : "JWS", "acc")} ${ui.badge("alg " + (d.header.alg || "?"), /none/i.test(d.header.alg || "") ? "crit" : "")} <span>${d.size} bytes</span>
                ${worst ? ui.badge(F.filter((f) => !["ok", "info"].includes(f.sev)).length + " issue(s)", SEVK[worst.sev]) : ui.badge("no issues", "ok")}</div></div>
            <div class="grid g2">${ui.panel("Header", `<pre class="out">${esc(JSON.stringify(d.header, null, 2))}</pre>`)}
              ${ui.panel("Payload", d.jwe ? ui.empty("ENCRYPTED", "Only the recipient's key can decrypt a JWE payload.") : `<pre class="out">${esc(JSON.stringify(d.payload, null, 2))}</pre>`)}</div>
            ${cl.length ? ui.panel("Claims", ui.table(["Claim", "Meaning", "Value", "When"], cl.map((c) => [`<span class="mono">${esc(c.name)}</span>`, esc(c.label), `<span class="mono break">${esc(val(c.value).slice(0, 400))}</span>`,
              c.time ? `<span class="mono">${esc(c.iso)}</span><br><span class="small ${c.name === "exp" && c.value < now ? "c-crit" : "muted"}">${esc(c.rel)}</span>` : ""]), { raw: true })) : ""}
            ${ui.panel("Findings", F.map((f) => `<div class="finding ${SEVK[f.sev]}"><header>${ui.sev(SEVK[f.sev])}<h3>${esc(f.title)}</h3></header>${f.detail ? `<div class="det">${esc(f.detail)}</div>` : ""}${f.fix ? `<div class="det"><b class="c-acc">Fix:</b> ${esc(f.fix)}</div>` : ""}</div>`).join("") || ui.empty("NOTHING TO FLAG"))}
            ${d.jwe ? "" : ui.panel("Verify signature", `<p class="small muted" style="margin-top:0">Paste the HMAC shared secret, or the issuer's <b>public</b> key as JWK / JWKS JSON or PEM (PUBLIC KEY, RSA PUBLIC KEY or CERTIFICATE). Verification uses your browser's WebCrypto.</p>
              <textarea id="jw-key" rows="5" spellcheck="false" autocapitalize="off" placeholder="your-256-bit-secret  ·  {&quot;kty&quot;:&quot;RSA&quot;,…}  ·  -----BEGIN PUBLIC KEY-----"></textarea>
              <div class="spacer"></div>
              <div class="row"><button class="btn pri" id="jw-verify">${W.icon(W.I.check)} Verify</button>
                <label class="lbl" for="jw-enc" style="margin:0">Secret encoding</label>${ui.seg("jw-enc", [["utf8", "Text"], ["base64", "Base64"], ["hex", "Hex"]], "utf8")}</div>
              <div class="spacer"></div><div id="jw-vres"></div>`)}`;
          if (!d.jwe) {
            const enc = W.seg("jw-enc");
            W.act("#jw-verify", async () => {
              const key = $("#jw-key").value;
              if (!key.trim()) throw new Error("Paste a secret or public key");
              const box = $("#jw-vres");
              box.innerHTML = ui.loader("VERIFYING");
              try {
                const r = await W.eng.jwt.verify(d, key, { secretEncoding: enc() });
                box.innerHTML = `<div class="callout ${r.ok ? "ok" : "bad"}"><b>${r.ok ? "Signature valid" : "Signature INVALID"}</b> — ${esc(r.alg)} with ${esc(r.keyType)} ${esc(r.keyFormat)} key.${r.notes.length ? `<ul style="margin:6px 0 0;padding-left:18px">${r.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
                  ${r.ok ? "" : `<div class="small muted" style="margin-top:6px">Wrong key, wrong secret encoding, or the token was modified.</div>`}</div>`;
              } catch (e) { box.innerHTML = `<div class="callout bad">${esc(e.message)}</div>`; }
            });
          }
        }
        if (ta.value.trim()) run();
      });
    },
  });
})();
