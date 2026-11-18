/* JWT inspector engine — decode, audit and verify JSON Web Tokens (JWS compact form).
 *   decode(token)              → {header, payload, signature, signingInput, jwe, errors}
 *   claims(payload, now)       → [{name, value, time?, iso?, rel?}]
 *   analyse(decoded, {now})    → [{sev, title, detail, fix, id}]
 *   verify(token, key, opts)   → Promise<{ok, alg, keyType, notes}>   (WebCrypto; HS*, RS*, PS*, ES*, EdDSA)
 * Keys: HMAC secret (utf8 | base64 | hex), JWK / JWKS JSON, or PEM (PUBLIC KEY, RSA PUBLIC KEY, CERTIFICATE).
 * Private keys are refused — verification only ever needs the public half. */
(function (W) {
  "use strict";
  const ALGS = {
    HS256: { kind: "hmac", hash: "SHA-256" }, HS384: { kind: "hmac", hash: "SHA-384" }, HS512: { kind: "hmac", hash: "SHA-512" },
    RS256: { kind: "rsa", name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, RS384: { kind: "rsa", name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, RS512: { kind: "rsa", name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
    PS256: { kind: "rsa", name: "RSA-PSS", hash: "SHA-256", salt: 32 }, PS384: { kind: "rsa", name: "RSA-PSS", hash: "SHA-384", salt: 48 }, PS512: { kind: "rsa", name: "RSA-PSS", hash: "SHA-512", salt: 64 },
    ES256: { kind: "ec", name: "ECDSA", hash: "SHA-256", crv: "P-256", sig: 64 }, ES384: { kind: "ec", name: "ECDSA", hash: "SHA-384", crv: "P-384", sig: 96 }, ES512: { kind: "ec", name: "ECDSA", hash: "SHA-512", crv: "P-521", sig: 132 },
    EdDSA: { kind: "okp", name: "Ed25519" }, Ed25519: { kind: "okp", name: "Ed25519" },
  };
  const TIME_CLAIMS = { exp: "Expires", nbf: "Not before", iat: "Issued at", auth_time: "Authenticated at", updated_at: "Updated at" };
  const REGISTERED = { iss: "Issuer", sub: "Subject", aud: "Audience", jti: "Token ID", azp: "Authorised party", scope: "Scope", nonce: "Nonce", sid: "Session ID", client_id: "Client ID" };
  const SENSITIVE = /pass(word|wd)?$|^pwd$|secret|ssn$|social.?security|credit.?card|card.?num|^cvv|cvc$|api.?key|private.?key|access.?key|client.?secret|^pin$/i;
  const PII = /^(email|e-mail|phone(_number)?|phone.?number|mobile|address|street|birth.?date|dob|date.?of.?birth|national.?id|passport)$/i;

  function b64uJSON(seg, what) {
    let txt;
    try { txt = W.utf8(W.fromB64(seg)); } catch { throw new Error(`${what} is not valid base64url`); }
    try { return { json: JSON.parse(txt), text: txt }; } catch { throw new Error(`${what} is not JSON`); }
  }
  /** Decode a compact JWS (3 parts) or show the protected header of a JWE (5 parts). */
  function decode(token) {
    const t = String(token == null ? "" : token).trim().replace(/^(bearer|authorization:\s*bearer)\s+/i, "").replace(/\s+/g, "");
    if (!t) throw new Error("paste a token");
    const parts = t.split(".");
    if (parts.length !== 3 && parts.length !== 5) throw new Error(`a JWT has 3 dot-separated parts (JWE has 5); this has ${parts.length}`);
    if (parts.some((p, i) => p && !/^[A-Za-z0-9_-]+={0,2}$/.test(p) && !(parts.length === 3 && i === 2 && p === ""))) throw new Error("token contains characters outside base64url");
    const h = b64uJSON(parts[0], "header");
    if (parts.length === 5) return { jwe: true, header: h.json, headerText: h.text, payload: null, parts, token: t, size: t.length };
    const p = b64uJSON(parts[1], "payload");
    return { jwe: false, header: h.json, headerText: h.text, payload: p.json, payloadText: p.text, signature: parts[2], signingInput: parts[0] + "." + parts[1], parts, token: t, size: t.length,
      sigBytes: parts[2] ? W.fromB64(parts[2]).length : 0 };
  }

  const rel = (sec, now) => {
    const d = sec - now, a = Math.abs(d);
    const u = a < 90 ? `${Math.round(a)}s` : a < 5400 ? `${Math.round(a / 60)}m` : a < 129600 ? `${Math.round(a / 3600)}h` : a < 86400 * 400 ? `${Math.round(a / 86400)}d` : `${(a / 86400 / 365).toFixed(1)}y`;
    return d >= 0 ? `in ${u}` : `${u} ago`;
  };
  const dur = (s) => (s < 3600 ? `${Math.round(s / 60)} min` : s < 172800 ? `${(s / 3600).toFixed(s % 3600 ? 1 : 0)} h` : `${Math.round(s / 86400)} days`);
  /** Claim rows with readable times. now = seconds since epoch. */
  function claims(payload, now = Date.now() / 1000) {
    if (!payload || typeof payload !== "object") return [];
    return Object.entries(payload).map(([name, value]) => {
      const row = { name, value, label: TIME_CLAIMS[name] || REGISTERED[name] || "" };
      if (TIME_CLAIMS[name] && typeof value === "number" && isFinite(value)) {
        const ms = value * 1000;
        if (Math.abs(ms) < 8.64e15) { row.time = true; row.iso = new Date(ms).toISOString().replace(".000Z", "Z"); row.rel = rel(value, now); }
      }
      return row;
    });
  }

  function walk(obj, fn, path = "", depth = 0) {
    if (!obj || typeof obj !== "object" || depth > 6) return;
    for (const [k, v] of Object.entries(obj)) { fn(k, v, path ? path + "." + k : k); walk(v, fn, path ? path + "." + k : k, depth + 1); }
  }

  /** Configuration weaknesses. sev: critical | high | medium | low | info | ok. */
  function analyse(d, opts = {}) {
    const now = opts.now != null ? opts.now : Date.now() / 1000;
    const F = [], add = (sev, title, detail, fix, id) => F.push({ sev, title, detail: detail || "", fix: fix || "", id });
    const h = d.header || {};
    const alg = typeof h.alg === "string" ? h.alg : null;
    if (d.jwe) {
      add("info", `Encrypted token (JWE, ${h.alg || "?"} / ${h.enc || "?"})`, "The payload is encrypted; only the protected header can be read without the recipient's key.", "", "jwe");
      if (h.alg === "RSA1_5") add("medium", "JWE key wrap RSA1_5", "RSAES-PKCS1-v1_5 key transport is vulnerable to padding-oracle attacks (Bleichenbacher).", "Use RSA-OAEP-256 or ECDH-ES.", "jwe-rsa15");
      if (h.zip) add("info", "Compressed JWE (zip)", "Compression before encryption can leak plaintext length (CRIME-style) if attackers control part of the content.", "Avoid zip for tokens mixing secrets with attacker-controlled data.", "jwe-zip");
      return F;
    }
    // ---- header
    if (!alg) add("high", "No alg in header", "A JWS must declare its algorithm; libraries may fall back to unsafe defaults.", "Always set alg and pin the expected algorithm on the verifier.", "alg-missing");
    else if (/^none$/i.test(alg)) add("critical", `alg "${alg}" — unsigned token`, "Anyone can forge this token. If the server accepts it, authentication is bypassed.", "Reject alg none on the server and pin the expected algorithm(s) in the verifier.", "alg-none");
    else if (!ALGS[alg]) add("medium", `Unknown or non-standard alg "${alg}"`, "Unrecognised algorithms suggest custom crypto or a typo the verifier may mishandle.", "Use a registered algorithm such as ES256, PS256, RS256 or EdDSA.", "alg-unknown");
    else if (ALGS[alg].kind === "hmac") add("info", `Symmetric ${alg}`, "Every service that can verify this token can also mint one. The shared secret must be long (≥ 256 bits) and random — short secrets can be brute-forced offline from any captured token.", "Use a 32+ byte random secret, or switch to an asymmetric algorithm (ES256/EdDSA) when several services verify tokens.", "alg-hmac");
    else add("ok", `Asymmetric ${alg}`, "Verifiers only need the public key.", "", "alg-asym");
    if (alg && !/^none$/i.test(alg) && !d.signature) add("high", "Signature is empty", `The header says ${alg} but the signature segment is blank — a stripped signature.`, "Servers must reject tokens whose signature is missing.", "sig-empty");
    if (alg && /^none$/i.test(alg) && d.signature) add("medium", "alg none but a signature is present", "Inconsistent token — possibly tampered.", "Reject it.", "none-sig");
    if (alg && ALGS[alg] && ALGS[alg].sig && d.signature && d.sigBytes !== ALGS[alg].sig) add("low", `Signature length ${d.sigBytes} bytes doesn't match ${alg} (${ALGS[alg].sig})`, "JOSE ECDSA signatures are raw r‖s, not DER. A DER signature indicates a non-conforming library.", "Emit the raw IEEE P1363 signature.", "sig-len");
    if (h.jwk) add("high", "Public key embedded in header (jwk)", "If the server verifies with a key taken from the token, anyone can sign tokens with their own key.", "Verify only with keys from your own trusted key store; ignore header-supplied keys.", "hdr-jwk");
    if (h.jku) add("medium", `Key set URL in header (jku: ${String(h.jku).slice(0, 120)})`, "If the server fetches keys from a URL the token chooses, an attacker can point it at their own key set (and it can be an SSRF vector).", "Only use pre-configured JWKS URLs; never follow jku from the token, or strictly allow-list it.", "hdr-jku");
    if (h.x5u) add("medium", `Certificate URL in header (x5u: ${String(h.x5u).slice(0, 120)})`, "Same risk as jku: keys fetched from a token-chosen URL.", "Ignore x5u or strictly allow-list it.", "hdr-x5u");
    if (h.x5c) add("low", "Certificate chain embedded (x5c)", "Safe only if the verifier validates the chain to a pinned trust anchor and checks the subject.", "Confirm chain validation; otherwise the token is self-signed by anyone.", "hdr-x5c");
    if (h.kid != null) {
      const k = String(h.kid);
      if (/\.\.|[/\\]|['";]|--|\s|\|/.test(k)) add("medium", `kid contains path or query metacharacters (${k.slice(0, 80)})`, "If the server uses kid in a file path, SQL query or command, it may be injectable.", "Treat kid as an opaque key into an allow-listed key map.", "hdr-kid-meta");
      else add("info", `Key ID (kid: ${k.slice(0, 80)})`, "Used to pick the verification key.", "Make sure the server looks kid up in a fixed key map.", "hdr-kid");
    }
    if (h.crit) add("info", `Critical header params: ${[].concat(h.crit).join(", ")}`, "Verifiers must understand every listed parameter or reject the token.", "", "hdr-crit");
    if (h.typ && !/^(jwt|at\+jwt|application\/(at\+)?jwt|jose|dpop\+jwt|logout\+jwt|secevent\+jwt)$/i.test(h.typ)) add("info", `Unusual typ "${h.typ}"`, "", "", "hdr-typ");
    if (h.b64 === false) add("info", "Unencoded payload (b64: false)", "RFC 7797 detached/unencoded payloads are rarely supported consistently.", "", "hdr-b64");
    // ---- claims
    const p = d.payload;
    if (!p || typeof p !== "object" || Array.isArray(p)) { add("medium", "Payload is not a JSON object", "JWT claims sets must be JSON objects.", "", "payload-type"); return F; }
    const num = (x) => typeof x === "number" && isFinite(x);
    if (p.exp == null) add("medium", "No exp (expiry) claim", "The token never expires: a leaked token works forever.", "Add a short exp (minutes to hours) and refresh tokens for longer sessions.", "exp-missing");
    else if (!num(p.exp)) add("medium", "exp is not a number", "NumericDate claims must be seconds since the epoch; string values may be ignored by verifiers.", "Use a numeric exp.", "exp-type");
    else if (p.exp > 1e11) add("low", "exp looks like milliseconds", "exp should be in seconds; a millisecond value means the token effectively never expires.", "Divide by 1000.", "exp-ms");
    else if (p.exp < now) add("info", `Expired ${rel(p.exp, now)}`, new Date(p.exp * 1000).toISOString(), "", "exp-past");
    const start = num(p.iat) ? p.iat : num(p.nbf) ? p.nbf : null;
    if (num(p.exp) && start != null && p.exp <= 1e11) {
      const life = p.exp - start;
      if (life > 7 * 86400) add("medium", `Very long lifetime (${dur(life)})`, "Long-lived bearer tokens widen the window for replay if one leaks.", "Keep access tokens to minutes or hours; use refresh tokens with rotation.", "lifetime-long");
      else if (life > 86400) add("low", `Long lifetime (${dur(life)})`, "", "Consider a lifetime of an hour or less for access tokens.", "lifetime-long");
      else if (life > 0) add("ok", `Lifetime ${dur(life)}`, "", "", "lifetime-ok");
      else add("low", "exp is not after iat/nbf", "The token was never valid.", "", "lifetime-neg");
    } else if (num(p.exp) && start == null) add("info", "No iat claim", "Without iat the token's age can't be checked.", "Add iat.", "iat-missing");
    if (num(p.nbf) && p.nbf > now) add("info", `Not valid yet (nbf ${rel(p.nbf, now)})`, "", "", "nbf-future");
    if (num(p.iat) && p.iat > now + 300) add("low", `Issued in the future (iat ${rel(p.iat, now)})`, "Clock skew on the issuer, or a forged token.", "Check issuer clocks; verifiers should reject far-future iat.", "iat-future");
    if (p.iss == null) add("low", "No iss (issuer) claim", "Verifiers can't confirm which issuer minted the token.", "Add iss and validate it.", "iss-missing");
    if (p.aud == null) add("low", "No aud (audience) claim", "A token for one service may be replayed against another that trusts the same issuer/key.", "Add aud and have each service check it.", "aud-missing");
    const sens = [], pii = [];
    walk(p, (k, v, path) => { if (SENSITIVE.test(k) && v !== null && v !== "" && typeof v !== "boolean") sens.push(path); else if (PII.test(k)) pii.push(path); });
    if (sens.length) add("high", `Sensitive-looking claims: ${sens.join(", ")}`, "JWT payloads are only base64url-encoded — anyone holding the token can read them.", "Never put secrets in a JWS; reference them server-side, or use JWE.", "claims-sensitive");
    if (pii.length) add("low", `Personal data in claims: ${pii.join(", ")}`, "Readable by anyone who sees the token (logs, browser storage, proxies).", "Minimise claims; keep PII server-side.", "claims-pii");
    if (/admin|role|groups?|is_?admin|permissions?|scope/i.test(Object.keys(p).join(" "))) add("info", "Authorisation claims present", "Role/permission claims are only trustworthy if the signature is verified with a pinned algorithm and key.", "", "claims-authz");
    if (d.size > 4096) add("info", `Large token (${d.size} bytes)`, "Big tokens can exceed cookie/header limits.", "", "size");
    return F;
  }

  // ------------------------------------------------------------------ keys
  function pemBlocks(text) {
    const out = [], re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g; let m;
    while ((m = re.exec(text))) out.push({ type: m[1], der: W.fromB64(m[2].replace(/[^A-Za-z0-9+/=]/g, "")) });
    return out;
  }
  function tlv(b, off) {
    const tag = b[off]; let len = b[off + 1], hdr = 2;
    if (len & 0x80) { const n = len & 0x7f; if (n < 1 || n > 4) throw new Error("bad DER length"); len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i]; hdr = 2 + n; }
    if (off + hdr + len > b.length) throw new Error("truncated DER");
    return { tag, start: off, body: off + hdr, end: off + hdr + len };
  }
  function children(b, node) { const out = []; let o = node.body; while (o < node.end) { const c = tlv(b, o); out.push(c); o = c.end; } return out; }
  /** X.509 certificate DER → SubjectPublicKeyInfo DER. */
  function certSpki(der) {
    const cert = tlv(der, 0), tbs = children(der, cert)[0], kids = children(der, tbs);
    const i = kids[0].tag === 0xa0 ? 6 : 5;
    if (!kids[i] || kids[i].tag !== 0x30) throw new Error("couldn't find the public key in the certificate");
    return der.slice(kids[i].start, kids[i].end);
  }
  function derLen(n) { if (n < 128) return [n]; const o = []; while (n) { o.unshift(n & 255); n >>= 8; } return [0x80 | o.length, ...o]; }
  /** PKCS#1 RSAPublicKey → SPKI. */
  function pkcs1ToSpki(pk) {
    const algId = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
    const bit = [0x03, ...derLen(pk.length + 1), 0x00, ...pk];
    const body = algId.concat(bit);
    return new Uint8Array([0x30, ...derLen(body.length), ...body]);
  }
  const OIDS = { "2a864886f70d010101": "RSA", "2a8648ce3d0201": "EC", "2b6570": "Ed25519" };
  function spkiKind(spki) {
    const algId = children(spki, tlv(spki, 0))[0], oidNode = algId && children(spki, algId)[0];
    const oid = oidNode && oidNode.tag === 0x06 ? W.hex(spki.slice(oidNode.body, oidNode.end)) : "";
    return OIDS[oid] || "unknown";
  }

  /** Parse what the user pasted into {format, jwk?|spki?|secret?}. */
  function parseKey(text, header = {}, opts = {}) {
    const s = String(text == null ? "" : text).trim();
    if (!s) throw new Error("supply a key or secret");
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(s)) throw new Error("that's a private key — paste the PUBLIC key (or certificate) instead; verification never needs the private half");
    if (/-----BEGIN /.test(s)) {
      const b = pemBlocks(s)[0]; if (!b) throw new Error("malformed PEM");
      if (b.type === "PUBLIC KEY") return { format: "spki", spki: b.der, kind: spkiKind(b.der), pem: b.type };
      if (b.type === "RSA PUBLIC KEY") return { format: "spki", spki: pkcs1ToSpki(b.der), kind: "RSA", pem: b.type };
      if (b.type === "CERTIFICATE") { const spki = certSpki(b.der); return { format: "spki", spki, kind: spkiKind(spki), pem: b.type }; }
      throw new Error(`unsupported PEM type ${b.type}`);
    }
    if (/^[{[]/.test(s)) {
      let j; try { j = JSON.parse(s); } catch { throw new Error("key looks like JSON but doesn't parse"); }
      let notes = [];
      if (Array.isArray(j)) j = { keys: j };
      if (j.keys) {
        const list = j.keys.filter((k) => !header.kid || k.kid === header.kid);
        if (!list.length) throw new Error(header.kid ? `no key with kid "${header.kid}" in the JWKS` : "JWKS has no keys");
        j = list[0]; if (j.kid) notes.push(`using JWKS key kid=${j.kid}`);
      }
      if (!j.kty) throw new Error("JWK has no kty");
      const pub = Object.assign({}, j);
      if (pub.d || pub.p) notes.push("private JWK supplied — only its public part was used");
      for (const k of ["d", "p", "q", "dp", "dq", "qi", "oth", "alg", "key_ops", "use", "ext"]) delete pub[k];
      if (j.kty === "oct") return { format: "secret", secret: W.fromB64(j.k || ""), kind: "oct", notes };
      return { format: "jwk", jwk: pub, kind: j.kty === "RSA" ? "RSA" : j.kty === "EC" ? "EC" : j.kty === "OKP" ? j.crv : j.kty, notes };
    }
    const enc = opts.secretEncoding || "utf8";
    const secret = enc === "base64" ? W.fromB64(s) : enc === "hex" ? W.fromHex(s) : W.bytes(s);
    return { format: "secret", secret, kind: "oct" };
  }

  /** Verify the signature. Resolves {ok, alg, keyType, notes}. Throws on unsupported alg / unusable key. */
  async function verify(token, keyText, opts = {}) {
    const d = typeof token === "object" && token.signingInput ? token : decode(token);
    if (d.jwe) throw new Error("JWE tokens are encrypted, not signed — nothing to verify here");
    const alg = opts.alg || d.header.alg;
    if (!alg || /^none$/i.test(alg)) throw new Error(`alg "${alg || "missing"}" — the token is unsigned; there is nothing to verify (and servers must reject it)`);
    const A = ALGS[alg]; if (!A) throw new Error(`unsupported algorithm ${alg}`);
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) throw new Error("WebCrypto unavailable — open Wakizashi over https or localhost");
    const key = parseKey(keyText, d.header, opts);
    const notes = (key.notes || []).slice();
    const data = W.bytes(d.signingInput), sig = W.fromB64(d.signature || "");
    let ck, params;
    if (A.kind === "hmac") {
      if (key.format !== "secret") throw new Error(`${alg} is an HMAC algorithm — supply the shared secret, not a ${key.kind} public key`);
      if (key.secret.length < 32) notes.push(`secret is only ${key.secret.length} bytes — ${alg} secrets should be at least 32 random bytes`);
      ck = await subtle.importKey("raw", key.secret, { name: "HMAC", hash: A.hash }, false, ["verify"]);
      params = { name: "HMAC" };
    } else {
      if (key.format === "secret") throw new Error(`${alg} needs a public key (JWK or PEM), not a shared secret`);
      const want = A.kind === "rsa" ? "RSA" : A.kind === "ec" ? "EC" : "Ed25519";
      if (key.kind !== want) throw new Error(`${alg} needs an ${want} key but a ${key.kind} key was supplied`);
      const imp = A.kind === "rsa" ? { name: A.name, hash: A.hash } : A.kind === "ec" ? { name: "ECDSA", namedCurve: key.jwk ? key.jwk.crv : A.crv } : { name: "Ed25519" };
      if (A.kind === "ec" && key.jwk && key.jwk.crv !== A.crv) throw new Error(`${alg} uses ${A.crv} but the JWK is ${key.jwk.crv}`);
      try {
        ck = key.format === "jwk" ? await subtle.importKey("jwk", key.jwk, imp, false, ["verify"]) : await subtle.importKey("spki", key.spki, imp, false, ["verify"]);
      } catch (e) {
        if (A.kind === "okp") throw new Error("this browser's WebCrypto doesn't support Ed25519 yet");
        throw new Error(`couldn't import the key for ${alg}: ${e.message || e}`);
      }
      params = A.kind === "rsa" ? (A.salt ? { name: "RSA-PSS", saltLength: A.salt } : { name: A.name }) : A.kind === "ec" ? { name: "ECDSA", hash: A.hash } : { name: "Ed25519" };
      if (A.kind === "rsa" && ck.algorithm && ck.algorithm.modulusLength < 2048) notes.push(`RSA key is only ${ck.algorithm.modulusLength} bits — use 2048 or more`);
    }
    const ok = await subtle.verify(params, ck, sig, data);
    if (opts.alg && opts.alg !== d.header.alg) notes.push(`verified as ${opts.alg} although the header says ${d.header.alg}`);
    return { ok, alg, keyType: key.kind, keyFormat: key.pem || key.format, notes };
  }

  W.eng.jwt = { ALGS, decode, claims, analyse, verify, parseKey, certSpki, pkcs1ToSpki, spkiKind };
})(typeof window !== "undefined" ? window.W : globalThis.W);
