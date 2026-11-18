// PHISH triage — mirrors Katana tests/test_defense.py::TestPhish plus header/MIME coverage.
(() => {
"use strict";
const P = W.eng.phish;

test("lookalike + link-text mismatch (Katana test_lookalike)", () => {
  const eml = 'From: "PayPal" <service@paypal.com>\nReply-To: x@paypa1-secure.top\nSubject: Urgent: verify your account\n' +
    'Content-Type: text/html\n\n<a href="http://paypa1-secure.top/login">https://www.paypal.com</a>';
  const r = P.analyze(eml);
  const txt = r.urls.flatMap((u) => u.flags.map((f) => f.text)).join(" ");
  assert.ok(txt.includes("link text shows paypal.com"), txt);
  assert.ok(txt.includes("lookalike of paypal.com"), txt);
  assert.ok(["malicious", "suspicious"].includes(r.verdict));
});

test("double-extension attachment (Katana test_attachment)", () => {
  const eml = "From: a@b.com\nSubject: invoice\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: text/plain\n\nsee attached\n" +
    '--X\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="invoice.pdf.exe"\nContent-Transfer-Encoding: base64\n\n' +
    Buffer.concat([Buffer.from("MZ"), Buffer.alloc(100)]).toString("base64") + "\n--X--\n";
  const r = P.analyze(eml);
  assert.equal(r.attachments.length, 1);
  const a = r.attachments[0];
  assert.ok(a.flags.map((f) => f.text).join(" ").includes("double extension"));
  assert.equal(a.size, 102);
  assert.equal(a.detected, "PE / DOS executable");
  const ref = require_sha256(Buffer.concat([Buffer.from("MZ"), Buffer.alloc(100)]));
  assert.equal(a.hashes.sha256, ref);
  assert.equal(r.iocs.sha256[0], ref);
});
function require_sha256(buf) { return W.eng.phish.sha256(new Uint8Array(buf)); }

test("sync SHA-1 / SHA-256 match WebCrypto", async () => {
  for (const s of ["", "abc", "a".repeat(1000), "The quick brown fox jumps over the lazy dog"]) {
    assert.equal(P.sha256(s), await W.hash.sha("SHA-256", s), s.slice(0, 10));
    assert.equal(P.sha1(s), await W.hash.sha("SHA-1", s), s.slice(0, 10));
  }
});

test("full phish fixture: auth, hops, origin IP, encoded subject, QP, forms, lures, redirects", () => {
  const r = P.analyze(fixture("yoroi-b-phish.eml"));
  const h = r.headers;
  assert.equal(r.subject, "Urgent: your account will be suspended within 24 hours");
  assert.deepEqual({ spf: h.auth.spf, dkim: h.auth.dkim, dmarc: h.auth.dmarc }, { spf: "fail", dkim: "none", dmarc: "fail" });
  assert.equal(h.hops.length, 3);
  assert.equal(h.hops[0].ip, "45.9.148.108");             // chronological: origin first; public IP preferred over HELO literal
  assert.deepEqual(h.hops[0].ips, ["45.9.148.108", "192.168.1.20"]);
  assert.equal(h.hops[0].by, "mail.paypa1-secure.top");
  assert.equal(h.hops[1].delay_s, 2);
  assert.equal(h.hops[2].delay_s, 53);
  assert.equal(h.origin_ip, "45.9.148.108");             // first public hop IP
  const ht = h.flags.map((f) => f.text).join(" | ");
  assert.ok(ht.includes("SPF fail") && ht.includes("DMARC fail"), ht);
  assert.ok(ht.includes("Reply-To domain (paypa1-secure.top) differs from From (paypal.com)"), ht);
  assert.ok(ht.includes("differs from Return-Path"), ht);
  const ut = r.urls.flatMap((u) => u.flags.map((f) => f.text)).join(" | ");
  assert.ok(ut.includes("URL shortener"), ut);
  assert.ok(ut.includes("open-redirect style parameter 'url' → evil.workers.dev"), ut);
  assert.ok(ut.includes("high-abuse TLD .top"), ut);
  assert.ok(r.urls.some((u) => u.url.startsWith("https://bit.ly/")));
  assert.equal(r.urls.filter((u) => u.url === "https://bit.ly/3xYzAbC").length, 1);   // deduped across text + html
  assert.deepEqual(r.forms, ["https://collect.paypa1-secure.top/p"]);
  assert.ok(r.lures.includes("verify your account") && r.lures.includes("within 24 hours") && r.lures.includes("immediately"), r.lures.join(","));
  assert.equal(r.verdict, "malicious");
  assert.ok(r.score >= 12);
  assert.ok(r.redflags[0].level === "high");
  assert.ok(r.iocs.domain.includes("paypa1-secure.top"));
  assert.ok(r.blockable.includes("bit.ly") && r.blockable.some((x) => x.startsWith("http://paypa1-secure.top")));
  assert.ok(r.body_preview.includes("unusual sign-in activity"));
});

test("benign fixture stays benign", () => {
  const r = P.analyze(fixture("yoroi-b-benign.eml"));
  assert.equal(r.verdict, "likely benign", JSON.stringify(r.redflags));
  assert.equal(r.headers.origin_ip, "209.85.220.41");
  assert.equal(r.headers.auth.dmarc, "pass");
  assert.equal(r.urls.length, 1);
  assert.deepEqual(r.urls[0].flags, []);
});

test("display-name spoofing, punycode and lookalike sender domains", () => {
  const a = P.analyze('From: "billing@paypal.com" <x@evil.example>\nSubject: hi\n\nbody');
  assert.ok(a.headers.flags.some((f) => /Display name contains a different address/.test(f.text)));
  const b = P.analyze('From: "Microsoft Account Team" <alerts.secure@gmail.com>\nSubject: hi\n\nbody');
  assert.ok(b.headers.flags.some((f) => f.level === "high" && /impersonates 'microsoft'.*free-mail/.test(f.text)), JSON.stringify(b.headers.flags));
  const c = P.analyze("From: Support <help@micros0ft.com>\nSubject: hi\n\nbody");
  assert.ok(c.headers.flags.some((f) => /lookalike of microsoft\.com/.test(f.text)));
  const d = P.analyze("From: x@xn--pypal-4ve.com\nSubject: hi\n\nhttps://xn--pypal-4ve.com/");
  assert.ok(d.headers.flags.some((f) => /punycode/.test(f.text)));
  assert.ok(d.urls[0].flags.some((f) => /punycode/.test(f.text)));
});

test("url flags: raw IP, @ authority, nested subdomains, brand mention", () => {
  const t = (u) => P.urlFlags(u).map((f) => f[1]).join(" | ");
  assert.ok(t("http://185.220.101.4/a").includes("raw IP"));
  assert.ok(t("https://www.paypal.com@evil.example/").includes("'@' in authority"));
  assert.ok(t("https://a.b.c.d.evil.example/").includes("deeply nested"));
  assert.ok(t("https://paypal-login.evil.example/").includes("mentions 'paypal' but domain is evil.example"));
  assert.equal(t("https://www.paypal.com/signin"), "");
  assert.deepEqual(P.urlFlags("http://exa mple.com/"), [["high", "malformed URL"]]);
  assert.equal(P.regDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(P.lev("paypa1", "paypal"), 1);
});

test("MIME details: RFC 2231 filenames, HTML attachments, zip with macro, body-only paste", () => {
  const zip = Buffer.concat([Buffer.from([0x50, 0x4b, 3, 4, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0]), Buffer.from("word/vbaProject.bin")]);
  const eml = "From: a@b.example\nSubject: docs\nContent-Type: multipart/mixed; boundary=\"Q\"\n\n--Q\nContent-Type: text/plain\n\nhi\n" +
    "--Q\nContent-Type: text/html; name=login.html\nContent-Disposition: attachment; filename*=utf-8''Rechnung%20login.html\n\n<html><form action=x><input type=password></form><script>location.href=atob('aA==')</script></html>\n" +
    "--Q\nContent-Type: application/zip\nContent-Disposition: attachment; filename=\"a.zip\"\nContent-Transfer-Encoding: base64\n\n" + zip.toString("base64") + "\n--Q--\n";
  const r = P.analyze(eml);
  assert.equal(r.attachments.length, 2);
  assert.equal(r.attachments[0].name, "Rechnung login.html");
  const f0 = r.attachments[0].flags.map((f) => f.text).join(" | ");
  assert.ok(/credential phishing page/.test(f0) && /HTML smuggling/.test(f0), f0);
  assert.ok(r.attachments[1].flags.some((f) => /VBA macros/.test(f.text)), JSON.stringify(r.attachments[1]));
  const body = P.analyze("Hello, please verify your account at hxxp://not-linked.example and https://evil.example/login now");
  assert.equal(body.urls.length, 1);
  assert.ok(body.lures.includes("verify your account"));
  assert.equal(P.decodeWords("=?iso-8859-1?Q?Caf=E9?= ok"), "Café ok");
});

test("attachment YARA hits feed the verdict", () => {
  const eml = "From: a@b.example\nSubject: x\nContent-Type: multipart/mixed; boundary=Z\n\n--Z\nContent-Type: text/plain\n\nsee file\n--Z\n" +
    "Content-Type: application/octet-stream\nContent-Disposition: attachment; filename=update.txt\n\n<?php system($_GET['c']); ?>\n--Z--\n";
  const r = P.analyze(eml);
  const a = r.attachments[0];
  assert.ok(a.yara.some((y) => y.rule === "Aegis_Webshell_Generic"));
  assert.ok(a.flags.some((f) => f.level === "high" && /YARA Aegis_Webshell_Generic/.test(f.text)));
});
})();
