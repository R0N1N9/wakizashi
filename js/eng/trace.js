/* TRACE — tracker, redirect-wrapper and homograph analysis for links and email HTML (port of Katana
 * shinobi/trace.py + Karambit TraceEngine), extended with redirect unwrapping and IDN/punycode checks.
 *
 *   cleanUrl(url)   → { input, url, clean, host, hostUnicode, removed[{param,value,what}], unwrapped[{via,from}],
 *                       flags[{level,text}], shortener, idn{...}|null, changed }
 *   analyze(text)   → { mode: "url"|"html", links[], beacons[], sanitized[], remoteImages, summary }
 *   punyDecode / punyEncode / toUnicodeHost — RFC 3492
 * All local — nothing is fetched, so shorteners (t.co, bit.ly…) are flagged as unresolvable rather than expanded.
 */
(function (W) {
  "use strict";

  // Prefix match ("utm_") or exact key → why it exists. From trace.py, plus a wider modern list.
  const TRACK_PARAMS = {
    "utm_": "Urchin / Google Analytics campaign tag", "gclid": "Google Ads click id", "gclsrc": "Google Ads source", "dclid": "DoubleClick click id",
    "wbraid": "Google Ads (iOS) click id", "gbraid": "Google Ads (iOS) click id", "gad_source": "Google Ads source", "gad_campaignid": "Google Ads campaign",
    "srsltid": "Google Merchant click id", "_ga": "Google Analytics cross-domain id", "_gl": "Google linker id",
    "fbclid": "Facebook click id", "fb_action_ids": "Facebook action id", "fb_action_types": "Facebook action type", "fb_ref": "Facebook referrer", "fb_source": "Facebook source",
    "igshid": "Instagram share id", "igsh": "Instagram share id", "twclid": "Twitter/X click id", "ttclid": "TikTok click id", "li_fat_id": "LinkedIn click id",
    "msclkid": "Microsoft Ads click id", "yclid": "Yandex click id", "ysclid": "Yandex click id", "epik": "Pinterest click id", "sccid": "Snapchat click id",
    "rdt_cid": "Reddit click id", "irclickid": "Impact affiliate click id", "clickid": "affiliate click id", "click_id": "affiliate click id",
    "mc_eid": "Mailchimp recipient id", "mc_cid": "Mailchimp campaign id", "_hsenc": "HubSpot contact token", "_hsmi": "HubSpot message id", "__hssc": "HubSpot session",
    "__hstc": "HubSpot visitor", "__hsfp": "HubSpot fingerprint", "hsctatracking": "HubSpot CTA tracking", "vero_id": "Vero recipient id", "vero_conv": "Vero conversion id",
    "oly_enc_id": "Omeda recipient id", "oly_anon_id": "Omeda anon id", "ck_subscriber_id": "ConvertKit id", "mkt_tok": "Marketo token", "sc_cid": "Snapchat campaign",
    "s_cid": "Adobe campaign id", "s_kwcid": "Adobe keyword id", "ef_id": "Adobe Advertising id", "cmpid": "campaign id", "ncid": "network campaign id",
    "spm": "Alibaba tracking", "scm": "Alibaba tracking", "trk": "LinkedIn tracking", "trkcampaign": "LinkedIn campaign", "trackingid": "LinkedIn tracking id",
    "lipi": "LinkedIn page instance", "_openstat": "Openstat tracking", "icid": "internal campaign id", "wickedid": "Wicked Reports id", "rb_clickid": "click id",
    "hsa_": "Google Ads smart-bidding tag", "pk_": "Matomo/Piwik campaign", "mtm_": "Matomo campaign", "piwik_": "Piwik campaign", "matomo_": "Matomo campaign",
    "ref_src": "referrer source", "ref_url": "referrer url", "wt_mc": "Webtrends campaign", "wt.mc_id": "Webtrends campaign", "at_medium": "AT Internet tag",
    "at_campaign": "AT Internet tag", "zanpid": "Zanox click id", "awc": "Awin click id", "cjevent": "CJ affiliate event", "ranmid": "Rakuten merchant", "ransiteid": "Rakuten site id",
    "ranEAID": "Rakuten affiliate", "dm_i": "dotdigital id", "elqtrackid": "Eloqua tracking id", "elqtrack": "Eloqua tracking", "elq": "Eloqua recipient", "mbid": "Marketo id",
    "nr_email_referer": "newsletter referrer", "ss_source": "Squarespace source", "ss_campaign_id": "Squarespace campaign", "__s": "Drip subscriber", "_kx": "Klaviyo recipient",
    "gs_l": "Google search telemetry", "ved": "Google result-click telemetry", "ei": "Google search session", "oq": "Google original query", "sca_esv": "Google search telemetry",
    "uact": "Google telemetry", "mibextid": "Facebook in-app share id", "xmt": "Threads share id",
  };
  // Host-scoped params: only tracking on these sites (elsewhere they may be meaningful).
  const HOST_PARAMS = [
    [/(^|\.)(youtube\.com|youtu\.be)$/, { si: "YouTube share id (ties the link to your account)", feature: "YouTube share source", pp: "YouTube player telemetry", ab_channel: "YouTube channel tag" }],
    [/(^|\.)spotify\.com$/, { si: "Spotify share id (ties the link to your account)", context: "Spotify share context", nd: "Spotify share flag", dl_branch: "Spotify deep-link" }],
    [/(^|\.)(twitter\.com|x\.com)$/, { s: "X share source (app/platform)", t: "X share id (ties the link to your account)", ref_src: "X referrer" }],
    [/(^|\.)instagram\.com$/, { igsh: "Instagram share id", img_index: "Instagram share position", utm_source: "Instagram source" }],
    [/(^|\.)tiktok\.com$/, { _r: "TikTok share flag", _t: "TikTok share id (account-linked)", is_from_webapp: "TikTok source", sender_device: "TikTok sender device", is_copy_url: "TikTok copy flag", share_app_id: "TikTok app id", share_link_id: "TikTok share id" }],
    [/(^|\.)reddit\.com$/, { share_id: "Reddit share id (account-linked)", rdt: "Reddit click id", context: "Reddit share context", ref: "Reddit referrer", ref_source: "Reddit referrer" }],
    [/(^|\.)amazon\.[a-z.]+$/, { ref: "Amazon referrer", ref_: "Amazon referrer", tag: "Amazon affiliate tag", pf_rd_: "Amazon placement tracking", pd_rd_: "Amazon placement tracking", _encoding: "Amazon encoding flag", psc: "Amazon variant flag", qid: "Amazon search timestamp", sr: "Amazon search rank", crid: "Amazon search id", sprefix: "Amazon search prefix", keywords: "Amazon search terms", content_id: "Amazon content id", linkcode: "Amazon affiliate", linkid: "Amazon affiliate", camp: "Amazon affiliate", creative: "Amazon affiliate" }],
    [/(^|\.)(ebay\.[a-z.]+)$/, { _trkparms: "eBay tracking", _trksid: "eBay tracking", hash: "eBay item hash", mkcid: "eBay campaign", mkevt: "eBay event", campid: "eBay affiliate" }],
    [/(^|\.)aliexpress\.[a-z]+$/, { algo_pvid: "AliExpress tracking", algo_exp_id: "AliExpress tracking", pdp_npi: "AliExpress tracking", aff_platform: "AliExpress affiliate", sk: "AliExpress affiliate" }],
    [/(^|\.)linkedin\.com$/, { trk: "LinkedIn tracking", trkinfo: "LinkedIn tracking", refid: "LinkedIn referrer", origin: "LinkedIn origin", lipi: "LinkedIn page instance", rcm: "LinkedIn share id (account-linked)" }],
    [/(^|\.)facebook\.com$/, { __tn__: "Facebook tracking", __cft__: "Facebook tracking", eid: "Facebook event id", ref: "Facebook referrer", sfnsn: "Facebook share", mibextid: "Facebook in-app share" }],
    [/(^|\.)google\.[a-z.]+$/, { sxsrf: "Google search telemetry", source: "Google source", sourceid: "Google source id", ie: "Google encoding", rlz: "Google install id", aqs: "Google search telemetry", biw: "Google viewport", bih: "Google viewport", dpr: "Google device pixel ratio" }],
    [/(^|\.)medium\.com$/, { source: "Medium referrer" }],
    [/(^|\.)bing\.com$/, { form: "Bing source", cvid: "Bing session id", pc: "Bing partner code" }],
  ];
  // Redirect wrappers we can unwrap offline: host test, path test, param carrying the target.
  const WRAPPERS = [
    { via: "Google redirect", host: /(^|\.)google\.[a-z.]+$/, path: /^\/(url|imgres|aclk|interstitial)$/, keys: ["q", "url", "imgurl", "adurl"] },
    { via: "Facebook link shim", host: /^(l|lm|m|www)\.facebook\.com$/, path: /^\/l\.php$/, keys: ["u"] },
    { via: "Instagram link shim", host: /^l\.instagram\.com$/, path: /.*/, keys: ["u"] },
    { via: "Messenger link shim", host: /^l\.messenger\.com$/, path: /^\/l\.php$/, keys: ["u"] },
    { via: "Outlook Safe Links", host: /safelinks\.protection\.outlook\.com$/, path: /.*/, keys: ["url"] },
    { via: "LinkedIn redirect", host: /(^|\.)linkedin\.com$/, path: /^\/(redir\/redirect|redir\/general-malware-page|safety\/go)\/?$/, keys: ["url"] },
    { via: "Slack redirect", host: /^slack-redir\.net$/, path: /^\/link$/, keys: ["url"] },
    { via: "YouTube redirect", host: /(^|\.)youtube\.com$/, path: /^\/redirect$/, keys: ["q"] },
    { via: "Steam link filter", host: /^steamcommunity\.com$/, path: /^\/linkfilter\/?$/, keys: ["url", "u"] },
    { via: "Reddit outbound", host: /^out\.reddit\.com$/, path: /.*/, keys: ["url"] },
    { via: "Discord/Twitch redirect", host: /^(www\.)?(twitch\.tv|discord\.com)$/, path: /^\/(redirect|external)/, keys: ["url", "to"] },
    { via: "VK away", host: /^(m\.)?vk\.com$/, path: /^\/away\.php$/, keys: ["to"] },
    { via: "DuckDuckGo redirect", host: /(^|\.)duckduckgo\.com$/, path: /^\/l\/?$/, keys: ["uddg"] },
    { via: "Yandex redirect", host: /(^|\.)yandex\.[a-z]+$/, path: /^\/(redirect|clck\/jsredir)/, keys: ["url", "to"] },
    { via: "Bing click", host: /(^|\.)bing\.com$/, path: /^\/ck\/a$/, keys: ["u"], decode: (v) => { const s = v.replace(/^a1/, ""); try { return W.utf8(W.fromB64(s)); } catch { return null; } } },
    { via: "Mimecast", host: /(^|\.)mimecastprotect\.com$/, path: /.*/, keys: ["domain"], hostOnly: true },
    { via: "Generic redirect", host: /.*/, path: /\/(redirect|redir|out|away|go|exit|click|link|leave|track)(\.php|\.aspx?)?\/?$/i, keys: ["url", "u", "to", "target", "dest", "destination", "redirect", "redirect_url", "redirect_uri", "goto", "link", "out", "r", "rurl", "next", "continue", "return", "returnurl"] },
  ];
  const REDIRECT_KEYS = new Set(["url", "u", "redirect", "redirect_uri", "redir", "r", "rurl", "next", "dest", "destination", "return", "returnurl", "continue", "target", "link", "out", "goto", "q"]);
  const SHORTENERS = new Set(["bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd", "cutt.ly", "rb.gy", "bitly.com", "t.ly", "shorturl.at", "rebrand.ly",
    "lnkd.in", "trib.al", "dlvr.it", "ift.tt", "tiny.cc", "soo.gd", "s.id", "v.gd", "shrtco.de", "qr.ae", "amzn.to", "amzn.eu", "a.co", "youtu.be", "fb.me", "fb.watch", "spoti.fi",
    "t.me", "wp.me", "bl.ink", "short.io", "tiny.one", "rotf.lol", "linktr.ee", "on.soundcloud.com", "apple.co", "g.co", "forms.gle", "maps.app.goo.gl", "pin.it", "redd.it", "vm.tiktok.com", "x.gd", "urlz.fr", "shorturl.asia", "clck.ru", "surl.li"]);
  const NON_REDIRECT_SHORT = new Set(["youtu.be", "t.me", "linktr.ee", "redd.it"]);
  const TRACKER_HOSTS = {
    "list-manage.com": "Mailchimp", "sendgrid.net": "SendGrid", "mailgun.org": "Mailgun", "sparkpostmail.com": "SparkPost", "exct.net": "Salesforce Marketing Cloud",
    "rs6.net": "Constant Contact", "mcdlv.net": "Mailchimp", "hubspotemail.net": "HubSpot", "hs-sites.com": "HubSpot", "ct.sendgrid.net": "SendGrid", "mandrillapp.com": "Mandrill",
    "customeriomail.com": "Customer.io", "click.mailerlite.com": "MailerLite", "tracking.mailerlite.com": "MailerLite", "awstrack.me": "Amazon SES open tracking", "sentry.io": "telemetry",
    "doubleclick.net": "DoubleClick", "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager", "facebook.com/tr": "Meta Pixel",
    "px.ads.linkedin.com": "LinkedIn Insight", "bat.bing.com": "Microsoft UET", "analytics.twitter.com": "X pixel", "snap.licdn.com": "LinkedIn", "quantserve.com": "Quantcast",
    "scorecardresearch.com": "Comscore", "hotjar.com": "Hotjar", "fullstory.com": "FullStory", "segment.io": "Segment", "mixpanel.com": "Mixpanel", "amplitude.com": "Amplitude",
    "matomo": "Matomo", "piwik": "Piwik", "mailtrack.io": "Mailtrack", "getnotify.com": "GetNotify", "yesware.com": "Yesware", "bananatag.com": "Bananatag", "mixmax.com": "Mixmax",
    "superhuman.com": "Superhuman read receipts", "streak.com": "Streak", "klclick.com": "Klaviyo", "klaviyomail.com": "Klaviyo", "convertkit-mail": "ConvertKit", "substack.com/o/": "Substack open pixel",
  };

  // ------------------------------------------------------------------ punycode (RFC 3492)
  const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, IBIAS = 72, IN = 128;
  const adapt = (d, n, first) => { d = first ? Math.floor(d / DAMP) : d >> 1; d += Math.floor(d / n); let k = 0; while (d > ((BASE - TMIN) * TMAX) >> 1) { d = Math.floor(d / (BASE - TMIN)); k += BASE; } return k + Math.floor((BASE - TMIN + 1) * d / (d + SKEW)); };
  const digitOf = (c) => c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : BASE;
  function punyDecode(s) {
    const out = []; let b = s.lastIndexOf("-"); if (b < 0) b = 0;
    for (let j = 0; j < b; j++) { if (s.charCodeAt(j) >= 0x80) throw new Error("bad punycode"); out.push(s.charCodeAt(j)); }
    let n = IN, i = 0, bias = IBIAS;
    for (let p = b > 0 ? b + 1 : 0; p < s.length;) {
      const oldi = i;
      for (let w = 1, k = BASE; ; k += BASE) {
        if (p >= s.length) throw new Error("bad punycode");
        const d = digitOf(s.charCodeAt(p++)); if (d >= BASE) throw new Error("bad punycode");
        i += d * w; const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
        if (d < t) break; w *= BASE - t;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1)); i %= out.length + 1;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  function punyEncode(str) {
    const cps = Array.from(str, (c) => c.codePointAt(0)); let out = cps.filter((c) => c < 0x80).map((c) => String.fromCharCode(c)).join("");
    const b = out.length; let h = b; if (b) out += "-";
    let n = IN, delta = 0, bias = IBIAS;
    const enc = (d) => String.fromCharCode(d + 22 + 75 * (d < 26));
    while (h < cps.length) {
      const m = Math.min(...cps.filter((c) => c >= n)); delta += (m - n) * (h + 1); n = m;
      for (const c of cps) {
        if (c < n) delta++;
        if (c === n) {
          let q = delta;
          for (let k = BASE; ; k += BASE) { const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias; if (q < t) break; out += enc(t + (q - t) % (BASE - t)); q = Math.floor((q - t) / (BASE - t)); }
          out += enc(q); bias = adapt(delta, h + 1, h === b); delta = 0; h++;
        }
      }
      delta++; n++;
    }
    return out;
  }
  const toUnicodeHost = (h) => h.split(".").map((l) => (/^xn--/i.test(l) ? (() => { try { return punyDecode(l.slice(4).toLowerCase()); } catch { return l; } })() : l)).join(".");

  // Mixed-script / confusable check for IDN homographs
  const SCRIPTS = [["Latin", /[A-Za-zÀ-ɏ]/u], ["Cyrillic", /\p{Script=Cyrillic}/u], ["Greek", /\p{Script=Greek}/u], ["Armenian", /\p{Script=Armenian}/u],
    ["Cherokee", /\p{Script=Cherokee}/u], ["Han", /\p{Script=Han}/u], ["Arabic", /\p{Script=Arabic}/u], ["Hebrew", /\p{Script=Hebrew}/u]];
  const CONFUSABLE = { "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ӏ": "l", "ο": "o", "α": "a", "ν": "v", "τ": "t", "ρ": "p", "ι": "i", "κ": "k", "ս": "u", "օ": "o", "ᴠ": "v", "ⅼ": "l", "ı": "i", "ɑ": "a", "ẹ": "e", "ọ": "o" };
  function idnCheck(host) {
    const uni = toUnicodeHost(host);
    if (uni === host && !/[^\x00-\x7f]/.test(host)) return null;
    const labels = uni.split(".");
    const res = { ascii: host, unicode: uni, scripts: [], mixed: false, lookalike: null };
    for (const l of labels) {
      const sc = SCRIPTS.filter(([, re]) => re.test(l)).map(([n]) => n);
      res.scripts.push(...sc);
      if (sc.length > 1) res.mixed = true;
    }
    res.scripts = W.uniq(res.scripts);
    const skeleton = Array.from(uni, (c) => CONFUSABLE[c] || c).join("");
    if (skeleton !== uni && /^[\x00-\x7f]+$/.test(skeleton)) res.lookalike = skeleton;
    return res;
  }

  // ------------------------------------------------------------------ URL cleaning
  function trackDesc(key, host) {
    const k = key.toLowerCase();
    for (const [re, map] of HOST_PARAMS) if (re.test(host)) for (const [p, d] of Object.entries(map)) if (k === p.toLowerCase() || (p.endsWith("_") && k.startsWith(p.toLowerCase()))) return d;
    for (const [p, d] of Object.entries(TRACK_PARAMS)) { const pl = p.toLowerCase(); if (pl.endsWith("_") ? k.startsWith(pl) : k === pl) return d; }
    return null;
  }
  const safeDecode = (s) => { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch { return s; } };
  function parseQuery(q) { return q ? q.split("&").filter(Boolean).map((kv) => { const i = kv.indexOf("="); return i < 0 ? [kv, null, kv] : [kv.slice(0, i), kv.slice(i + 1), kv]; }) : []; }
  function proofpoint(u) {
    // urldefense.proofpoint.com/v2/url?u=https-3A__example.com_x&d=…   and   urldefense.com/v3/__https://example.com/x__;!!…
    let m = u.match(/^https?:\/\/urldefense(?:\.proofpoint)?\.com\/v3\/__(.+?)__;/i);
    if (m) return m[1].replace(/\*/g, "");
    m = u.match(/^https?:\/\/urldefense\.proofpoint\.com\/v[12]\/url\?(?:.*&)?u=([^&]+)/i);
    if (m) return safeDecode(m[1].replace(/-([0-9A-F]{2})/g, "%$1").replace(/_/g, "/"));
    return null;
  }
  function splitUrl(s) {
    const m = String(s).match(/^([a-z][a-z0-9+.-]*:)?(\/\/([^/?#]*))?([^?#]*)(\?[^#]*)?(#.*)?$/i);
    return m ? { scheme: (m[1] || "").toLowerCase(), auth: m[3] || "", path: m[4] || "", query: (m[5] || "").slice(1), hash: (m[6] || "").slice(1) } : null;
  }

  function cleanUrl(input) {
    let raw = String(input || "").trim().replace(/&amp;/g, "&").replace(/^<|>$/g, "");
    let added = false;
    if (raw && !/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) && /^[\w.-]+\.[a-z]{2,}(\/|$|\?)/i.test(raw)) { raw = "https://" + raw; added = true; }
    const res = { input: String(input || "").trim(), removed: [], unwrapped: [], flags: [], shortener: false, idn: null };
    let url = raw;
    for (let hop = 0; hop < 8; hop++) {
      const pp = proofpoint(url); if (pp) { res.unwrapped.push({ via: "Proofpoint URL Defense", from: url }); url = pp; continue; }
      const p = splitUrl(url); if (!p || !p.auth) break;
      const host = p.auth.split("@").pop().split(":")[0].toLowerCase(), path = p.path || "/";
      let next = null, via = null;
      for (const w of WRAPPERS) {
        if (!w.host.test(host) || !w.path.test(path)) continue;
        for (const [k, v] of parseQuery(p.query)) if (v != null && w.keys.includes(k.toLowerCase())) {
          let t = safeDecode(v); if (w.decode) t = w.decode(v) || t;
          if (w.hostOnly) t = "https://" + t;
          if (/^https?:\/\//i.test(t) || (w.hostOnly && t)) { next = t; via = w.via; break; }
        }
        if (next) break;
      }
      if (!next) break;
      res.unwrapped.push({ via, from: url }); url = next;
    }
    const p = splitUrl(url);
    if (!p || !p.auth) { res.url = url; res.clean = url; res.host = ""; res.changed = url !== raw; res.flags.push({ level: "info", text: "Not an absolute URL — nothing to check" }); return res; }
    const userinfo = p.auth.includes("@") ? p.auth.slice(0, p.auth.lastIndexOf("@")) : "";
    const host = p.auth.split("@").pop().split(":")[0].toLowerCase();
    res.host = host; res.hostUnicode = toUnicodeHost(host);
    const kept = [];
    for (const [k, v, rawKv] of parseQuery(p.query)) {
      const d = trackDesc(safeDecode(k), host);
      if (d) res.removed.push({ param: safeDecode(k), value: v == null ? "" : safeDecode(v).slice(0, 120), what: d });
      else kept.push(rawKv);
    }
    let hash = p.hash;
    if (/^(:~:text=|xtor=|utm_)/.test(hash)) { res.removed.push({ param: "#" + hash.split("=")[0], value: hash.slice(0, 80), what: hash.startsWith(":~:") ? "text fragment (shows what you highlighted)" : "fragment tracking tag" }); hash = ""; }
    if (/(^|\.)amazon\.[a-z.]+$/.test(host)) { const m = p.path.match(/\/(?:[^/]+\/)?(?:dp|gp\/product)\/([A-Z0-9]{10})/); if (m && p.path !== "/dp/" + m[1]) { res.removed.push({ param: "path", value: p.path.slice(0, 80), what: "Amazon slug / ref path segments" }); p.path = "/dp/" + m[1]; } }
    p.path = p.path.replace(/\/ref=[^/?#]*$/, (x) => { res.removed.push({ param: "path", value: x, what: "Amazon ref path" }); return ""; });
    res.clean = `${p.scheme}//${p.auth}${p.path}${kept.length ? "?" + kept.join("&") : ""}${hash ? "#" + hash : ""}`;
    if (added && !res.unwrapped.length) res.clean = res.clean.replace(/^https:\/\//, "");
    res.url = url;
    res.changed = res.clean !== res.input;
    // flags
    if (SHORTENERS.has(host)) { res.shortener = true; res.flags.push({ level: NON_REDIRECT_SHORT.has(host) ? "low" : "high", text: NON_REDIRECT_SHORT.has(host) ? `Short-link domain (${host}) — destination is on the same service` : `Link shortener (${host}) — can't be expanded offline; opening it logs your click/IP before redirecting` }); }
    for (const [th, who] of Object.entries(TRACKER_HOSTS)) if ((host + p.path).toLowerCase().includes(th)) { res.flags.push({ level: "high", text: `Known tracker host: ${who} (${th})` }); break; }
    if (res.unwrapped.length) res.flags.push({ level: "medium", text: `Unwrapped ${res.unwrapped.length} redirect wrapper(s): ${res.unwrapped.map((u) => u.via).join(" → ")}` });
    const leftover = kept.map((kv) => kv.split("=")).filter(([k, v]) => REDIRECT_KEYS.has(safeDecode(k).toLowerCase()) && v && /^https?(:|%3a)/i.test(v));
    if (leftover.length) res.flags.push({ level: "medium", text: `Redirect parameter still present (${leftover.map((x) => x[0]).join(", ")}) — it leaks where you go next` });
    if (res.removed.length) res.flags.push({ level: "medium", text: `${res.removed.length} tracking parameter(s) stripped` });
    if (/\/(pixel|track|open|beacon|collect|wf\/open|e\/o)(\.\w{2,4})?$/i.test(p.path) || /\/(pixel|beacon)\//i.test(p.path)) res.flags.push({ level: "medium", text: "Path looks like an open-tracking / beacon endpoint" });
    if (userinfo) res.flags.push({ level: "high", text: `Credentials-style prefix "${userinfo.slice(0, 40)}@" — the real host is ${host}` });
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || /^\d{8,10}$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) res.flags.push({ level: "medium", text: "Raw IP address instead of a domain name" });
    if (p.scheme === "http:") res.flags.push({ level: "low", text: "Plain http — anyone on the network can see and change it" });
    const idn = idnCheck(host);
    if (idn) {
      res.idn = idn;
      if (idn.lookalike) res.flags.push({ level: "high", text: `Homograph: ${idn.unicode} looks like ${idn.lookalike} but uses ${idn.scripts.join(" + ")} characters` });
      else if (idn.mixed) res.flags.push({ level: "high", text: `Mixed scripts in one label (${idn.scripts.join(" + ")}) — classic IDN spoofing` });
      else res.flags.push({ level: "info", text: `Internationalised domain: ${idn.unicode} (${idn.scripts.join(", ")})` });
    }
    return res;
  }

  // ------------------------------------------------------------------ text / HTML analysis (trace.py analyze)
  const IMG = /<img\b[^>]*>/gi, SRC = /\bsrc\s*=\s*['"]?([^'">\s]+)/i, WH = /\b(width|height)\s*=\s*['"]?(\d+)/gi, STYLE = /\bstyle\s*=\s*['"]([^'"]*)['"]/i;
  const HREF = /<a\b[^>]*\bhref\s*=\s*['"]?([^'">\s]+)/gi, LINKS = /\b(?:https?:\/\/|www\.)[^\s<>"'`)\]]+/gi;
  const unesc = (s) => s.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
  function looksLikePixel(tag) {
    const dims = [...tag.matchAll(WH)].map((m) => +m[2]);
    const st = tag.match(STYLE);
    return dims.some((v) => v <= 2) || !!(st && /display\s*:\s*none|width\s*:\s*[012]px|height\s*:\s*[012]px|opacity\s*:\s*0|visibility\s*:\s*hidden/i.test(st[1]));
  }
  function analyze(text) {
    text = String(text || "").trim();
    const isHtml = /<(img|a|html|body|table|div)\b/i.test(text);
    const out = { mode: isHtml ? "html" : "url", links: [], beacons: [], sanitized: [], remoteImages: 0, summary: "" };
    if (!isHtml) {
      const urls = W.uniq((text.match(LINKS) || []).map((u) => u.replace(/[.,;:!?]+$/, "")));
      const list = urls.length ? urls : text.split(/\s+/).filter((x) => /\.\w{2,}/.test(x)).slice(0, 1);
      for (const u of list) { const r = cleanUrl(u); out.links.push(r); out.sanitized.push(r.clean); }
      out.cleanedText = urls.length ? out.links.reduce((t, r) => t.split(r.input).join(r.clean), text) : out.sanitized.join("\n");
    } else {
      for (const tag of text.match(IMG) || []) {
        out.remoteImages++;
        const m = tag.match(SRC); if (!m) continue;
        const url = unesc(m[1]); const p = splitUrl(url); const host = p && p.auth ? p.auth.split("@").pop().split(":")[0].toLowerCase() : "";
        const who = Object.entries(TRACKER_HOSTS).find(([th]) => url.toLowerCase().includes(th));
        if (looksLikePixel(tag) || who || /\/(open|track|pixel|beacon|wf\/open|e\/o)(\/|\.|\?|$)/i.test(url))
          out.beacons.push({ url: url.slice(0, 240), host, tracker: who ? who[1] : "likely open-tracking pixel", level: who ? "high" : "medium" });
      }
      for (const href of W.uniq([...text.matchAll(HREF)].map((m) => unesc(m[1])))) if (/^https?:\/\//i.test(href)) { const r = cleanUrl(href); out.links.push(r); out.sanitized.push(r.clean); }
    }
    const hi = out.links.reduce((n, l) => n + l.flags.filter((f) => f.level === "high").length, 0);
    const stripped = out.links.reduce((n, l) => n + l.removed.length, 0);
    out.summary = isHtml
      ? `${out.beacons.length} tracking beacon(s), ${out.remoteImages} remote image(s), ${out.links.length} link(s), ${stripped} tracker(s) stripped. Remote images confirm your address is live and log your IP — load them only from senders you trust.`
      : `${out.links.length} link(s), ${stripped} tracker(s) stripped, ${out.links.reduce((n, l) => n + l.unwrapped.length, 0)} redirect(s) unwrapped, ${hi} high-risk flag(s).`;
    return out;
  }

  W.eng.trace = { cleanUrl, analyze, punyDecode, punyEncode, toUnicodeHost, idnCheck, TRACK_PARAMS, SHORTENERS };
})(typeof window !== "undefined" ? window.W : globalThis.W);
