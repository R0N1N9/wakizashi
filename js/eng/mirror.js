/* MIRROR — "what sites see". Pure scoring of a browser fingerprint the view gathers locally, plus the persona
 * hygiene checks of Katana shinobi/mirror.py (function-word stylometry, locale tells, cross-persona contamination).
 *
 *   score(facts) → { signals[{id,label,value,bits,rating,why,tip}], bits, effectiveBits, oneIn, population, verdict, tips[] }
 *   stylometry([{label,text}]) / tellsScan(text) / contamination(personas) — straight ports of mirror.py
 *
 * Uniqueness heuristic: each signal gets a surprisal estimate (bits ≈ −log2 of how common its value is), tuned
 * from published fingerprinting studies (EFF Panopticlick 2010, AmIUnique 2016, Gómez-Boix et al. 2018). Signals
 * are correlated (an iPhone UA implies its screen size, fonts and GPU), so the sum is discounted by 30% before
 * comparing against ~5.5 billion internet users (≈ 32.4 bits). It is an order-of-magnitude estimate, not a
 * measurement — a real study needs a population to compare against, and this page never sends your data anywhere.
 */
(function (W) {
  "use strict";
  const POP = 5.5e9, POP_BITS = Math.log2(POP), CORRELATION = 0.7;
  const rate = (bits) => bits >= 6 ? "high" : bits >= 3 ? "medium" : "low";
  const COMMON_SCREENS = new Set(["1920x1080", "1366x768", "1536x864", "1440x900", "1280x720", "2560x1440", "1600x900", "1280x800", "390x844", "393x873", "414x896", "375x812", "360x800", "412x915", "393x852", "430x932", "375x667", "1280x1024", "1680x1050", "3840x2160", "2560x1600", "1512x982", "1470x956", "1728x1117"]);
  const COMMON_TZ = { "America/New_York": 3.5, "America/Chicago": 4.2, "America/Los_Angeles": 4, "Europe/London": 4.5, "Europe/Berlin": 4.5, "Europe/Paris": 4.8, "Asia/Kolkata": 3.5, "Asia/Shanghai": 3, "Asia/Tokyo": 4.5, "America/Sao_Paulo": 4.5, "UTC": 7 };

  function uaBits(ua, hints) {
    if (!ua) return [2, "No user agent"];
    const m = ua.match(/(Chrome|Firefox|Edg|Safari|OPR|SamsungBrowser)\/(\d+)/g) || [];
    const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /SamsungBrowser/.test(ua) ? "Samsung" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "other";
    const os = /Windows NT/.test(ua) ? "Windows" : /Mac OS X/.test(ua) && !/Mobile/.test(ua) ? "macOS" : /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : /CrOS/.test(ua) ? "ChromeOS" : "other";
    let bits = 6; // a mainstream, current UA string is shared by a few % of users
    if (browser === "other" || os === "other") bits += 5;
    if (browser === "Firefox" || browser === "Opera" || browser === "Samsung") bits += 1.5;
    if (os === "Linux") bits += 2.5;
    if (/HeadlessChrome|Electron|PhantomJS/i.test(ua)) bits += 6;
    if (/Android/.test(ua) && /; [^;)]*Build\//.test(ua)) bits += 4; // device model in the UA
    if (!m.length) bits += 3;
    if (hints && hints.model) bits += 3;
    return [bits, `${browser} on ${os}`];
  }

  /** facts: what the view could read. Missing fields are simply skipped. */
  function score(f = {}) {
    const S = [];
    const add = (id, label, value, bits, why, tip) => S.push({ id, label, value: value == null || value === "" ? "—" : String(value), bits: +(+bits).toFixed(1), rating: rate(bits), why, tip });
    const [ub, ubl] = uaBits(f.ua, f.uaHints);
    add("ua", "User agent", f.ua, ub, `Identifies ${ubl}, its exact version and often the OS build. Sent with every request.`, "Keep the browser updated (old versions stand out) and avoid UA-spoofing extensions — a fake UA that disagrees with other signals is rarer still.");
    if (f.uaHints) add("hints", "Client hints", [f.uaHints.platform, f.uaHints.platformVersion, f.uaHints.model, f.uaHints.arch, f.uaHints.bitness].filter(Boolean).join(" · ") || (f.uaHints.brands || []).join(", "), (f.uaHints.platformVersion ? 1.5 : 0.5) + (f.uaHints.model ? 3 : 0), "Chromium's structured UA. High-entropy values (exact OS version, device model) are only given when a site asks for them.", "Brave/Firefox don't expose high-entropy hints; Chrome reveals them to any site that requests them.");
    const langs = f.languages || (f.language ? [f.language] : []);
    const primary = String(langs[0] || "").toLowerCase();
    add("lang", "Languages", langs.join(", "), (primary === "en-us" ? 1.5 : /^(en|es|zh|fr|de|pt|ru|ja)/.test(primary) ? 3.5 : 6) + Math.max(0, langs.length - 1) * 1.6, "The Accept-Language header and navigator.languages. A multi-language list is far rarer than one language.", "List only one language (the one most visitors to your sites use) in browser settings.");
    const tzB = f.timezone ? (COMMON_TZ[f.timezone] || 5.5) : 3;
    add("tz", "Time zone", f.timezone ? `${f.timezone} (UTC${f.tzOffset >= 0 ? "+" : ""}${(f.tzOffset / 60).toFixed(f.tzOffset % 60 ? 1 : 0)})` : null, tzB, "Narrows you to a region. A VPN exit in another country plus your real time zone is a classic correlation.", "Tor Browser / Mullvad Browser / Firefox resistFingerprinting report UTC. Otherwise match your VPN exit's region if you rely on location hiding.");
    if (f.screen) {
      const sz = `${f.screen.w}x${f.screen.h}`;
      add("screen", "Screen", `${sz} @${f.dpr || 1}x · ${f.screen.depth}-bit · avail ${f.screen.availW}x${f.screen.availH}`,
        (COMMON_SCREENS.has(sz) ? 3 : 7) + ((f.dpr || 1) % 1 ? 2 : 0) + (f.screen.depth !== 24 && f.screen.depth !== 30 ? 2 : 0) + (f.screen.h - f.screen.availH > 120 ? 1.5 : 0),
        "Resolution, pixel ratio and the space your taskbar/dock takes. Odd sizes or zoom levels stand out.", "Keep the browser window maximised at a standard zoom; letterboxing in Tor/Mullvad Browser rounds the window size.");
    }
    if (f.cores != null) add("cores", "CPU threads", f.cores, [4, 8].includes(+f.cores) ? 2 : [2, 6, 12, 16].includes(+f.cores) ? 3 : 5, "navigator.hardwareConcurrency — splits users by CPU class.", "Hardened browsers report a fixed value (2 or 4).");
    if (f.memory != null) add("mem", "Device memory", f.memory + " GB", +f.memory === 8 ? 1.5 : 2.5, "navigator.deviceMemory (Chromium only, rounded and capped at 8 GB).", "Firefox/Safari don't expose it.");
    if (f.platform) add("platform", "Platform", f.platform, /^(Win32|MacIntel|iPhone|Linux armv8l|Linux aarch64)$/.test(f.platform) ? 1.5 : 4, "navigator.platform — redundant with the UA unless they disagree.", "Don't spoof the UA without spoofing this too (mismatches are very identifying).");
    add("storage", "Cookies & storage", [f.cookies ? "cookies on" : "cookies off", f.localStorage ? "localStorage" : "no localStorage", f.indexedDB ? "IndexedDB" : "no IndexedDB"].join(" · "), (f.cookies ? 0.3 : 4) + (f.localStorage ? 0 : 2), "Whether a site can store an ID on your device at all. Stored IDs are the strongest tracker — no fingerprint needed.", "Block third-party cookies, clear site data on close, use container tabs / separate profiles per identity.");
    add("dnt", "Do Not Track / GPC", `DNT ${f.dnt ? "on" : "off"} · GPC ${f.gpc ? "on" : "off"}`, (f.dnt ? 1.2 : 0.3) + (f.gpc ? 1.5 : 0.2), "Privacy signals. Ironically DNT is a bit of entropy since few people set it; GPC has legal weight in some US states / under GDPR.", "Keep GPC on (it can legally bind sites); DNT is obsolete — leave it off unless your browser forces it.");
    add("touch", "Touch support", `${f.touchPoints || 0} touch point(s)`, (f.touchPoints > 0) === !!f.mobile ? 0.8 : 3, "maxTouchPoints. A touch screen on a desktop OS (or none on a phone) narrows the device.", "Nothing to do — just know it's visible.");
    if (f.canvasHash) add("canvas", "Canvas fingerprint", f.canvasHash.slice(0, 16), f.canvasNoise ? 1 : 8.5, f.canvasNoise ? "Canvas read-back looks randomised (your browser adds noise) — this hash changes per visit." : "Drawing the same text/shapes produces slightly different pixels per GPU, driver and font stack. Stable and highly identifying.", "Brave (farbling), Firefox resistFingerprinting, Tor/Mullvad Browser randomise or block canvas read-back.");
    if (f.webglRenderer || f.webglVendor) add("webgl", "WebGL renderer", [f.webglVendor, f.webglRenderer].filter(Boolean).join(" · "), /SwiftShader|llvmpipe|Software/i.test(f.webglRenderer || "") ? 5 : /Apple GPU|Apple M\d/.test(f.webglRenderer || "") ? 4 : 7, "The unmasked GPU string names your graphics chip and driver.", "Firefox resistFingerprinting / Tor report a generic renderer; disabling WebGL also works but is itself rare.");
    else add("webgl", "WebGL renderer", "unavailable", 4, "WebGL is disabled or blocked — fairly uncommon.", "Fine for privacy; just know it's a signal too.");
    if (f.audio != null) add("audio", "Audio stack", f.audio ? `AudioContext · ${f.sampleRate || "?"} Hz · ${f.audioChannels || "?"} ch` : "unavailable", f.audio ? (+f.sampleRate === 48000 || +f.sampleRate === 44100 ? 2 : 4) : 3, "Audio sample rate and channel count; scripts can also render an oscillator offline for a per-device hash (not done here).", "Hardened browsers fix or randomise audio rendering.");
    if (f.fonts) add("fonts", "Installed fonts (probe)", `${f.fonts.length}/${f.fontsTested || "?"}: ${f.fonts.slice(0, 8).join(", ")}${f.fonts.length > 8 ? "…" : ""}`, Math.min(12, 2 + f.fonts.length * 0.7), "Measuring text in candidate fonts reveals which are installed. Office suites, design tools and language packs add rare ones.", "Tor/Mullvad Browser and Firefox resistFingerprinting restrict fonts to a bundled set.");
    if (f.webrtc != null) add("webrtc", "WebRTC", f.webrtc ? "available" : "disabled", f.webrtc ? 0.5 : 3, "WebRTC can reveal local/public IP addresses via ICE candidates — even behind some VPNs (not tested here: that would need a network request).", "Use a VPN that blocks WebRTC leaks, or set WebRTC IP handling to 'disable non-proxied UDP'.");
    if (f.media) add("media", "Media devices", `${f.media.audioinput || 0} mic · ${f.media.videoinput || 0} cam · ${f.media.audiooutput || 0} out`, 2 + ((f.media.audioinput || 0) + (f.media.videoinput || 0) > 2 ? 1.5 : 0), "Counts are visible without permission (names need permission).", "Unplug unused devices; hardened browsers hide counts.");
    if (f.webdriver) add("bot", "Automation flag", "navigator.webdriver = true", 8, "The browser says it's controlled by automation — extremely rare for real users.", "Only expected in testing tools.");
    if (f.colorScheme || f.reducedMotion) add("prefs", "Display preferences", [f.colorScheme, f.reducedMotion ? "reduced motion" : "", f.contrast ? "more contrast" : ""].filter(Boolean).join(" · "), (f.colorScheme === "dark" ? 1 : 0.5) + (f.reducedMotion ? 2 : 0) + (f.contrast ? 2 : 0), "CSS media queries expose dark mode and accessibility settings.", "Accessibility comes first — just know these are visible.");
    if (f.pdfViewer != null) add("pdf", "Built-in PDF viewer", f.pdfViewer ? "yes" : "no", f.pdfViewer ? 0.2 : 2.5, "Whether the browser can show PDFs inline.", "—");

    const bits = S.reduce((n, s) => n + s.bits, 0);
    const eff = bits * CORRELATION;
    const oneIn = Math.pow(2, Math.min(eff, 60));
    const unique = eff >= POP_BITS;
    const verdict = unique ? "Very likely unique among all internet users" : eff >= POP_BITS - 6 ? "Probably unique on any large site" : eff >= 18 ? "Identifiable within a large crowd" : "Blends in reasonably well";
    const top = S.slice().sort((a, b) => b.bits - a.bits);
    const tips = W.uniq(top.filter((s) => s.rating !== "low" && s.tip && s.tip !== "—").slice(0, 6).map((s) => `${s.label}: ${s.tip}`)).concat(PERSONA_TIPS);
    return { signals: S, bits: +bits.toFixed(1), effectiveBits: +eff.toFixed(1), oneIn, population: POP, populationBits: +POP_BITS.toFixed(1), unique, verdict, tips,
      note: `Sum of per-signal estimates (${bits.toFixed(1)} bits) × ${CORRELATION} correlation discount = ${eff.toFixed(1)} bits ≈ 1 in ${fmtBig(oneIn)}. ~${fmtBig(POP)} internet users ≈ ${POP_BITS.toFixed(1)} bits.` };
  }
  const PERSONA_TIPS = [
    "Compartmentalise: one browser profile (or container) per identity — a fingerprint links accounts used from the same profile.",
    "Fingerprint resistance works best when many people share it: Tor Browser or Mullvad Browser make everyone look the same, while a unique mix of privacy extensions makes you stand out.",
    "Writing style is a fingerprint too — check personas against each other in the Stylometry tab before publishing as a cover identity.",
  ];
  const fmtBig = (n) => n >= 1e12 ? (n / 1e12).toFixed(n >= 1e13 ? 0 : 1) + " trillion" : n >= 1e9 ? (n / 1e9).toFixed(1) + " billion" : n >= 1e6 ? (n / 1e6).toFixed(1) + " million" : n >= 1e3 ? Math.round(n / 1e3) + " thousand" : String(Math.round(n));

  // ------------------------------------------------------------------ stylometry (port of mirror.py)
  const FUNCTION_WORDS = ("a about above after again against all am an and any are aren't as at be because been before being below between both but by can cannot could couldn't did didn't do does doesn't doing don't down during " +
    "each few for from further had hadn't has hasn't have haven't having he he'd he'll he's her here hers herself him himself his how i i'd i'll i'm i've if in into is isn't it it's its itself just let's me " +
    "more most my myself no nor not of off on once only or other ought our ours ourselves out over own same she should so some such than that the their them themselves then there these they this those through to " +
    "too under until up very was we were what when where which while who whom why will with would you your yours").split(" ");
  const LOCALE_TELLS = {
    "British/Commonwealth spelling": /\b(colour|favour|behaviour|organise|realise|analyse|centre|licence|defence|catalogue|travelled|programme|whilst|flat|lift|mobile|holiday)\b/gi,
    "American spelling": /\b(color|favor|behavior|organize|realize|analyze|center|license|defense|catalog|traveled|apartment|elevator|cellphone|vacation)\b/gi,
    "time zone / locale mention": /\b(GMT|UTC|EST|PST|CET|AEST|IST)\b|\b\d{1,2}(:\d{2})?\s?(am|pm)\b/gi,
    "emoji / emoticon habit": /[:;]-?[)D(P]|[\u{1F300}-\u{1FAFF}]/gu,
    "date format DD/MM": /\b(3[01]|[12]\d|0?[1-9])\/(1[0-2]|0?[1-9])\/\d{2,4}\b/g,
  };
  const tokens = (t) => String(t).toLowerCase().match(/[a-z']+/g) || [];
  function vector(text) {
    const toks = tokens(text), n = toks.length || 1, c = {};
    for (const t of toks) c[t] = (c[t] || 0) + 1;
    const v = {}; for (const w of FUNCTION_WORDS) v[w] = (c[w] || 0) / n;
    const words = text.match(/\b\w+\b/g) || [], wc = words.length || 1;
    const sents = text.split(/[.!?]+/).filter((s) => s.trim()), sc = sents.length || 1;
    v._avg_word_len = (words.reduce((a, w) => a + w.length, 0) / wc) / 12;
    v._ttr = new Set(words.map((w) => w.toLowerCase())).size / wc;
    v._avg_sent_len = Math.min((wc / sc) / 40, 1);
    v._comma_rate = Math.min((text.match(/,/g) || []).length / wc, 1);
    v._excl_rate = Math.min((text.match(/!/g) || []).length / sc, 1);
    return v;
  }
  function cosine(a, b) {
    let dot = 0, na = 0, nb = 0;
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) dot += (a[k] || 0) * (b[k] || 0);
    for (const x of Object.values(a)) na += x * x; for (const x of Object.values(b)) nb += x * x;
    return na && nb ? dot / Math.sqrt(na * nb) : 0;
  }
  function tellsScan(text, label) {
    const hits = [];
    for (const [name, re] of Object.entries(LOCALE_TELLS)) { const f = (String(text).match(re) || []).filter(Boolean).slice(0, 5); if (f.length) hits.push({ tell: name, examples: f }); }
    return { label: label || null, hits };
  }
  function stylometry(samples) {
    samples = (samples || []).filter((s) => s && String(s.text || "").trim());
    if (samples.length < 2) throw new Error("Provide at least two writing samples to compare");
    const vecs = samples.map((s, i) => [s.label || `Sample ${i + 1}`, vector(s.text), tokens(s.text).length]);
    const pairs = [];
    for (let i = 0; i < vecs.length; i++) for (let j = i + 1; j < vecs.length; j++) {
      const sim = cosine(vecs[i][1], vecs[j][1]);
      pairs.push({ a: vecs[i][0], b: vecs[j][0], similarity: +sim.toFixed(4), verdict: sim >= 0.97 ? "same author likely" : sim >= 0.93 ? "possible match" : "different authors likely", low_confidence: Math.min(vecs[i][2], vecs[j][2]) < 60 });
    }
    pairs.sort((a, b) => b.similarity - a.similarity);
    return { pairs, samples: vecs.map((v) => ({ label: v[0], tokens: v[2] })), tells: samples.map((s) => tellsScan(s.text, s.label)),
      note: "Function-word stylometry. A strong signal across 200+ words, a hint below that. Not courtroom proof." };
  }

  // ------------------------------------------------------------------ persona contamination (port of mirror.py)
  const norm = (v) => String(v).trim().toLowerCase().replace(/\s+/g, "");
  function contamination(personas) {
    const idx = new Map();
    for (const p of personas || []) {
      const name = p.name || "unnamed";
      for (const kind of ["handles", "emails", "avatars"]) for (const v of p[kind] || []) {
        const k = kind + "\0" + norm(v); if (!norm(v)) continue;
        if (!idx.has(k)) idx.set(k, { value: v, kind, personas: new Set() });
        idx.get(k).personas.add(name);
      }
    }
    const collisions = [...idx.values()].filter((d) => d.personas.size > 1).map((d) => ({ kind: d.kind, value: d.value, shared_by: [...d.personas].sort() }));
    const risks = (personas || []).map((p) => {
      const name = p.name || "unnamed", handles = p.handles || [], emails = p.emails || [];
      const shared = collisions.filter((c) => c.shared_by.includes(name));
      let score = 0; const reasons = [];
      if (shared.length) { score += 40 + 10 * (shared.length - 1); reasons.push(`${shared.length} identifier(s) shared with another persona`); }
      const locals = new Set(emails.map((e) => norm(String(e).split("@")[0])));
      if (handles.some((h) => locals.has(norm(h)))) { score += 20; reasons.push("handle matches an email local-part"); }
      if (handles.length > 1 && new Set(handles.map(norm)).size < handles.length) { score += 10; reasons.push("duplicate handles within the persona"); }
      if (!p.notes) reasons.push("no cover notes / backstory recorded");
      return { persona: name, score: Math.min(score, 100), level: score >= 60 ? "critical" : score >= 40 ? "high" : score >= 20 ? "medium" : "low", reasons };
    }).sort((a, b) => b.score - a.score);
    return { collisions, risks, summary: `${collisions.length} cross-persona identifier collision(s) across ${(personas || []).length} persona(s).` };
  }

  W.eng.mirror = { score, stylometry, tellsScan, contamination, fmtBig, FUNCTION_WORDS };
})(typeof window !== "undefined" ? window.W : globalThis.W);
