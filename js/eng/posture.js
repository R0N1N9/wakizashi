/* POSTURE — pure scoring for the browser/device posture audit (the web cousin of Karambit's Aegis
 * HardeningAudit). The view gathers a facts object with local APIs only; this turns it into weighted
 * checks and a 0–100 score. Nothing here touches the DOM or the network.
 *
 *   W.eng.posture.evaluate(facts) → {checks[{id, group, title, status, weight, detail, fix}], score, posture,
 *                                   counts{pass, warn, fail, info}, fixes[], browser, os}
 *   W.eng.posture.parseUA(ua, uaData) → {name, major, engine, os, osVersion, mobile}
 *   W.eng.posture.expectedMajor(name, now) → latest stable major we'd expect on that date
 * status: "pass" | "warn" | "fail" | "info". Score = weighted pass ratio (warn = half, info excluded).
 */
(function (W) {
  "use strict";

  const DAY = 86400000;
  // release-train anchors (major, stable date) — 4-week cadence for Chrome and Firefox since these releases
  const TRAINS = { chromium: [142, Date.UTC(2025, 9, 28)], firefox: [145, Date.UTC(2025, 10, 11)] };
  const FIREFOX_ESR = [115, 128, 140, 153];

  function expectedMajor(name, now) {
    const t = typeof now === "number" ? now : Date.parse(now || "") || Date.now();
    const fam = /^(chrome|edge|brave|chromium)/i.test(name) ? "chromium" : /firefox/i.test(name) ? "firefox" : /safari/i.test(name) ? "safari" : null;
    if (fam === "chromium" || fam === "firefox") { const [m, d] = TRAINS[fam]; return t < d ? null : m + Math.floor((t - d) / (28 * DAY)); }
    if (fam === "safari") {
      const d = new Date(t), y = d.getUTCFullYear() - (d.getUTCMonth() < 8 ? 1 : 0);   // new Safari every September
      return y >= 2025 ? 26 + (y - 2025) : y - 2006;
    }
    return null;
  }

  function parseUA(ua, uaData) {
    ua = String(ua || "");
    const o = { name: "Unknown", major: null, engine: "unknown", os: "Unknown", osVersion: null, mobile: /Mobi|Android|iPhone|iPad/i.test(ua) };
    const brands = (uaData && (uaData.fullVersionList || uaData.brands)) || [];
    const brand = (re) => brands.find((b) => re.test(b.brand));
    let m;
    if ((m = /Edg(?:e|A|iOS)?\/(\d+)/.exec(ua))) Object.assign(o, { name: "Edge", major: +m[1], engine: "blink" });
    else if ((m = /(?:OPR|Opera)\/(\d+)/.exec(ua))) Object.assign(o, { name: "Opera", major: +m[1], engine: "blink" });
    else if ((m = /SamsungBrowser\/(\d+)/.exec(ua))) Object.assign(o, { name: "Samsung Internet", major: +m[1], engine: "blink" });
    else if ((m = /(?:Firefox|FxiOS)\/(\d+)/.exec(ua))) Object.assign(o, { name: "Firefox", major: +m[1], engine: /FxiOS/.test(ua) ? "webkit" : "gecko" });
    else if ((m = /(?:Chrome|CriOS|HeadlessChrome|Chromium)\/(\d+)/.exec(ua))) Object.assign(o, { name: /HeadlessChrome/.test(ua) ? "Chrome (headless)" : "Chrome", major: +m[1], engine: /CriOS/.test(ua) ? "webkit" : "blink" });
    else if ((m = /Version\/(\d+)[\d.]* (?:Mobile\/\S+ )?Safari/.exec(ua))) Object.assign(o, { name: "Safari", major: +m[1], engine: "webkit" });
    const br = brand(/Brave/);
    if (br) Object.assign(o, { name: "Brave", major: +String(br.version).split(".")[0] || o.major });
    // iOS browsers all run WebKit: their version is the OS's Safari
    if (/CriOS|FxiOS|EdgiOS/.test(ua)) o.engine = "webkit";

    if ((m = /Windows NT (\d+\.\d+)/.exec(ua))) { o.os = "Windows"; o.osVersion = m[1]; }
    else if ((m = /Android (\d+(?:\.\d+)?)/.exec(ua))) { o.os = "Android"; o.osVersion = m[1]; }
    else if ((m = /(?:iPhone|iPad|iPod).*? OS (\d+)[_.](\d+)/.exec(ua))) { o.os = "iOS"; o.osVersion = m[1] + "." + m[2]; }
    else if ((m = /Mac OS X (\d+)[_.](\d+)/.exec(ua))) { o.os = "macOS"; o.osVersion = m[1] + "." + m[2]; }
    else if (/CrOS/.test(ua)) o.os = "ChromeOS";
    else if (/Linux/.test(ua)) o.os = "Linux";
    if (uaData) {
      if (uaData.platform) o.os = { "Chrome OS": "ChromeOS", macOS: "macOS" }[uaData.platform] || uaData.platform;
      if (uaData.platformVersion) o.platformVersion = String(uaData.platformVersion);
      if (typeof uaData.mobile === "boolean") o.mobile = uaData.mobile;
    }
    return o;
  }

  function osCheck(b) {
    const pv = b.platformVersion ? parseInt(b.platformVersion, 10) : null;
    if (b.os === "Windows") {
      if (pv != null && !isNaN(pv)) {
        if (pv >= 13) return ["pass", "Windows 11 (platform version " + b.platformVersion + ")"];
        if (pv >= 1) return ["fail", "Windows 10 — out of mainstream support since October 2025", "Upgrade to Windows 11, or enrol in Extended Security Updates while you migrate."];
        return ["fail", "Windows 7/8.x — no longer receives security updates", "Move to a supported OS (Windows 11 or a current Linux/macOS)."];
      }
      return ["info", "Windows (exact version hidden by the browser)", "Check Settings → Windows Update; Windows 10 is out of support."];
    }
    if (b.os === "Android") {
      const v = pv != null && !isNaN(pv) ? pv : b.osVersion && b.osVersion !== "10" ? parseInt(b.osVersion, 10) : null;   // Chrome freezes UA at "Android 10"
      if (v == null) return ["info", "Android (version hidden by the browser)", "Settings → System → Software update; aim for Android 14+."];
      if (v >= 14) return ["pass", `Android ${v}`];
      if (v >= 12) return ["warn", `Android ${v} — nearing end of security support`, "Update the OS, or plan a device that still gets monthly patches."];
      return ["fail", `Android ${v} — no longer receives security patches`, "Replace or update the device; unpatched Android is trivially exploitable via the browser."];
    }
    if (b.os === "iOS") {
      const v = parseInt(b.osVersion, 10);
      if (v >= 18) return ["pass", `iOS ${b.osVersion}${v === 18 ? " (or newer — Safari freezes this value)" : ""}`];
      if (v === 17) return ["warn", `iOS ${b.osVersion} — older release`, "Settings → General → Software Update."];
      return ["fail", `iOS ${b.osVersion} — no longer patched`, "Update iOS, or replace the device if it can't run a current release."];
    }
    if (b.os === "macOS") return ["info", "macOS (browsers freeze the reported version)", "Apple menu → System Settings → General → Software Update."];
    if (b.os === "ChromeOS") return ["info", "ChromeOS", "Check that the device hasn't passed its Auto Update Expiration date."];
    if (b.os === "Linux") return ["info", "Linux", "Keep your distribution on a supported release and apply updates."];
    return ["info", "Operating system not identified"];
  }

  const PERMS = [
    ["camera", "Camera", 8], ["microphone", "Microphone", 8], ["geolocation", "Location", 6],
    ["notifications", "Notifications", 5], ["clipboard-read", "Clipboard read", 3], ["midi", "MIDI (SysEx)", 2],
  ];

  function evaluate(f) {
    f = f || {};
    const now = Date.parse(f.now || "") || Date.now();
    const b = parseUA(f.ua, f.uaData);
    const checks = [];
    const add = (id, group, title, weight, status, detail, fix) => checks.push({ id, group, title, weight, status, detail: detail || "", fix: status === "pass" || status === "info" ? (fix && status === "info" ? fix : "") : fix || "" });

    // --- browser & platform
    add("secure-context", "Browser", "Secure context (HTTPS)", 10, f.secureContext ? "pass" : "fail",
      f.secureContext ? `Served over ${f.protocol || "https:"} — WebCrypto, service worker and storage protections are active` : `Page loaded over ${f.protocol || "?"} — traffic can be read or modified`,
      "Open Wakizashi over https:// (or localhost). Never use security tools over plain HTTP.");
    const exp = b.major != null ? expectedMajor(b.name, now) : null;
    if (b.major != null && exp != null) {
      const behind = exp - b.major;
      const esr = /Firefox/.test(b.name) && FIREFOX_ESR.includes(b.major);
      const safari = b.name === "Safari";
      // ±1 release of slack for holiday skips / staged roll-outs
      const st = behind <= (safari ? 0 : 3) ? "pass" : esr && behind <= 14 ? "warn" : behind <= (safari ? 1 : 6) ? "warn" : "fail";
      add("browser-current", "Browser", "Browser up to date", 15, st,
        `${b.name} ${b.major}${behind > 0 ? ` — about ${behind} release${behind === 1 ? "" : "s"} behind (expected ≈ ${exp})` : " — current"}${esr ? " (ESR channel)" : ""}`,
        "Update the browser now (Menu → Help → About) and restart it; turn on automatic updates. Browser bugs are the #1 drive-by entry point.");
    } else add("browser-current", "Browser", "Browser up to date", 15, "info", `${b.name}${b.major ? " " + b.major : ""} — version freshness can't be judged`, "Keep automatic updates on.");
    const [ost, odet, ofix] = osCheck(b);
    add("os-support", "Browser", "Operating system supported", 10, ost, odet, ofix);
    add("automation", "Browser", "Not under automation control", 4, f.webdriver ? "warn" : "pass",
      f.webdriver ? "navigator.webdriver is true — this browser is being driven by automation (WebDriver/CDP)" : "No automation flag",
      "If you didn't start a test harness, close the browser and check for remote-debugging flags or unwanted extensions.");

    // --- privacy signals
    add("gpc", "Privacy", "Global Privacy Control", 6, f.gpc === true ? "pass" : "warn",
      f.gpc === true ? "Sec-GPC is sent: sites are told not to sell/share your data" : f.gpc === false ? "GPC is supported but off" : "GPC not supported by this browser",
      "Turn on GPC: Firefox → Settings → Privacy → “Tell websites not to sell or share my data”; Brave/DuckDuckGo send it by default; Chrome needs an extension.");
    add("dnt", "Privacy", "Do Not Track header", 2, f.dnt === "1" ? "pass" : "info", f.dnt === "1" ? "DNT: 1 is sent" : "DNT off — deprecated; GPC is the signal that carries legal weight", "");
    let tpc = f.thirdPartyCookies || "unknown", tpcWhy = "";
    if (tpc === "unknown") {
      if (/Firefox/.test(b.name)) { tpc = "blocked"; tpcWhy = "Firefox Total Cookie Protection partitions third-party cookies by default"; }
      else if (b.engine === "webkit" || b.name === "Safari") { tpc = "blocked"; tpcWhy = "WebKit Intelligent Tracking Prevention blocks third-party cookies by default"; }
      else if (b.name === "Brave") { tpc = "blocked"; tpcWhy = "Brave Shields block cross-site cookies by default"; }
      else if (/Chrome|Edge|Opera|Samsung/.test(b.name)) { tpc = "likely-allowed"; tpcWhy = `${b.name} allows third-party cookies unless you turn them off`; }
    }
    add("third-party-cookies", "Privacy", "Third-party cookies blocked", 8,
      tpc === "blocked" ? "pass" : tpc === "allowed" ? "fail" : tpc === "likely-allowed" ? "warn" : "info",
      tpcWhy || (tpc === "allowed" ? "Cross-site cookies are allowed" : tpc === "blocked" ? "Cross-site cookies are blocked" : "Could not be determined offline"),
      "Block third-party cookies: Chrome → Settings → Privacy and security → Third-party cookies → Block; Edge → Cookies and site permissions; or switch to Firefox/Brave/Safari.");
    const fp = [];
    if (f.deviceMemory) fp.push(`device memory ${f.deviceMemory} GB`);
    if (f.hardwareConcurrency && f.hardwareConcurrency > 8) fp.push(`${f.hardwareConcurrency} CPU threads`);
    if (f.screen && f.screen.w && ![[1920, 1080], [1366, 768], [1536, 864], [1440, 900], [1280, 720], [390, 844], [393, 873], [412, 915], [414, 896], [375, 812], [360, 800], [2560, 1440]].some(([w, h]) => w === f.screen.w && h === f.screen.h)) fp.push(`uncommon screen ${f.screen.w}×${f.screen.h}@${f.screen.dpr || 1}x`);
    if ((f.languages || []).length > 2) fp.push(`${f.languages.length} languages`);
    if (f.timezone && f.timezone !== "UTC" && f.timezone !== "Etc/UTC") fp.push(`time zone ${f.timezone}`);
    if (f.apis && f.apis.getBattery) fp.push("Battery Status API");
    if (f.uaData && f.uaData.highEntropy) fp.push("UA client hints (high-entropy) readable");
    if ((f.plugins || 0) > 5) fp.push(`${f.plugins} plugins`);
    if (f.apis && f.apis.webgl && f.apis.webglRenderer) fp.push(`GPU "${String(f.apis.webglRenderer).slice(0, 40)}"`);
    const rfp = /Firefox/.test(b.name) && (f.timezone === "UTC" || f.timezone === "Etc/UTC");
    add("fingerprint", "Privacy", "Fingerprinting surface", 6, rfp || fp.length <= 3 ? "pass" : fp.length <= 5 ? "warn" : "fail",
      (rfp ? "Looks like resistFingerprinting is on. " : "") + (fp.length ? "Distinguishing signals exposed: " + fp.join(", ") : "Few distinguishing signals exposed"),
      "Use a browser with fingerprinting protection (Brave, Firefox with Enhanced Tracking Protection “Strict”, Mullvad/Tor Browser) and avoid niche extensions.");
    const rtc = f.webrtc || {};
    if (!rtc.available) add("webrtc", "Privacy", "WebRTC local-IP leak", 8, "pass", "WebRTC is unavailable or disabled — no ICE candidates can leak", "");
    else if (rtc.leak === "private" || rtc.leak === "public") add("webrtc", "Privacy", "WebRTC local-IP leak", 8, "fail",
      `ICE host candidates expose a raw ${rtc.leak} IP (${(rtc.ips || []).slice(0, 3).join(", ")}) to any page`,
      "Enable mDNS ICE candidates (default in current browsers), use uBlock Origin “Prevent WebRTC leaking local IP”, or set media.peerconnection.ice.default_address_only in Firefox.");
    else if (rtc.leak === "mdns" || rtc.leak === "none") add("webrtc", "Privacy", "WebRTC local-IP leak", 8, "pass", rtc.leak === "mdns" ? "Host candidates are masked with mDNS (.local) names" : "No host candidates gathered", "");
    else add("webrtc", "Privacy", "WebRTC local-IP leak", 8, "info", "Could not complete the ICE probe", "");

    // --- permissions this origin holds
    for (const [id, name, w] of PERMS) {
      const st = f.permissions && f.permissions[id];
      if (!st || st === "unsupported") { add("perm-" + id, "Permissions", `${name} permission`, w, "info", "Not queryable in this browser", ""); continue; }
      add("perm-" + id, "Permissions", `${name} permission`, w, st === "granted" ? "warn" : "pass",
        st === "granted" ? `Already granted to this origin (${f.origin || "this site"}) — a compromised page here could use it silently` : `State: ${st}`,
        `Revoke it: click the site-settings icon in the address bar → ${name} → Ask/Block. Wakizashi never needs it.`);
    }

    // --- device / app hygiene
    const pa = f.apis ? f.apis.platformAuthenticator : null;
    add("passkeys", "Device", "Passkeys / platform authenticator", 4, pa === true ? "pass" : pa === false ? "warn" : "info",
      pa === true ? "A user-verifying platform authenticator is available — use passkeys instead of passwords" : pa === false ? "No platform authenticator (no Windows Hello / Touch ID / screen-lock-backed key)" : "WebAuthn not available here",
      "Set up a device screen lock / Windows Hello / Touch ID, then register passkeys on important accounts.");
    const powerful = ["bluetooth", "usb", "serial", "hid"].filter((k) => f.apis && f.apis[k]);
    add("device-apis", "Device", "Powerful device APIs", 0, "info", powerful.length ? `Exposed (each still asks first): ${powerful.map((x) => "Web " + x.toUpperCase().replace("BLUETOOTH", "Bluetooth")).join(", ")}` : "No WebUSB/WebSerial/WebHID/Web Bluetooth exposed", "Deny device-access prompts you didn't expect.");
    const sto = f.storage || {};
    add("storage-persist", "App", "Persistent storage for cases", 3, sto.persisted === true ? "pass" : sto.persisted === false ? "warn" : "info",
      sto.persisted === true ? "The browser won't evict Wakizashi's data under storage pressure" : sto.persisted === false ? "Best-effort storage — cases and rules may be evicted when the disk is low" : "Storage Manager API unavailable",
      "Press “Request persistent storage” below, or install Wakizashi as an app; export cases regularly (Settings → backup).");
    const sw = f.serviceWorker || {};
    add("offline", "App", "Offline shell (service worker)", 3, sw.controlled ? "pass" : sw.supported ? "warn" : "info",
      sw.controlled ? "Running from the cached, version-pinned app shell" : sw.supported ? "Service worker supported but not controlling this page yet" : "Service workers unavailable (private window or insecure context?)",
      "Reload once over https:// so the offline shell installs.");
    add("installed", "App", "Installed as an app", 2, f.standalone ? "pass" : "info", f.standalone ? "Running in its own window" : "Running in a browser tab", "Install Wakizashi (address bar install icon / Share → Add to Home Screen) for an isolated window.");
    add("cookies", "App", "Cookies / storage enabled", 0, "info", f.cookieEnabled === false ? "Cookies are disabled" : "Cookies enabled", "");
    if (f.crossOriginIsolated != null) add("coi", "App", "Cross-origin isolated", 0, "info", f.crossOriginIsolated ? "Yes" : "No (not needed by Wakizashi)", "");

    const scored = checks.filter((c) => c.status !== "info" && c.weight > 0);
    const total = scored.reduce((a, c) => a + c.weight, 0);
    const earned = scored.reduce((a, c) => a + (c.status === "pass" ? c.weight : c.status === "warn" ? c.weight / 2 : 0), 0);
    const score = total ? Math.round((earned * 100) / total) : 0;
    const posture = score >= 90 ? "HARDENED" : score >= 75 ? "SOLID" : score >= 55 ? "EXPOSED" : "AT RISK";
    const rank = { fail: 0, warn: 1, pass: 2, info: 3 };
    checks.sort((a, z) => rank[a.status] - rank[z.status] || z.weight - a.weight);
    const counts = { pass: 0, warn: 0, fail: 0, info: 0 };
    for (const c of checks) counts[c.status]++;
    const fixes = checks.filter((c) => (c.status === "fail" || c.status === "warn") && c.fix);
    return { checks, score, posture, counts, fixes, browser: b, os: b.os };
  }

  /** Classify ICE candidate lines → {leak: none|mdns|private|public, ips}. */
  function classifyCandidates(lines) {
    const ips = [];
    let mdns = false;
    for (const l of lines || []) {
      const m = /candidate:\S+ \d+ \S+ \d+ (\S+) \d+ typ host/i.exec(String(l));
      if (!m) continue;
      if (/\.local$/i.test(m[1])) { mdns = true; continue; }
      ips.push(m[1]);
    }
    const B = W.eng.block;
    const pub = ips.filter((ip) => (B && B.isPublicIp ? B.isPublicIp(ip) : false));
    return { leak: pub.length ? "public" : ips.length ? "private" : mdns ? "mdns" : "none", ips: [...new Set(ips)] };
  }

  W.eng.posture = { evaluate, parseUA, expectedMajor, classifyCandidates };
})(typeof window !== "undefined" ? window.W : globalThis.W);
