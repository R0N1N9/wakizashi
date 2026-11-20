/* Wakizashi service worker — offline-first app shell.
   PRECACHE and VERSION are rewritten by `node tools/sync.js`; don't edit those two lines by hand. */
const VERSION = "wkz-fd8cba37919a";
const PRECACHE = [/*PRECACHE*/
  "./",
  "index.html",
  "manifest.webmanifest",
  "css/app.css",
  "js/core.js",
  "js/shell.js",
  "assets/icon.svg",
  "assets/icon-192.png",
  "assets/icon-512.png",
  "assets/icon-maskable-512.png",
  "assets/apple-touch-icon.png",
  "assets/favicon-32.png",
  "css/kemuridama.css",
  "css/naginata.css",
  "css/yoroi-b.css",
  "css/yoroi.css",
  "js/eng/block.js",
  "js/eng/cipher.js",
  "js/eng/cvss.js",
  "js/eng/decoy.js",
  "js/eng/detect.js",
  "js/eng/footprint.js",
  "js/eng/headers.js",
  "js/eng/ioc.js",
  "js/eng/jwt.js",
  "js/eng/kpack.js",
  "js/eng/logs.js",
  "js/eng/mirror.js",
  "js/eng/passgen.js",
  "js/eng/phish.js",
  "js/eng/pivot.js",
  "js/eng/playbooks.js",
  "js/eng/posture.js",
  "js/eng/regexgen.js",
  "js/eng/scope.js",
  "js/eng/scrub.js",
  "js/eng/sigma.js",
  "js/eng/stego.js",
  "js/eng/stix.js",
  "js/eng/subnet.js",
  "js/eng/synth.js",
  "js/eng/trace.js",
  "js/eng/transforms.js",
  "js/eng/triage.js",
  "js/eng/words.js",
  "js/eng/workbench.js",
  "js/eng/yara.js",
  "js/eng/yaragen.js",
  "js/views/yumi/case.js",
  "js/views/yumi/extract.js",
  "js/views/yumi/kev.js",
  "js/views/yumi/pivot.js",
  "js/views/yumi/regex.js",
  "js/views/yumi/toolkit.js",
  "js/views/yumi/triage.js",
  "js/views/yumi/workbench.js",
  "js/views/yumi/yara.js",
  "js/views/yoroi/block.js",
  "js/views/yoroi/hunt.js",
  "js/views/yoroi/phish.js",
  "js/views/yoroi/posture.js",
  "js/views/yoroi/respond.js",
  "js/views/yoroi/rules.js",
  "js/views/yoroi/synth.js",
  "js/views/yoroi/yara.js",
  "js/views/naginata/cvss.js",
  "js/views/naginata/headers.js",
  "js/views/naginata/jwt.js",
  "js/views/naginata/report.js",
  "js/views/naginata/scope.js",
  "js/views/naginata/subnet.js",
  "js/views/kemuridama/_kit.js",
  "js/views/kemuridama/cipher.js",
  "js/views/kemuridama/decoy.js",
  "js/views/kemuridama/footprint.js",
  "js/views/kemuridama/mirror.js",
  "js/views/kemuridama/passgen.js",
  "js/views/kemuridama/scrub.js",
  "js/views/kemuridama/stego.js",
  "js/views/kemuridama/trace.js",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(PRECACHE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k.startsWith("wkz-") && k !== VERSION).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// Same-origin GETs: serve from cache, refresh in the background (stale-while-revalidate).
// Navigations fall back to the cached app shell so deep links work offline.
// Cross-origin requests (article fetches, KEV feed) always go to the network and are never cached here.
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (req.mode === "navigate") {
    e.respondWith(fetch(req).then((r) => { const copy = r.clone(); caches.open(VERSION).then((c) => c.put("./index.html", copy)); return r; })
      .catch(() => caches.match("./index.html")));
    return;
  }
  e.respondWith(caches.open(VERSION).then(async (c) => {
    const hit = await c.match(req, { ignoreSearch: true });
    const net = fetch(req).then((r) => { if (r && r.ok) c.put(req, r.clone()); return r; }).catch(() => hit);
    return hit || net;
  }));
});
