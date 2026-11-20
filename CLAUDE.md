# Wakizashi 脇差 — contributor guide

Wakizashi is the **web edition** of the RoninSec *Katana* security suite: a static, installable PWA that runs
**entirely in the browser** (desktop and mobile), the way *Tantō* is the native Android edition. The three
products share an identity — layers, colours, naming — but no code: every engine here is plain JavaScript.

| Repo | What | Reference |
|---|---|---|
| `R0N1N9/wakizashi` | this — static web app | — |
| `R0N1N9/cti-tools` (a.k.a. katana) | desktop suite: Python stdlib server + vanilla JS GUIs | engines in `katana/{cti,defense,offense,shinobi}/*.py` |
| `R0N1N9/tanto` | native Android (Kotlin/Compose) | `app/src/main/java/sec/ronin/tanto/feature/**` |

When porting a feature, read the Katana Python engine (most complete) and Tantō's Kotlin (already re-shaped
for a single-device, no-server world) and port the *behaviour*, not the code.

## Layers (identical to Katana)

| id | Name | Kanji | Role | Accent |
|---|---|---|---|---|
| `yumi` | Yumi | 弓 | CTI / threat intel | `#2fd6cf` teal |
| `yoroi` | Yoroi | 鎧 | Defense / blue team | `#4d8bff` cobalt |
| `naginata` | Naginata | 薙刀 | Offense / red team | `#ff4b5c` red |
| `kemuridama` | Kemuridama | 煙玉 | Counterintel / OPSEC | `#a855f7` violet |

Brand: Wakizashi amber `#ffb547`, kanji 脇差. Icons in `assets/` are generated from glyph outlines (no font dependency).

## Layout

```
index.html            app shell (script/style tags between <!--ENGINES-->, <!--VIEWS-->, <!--STYLES--> are GENERATED)
sw.js                 service worker (PRECACHE + VERSION are GENERATED)
css/app.css           design system — shared classes (panel, btn, tabs, seg, tbl, badge, chip, finding, callout, drop…)
css/<layer>.css       optional layer-specific styles (auto-linked by sync)
js/core.js            the `W` runtime: registry, helpers, hashing, store, cases, UI helpers
js/eng/<name>.js      PURE engines → W.eng.<name>   (no DOM at load; unit-tested in Node)
js/views/<layer>/<tool>.js   one tool per file → W.tool(layer, id, {...})
js/views/<layer>/_kit.js     optional shared helpers for a layer ("_" sorts first, so it loads before the tools)
js/shell.js           layers, router, chrome, home grids, settings, PWA — loads last
tools/sync.js         regenerates the generated bits — run after adding/removing/renaming files
tests/run.js          zero-dep test runner; tests/*.test.js
```

**After adding, removing or renaming any file in `js/eng`, `js/views/*` or `css/`: run `node tools/sync.js`.**
CI fails if `node tools/sync.js --check` reports drift.

## Writing an engine (`js/eng/<name>.js`)

```js
(function (W) {
  "use strict";
  function extract(text) { /* pure */ }
  W.eng.ioc = { extract };
})(typeof window !== "undefined" ? window.W : globalThis.W);
```

- Pure functions; no `document`/`window` access at load time (they run in Node's `vm` for tests).
- Reference other engines lazily inside functions (`W.eng.yara.compile(...)`) — load order is alphabetical.
- Use core helpers: `W.bytes/utf8/latin1/hex/b64/fromB64/entropy`, `W.hash.md5` (sync), `W.hash.sha(alg, data)` /
  `W.hash.all(data)` (async, WebCrypto), `W.refang/defang/detectType`, `W.RE`.
- Add `tests/<name>.test.js` with real fixtures (put inputs in `tests/fixtures/`). `node tests/run.js` must pass.
  Each test file runs in its own function scope (engines and `W` are shared), so top-level names can't collide.

## Writing a tool view (`js/views/<layer>/<tool>.js`)

```js
(function () {
  "use strict";
  const { $, esc, ui } = W;
  W.tool("yumi", "extract", {
    name: "Extract", order: 10,
    desc: "Pull IOCs out of any text; refang, dedupe, export.",          // shown on the layer home tile
    icon: '<path d="M4 4h16v6H4zM4 14h7v6H4z"/>',                         // 24x24 stroke paths
    help: { steps: ["Paste…", "Press Extract…"], tips: [] },             // Settings → Tool guide (sync --check requires 2+ steps)
    render(el, arg) {                                                     // arg = value passed via W.go(layer, tool, arg)
      el.innerHTML = ui.head("Extract", "IOC extraction", "subtitle…") + `…`;
      W.act("#ex-go", async () => { … });                                 // async buttons: disables + toasts errors
    },
  });
})();
```

- Header convention: `ui.head(CODE, Title, sub)` renders `CODE | Title` — don't repeat the same word twice.
- Prefix element ids with a short tool prefix (`ex-`, `wb-`…) — all tools share one document.
- Store keys: `W.store.get/set("<layer>.<tool>.<key>")`. Cases: `W.Case.add([{value,type,verdict,tags,note}])`.
- Cross-tool links: `W.go("yumi", "pivot", "8.8.8.8")`. Toasts: `W.toast(msg, isError)`. Modals: `W.modal(html, {title})`.
- Files: `ui.drop(id, text, accept)` + `W.dropZone(id, file => …)`, read with `W.readFile(file, "buffer"|"text"|"dataurl")`.
- Downloads: `W.download(name, data, mime)`. Copy: `W.copy(text)`.

## Non-negotiables

- **Escape everything** user- or file-derived with `W.esc` before putting it in HTML. No `eval`, `new Function`,
  inline event handlers or inline `<script>` (CSP forbids them).
- **No third-party code, fonts, CDNs or trackers.** Network only when the user presses a button that says it
  fetches (CSP allows `connect-src https:`). Never send case data anywhere.
- **Mobile first.** Must work at 360px wide with no horizontal page scroll: use `.grid.g2/.g3`, `.row` (wraps),
  `.tablewrap` for tables, `.break` for long strings; touch targets ≥ 40px (the CSS handles inputs/buttons).
  Check both a 1360×900 desktop and a 390×844 phone viewport.
- **Naginata (offense) is for authorised testing only.** Every Naginata tool's `render` starts with
  `W.roeGate(el, () => …)`. Build planners, analysers, decoders, scorers, report writers — never exploit
  payloads, malware, C2, credential theft, phishing kits or detection/AV evasion.
- Dark console aesthetic: use the design-system classes; accent comes from `var(--acc)` (current layer).

## Verify before you push

```bash
node tests/run.js
node tools/sync.js --check
python3 -m http.server 8800    # then open http://localhost:8800 (service worker needs localhost/https)
```

Screenshot new screens with Playwright at desktop and phone sizes; check the console for errors.

## Git

Feature branch → PR → squash-merge into `main`. GitHub Pages deploys `main` via `.github/workflows/pages.yml`.
