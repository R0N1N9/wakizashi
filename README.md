<p align="center"><img src="assets/icon-192.png" width="96" alt="Wakizashi 脇差 icon"></p>

# Wakizashi 脇差

**The web edition of the RoninSec security suite.** Threat intel, detection engineering, assessment
reporting and personal OPSEC — as an installable web app that runs **entirely in your browser** on desktop
and mobile. No server, no account, no telemetry, no third-party code.

| | Katana 刀 | Karambit | **Wakizashi 脇差** |
|---|---|---|---|
| Platform | Desktop (Python server + web GUI) | Native Android | **Any modern browser — installable PWA** |
| Repo | `R0N1N9/cti-tools` | `R0N1N9/karambit` | `R0N1N9/wakizashi` |

The wakizashi is the short companion blade worn beside the katana — this is the one you always have on you.

## Layers

Same four layers, colours and names as Katana:

| Layer | Kanji | Role | Tools |
|---|---|---|---|
| **Yumi** | 弓 | CTI / threat intel | <!--TOOLS:yumi--> |
| **Yoroi** | 鎧 | Defense / blue team | <!--TOOLS:yoroi--> |
| **Naginata** | 薙刀 | Assessment / red team (authorised use) | <!--TOOLS:naginata--> |
| **Kemuridama** | 煙玉 | Counterintel / personal OPSEC | <!--TOOLS:kemuridama--> |

Highlights:

- **Enrichment workbench** — paste a report (or fetch an article): IOCs + host artifacts, MITRE ATT&CK
  mapping (labelled *and* inferred), actor/tooling attribution, drafted Sigma + YARA with false-positive risk,
  an enriched **STIX 2.1** bundle (OpenCTI-ready, ids compatible with Katana) and a one-click case.
- **Cases** shared by every layer, exported as Markdown, CSV, JSON or STIX.
- **Log hunting** with built-in behavioural detections and a Sigma engine, plus **rule synthesis** from the
  events you mark as malicious (graded by precision / recall so you ship rules that don't false-positive).
- **YARA-lite** engine for building, testing and scanning files — fully in-browser.
- **File triage** (PE imports + imphash, sections, Office macros / remote templates, APK, PDF), metadata
  scrubbing, AES-256-GCM encryption, and more.

## Use it

- **Hosted:** GitHub Pages (`https://r0n1n9.github.io/wakizashi/`) — see *Deploy* below.
- **Install:** open it, then use your browser's *Install app* (desktop / Android) or *Share → Add to Home
  Screen* (iOS). It works offline after the first visit.
- **Locally:** any static server, e.g. `python3 -m http.server 8800` then open <http://localhost:8800>.
  (WebCrypto and the service worker need `https://` or `localhost`.)

## Privacy & safety

- Everything — parsing, hashing, crypto, YARA, Sigma — runs on your device. Files you drop are never uploaded.
- The app makes network requests only when you press a button that says it fetches (an article URL, the
  CISA KEV catalog). Pivot links open third-party sites only when you click them.
- Data (cases, rule libraries, notes) lives in this browser's storage. Export/import it from **Settings**.
- Naginata's tools are for **authorised** testing and sit behind a rules-of-engagement acknowledgement.
  Wakizashi plans, analyses and reports; it does not attack anything.

## Develop

Zero dependencies, no build step. See [`CLAUDE.md`](CLAUDE.md) for the module contract.

```bash
node tests/run.js            # unit tests (engines run in Node's vm)
node tools/sync.js           # regenerate script tags + service-worker precache after adding files
node tools/sync.js --check   # what CI runs
```

## Deploy

`.github/workflows/pages.yml` publishes `main` to GitHub Pages. One-time setup: **Settings → Pages → Source:
GitHub Actions**. CI (`ci.yml`) runs syntax checks, the sync check and the unit tests on every PR.

---

By RoninSec. Built as a defensive-security and authorised-testing toolkit.
