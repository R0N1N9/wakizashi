<p align="center"><img src="assets/icon-192.png" width="96" alt="Wakizashi 脇差 icon"></p>

# Wakizashi 脇差

**The web edition of the RoninSec security suite.** Threat intel, detection engineering, assessment
reporting and personal OPSEC — as an installable web app that runs **entirely in your browser** on desktop
and mobile. No server, no account, no telemetry, no third-party code.

Wakizashi is the web blade of **Daishō**, the RoninSec blade suite
(Katana desktop · Wakizashi web · Tantō mobile).

| | Katana 刀 | Tantō 短刀 | **Wakizashi 脇差** |
|---|---|---|---|
| Platform | Desktop (Python server + web GUI) | Native Android | **Any modern browser — installable PWA** |
| Get it | [Source & install](https://github.com/R0N1N9/katana) *(private repo)* | [Download APK (nightly)](https://github.com/R0N1N9/tanto/releases/download/nightly/roninsec-debug.apk) · [Releases](https://github.com/R0N1N9/tanto/releases) | **[Open the web app](https://r0n1n9.github.io/wakizashi/)** |
| Repo | `R0N1N9/katana` | [`R0N1N9/tanto`](https://github.com/R0N1N9/tanto) | [`R0N1N9/wakizashi`](https://github.com/R0N1N9/wakizashi) |

The same links are inside the app under **Settings → Daishō suite**.

The wakizashi is the short companion blade worn beside the katana — this is the one you always have on you.

## Layers

Same four layers, colours and names as Katana:

| Layer | Kanji | Role | Tools |
|---|---|---|---|
| **Yumi** | 弓 | CTI / threat intel | Extract · Pivot · Workbench · Case · YARA · Triage · Toolkit · Regex · KEV |
| **Yoroi** | 鎧 | Defense / blue team | Hunt · Rules · Synth · YARA · Phish · Block · Respond · Posture |
| **Naginata** | 薙刀 | Assessment / red team (authorised use) | Scope · Subnet · CVSS · Headers · JWT · Report |
| **Kemuridama** | 煙玉 | Counterintel / personal OPSEC | Scrub · Cipher · Mirror · Decoy · Passwords · Trace · Footprint · Stego |

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

## All tools

### Yumi

| Tool | What it does |
|---|---|
| **Extract** | Pull IOCs and host artifacts out of any text — refang, dedupe, export, add to a case. |
| **Pivot** | One indicator → every reputation, intel and infrastructure page worth opening. |
| **Workbench** | Report → ATT&CK mapping, attribution, Sigma + YARA, a STIX bundle and a ready-made case. |
| **Case** | Investigations shared by every layer — indicators, verdicts, notes; export Markdown, CSV, JSON or STIX. |
| **YARA** | Build YARA rules from IOCs, a sample, strings or a template; validate, test and keep a library. |
| **Triage** | Static file analysis — hashes, imphash, PE/ELF/PDF/Office/APK structure, capabilities, embedded IOCs. |
| **Toolkit** | CyberChef-style transform chain: Base64, hex, XOR, gzip, URL, PowerShell -enc, hashes, refang… |
| **Regex** | Turn an example (mutex, UA, path, C2 URI) into ranked regexes for YARA and hunt queries. |
| **KEV** | Search CISA's Known Exploited Vulnerabilities catalog — cached for offline use. |

### Yoroi

| Tool | What it does |
|---|---|
| **Hunt** | Threat hunt through auth, web, Windows, JSON or CSV logs with 25 detections + Sigma. |
| **Rules** | Toggle detections, tune thresholds, write and test Sigma rules for HUNT. |
| **Synth** | Turn marked malicious log lines into a graded Sigma rule (precision / recall / F1). |
| **YARA** | Scan files with bundled + custom YARA-lite rules and manage your rule library. |
| **Phish** | Triage a reported email: SPF/DKIM/DMARC, relay path, lookalike links, attachments, verdict. |
| **Block** | Turn IPs, domains, URLs and hashes into firewall, DNS, IDS, Sigma, KQL, EDR and STIX countermeasures. |
| **Respond** | Incident board: NIST 800-61 phases, playbook checklists, IOCs, evidence, timeline, Markdown report. |
| **Posture** | Audit this browser and device: updates, privacy signals, permissions, WebRTC leaks — scored 0–100 with fixes. |

### Naginata

| Tool | What it does |
|---|---|
| **Scope** | Engagement details, in/out-of-scope lists (CIDR, ranges, wildcards), an is-it-in-scope checker and an asset tracker. |
| **Subnet** | IPv4 + IPv6 CIDR calculator — hosts, masks, binary view, splitting, supernets and range ↔ CIDR. |
| **CVSS** | CVSS v3.1 calculator — base, temporal and environmental scores, severity, vector parse and export. |
| **Headers** | Review pasted HTTP response headers — CSP, HSTS, framing, CORS, cookies, disclosure — with an A–F grade and fixes. |
| **JWT** | Decode a JSON Web Token, read its claims and times, flag weak configuration and verify the signature with your key. |
| **Report** | Write up findings with severity, CVSS, affected assets (scope-checked), evidence and fixes — export Markdown or HTML. |

### Kemuridama

| Tool | What it does |
|---|---|
| **Scrub** | See the hidden metadata in photos and documents — GPS, camera serials, authors — and download a losslessly cleaned copy. |
| **Cipher** | Encrypt text and files with AES-256-GCM (passphrase or generated key); one-time pads and Shamir secret sharing. |
| **Mirror** | What every website can read about this browser — each signal rated for how identifying it is, with a uniqueness estimate and fixes. |
| **Decoy** | Generate a clearly fictitious cover identity from a seed (name, address, fiction-range phone, aliases), plus canary tokens and honeytokens. |
| **Passwords** | Generate strong random passwords and word passphrases, and check how fast a password you type would fall to real attacks. |
| **Trace** | Strip tracking parameters, unwrap redirect wrappers (Google, Facebook, Outlook Safe Links…), flag shorteners and look-alike domains. |
| **Footprint** | Self-OSINT: lookup links for your usernames, emails, phone and name, data-broker opt-outs, and an OPSEC checklist that tracks your progress. |
| **Stego** | Privacy demo: hide a short message in a PNG's least-significant bits (optionally AES-encrypted) and reveal it again. Katana-compatible. |

## Use it

- **Hosted:** **<https://r0n1n9.github.io/wakizashi/>** (GitHub Pages — see *Deploy* below).
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
