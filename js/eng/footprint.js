/* FOOTPRINT — self-OSINT link builder + OPSEC posture score (port of Katana shinobi/footprint.py + dossier.py).
 *
 * Katana checks your usernames against 30+ platforms over the network; Wakizashi builds the same lookups as
 * links you open yourself (nothing is fetched or scraped automatically, and nothing you type leaves the page
 * until you click a link — at which point that site sees the query).
 *
 *   classify(input) → "email" | "phone" | "username" | "name" | "domain"
 *   links(input, kind?) → { kind, value, groups: [{id, title, items:[{label, url, note?}]}] }
 *   BROKERS, QUESTIONS, DOMAINS, score(answers) → dossier scorecard
 */
(function (W) {
  "use strict";
  const enc = encodeURIComponent;
  // [name, category, profile URL template] — mirrors katana/cti/osint.py SITES (+ a few more)
  const SITES = [
    ["GitHub", "dev", "https://github.com/{u}"], ["GitLab", "dev", "https://gitlab.com/{u}"], ["Codeberg", "dev", "https://codeberg.org/{u}"],
    ["Docker Hub", "dev", "https://hub.docker.com/u/{u}"], ["PyPI", "dev", "https://pypi.org/user/{u}/"], ["npm", "dev", "https://www.npmjs.com/~{u}"],
    ["Dev.to", "dev", "https://dev.to/{u}"], ["Hugging Face", "dev", "https://huggingface.co/{u}"], ["Replit", "dev", "https://replit.com/@{u}"],
    ["Stack Overflow (search)", "dev", "https://stackoverflow.com/users?tab=Reputation&filter=all&search={u}"], ["Keybase", "identity", "https://keybase.io/{u}"],
    ["Gravatar", "identity", "https://gravatar.com/{u}"], ["About.me", "identity", "https://about.me/{u}"], ["Linktree", "identity", "https://linktr.ee/{u}"],
    ["Hacker News", "social", "https://news.ycombinator.com/user?id={u}"], ["Reddit", "social", "https://www.reddit.com/user/{u}"],
    ["Mastodon (.social)", "social", "https://mastodon.social/@{u}"], ["Bluesky", "social", "https://bsky.app/profile/{u}.bsky.social"],
    ["Threads", "social", "https://www.threads.net/@{u}"], ["X / Twitter", "social", "https://x.com/{u}"], ["Instagram", "social", "https://www.instagram.com/{u}/"],
    ["TikTok", "social", "https://www.tiktok.com/@{u}"], ["Facebook", "social", "https://www.facebook.com/{u}"], ["LinkedIn", "social", "https://www.linkedin.com/in/{u}"],
    ["Pinterest", "social", "https://www.pinterest.com/{u}/"], ["Tumblr", "social", "https://{u}.tumblr.com"], ["Telegram", "social", "https://t.me/{u}"],
    ["Medium", "social", "https://medium.com/@{u}"], ["Substack", "social", "https://{u}.substack.com"], ["Quora", "social", "https://www.quora.com/profile/{u}"],
    ["Wikipedia", "social", "https://en.wikipedia.org/wiki/User:{u}"], ["Flickr", "media", "https://www.flickr.com/people/{u}/"], ["YouTube", "media", "https://www.youtube.com/@{u}"],
    ["Twitch", "media", "https://www.twitch.tv/{u}"], ["SoundCloud", "media", "https://soundcloud.com/{u}"], ["Vimeo", "media", "https://vimeo.com/{u}"],
    ["Spotify (search)", "media", "https://open.spotify.com/search/{u}/users"], ["DeviantArt", "media", "https://www.deviantart.com/{u}"], ["Behance", "media", "https://www.behance.net/{u}"],
    ["Dribbble", "media", "https://dribbble.com/{u}"], ["Patreon", "media", "https://www.patreon.com/{u}"], ["Steam", "gaming", "https://steamcommunity.com/id/{u}"],
    ["Chess.com", "gaming", "https://www.chess.com/member/{u}"], ["Lichess", "gaming", "https://lichess.org/@/{u}"], ["Roblox (search)", "gaming", "https://www.roblox.com/search/users?keyword={u}"],
    ["Pastebin", "leaks", "https://pastebin.com/u/{u}"], ["HackerOne", "security", "https://hackerone.com/{u}"], ["Bugcrowd", "security", "https://bugcrowd.com/{u}"],
    ["TryHackMe", "security", "https://tryhackme.com/p/{u}"], ["Hack The Box (search)", "security", "https://app.hackthebox.com/search?q={u}"],
    ["Etsy (shop)", "commerce", "https://www.etsy.com/shop/{u}"], ["eBay", "commerce", "https://www.ebay.com/usr/{u}"], ["Goodreads (search)", "other", "https://www.goodreads.com/search?q={u}&search_type=people"],
    ["Strava (search)", "other", "https://www.strava.com/athletes/search?text={u}"], ["Venmo", "other", "https://account.venmo.com/u/{u}"], ["Cash App", "other", "https://cash.app/${u}"],
  ];
  // DATA_BROKERS from footprint.py (+ a few)
  const BROKERS = [
    ["Spokeo", "https://www.spokeo.com/optout"], ["Whitepages", "https://www.whitepages.com/suppression-requests"], ["BeenVerified", "https://www.beenverified.com/app/optout/search"],
    ["Intelius", "https://www.intelius.com/opt-out"], ["TruePeopleSearch", "https://www.truepeoplesearch.com/removal"], ["PeopleFinders", "https://www.peoplefinders.com/opt-out"],
    ["Radaris", "https://radaris.com/control/privacy"], ["MyLife", "https://www.mylife.com/ccpa/index.pubview"], ["FastPeopleSearch", "https://www.fastpeoplesearch.com/removal"],
    ["Acxiom", "https://isapps.acxiom.com/optout/optout.aspx"], ["Nuwber", "https://nuwber.com/removal/link"], ["ThatsThem", "https://thatsthem.com/optout"],
    ["Google — Results about you", "https://myactivity.google.com/results-about-you"], ["Have I Been Pwned — opt out", "https://haveibeenpwned.com/OptOut"],
  ].map(([name, url]) => ({ name, url }));

  function classify(v) {
    v = String(v || "").trim();
    if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return "email";
    if (/^\+?[\d\s().-]{7,20}$/.test(v) && (v.match(/\d/g) || []).length >= 7) return "phone";
    if (/^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v) && !/\s/.test(v)) return "domain";
    if (/\s/.test(v)) return "name";
    return "username";
  }
  const g = (q) => `https://www.google.com/search?q=${enc(q)}`, ddg = (q) => `https://duckduckgo.com/?q=${enc(q)}`, bing = (q) => `https://www.bing.com/search?q=${enc(q)}`;
  const searchSet = (q, note) => [{ label: `Google: ${q}`, url: g(q), note }, { label: `DuckDuckGo: ${q}`, url: ddg(q) }, { label: `Bing: ${q}`, url: bing(q) }];

  function links(input, kind) {
    const value = String(input || "").trim().replace(/^@/, "");
    kind = kind || classify(value);
    const groups = [], add = (id, title, items) => items.length && groups.push({ id, title, items });
    const q = `"${value}"`;
    if (kind === "username") {
      const u = enc(value);
      add("profiles", `Profiles named “${value}” (${SITES.length} sites)`, SITES.map(([n, cat, t]) => ({ label: n, url: t.replace(/\{u\}/g, u), cat })));
      add("search", "Search engines", [...searchSet(q), { label: `Google: ${q} -site:github.com`, url: g(`${q} -site:github.com`) },
        { label: `Google: ${q} (paste sites)`, url: g(`${q} site:pastebin.com OR site:ghostbin.com OR site:rentry.co OR site:justpaste.it`) },
        { label: `Google: inurl:${value}`, url: g(`inurl:${value}`) }]);
      add("tools", "Username search tools (open in their site)", [{ label: "WhatsMyName", url: `https://whatsmyname.app/?q=${u}`, note: "checks 600+ sites from your browser" },
        { label: "Namechk", url: `https://namechk.com/` }, { label: "Wayback Machine (profile history)", url: `https://web.archive.org/web/*/${u}*` }]);
    } else if (kind === "email") {
      const [local, dom] = value.split("@");
      add("breach", "Breach & exposure checks (links only)", [
        { label: "Have I Been Pwned", url: `https://haveibeenpwned.com/account/${enc(value)}`, note: "breach list for this address" },
        { label: "Firefox Monitor / Mozilla Monitor", url: "https://monitor.mozilla.org/" },
        { label: "Intelligence X (search)", url: `https://intelx.io/?s=${enc(value)}` },
        { label: "DeHashed (search)", url: `https://dehashed.com/search?query=${enc(value)}` },
        { label: "Gravatar profile (md5 of address)", url: `https://gravatar.com/${W.hash.md5(value.toLowerCase())}`, note: "a public avatar tied to this email across every Gravatar-using site" }]);
      add("search", "Search engines", [...searchSet(q), { label: `Google: ${q} (documents)`, url: g(`${q} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:txt`) },
        { label: `Google: "${local}" (local-part as a handle)`, url: g(`"${local}" -"${value}"`), note: "the part before @ is often reused as a username" }]);
      add("profiles", `Profiles named “${local}”`, SITES.slice(0, 30).map(([n, cat, t]) => ({ label: n, url: t.replace(/\{u\}/g, enc(local)), cat })));
      if (!/^(gmail|googlemail|outlook|hotmail|live|yahoo|icloud|me|proton|protonmail|pm|gmx|aol|mail|yandex|fastmail|zoho)\./i.test(dom))
        add("domain", `Your domain (${dom})`, domainLinks(dom));
    } else if (kind === "phone") {
      const digits = value.replace(/[^\d+]/g, ""), plain = digits.replace(/^\+/, "");
      add("search", "Search engines (try several formats)", [...searchSet(`"${value}"`), ...searchSet(`"${plain}"`).slice(0, 1),
        { label: `Google: "${plain.slice(-10)}" (national format)`, url: g(`"${plain.slice(-10)}"`) }]);
      add("lookup", "Caller-ID / reverse lookup sites (they log searches)", [
        { label: "Sync.me", url: `https://sync.me/search/?number=${enc(digits)}` }, { label: "Truecaller (search)", url: `https://www.truecaller.com/search/global/${enc(plain)}` },
        { label: "WhoCallsMe", url: `https://whocallsme.com/Phone-Number.aspx/${enc(plain)}` }]);
      add("messaging", "Messaging apps that reveal a profile for a number", [{ label: "WhatsApp click-to-chat", url: `https://wa.me/${enc(plain)}`, note: "shows the profile name/photo if your privacy settings allow it" },
        { label: "Telegram (needs the app)", url: `https://t.me/+${enc(plain)}` }]);
    } else if (kind === "domain") {
      add("domain", `Domain ${value}`, domainLinks(value));
      add("search", "Search engines", [...searchSet(`site:${value}`), { label: `Google: "@${value}" (addresses on it)`, url: g(`"@${value}"`) }]);
    } else { // full name
      add("search", "Search engines", [...searchSet(q), { label: `Google: ${q} (documents)`, url: g(`${q} filetype:pdf OR filetype:doc OR filetype:docx`) },
        { label: `Google: ${q} + resume / CV`, url: g(`${q} (resume OR cv OR curriculum)`) }, { label: `Google Images: ${q}`, url: `https://www.google.com/search?tbm=isch&q=${enc(q)}` },
        { label: `Google: ${q} site:linkedin.com`, url: g(`${q} site:linkedin.com`) }, { label: `Google News: ${q}`, url: `https://news.google.com/search?q=${enc(q)}` }]);
      add("people", "People-search sites (they show what they hold — then opt out below)", [
        { label: "TruePeopleSearch", url: `https://www.truepeoplesearch.com/results?name=${enc(value)}` }, { label: "FastPeopleSearch", url: `https://www.fastpeoplesearch.com/name/${enc(value.toLowerCase().replace(/\s+/g, "-"))}` },
        { label: "Whitepages", url: `https://www.whitepages.com/name/${enc(value.replace(/\s+/g, "-"))}` }, { label: "Radaris", url: `https://radaris.com/p/${enc(value.replace(/\s+/g, "/"))}/` },
        { label: "Spokeo", url: `https://www.spokeo.com/${enc(value.replace(/\s+/g, "-"))}` }]);
      const handle = value.toLowerCase().replace(/[^a-z0-9]+/g, "");
      add("profiles", `Profiles named “${handle}” (name squashed into a handle)`, SITES.slice(0, 24).map(([n, cat, t]) => ({ label: n, url: t.replace(/\{u\}/g, enc(handle)), cat })));
    }
    add("brokers", "Data-broker opt-outs", BROKERS.map((b) => ({ label: b.name, url: b.url })));
    return { kind, value, groups, note: "Links only — nothing was fetched. Each site you open sees what you searched for; use a private window if that matters." };
  }
  function domainLinks(d) {
    return [{ label: `RDAP / WHOIS: ${d}`, url: `https://client.rdap.org/?type=domain&object=${enc(d)}` }, { label: "crt.sh (certificates)", url: `https://crt.sh/?q=${enc("%." + d)}` },
      { label: "DNSDumpster", url: "https://dnsdumpster.com/" }, { label: "Wayback Machine", url: `https://web.archive.org/web/*/${enc(d)}*` },
      { label: "Have I Been Pwned (domain search, needs verification)", url: "https://haveibeenpwned.com/DomainSearch" }];
  }

  // ------------------------------------------------------------------ DOSSIER (port of dossier.py)
  const DOMAINS = { device: "Device", accounts: "Accounts", network: "Network", comms: "Communications", identity: "Identity", physical: "Physical" };
  const QUESTIONS = [
    ["dev_fde", "device", "Is full-disk encryption on for every device you travel with?", 10, "Enable FileVault / BitLocker / LUKS. Without it, a seized or stolen device gives up everything."],
    ["dev_lock", "device", "Auto-lock under 5 min with a strong passphrase (not just biometrics)?", 6, "Set a short auto-lock and a 6+ char passphrase; know how to force biometric-off before a border."],
    ["dev_updates", "device", "OS and apps patched within the last 30 days?", 7, "Patch now; most real-world compromise is n-day. Turn on auto-update."],
    ["dev_backup", "device", "Encrypted, tested backup you could restore from after loss/seizure?", 6, "Keep an encrypted backup you can restore; travel with the minimum and restore on arrival."],
    ["acc_pwmgr", "accounts", "Unique passwords from a password manager (no reuse)?", 9, "Adopt a password manager; reuse is how one breach becomes all of them."],
    ["acc_mfa", "accounts", "Phishing-resistant MFA (hardware key / passkey) on critical accounts?", 10, "Add a hardware security key or passkeys; SMS codes are phishable and SIM-swappable."],
    ["acc_sim", "accounts", "SIM/port-out lock or eSIM to resist SIM-swap?", 6, "Set a carrier port-out PIN; move 2FA off SMS."],
    ["acc_recovery", "accounts", "Recovery emails/phones separated from your public identity?", 5, "Use a dedicated, private recovery address not tied to your public handles."],
    ["net_vpn", "network", "Always-on trusted VPN/WireGuard on untrusted networks?", 8, "Run a reputable VPN with a kill-switch on all hostile Wi-Fi."],
    ["net_dns", "network", "Encrypted DNS (DoH/DoT) to a privacy resolver?", 5, "Enable DoH/DoT to Cloudflare/Quad9 so the local network can't log your lookups."],
    ["net_killswitch", "network", "VPN kill-switch so traffic drops if the tunnel fails?", 6, "Turn on the kill-switch; without it a VPN drop silently exposes you."],
    ["net_hotspot", "network", "Prefer your own eSIM/hotspot over public Wi-Fi?", 4, "Carry a data eSIM; your own uplink beats any shared network."],
    ["com_e2e", "comms", "Sensitive conversations on end-to-end encrypted apps (Signal)?", 8, "Move sensitive comms to Signal; disappearing messages for the rest."],
    ["com_meta", "comms", "Minimise metadata (disappearing messages, sealed sender)?", 4, "Enable disappearing messages and metadata-minimising features."],
    ["com_email", "comms", "Separate email identities for separate purposes?", 5, "Compartmentalise: distinct addresses (or aliases) per context."],
    ["id_personas", "identity", "Cover identities kept separate (no shared handles/emails/photos)?", 7, "Run MIRROR; never reuse a handle, email local-part or avatar across personas."],
    ["id_footprint", "identity", "Checked your public footprint / data-broker exposure in 6 months?", 5, "Run the lookups above and submit broker opt-outs; re-check periodically."],
    ["id_metadata", "identity", "Strip metadata from files/photos before sharing?", 5, "Run SCRUB before posting; EXIF GPS has deanonymised many people."],
    ["id_social", "identity", "Locked-down social privacy (no live location, limited audience)?", 4, "Disable location tags; delay posting travel; restrict audiences."],
    ["phy_privacy", "physical", "Privacy screen + situational awareness in public?", 3, "Use a privacy filter; sit with your back to a wall in transit hubs."],
    ["phy_usb", "physical", "USB data-blocker / own charger (no public USB data ports)?", 3, "Carry a data-blocker to defeat juice-jacking."],
    ["phy_border", "physical", "A border-crossing plan (power off, clean profile, minimal data)?", 5, "Power down before borders; travel with a clean profile and restore later."],
  ].map(([id, domain, text, weight, fix]) => ({ id, domain, text, weight, fix }));

  /** answers: {id: true|false}; missing = not done (counts against you), exactly as dossier.py */
  function score(answers = {}) {
    const by = {}; for (const d of Object.keys(DOMAINS)) by[d] = { got: 0, max: 0, gaps: 0 };
    const gaps = [];
    for (const q of QUESTIONS) {
      const d = by[q.domain]; d.max += q.weight;
      if (answers[q.id] === true) d.got += q.weight; else { d.gaps++; gaps.push(q); }
    }
    const got = Object.values(by).reduce((n, d) => n + d.got, 0), max = Object.values(by).reduce((n, d) => n + d.max, 0);
    const pct = max ? Math.round(100 * got / max) : 0;
    const grade = pct >= 90 ? "A" : pct >= 75 ? "B" : pct >= 60 ? "C" : pct >= 40 ? "D" : "F";
    gaps.sort((a, b) => b.weight - a.weight);
    return { score: pct, grade, answered: QUESTIONS.filter((q) => q.id in answers).length, total: QUESTIONS.length,
      domains: Object.entries(DOMAINS).map(([d, label]) => ({ domain: d, label, pct: by[d].max ? Math.round(100 * by[d].got / by[d].max) : 0, gaps: by[d].gaps })),
      priorities: gaps.slice(0, 10), gaps,
      summary: `OPSEC posture ${pct}/100 (grade ${grade}). ${gaps.length} gap(s); top fixes listed by impact.` };
  }

  W.eng.footprint = { classify, links, SITES, BROKERS, QUESTIONS, DOMAINS, score };
})(typeof window !== "undefined" ? window.W : globalThis.W);
