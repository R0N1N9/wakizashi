/* OSINT pivot catalogue: for an indicator, the reputation / intel / infrastructure pages worth opening.
   Links only — Wakizashi never queries these services itself. */
(function (W) {
  "use strict";
  const e = encodeURIComponent;
  const P = {
    ipv4: [
      ["VirusTotal", "reputation", (v) => `https://www.virustotal.com/gui/ip-address/${e(v)}`],
      ["AbuseIPDB", "reputation", (v) => `https://www.abuseipdb.com/check/${e(v)}`],
      ["GreyNoise", "reputation", (v) => `https://viz.greynoise.io/ip/${e(v)}`],
      ["Talos", "reputation", (v) => `https://talosintelligence.com/reputation_center/lookup?search=${e(v)}`],
      ["OTX", "intel", (v) => `https://otx.alienvault.com/indicator/ip/${e(v)}`],
      ["ThreatFox", "intel", (v) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(v)}`],
      ["Shodan", "infrastructure", (v) => `https://www.shodan.io/host/${e(v)}`],
      ["Censys", "infrastructure", (v) => `https://search.censys.io/hosts/${e(v)}`],
      ["urlscan", "infrastructure", (v) => `https://urlscan.io/search/#ip:${e(v)}`],
      ["Spur", "context", (v) => `https://spur.us/context/${e(v)}`],
      ["ipinfo", "context", (v) => `https://ipinfo.io/${e(v)}`],
      ["BGP.he.net", "context", (v) => `https://bgp.he.net/ip/${e(v)}`],
    ],
    domain: [
      ["VirusTotal", "reputation", (v) => `https://www.virustotal.com/gui/domain/${e(v)}`],
      ["Talos", "reputation", (v) => `https://talosintelligence.com/reputation_center/lookup?search=${e(v)}`],
      ["Safe Browsing", "reputation", (v) => `https://transparencyreport.google.com/safe-browsing/search?url=${e(v)}`],
      ["OTX", "intel", (v) => `https://otx.alienvault.com/indicator/domain/${e(v)}`],
      ["URLhaus", "intel", (v) => `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
      ["ThreatFox", "intel", (v) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(v)}`],
      ["urlscan", "infrastructure", (v) => `https://urlscan.io/search/#page.domain:${e(v)}`],
      ["crt.sh", "infrastructure", (v) => `https://crt.sh/?q=%25.${e(v)}`],
      ["SecurityTrails", "infrastructure", (v) => `https://securitytrails.com/domain/${e(v)}`],
      ["Shodan", "infrastructure", (v) => `https://www.shodan.io/search?query=hostname%3A${e(v)}`],
      ["WHOIS", "context", (v) => `https://who.is/whois/${e(v)}`],
      ["MX lookup", "context", (v) => `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${e(v)}`],
      ["Wayback", "context", (v) => `https://web.archive.org/web/*/${e(v)}`],
    ],
    url: [
      ["VirusTotal", "reputation", (v) => `https://www.virustotal.com/gui/search/${e(e(v))}`],
      ["URLhaus", "intel", (v) => `https://urlhaus.abuse.ch/browse.php?search=${e(v)}`],
      ["urlscan", "infrastructure", (v) => `https://urlscan.io/search/#${e('page.url:"' + v + '"')}`],
      ["Safe Browsing", "reputation", (v) => `https://transparencyreport.google.com/safe-browsing/search?url=${e(v)}`],
      ["Wayback", "context", (v) => `https://web.archive.org/web/*/${e(v)}`],
    ],
    hash: [
      ["VirusTotal", "reputation", (v) => `https://www.virustotal.com/gui/file/${e(v)}`],
      ["MalwareBazaar", "intel", (v) => `https://bazaar.abuse.ch/browse.php?search=${e(v)}`],
      ["OTX", "intel", (v) => `https://otx.alienvault.com/indicator/file/${e(v)}`],
      ["ThreatFox", "intel", (v) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${e(v)}`],
      ["Hybrid Analysis", "sandbox", (v) => `https://www.hybrid-analysis.com/search?query=${e(v)}`],
      ["Triage", "sandbox", (v) => `https://tria.ge/s?q=${e(v)}`],
      ["Joe Sandbox", "sandbox", (v) => `https://www.joesandbox.com/search?q=${e(v)}`],
      ["CIRCL hashlookup", "context", (v) => `https://hashlookup.circl.lu/lookup/${({ 32: "md5", 40: "sha1", 64: "sha256" })[v.length] || "sha256"}/${e(v)}`],
    ],
    cve: [
      ["NVD", "intel", (v) => `https://nvd.nist.gov/vuln/detail/${e(v)}`],
      ["CVE.org", "intel", (v) => `https://www.cve.org/CVERecord?id=${e(v)}`],
      ["CISA KEV", "intel", (v) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${e(v)}`],
      ["Vulners", "intel", (v) => `https://vulners.com/search?query=${e(v)}`],
      ["OTX", "intel", (v) => `https://otx.alienvault.com/indicator/cve/${e(v)}`],
      ["Exploit-DB", "context", (v) => `https://www.exploit-db.com/search?cve=${e(v)}`],
      ["GitHub advisories", "context", (v) => `https://github.com/advisories?query=${e(v)}`],
    ],
    email: [
      ["Have I Been Pwned", "exposure", (v) => `https://haveibeenpwned.com/account/${e(v)}`],
      ["Hunter verify", "context", (v) => `https://hunter.io/email-verifier/${e(v)}`],
      ["Epieos", "context", (v) => `https://epieos.com/?q=${e(v)}`],
      ["Google (exact)", "context", (v) => `https://www.google.com/search?q=%22${e(v)}%22`],
    ],
    asn: [
      ["BGP.he.net", "context", (v) => `https://bgp.he.net/${e(v.toUpperCase())}`],
      ["ipinfo", "context", (v) => `https://ipinfo.io/${e(v.toUpperCase())}`],
      ["RIPEstat", "context", (v) => `https://stat.ripe.net/${e(v.toUpperCase())}`],
      ["PeeringDB", "context", (v) => `https://www.peeringdb.com/search?q=${e(v.replace(/^AS/i, ""))}`],
      ["Shodan", "infrastructure", (v) => `https://www.shodan.io/search?query=asn%3A${e(v.toUpperCase())}`],
    ],
    attack: [["MITRE ATT&CK", "intel", (v) => `https://attack.mitre.org/techniques/${v.replace(".", "/")}/`]],
    btc: [["Blockchair", "chain", (v) => `https://blockchair.com/bitcoin/address/${e(v)}`], ["mempool.space", "chain", (v) => `https://mempool.space/address/${e(v)}`],
      ["WalletExplorer", "chain", (v) => `https://www.walletexplorer.com/address/${e(v)}`], ["Chainabuse", "reputation", (v) => `https://www.chainabuse.com/address/${e(v)}`]],
    eth: [["Etherscan", "chain", (v) => `https://etherscan.io/address/${e(v)}`], ["Blockchair", "chain", (v) => `https://blockchair.com/ethereum/address/${e(v)}`], ["Chainabuse", "reputation", (v) => `https://www.chainabuse.com/address/${e(v)}`]],
    username: [["WhatsMyName", "persona", (v) => `https://whatsmyname.app/?q=${e(v)}`], ["GitHub", "persona", (v) => `https://github.com/${e(v)}`],
      ["GitHub search", "persona", (v) => `https://github.com/search?q=${e(v)}&type=users`], ["Google (exact)", "persona", (v) => `https://www.google.com/search?q=%22${e(v)}%22`]],
  };
  P.ipv6 = P.ipv4.filter(([n]) => !["Spur"].includes(n));
  P.md5 = P.sha1 = P.sha256 = P.sha512 = P.hash;
  const PERSONA = [
    ["GitHub", "https://github.com/{u}"], ["GitLab", "https://gitlab.com/{u}"], ["X / Twitter", "https://x.com/{u}"], ["Instagram", "https://www.instagram.com/{u}/"],
    ["Reddit", "https://www.reddit.com/user/{u}"], ["TikTok", "https://www.tiktok.com/@{u}"], ["YouTube", "https://www.youtube.com/@{u}"], ["Twitch", "https://www.twitch.tv/{u}"],
    ["Telegram", "https://t.me/{u}"], ["Mastodon (social)", "https://mastodon.social/@{u}"], ["Bluesky", "https://bsky.app/profile/{u}.bsky.social"], ["Keybase", "https://keybase.io/{u}"],
    ["HackerOne", "https://hackerone.com/{u}"], ["Medium", "https://medium.com/@{u}"], ["Pastebin", "https://pastebin.com/u/{u}"], ["Docker Hub", "https://hub.docker.com/u/{u}"],
    ["npm", "https://www.npmjs.com/~{u}"], ["PyPI", "https://pypi.org/user/{u}/"], ["Steam", "https://steamcommunity.com/id/{u}"], ["Linktree", "https://linktr.ee/{u}"],
  ];

  /** links(value) → {type, value, groups:{category:[{name, url}]}} */
  function links(value) {
    let v = W.refang(String(value || "").trim()), type = W.detectType(v);
    if (type === "username") v = v.replace(/^@/, "");
    if (!type && /^[A-Za-z0-9_.-]{2,40}$/.test(v)) type = "username";
    const defs = P[type] || [];
    const groups = {};
    for (const [name, cat, fn] of defs) (groups[cat] = groups[cat] || []).push({ name, url: fn(v) });
    if (type === "username") groups.persona = (groups.persona || []).concat(PERSONA.map(([name, t]) => ({ name, url: t.replace("{u}", e(v)) })));
    return { type, value: v, groups };
  }
  W.eng.pivot = { links, SOURCES: P };
})(typeof window !== "undefined" ? window.W : globalThis.W);
