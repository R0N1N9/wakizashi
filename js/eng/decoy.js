/* DECOY — cover identities and tripwires.
 *
 *   persona({seed, country, sex, minAge, maxAge, baseEmail}) → fictitious persona, fully reproducible from the seed
 *   seedPhrase() → random seed     rng(seed) → deterministic float generator (xmur3 + sfc32)
 *   webbug / honeycred / alias / canaryDocx — port of Katana shinobi/decoy.py (canary tokens & honeytokens)
 *
 * Phone numbers come from ranges regulators reserve for fiction where one exists (NANP 555-0100…0199, Ofcom
 * drama ranges, ACMA's fictitious ranges, ARCEP's 01 99 00 / 06 39 98 blocks, the Bundesnetzagentur film/TV
 * blocks). For countries without one we return no number rather than risk a real person's. Street names are
 * generic and house numbers random, but any address may coincide with a real one — never use a persona to
 * deceive, defraud or impersonate; it exists to keep your real details out of sign-ups you don't trust.
 * The persona's password is NOT derived from the seed (it uses the crypto RNG), so sharing a seed never leaks it.
 */
(function (W) {
  "use strict";

  // ------------------------------------------------------------------ seeded RNG
  function xmur3(str) { let h = 1779033703 ^ str.length; for (let i = 0; i < str.length; i++) { h = Math.imul(h ^ str.charCodeAt(i), 3432918353); h = (h << 13) | (h >>> 19); } return () => { h = Math.imul(h ^ (h >>> 16), 2246822507); h = Math.imul(h ^ (h >>> 13), 3266489909); return (h ^= h >>> 16) >>> 0; }; }
  function rng(seed) {
    const s = xmur3(String(seed)); let a = s(), b = s(), c = s(), d = s();
    const next = () => { a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0; let t = (a + b) | 0; a = b ^ (b >>> 9); b = (c + (c << 3)) | 0; c = (c << 21) | (c >>> 11); d = (d + 1) | 0; t = (t + d) | 0; c = (c + t) | 0; return (t >>> 0) / 4294967296; };
    for (let i = 0; i < 12; i++) next();
    const r = { next, int: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)), pick: (arr) => arr[Math.floor(next() * arr.length)], digits: (n) => Array.from({ length: n }, () => Math.floor(next() * 10)).join(""),
      letter: () => "ABCDEFGHJKLMNPRSTUWXYZ"[Math.floor(next() * 22)] };
    return r;
  }
  const SEED_WORDS = "amber birch cobalt delta ember falcon granite harbor indigo juniper kestrel lantern meadow nimbus onyx pebble quartz raven saffron thistle umber velvet willow yonder zephyr".split(" ");
  function seedPhrase() { const P = W.eng.passgen; return [0, 1, 2].map(() => SEED_WORDS[P.randInt(SEED_WORDS.length)]).join("-") + "-" + (1000 + P.randInt(9000)); }

  // ------------------------------------------------------------------ compact per-country data
  // cities: [name, region, postcode-prefix, phone-area] — postcode builders below
  const C = {
    us: { name: "United States", flag: "US", cc: "+1", tld: "com",
      m: "James Michael Robert David William Daniel Matthew Andrew Joshua Ryan Tyler Brandon Kevin Jason Eric Nathan Kyle Aaron Adam Sean Logan Caleb Owen Wyatt Evan".split(" "),
      f: "Emily Sarah Jessica Ashley Megan Lauren Rachel Hannah Olivia Emma Abigail Madison Chloe Grace Natalie Brooke Kayla Allison Paige Morgan Avery Claire Leah Riley Nora".split(" "),
      last: "Smith Johnson Williams Brown Jones Miller Davis Wilson Anderson Taylor Thomas Moore Martin Jackson Thompson White Harris Clark Lewis Walker Hall Young Allen King Wright Scott Green Baker Adams Nelson Carter Mitchell Turner Parker Collins".split(" "),
      streets: "Maple Oak Pine Cedar Elm Willow Birch Walnut Chestnut Lakeview Hillcrest Ridgeview Meadow Sunset Highland Park Forest River Spring Orchard".split(" "), sfx: "St Ave Dr Ln Rd Ct Way Pl Blvd".split(" "),
      cities: [["Columbus", "OH", "432", "614"], ["Denver", "CO", "802", "303"], ["Portland", "OR", "972", "503"], ["Austin", "TX", "787", "512"], ["Raleigh", "NC", "276", "919"], ["Madison", "WI", "537", "608"], ["Boise", "ID", "837", "208"], ["Richmond", "VA", "232", "804"], ["Omaha", "NE", "681", "402"], ["Tucson", "AZ", "857", "520"], ["Albany", "NY", "122", "518"], ["Sacramento", "CA", "958", "916"]],
      post: (r, p) => p + r.digits(2), addr: (h, s, c, pc) => [`${h} ${s}`, `${c[0]}, ${c[1]} ${pc}`],
      phone: (r, c) => ({ number: `+1 (${c[3]}) 555-01${r.digits(2)}`, reserved: true, note: "NANP 555-0100…0199 is reserved for fiction" }) },
    ca: { name: "Canada", flag: "CA", cc: "+1", tld: "ca",
      m: "Liam Noah Ethan Lucas Benjamin Owen Nathan Jacob Samuel Alexandre Gabriel Félix Thomas Logan Connor Hunter Mason Carter Dylan Jack".split(" "),
      f: "Olivia Emma Charlotte Ava Sophie Chloé Léa Amelia Abigail Maya Zoé Emily Florence Rosalie Hannah Ella Avery Madeleine Stella Juliette".split(" "),
      last: "Smith Brown Tremblay Martin Roy Wilson MacDonald Gagnon Johnson Taylor Côté Campbell Anderson Leblanc Lee Gauthier White Morin Thompson Bouchard Scott Stewart Murray Fraser".split(" "),
      streets: "Maple Birch Spruce Cedar Pine Lakeshore Bay Queen King Victoria Elgin Bloor Main Church Wellington Front Park Ridge".split(" "), sfx: "St Ave Rd Dr Cres Blvd".split(" "),
      cities: [["Ottawa", "ON", "K1", "613"], ["Hamilton", "ON", "L8", "905"], ["Winnipeg", "MB", "R3", "204"], ["Halifax", "NS", "B3", "902"], ["Calgary", "AB", "T2", "403"], ["Victoria", "BC", "V8", "250"], ["Saskatoon", "SK", "S7", "306"], ["Québec", "QC", "G1", "418"]],
      post: (r, p) => `${p}${r.letter()} ${r.int(1, 9)}${r.letter()}${r.int(1, 9)}`, addr: (h, s, c, pc) => [`${h} ${s}`, `${c[0]}, ${c[1]} ${pc}`],
      phone: (r, c) => ({ number: `+1 (${c[3]}) 555-01${r.digits(2)}`, reserved: true, note: "NANP 555-0100…0199 is reserved for fiction" }) },
    uk: { name: "United Kingdom", flag: "GB", cc: "+44", tld: "co.uk",
      m: "Oliver George Harry Jack Charlie Thomas Oscar James William Henry Alfie Freddie Archie Leo Joshua Samuel Joseph Daniel Edward Max".split(" "),
      f: "Olivia Amelia Isla Ava Emily Sophie Grace Lily Freya Ella Poppy Evie Charlotte Isabella Daisy Phoebe Ruby Alice Florence Matilda".split(" "),
      last: "Smith Jones Williams Taylor Brown Davies Evans Wilson Thomas Johnson Roberts Robinson Thompson Wright Walker White Edwards Hughes Green Hall Lewis Harris Clarke Patel Jackson Wood Turner Martin Cooper Hill".split(" "),
      streets: "Church Station Victoria Park Mill Queens Kings Manor Orchard Grange Meadow Chapel Albert Springfield Windsor Highfield Willow Beech Elm".split(" "), sfx: "Road Street Lane Close Avenue Gardens Way Crescent Drive Grove".split(" "),
      cities: [["London", "Greater London", "N", "020"], ["Manchester", "Greater Manchester", "M", "0161"], ["Birmingham", "West Midlands", "B", "0121"], ["Leeds", "West Yorkshire", "LS", "0113"], ["Bristol", "Bristol", "BS", "0117"], ["Nottingham", "Nottinghamshire", "NG", "0115"], ["Sheffield", "South Yorkshire", "S", "0114"], ["Newcastle upon Tyne", "Tyne and Wear", "NE", "0191"]],
      post: (r, p) => `${p}${r.int(1, 20)} ${r.int(1, 9)}${r.letter()}${r.letter()}`, addr: (h, s, c, pc) => [`${h} ${s}`, c[0], pc],
      phone: (r, c) => { const area = { "020": "020 7946 0", "0161": "0161 496 0", "0121": "0121 496 0", "0113": "0113 496 0", "0117": "0117 496 0", "0115": "0115 496 0", "0114": "0114 496 0", "0191": "0191 498 0" }[c[3]];
        return r.next() < 0.6 ? { number: `+44 7700 900${r.digits(3)}`, reserved: true, note: "Ofcom drama range 07700 900000–900999" } : { number: area.replace(/^0/, "+44 ") + r.digits(3), reserved: true, note: "Ofcom drama range for " + c[0] }; } },
    au: { name: "Australia", flag: "AU", cc: "+61", tld: "com.au",
      m: "Oliver Noah Jack William Leo Lucas Thomas Henry Charlie James Liam Hudson Ethan Mason Harrison Cooper Archie Lachlan Isaac Max".split(" "),
      f: "Charlotte Olivia Amelia Isla Mia Ava Grace Willow Harper Chloe Ella Zoe Sienna Matilda Evie Ruby Sophie Lily Isabella Matilda".split(" "),
      last: "Smith Jones Williams Brown Wilson Taylor Johnson White Martin Anderson Thompson Nguyen Thomas Walker Harris Lee Ryan Robinson Kelly King Davis Wright Evans Roberts Murphy Mitchell".split(" "),
      streets: "George Wattle Banksia Acacia Eucalyptus Kookaburra Jacaranda Bottlebrush Hill Station Church Railway Ocean Beach Bay Park Victoria Queen High Grevillea".split(" "), sfx: "Street Road Avenue Parade Crescent Drive Place Court Close Terrace".split(" "),
      cities: [["Sydney", "NSW", "20", "02"], ["Newcastle", "NSW", "23", "02"], ["Canberra", "ACT", "26", "02"], ["Melbourne", "VIC", "30", "03"], ["Hobart", "TAS", "70", "03"], ["Brisbane", "QLD", "40", "07"], ["Adelaide", "SA", "50", "08"], ["Perth", "WA", "60", "08"]],
      post: (r, p) => p + r.digits(2), addr: (h, s, c, pc) => [`${h} ${s}`, `${c[0]} ${c[1]} ${pc}`],
      phone: (r, c) => r.next() < 0.5 ? { number: `+61 491 570 ${r.pick(["006", "156", "157", "158", "159", "110", "313", "737"])}`, reserved: true, note: "ACMA fictitious mobile number" }
        : { number: `+61 ${c[3].slice(1)} ${c[3] === "03" ? "7010" : "5550"} ${r.digits(4)}`, reserved: true, note: "ACMA fictitious landline range" } },
    de: { name: "Germany", flag: "DE", cc: "+49", tld: "de",
      m: "Lukas Leon Finn Jonas Paul Felix Elias Noah Luis Ben Maximilian Moritz Jan Tim Niklas Tobias Florian Julian Simon Fabian".split(" "),
      f: "Emma Mia Hannah Sophia Lena Lea Marie Anna Laura Lina Clara Leonie Johanna Lara Charlotte Julia Sarah Katharina Nele Paula".split(" "),
      last: "Müller Schmidt Schneider Fischer Weber Meyer Wagner Becker Schulz Hoffmann Koch Bauer Richter Klein Wolf Schröder Neumann Schwarz Zimmermann Braun Krüger Hofmann Hartmann Lange Werner".split(" "),
      streets: "Haupt Garten Linden Birken Schul Kirch Wald Berg Bahnhof Ahorn Eichen Rosen Wiesen Mühlen Feld Sonnen Tannen Buchen".split(" "), sfx: ["straße", "weg", "allee", "ring", "gasse"],
      cities: [["Berlin", "Berlin", "10", "030"], ["Hamburg", "Hamburg", "22", "040"], ["Frankfurt am Main", "Hessen", "60", "069"], ["München", "Bayern", "80", "089"]],
      post: (r, p) => p + r.digits(3), addr: (h, s, c, pc) => [`${s.replace(" ", "")} ${h}`, `${pc} ${c[0]}`], streetJoin: true,
      phone: (r, c) => ({ number: { "030": "+49 30 23125 ", "040": "+49 40 66969 ", "069": "+49 69 90009 ", "089": "+49 89 99998 " }[c[3]] + r.digits(3), reserved: true, note: "Bundesnetzagentur film/TV block — double-check before relying on it" }) },
    fr: { name: "France", flag: "FR", cc: "+33", tld: "fr",
      m: "Gabriel Louis Raphaël Jules Adam Lucas Léo Hugo Arthur Nathan Paul Tom Théo Noah Ethan Maël Sacha Antoine Victor Martin".split(" "),
      f: "Jade Louise Emma Alice Ambre Lina Rose Chloé Léa Anna Mia Inès Julia Léna Manon Camille Zoé Lou Juliette Margaux".split(" "),
      last: "Martin Bernard Dubois Thomas Robert Richard Petit Durand Leroy Moreau Simon Laurent Lefebvre Michel Garcia David Bertrand Roux Vincent Fournier Morel Girard Andre Mercier Dupont".split(" "),
      streets: ["de la Paix", "des Lilas", "du Moulin", "de la Gare", "des Écoles", "du Château", "des Tilleuls", "de l'Église", "Victor Hugo", "des Acacias", "du Marché", "Pasteur", "des Roses", "de la Fontaine"], sfx: ["rue", "avenue", "allée", "chemin", "place", "boulevard"],
      cities: [["Paris", "Île-de-France", "750", "01"], ["Lyon", "Auvergne-Rhône-Alpes", "690", "04"], ["Nantes", "Pays de la Loire", "440", "02"], ["Lille", "Hauts-de-France", "590", "03"], ["Bordeaux", "Nouvelle-Aquitaine", "330", "05"], ["Toulouse", "Occitanie", "310", "05"]],
      post: (r, p) => p + r.digits(2), addr: (h, s, c, pc) => [`${h} ${s}`, `${pc} ${c[0]}`], frStyle: true,
      phone: (r) => r.next() < 0.5 ? { number: `+33 1 99 00 ${r.digits(2)} ${r.digits(2)}`, reserved: true, note: "ARCEP block reserved for fiction" } : { number: `+33 6 39 98 ${r.digits(2)} ${r.digits(2)}`, reserved: true, note: "ARCEP mobile block reserved for fiction" } },
    es: { name: "Spain", flag: "ES", cc: "+34", tld: "es",
      m: "Hugo Martín Lucas Mateo Leo Daniel Alejandro Pablo Manuel Álvaro Adrián David Mario Diego Javier Marcos Sergio Iván Carlos Jorge".split(" "),
      f: "Lucía Sofía Martina María Julia Paula Valeria Emma Daniela Carla Alba Noa Alma Sara Carmen Vega Lara Elena Claudia Irene".split(" "),
      last: "García Rodríguez González Fernández López Martínez Sánchez Pérez Gómez Martín Jiménez Ruiz Hernández Díaz Moreno Muñoz Álvarez Romero Alonso Gutiérrez Navarro Torres Domínguez".split(" "),
      streets: ["Mayor", "del Sol", "de la Luna", "Real", "del Carmen", "de las Flores", "del Pilar", "Nueva", "de la Iglesia", "del Mar", "de los Olivos", "del Río"], sfx: ["Calle", "Avenida", "Paseo", "Plaza", "Camino"],
      cities: [["Madrid", "Madrid", "280"], ["Valencia", "Valencia", "460"], ["Sevilla", "Andalucía", "410"], ["Zaragoza", "Aragón", "500"], ["Bilbao", "País Vasco", "480"], ["Málaga", "Andalucía", "290"]],
      post: (r, p) => p + r.digits(2), addr: (h, s, c, pc) => [`${s}, ${h}`, `${pc} ${c[0]}`], esStyle: true,
      phone: () => ({ number: null, reserved: false, note: "Spain has no published fiction range — leave the field blank or use a VoIP/burner number" }) },
    it: { name: "Italy", flag: "IT", cc: "+39", tld: "it",
      m: "Leonardo Francesco Alessandro Lorenzo Mattia Tommaso Gabriele Andrea Riccardo Edoardo Matteo Giuseppe Antonio Federico Marco Luca Davide Simone Pietro Giovanni".split(" "),
      f: "Sofia Giulia Aurora Alice Ginevra Emma Giorgia Beatrice Greta Vittoria Anna Chiara Sara Martina Francesca Elena Ludovica Bianca Noemi Camilla".split(" "),
      last: "Rossi|Russo|Ferrari|Esposito|Bianchi|Romano|Colombo|Ricci|Marino|Greco|Bruno|Gallo|Conti|De Luca|Costa|Giordano|Mancini|Rizzo|Lombardi|Moretti|Barbieri|Fontana".split("|"),
      streets: ["Roma", "Garibaldi", "Mazzini", "dei Mille", "Dante", "Verdi", "della Libertà", "dei Tigli", "del Sole", "Cavour", "delle Rose", "San Francesco"], sfx: ["Via", "Viale", "Piazza", "Corso"],
      cities: [["Torino", "Piemonte", "101"], ["Bologna", "Emilia-Romagna", "401"], ["Firenze", "Toscana", "501"], ["Verona", "Veneto", "371"], ["Bari", "Puglia", "701"], ["Genova", "Liguria", "161"]],
      post: (r, p) => p + r.digits(2), addr: (h, s, c, pc) => [`${s} ${h}`, `${pc} ${c[0]}`], esStyle: true,
      phone: () => ({ number: null, reserved: false, note: "Italy has no published fiction range — leave the field blank or use a VoIP/burner number" }) },
    nl: { name: "Netherlands", flag: "NL", cc: "+31", tld: "nl",
      m: "Noah Daan Sem Lucas Levi Finn Milan Jesse Luuk Bram Thijs Lars Ruben Sven Stijn Tim Niels Jasper Thomas Koen".split(" "),
      f: "Emma Julia Mila Tess Sophie Zoë Sara Nora Yara Eva Lotte Anna Fleur Sanne Lisa Iris Femke Noor Roos Isa".split(" "),
      last: "de Jong|Jansen|de Vries|van den Berg|van Dijk|Bakker|Janssen|Visser|Smit|Meijer|de Boer|Mulder|de Groot|Bos|Vos|Peters|Hendriks|van Leeuwen|Dekker|Brouwer".split("|"),
      streets: "Kerk Molen School Dorps Linden Beuken Eiken Wilgen Tulpen Rozen Haven Stations Kastanje Berken Meidoorn".split(" "), sfx: ["straat", "laan", "weg", "plein", "gracht"],
      cities: [["Utrecht", "Utrecht", "35"], ["Eindhoven", "Noord-Brabant", "56"], ["Groningen", "Groningen", "97"], ["Leiden", "Zuid-Holland", "23"], ["Haarlem", "Noord-Holland", "20"], ["Arnhem", "Gelderland", "68"]],
      post: (r, p) => `${p}${r.digits(2)} ${r.letter()}${r.letter()}`, addr: (h, s, c, pc) => [`${s.replace(" ", "")} ${h}`, `${pc} ${c[0]}`], streetJoin: true,
      phone: () => ({ number: null, reserved: false, note: "The Netherlands has no published fiction range — leave the field blank or use a VoIP/burner number" }) },
  };
  const OCCUPATIONS = "graphic designer|logistics coordinator|lab technician|copy editor|office manager|landscape gardener|physiotherapist|data analyst|bookkeeper|museum guide|translator|sound engineer|pastry chef|librarian|project coordinator|surveyor|nurse|teacher|web developer|photographer".split("|");
  const ADJ = "quiet swift amber lucky silver lunar misty rapid sunny brave calm wild clever noble bright jolly dusty frosty golden mellow".split(" ");
  const NOUN = "fox otter heron lynx falcon badger maple comet river pebble harbor willow raven ember tundra cedar meadow koala panda bison".split(" ");
  const QUESTIONS = ["Mother's maiden name", "Name of your first pet", "City you were born in", "Your first school", "Favourite childhood friend", "Make of your first car"];

  const fold = (s) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/ß/g, "ss").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
  const pad2 = (n) => String(n).padStart(2, "0");

  function persona(o = {}) {
    const seed = String(o.seed || seedPhrase());
    const code = C[o.country] ? o.country : "us", c = C[code];
    const r = rng(seed + "|" + code + "|" + (o.sex || "any") + "|" + (o.minAge || 21) + "-" + (o.maxAge || 60));
    const sex = o.sex === "f" || o.sex === "m" ? o.sex : r.next() < 0.5 ? "f" : "m";
    const first = r.pick(c[sex]), last = r.pick(c.last), middle = r.pick(c[sex]);
    const minAge = W.clamp(+o.minAge || 21, 16, 90), maxAge = W.clamp(+o.maxAge || 60, minAge, 95);
    const today = o.today ? new Date(o.today) : new Date(), refYear = today.getUTCFullYear();
    const year = refYear - r.int(minAge, maxAge), month = r.int(1, 12), day = r.int(1, [31, year % 4 ? 28 : 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]);
    const city = r.pick(c.cities), house = r.int(2, 180);
    const stem = r.pick(c.streets), sfx = r.pick(c.sfx);
    const street = c.streetJoin ? stem + sfx : c.frStyle ? `${sfx} ${stem}` : c.esStyle ? `${sfx} ${stem}` : `${stem} ${sfx}`;
    const postcode = c.post(r, city[2]);
    const lines = c.addr(house, street, city, postcode);
    const phone = c.phone(r, city);
    const f = fold(first), l = fold(last), yy = String(year).slice(2), n2 = r.digits(2), n3 = r.int(100, 999);
    const handles = W.uniq([`${f}.${l}`, `${f}${l}${yy}`, `${f[0]}${l}${n2}`, `${f}_${l[0]}${n3}`, `${r.pick(ADJ)}${r.pick(NOUN)}${n3}`, `${l}.${f}${n2}`]);
    const answers = QUESTIONS.map((q) => ({ q, a: `${r.pick(ADJ)} ${r.pick(NOUN)} ${r.int(10, 99)}` }));
    const emails = aliasIdeas(handles, o.baseEmail, r);
    const pw = W.eng.passgen ? W.eng.passgen.password({ length: 20 }).value : null;
    return {
      fictitious: true, seed, country: code, countryName: c.name, sex,
      name: { first, middle, last, full: `${first} ${last}` },
      birthdate: `${year}-${pad2(month)}-${pad2(day)}`, age: refYear - year - (today.getUTCMonth() + 1 < month || (today.getUTCMonth() + 1 === month && today.getUTCDate() < day) ? 1 : 0),
      address: { lines, street: `${house} ${street}`, city: city[0], region: city[1], postcode, country: c.name },
      phone, occupation: r.pick(OCCUPATIONS), handles, emails, answers, password: pw,
      note: "Fictitious persona — for keeping your real details out of untrusted sign-ups. Don't use it to deceive, defraud or impersonate anyone, or where the law requires your real identity.",
    };
  }
  function aliasIdeas(handles, base, r) {
    const out = [];
    if (base && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(base)) {
      const [local, dom] = base.split("@");
      out.push({ kind: "plus-address", value: `${local}+${handles[4].replace(/\d+$/, "")}${r.int(10, 99)}@${dom}`, note: "Works with Gmail, Outlook, Proton, Fastmail, iCloud…; trivially reversible to your base address." });
    }
    out.push({ kind: "alias local-part", value: handles[0], note: "Create it at an alias service (SimpleLogin, addy.io, Firefox Relay, DuckDuckGo Email Protection, iCloud Hide My Email, Proton Pass) — mail forwards to you and the alias can be burned." });
    out.push({ kind: "alias local-part", value: handles[4], note: "Unlinkable to the name — best for forums and newsletters." });
    return out;
  }
  const COUNTRIES = Object.entries(C).map(([id, c]) => ({ id, name: c.name, reservedPhones: c.phone(rng("x"), c.cities[0]).reserved }));

  // ------------------------------------------------------------------ canary tokens / honeytokens (port of decoy.py)
  const B32L = "abcdefghijklmnopqrstuvwxyz234567";
  const rs = (alpha, n) => { const P = W.eng.passgen; let s = ""; for (let i = 0; i < n; i++) s += alpha[P.randInt(alpha.length)]; return s; };
  const tok = (n = 16) => rs(B32L, n);
  const now = () => W.nowIso();
  const cbUrl = (callback, token, path = "c") => `https://${String(callback || "canary.example.com").replace(/^https?:\/\//, "").replace(/^\/+|\/+$/g, "")}/${path}/${token}.png`;
  function webbug(callback, label = "webbug") {
    const token = tok(), url = cbUrl(callback, token);
    return { kind: "webbug", label, token, created: now(), url, fires_when: "the HTML/email/page is rendered and remote images load",
      snippets: { html_img: `<img src="${url}" width="1" height="1" alt="" style="display:none">`, css_bg: `.x{background:url("${url}")}`, email_sig: `<img src="${url}" width="1" height="1" style="opacity:0" alt="">`, markdown: `![](${url})` } };
  }
  function honeycred(flavor = "aws", label = "honeytoken") {
    const f = String(flavor).toLowerCase(), UD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", LD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const body = f === "aws" ? { aws_access_key_id: "AKIA" + rs(UD, 16), aws_secret_access_key: rs(LD + "+/", 40), hint: "drop in ~/.aws/credentials, a .env, or a repo; alert when someone tries to use it (CloudTrail / a canary service)" }
      : f === "github" ? { token: "ghp_" + rs(LD, 36), hint: "plant in a .git-credentials, CI secret or dotfile" }
      : f === "slack" ? { token: `xoxb-${rs("0123456789", 12)}-${rs("0123456789", 12)}-${rs("0123456789abcdef", 24)}`, hint: "plant in a config or wiki page" }
      : f === "stripe" ? { secret_key: "sk_live_" + rs(LD, 24), hint: "plant in server config / .env" }
      : { api_key: rs("0123456789abcdef", 48), hint: "generic bearer token bait" };
    return { kind: "honeycred", flavor: f, label, token: body, created: now(), fires_when: "someone attempts to authenticate with the planted credential",
      warning: "These are fake and authenticate to nothing. They only alert if you register them with a monitoring service you control (e.g. an AWS canary key) — never use them as real credentials." };
  }
  function alias(baseEmail, service) {
    const svc = String(service || "").toLowerCase().replace(/[^a-z0-9]/g, "") || "svc";
    if (!/@/.test(baseEmail || "")) return { kind: "alias", service, error: "provide a base email like you@domain.com" };
    const [local, dom] = String(baseEmail).split("@");
    return { kind: "alias", service, created: now(), plus: `${local}+${svc}${tok(4)}@${dom}`, dot_hint: "Gmail also ignores dots: j.o.e@gmail = joe@gmail",
      fires_when: "mail arrives to this alias from anyone but the intended service → that service leaked/sold it" };
  }
  async function canaryDocx(callback, label = "canary.docx") {
    const token = tok(), url = cbUrl(callback, token, "d");
    const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
    const ctypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';
    const rels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>';
    const doc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
      + '<w:p><w:r><w:t xml:space="preserve">Confidential. Do not distribute.</w:t></w:r></w:p><w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
      + `<w:r><w:instrText xml:space="preserve"> INCLUDEPICTURE "${esc(url)}" \\d </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:body></w:document>`;
    const data = await W.eng.kpack.zip([{ name: "[Content_Types].xml", data: ctypes }, { name: "_rels/.rels", data: rels }, { name: "word/document.xml", data: doc }]);
    return { kind: "canary_docx", label, token, created: now(), url, filename: /\.docx$/i.test(label) ? label : label + ".docx", data,
      fires_when: "the document is opened in Word and fields update (remote image fetch)", note: "Some readers ask before loading remote content; the beacon fires when the user allows it." };
  }

  W.eng.decoy = { persona, seedPhrase, rng, COUNTRIES, webbug, honeycred, alias, canaryDocx };
})(typeof window !== "undefined" ? window.W : globalThis.W);
