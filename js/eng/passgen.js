/* PASSGEN — random passwords / passphrases (crypto RNG, unbiased) and a zxcvbn-style strength estimate.
 *
 *   password({length, lower, upper, digits, symbols, ambiguous, each})   → {value, bits, pool}
 *   passphrase({words, sep, caps, number})                              → {value, bits, words}
 *   estimate(pw, userInputs?)  → {guesses, log10, bits, score 0-4, label, crack{...}, sequence[], warning, suggestions[]}
 *
 * The estimator follows zxcvbn's idea (Wheeler, USENIX Security 2016): find every pattern match (dictionary +
 * reversed + l33t, keyboard walks, sequences, repeats, dates/years), estimate guesses for each, then pick the
 * cheapest covering sequence with a dynamic program; unmatched characters are brute-forced at 10 guesses/char.
 * It is a "lite" port — smaller dictionaries — so it errs on the generous side for uncommon words.
 * Passwords are only ever held in memory by the caller; nothing here stores anything.
 */
(function (W) {
  "use strict";

  // ------------------------------------------------------------------ RNG
  function randInt(n) { // unbiased 0..n-1
    if (n <= 0 || n > 0x100000000) throw new Error("range");
    const lim = Math.floor(0x100000000 / n) * n, a = new Uint32Array(1);
    for (;;) { globalThis.crypto.getRandomValues(a); if (a[0] < lim) return a[0] % n; }
  }
  const pick = (arr) => arr[randInt(arr.length)];
  function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = randInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; }

  const SETS = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!@#$%^&*()-_=+[]{};:,.?/~" };
  const AMBIG = /[Il1O0o|`'"]/g;

  function password(o = {}) {
    const length = W.clamp(+o.length || 20, 4, 256);
    const use = ["lower", "upper", "digits", "symbols"].filter((k) => o[k] !== false && !(k === "symbols" && o.symbols == null && false));
    const sets = use.map((k) => (o.ambiguous === false ? SETS[k].replace(AMBIG, "") : SETS[k])).filter(Boolean);
    if (!sets.length) throw new Error("Pick at least one character class");
    const pool = sets.join("");
    let chars;
    if (o.each !== false && length >= sets.length) {
      chars = sets.map((s) => pick(s));                    // at least one of each class…
      while (chars.length < length) chars.push(pick(pool));
      shuffle(chars);                                       // …at a random position
    } else chars = Array.from({ length }, () => pick(pool));
    return { value: chars.join(""), bits: +(length * Math.log2(pool.length)).toFixed(1), pool: pool.length };
  }

  function passphrase(o = {}) {
    const list = W.eng.words.list, n = W.clamp(+o.words || 6, 3, 20);
    const sep = o.sep == null ? "-" : String(o.sep);
    let words = Array.from({ length: n }, () => pick(list));
    if (o.caps) words = words.map((w) => w[0].toUpperCase() + w.slice(1));
    let bits = n * Math.log2(list.length);
    if (o.number) { const i = randInt(n); words[i] += String(randInt(10)); bits += Math.log2(10) + Math.log2(n); }
    return { value: words.join(sep), bits: +bits.toFixed(1), words: n, listSize: list.length };
  }

  // ------------------------------------------------------------------ dictionaries
  // Frequently reported weak passwords (rank = position). Written for Wakizashi from public breach-analysis themes.
  const COMMON = ("123456 password 123456789 12345678 12345 qwerty 1234567 111111 1234567890 123123 abc123 1234 password1 iloveyou 1q2w3e4r 000000 " +
    "qwerty123 zaq12wsx dragon sunshine princess letmein 654321 monkey 27653 1qaz2wsx 123321 qwertyuiop superman asdfghjkl football " +
    "baseball welcome master shadow michael ashley jessica jordan hunter trustno1 batman access mustang 666666 121212 starwars 7777777 " +
    "secret charlie flower hottie loveme zxcvbnm whatever freedom passw0rd computer hello killer pepper soccer hockey ranger daniel " +
    "harley thomas robert matrix cheese tigger buster summer winter internet admin login root changeme default guest test test123 " +
    "pass1234 qwer1234 abcd1234 asdf1234 aaaaaa 112233 159753 987654321 999999 555555 696969 131313 222222 888888 11111111 " +
    "princess1 sunshine1 iloveyou1 football1 monkey1 shadow1 baseball1 dragon1 superman1 michael1 jordan23 liverpool chelsea arsenal " +
    "blink182 pokemon minecraft naruto samsung google apple banana orange chocolate cookie purple angel angels lovely babygirl " +
    "family forever friends jesus christ blessed nicole daniel1 andrew joshua hannah amanda jennifer london paris berlin america " +
    "canada mexico qazwsx asdfgh zxcvbn 1qazxsw2 q1w2e3r4 qweasd qweasdzxc qwe123 asd123 zxc123 mypassword password123 password12 " +
    "welcome1 admin123 letmein1 iloveu love123 hello123 abc12345 monkey123 dragon123 master123 secret123 summer2024 winter2024 " +
    "spring2025 autumn2025 p@ssw0rd p@ssword passwort motdepasse contrasena senha parola wachtwoord haslo salasana").split(" ");
  const COMMON_RANK = new Map(COMMON.map((w, i) => [w, i + 1]));
  const NAMES = ("james john robert michael william david richard joseph thomas charles mary patricia jennifer linda elizabeth barbara susan jessica sarah karen " +
    "nancy lisa betty margaret sandra ashley kimberly emily donna michelle carol amanda melissa deborah stephanie rebecca laura sharon cynthia kathleen amy " +
    "anna emma olivia sophia isabella mia charlotte amelia harper evelyn liam noah oliver elijah lucas mason logan ethan jacob jack alex max sam ben tom").split(" ");
  const NAME_RANK = new Map(NAMES.map((w, i) => [w, i + 1]));
  const LEET = { a: "4@", b: "8", c: "(<{", e: "3", g: "69", i: "1!|", l: "1|7", o: "0", s: "$5", t: "+7", x: "%", z: "2" };
  const UNLEET = {}; for (const [ch, subs] of Object.entries(LEET)) for (const s of subs) (UNLEET[s] = UNLEET[s] || []).push(ch);

  function dictRank(w) {
    if (COMMON_RANK.has(w)) return { rank: COMMON_RANK.get(w), dict: "common passwords" };
    if (NAME_RANK.has(w)) return { rank: NAME_RANK.get(w) * 3 + 40, dict: "names" };
    const ws = W.eng.words && W.eng.words.set;
    if (ws && ws.has(w)) return { rank: Math.round(w.length <= 4 ? 300 : 900), dict: "english words" };
    return null;
  }
  const nCk = (n, k) => { if (k > n) return 0; let r = 1; for (let d = 1; d <= k; d++) { r *= n--; r /= d; } return r; };
  function upperVariations(tok) {
    if (!/[A-Z]/.test(tok) || tok === tok.toLowerCase()) return 1;
    if (/^[A-Z][^A-Z]+$/.test(tok) || /^[^A-Z]+[A-Z]$/.test(tok) || /^[^a-z]+$/.test(tok)) return 2;
    const U = (tok.match(/[A-Z]/g) || []).length, L = (tok.match(/[a-z]/g) || []).length;
    let v = 0; for (let i = 1; i <= Math.min(U, L); i++) v += nCk(U + L, i);
    return Math.max(v, 1);
  }

  // ------------------------------------------------------------------ matchers
  function dictionaryMatches(pw, userInputs) {
    const out = [], lower = pw.toLowerCase(), n = pw.length;
    const user = new Map((userInputs || []).map((u) => String(u).toLowerCase()).filter((u) => u.length >= 3).map((u, i) => [u, i + 1]));
    const add = (i, j, word, extra) => {
      const info = user.has(word) ? { rank: user.get(word), dict: "your own details" } : dictRank(word);
      if (!info) return;
      const tok = pw.slice(i, j + 1);
      let g = info.rank * upperVariations(tok);
      if (extra.reversed) g *= 2;
      if (extra.l33t) g *= extra.l33tVar;
      out.push(Object.assign({ pattern: "dictionary", i, j, token: tok, matched: word, rank: info.rank, dict: info.dict, guesses: Math.max(g, 1) }, extra));
    };
    for (let i = 0; i < n; i++) for (let j = i + 2; j < Math.min(n, i + 24); j++) {
      const sub = lower.slice(i, j + 1);
      add(i, j, sub, {});
      const rev = [...sub].reverse().join(""); if (rev !== sub) add(i, j, rev, { reversed: true });
      if (/[^a-z]/.test(sub) && [...sub].some((c) => UNLEET[c])) {
        // try each l33t interpretation (bounded)
        let variants = [""];
        for (const c of sub) { const opts = UNLEET[c] ? [...UNLEET[c], c] : [c]; variants = variants.flatMap((v) => opts.map((o) => v + o)).slice(0, 64); }
        const subs = [...sub].filter((c) => UNLEET[c]).length;
        for (const v of W.uniq(variants)) if (v !== sub && /^[a-z]+$/.test(v)) add(i, j, v, { l33t: true, l33tVar: Math.max(2, 2 ** Math.min(subs, 4) / 2) });
      }
    }
    return out;
  }
  const ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"], SHIFT = { "~": "`", "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8", "(": "9", ")": "0", "_": "-", "+": "=", "{": "[", "}": "]", "|": "\\", ":": ";", '"': "'", "<": ",", ">": ".", "?": "/" };
  const OFFS = [0, 1, 1.25, 1.75];
  const POS = {}; ROWS.forEach((r, y) => [...r].forEach((c, x) => (POS[c] = [x + OFFS[y], y])));
  const keyOf = (c) => { c = c.toLowerCase(); return POS[c] ? c : SHIFT[c] || null; };
  const adjacent = (a, b) => { const p = POS[a], q = POS[b]; return p && q && a !== b && Math.abs(p[1] - q[1]) <= 1 && Math.abs(p[0] - q[0]) <= 1.3; };
  function spatialMatches(pw) {
    const out = [], n = pw.length; let i = 0;
    while (i < n - 2) {
      let j = i, turns = 0, dir = null, shifted = 0;
      while (j + 1 < n) {
        const a = keyOf(pw[j]), b = keyOf(pw[j + 1]);
        if (!a || !b || !adjacent(a, b)) break;
        const d = [Math.sign(POS[b][0] - POS[a][0]), POS[b][1] - POS[a][1]].join();
        if (d !== dir) { turns++; dir = d; }
        j++;
      }
      if (j - i + 1 >= 3) {
        const tok = pw.slice(i, j + 1), L = tok.length;
        for (const c of tok) if (SHIFT[c] || /[A-Z]/.test(c)) shifted++;
        let g = 0; const S = 94, D = 4.6;
        for (let k = 2; k <= L; k++) for (let t = 1; t <= Math.min(turns, k - 1); t++) g += nCk(k - 1, t - 1) * S * D ** t;
        if (shifted) { let v = 0; for (let k = 1; k <= Math.min(shifted, L - shifted); k++) v += nCk(L, k); g *= shifted === L ? 2 : Math.max(v, 2); }
        out.push({ pattern: "keyboard", i, j, token: tok, turns, guesses: g });
        i = j; continue;
      }
      i++;
    }
    return out;
  }
  function sequenceMatches(pw) {
    const out = [], n = pw.length;
    const cls = (c) => /[a-z]/.test(c) ? "lower" : /[A-Z]/.test(c) ? "upper" : /\d/.test(c) ? "digit" : null;
    let i = 0;
    while (i < n - 2) {
      const d = pw.charCodeAt(i + 1) - pw.charCodeAt(i), c = cls(pw[i]);
      if (!c || ![1, -1, 2, -2].includes(d) || cls(pw[i + 1]) !== c) { i++; continue; }
      let j = i + 1;
      while (j + 1 < n && pw.charCodeAt(j + 1) - pw.charCodeAt(j) === d && cls(pw[j + 1]) === c) j++;
      if (j - i + 1 >= 3) {
        const tok = pw.slice(i, j + 1), first = tok[0];
        let base = /[a0z9A1]/.test(first) ? 4 : c === "digit" ? 10 : 26;
        if (d < 0) base *= 2;
        out.push({ pattern: "sequence", i, j, token: tok, guesses: base * tok.length * (Math.abs(d) === 2 ? 2 : 1) });
        i = j + 1; continue;
      }
      i++;
    }
    return out;
  }
  function repeatMatches(pw) {
    const out = [], re = /(.+?)\1+/g; let m;
    while ((m = re.exec(pw))) {
      const unit = m[1], count = m[0].length / unit.length;
      const g = Math.max(estimate(unit, null, true).guesses, unit.length === 1 ? 10 : 50) * count;
      out.push({ pattern: "repeat", i: m.index, j: m.index + m[0].length - 1, token: m[0], unit, count, guesses: g });
      re.lastIndex = m.index + m[0].length;
    }
    return out;
  }
  const REF_YEAR = 2026, MIN_YEAR_SPACE = 20;
  function dateMatches(pw) {
    const out = [];
    const yearSpace = (y) => Math.max(Math.abs(y - REF_YEAR), MIN_YEAR_SPACE);
    const fullYear = (y) => y < 100 ? (y > 50 ? 1900 + y : 2000 + y) : y;
    const okDMY = (d, m, y) => d >= 1 && d <= 31 && m >= 1 && m <= 12 && y >= 1900 && y <= 2050;
    for (let i = 0; i < pw.length; i++) for (let L = 4; L <= 10 && i + L <= pw.length; L++) {
      const tok = pw.slice(i, i + L);
      let ok = false, sep = false, y = 0;
      const s = tok.match(/^(\d{1,4})([\s/._-])(\d{1,2})\2(\d{1,4})$/);
      if (s) {
        const a = +s[1], b = +s[3], c = +s[4];
        for (const [d, m, yy] of [[a, b, c], [b, a, c], [c, b, a]]) { const Y = fullYear(yy); if (okDMY(d, m, Y)) { ok = true; y = Y; break; } }
        sep = true;
      } else if (/^\d+$/.test(tok) && L >= 4 && L <= 8) {
        const splits = { 4: [[1, 2], [2, 3]], 5: [[1, 3], [2, 3]], 6: [[2, 4], [4, 5]], 7: [[1, 3], [2, 4], [4, 5]], 8: [[2, 4], [4, 6]] }[L] || [];
        for (const [p, q] of splits) {
          const a = +tok.slice(0, p), b = +tok.slice(p, q), c = +tok.slice(q);
          for (const [d, m, yy] of [[a, b, c], [b, a, c], [c, b, a], [b, c, a]]) { const Y = fullYear(yy); if (okDMY(d, m, Y) && String(yy).length !== 3) { ok = true; y = Y; break; } }
          if (ok) break;
        }
      }
      if (ok) out.push({ pattern: "date", i, j: i + L - 1, token: tok, year: y, guesses: Math.max(365 * yearSpace(y) * (sep ? 4 : 1), 10000) });
    }
    const yre = /(19\d\d|20\d\d)/g; let m;
    while ((m = yre.exec(pw))) { const y = +m[1]; if (y <= 2050) out.push({ pattern: "year", i: m.index, j: m.index + 3, token: m[1], guesses: yearSpace(y) }); }
    return out;
  }

  // ------------------------------------------------------------------ search (zxcvbn's most-guessable sequence)
  const fact = (n) => { let r = 1; for (let i = 2; i <= n; i++) r *= i; return r; };
  const MIN_SUBMATCH = 10000; // zxcvbn's MIN_GUESSES_BEFORE_GROWING_SEQUENCE
  function bruteforce(i, j, pw) {
    const L = j - i + 1;
    let g = 10 ** L;
    if (!isFinite(g)) g = Number.MAX_VALUE;
    return { pattern: "bruteforce", i, j, token: pw.slice(i, j + 1), guesses: Math.max(g, L === 1 ? 11 : 51) };
  }
  function estimate(pw, userInputs, inner) {
    pw = String(pw == null ? "" : pw).slice(0, 100);
    const n = pw.length;
    if (!n) return result(pw, 1, [], inner);
    const matches = [...dictionaryMatches(pw, userInputs), ...spatialMatches(pw), ...sequenceMatches(pw), ...(inner ? [] : repeatMatches(pw)), ...dateMatches(pw)];
    const byEnd = Array.from({ length: n }, () => []);
    for (const m of matches) byEnd[m.j].push(m);
    // opt[k] : Map<l, {g, prod, seq}> — best product of guesses for prefix [0..k] using l matches
    const opt = Array.from({ length: n }, () => new Map());
    const consider = (m) => {
      const k = m.j;
      if (m.i === 0) { relax(k, 1, m.guesses, [m]); return; }
      for (const [l, st] of opt[m.i - 1]) relax(k, l + 1, st.prod * m.guesses, st.seq.concat(m));
    };
    const relax = (k, l, prod, seq) => {
      if (seq.length >= 2 && seq[seq.length - 1].pattern === "bruteforce" && seq[seq.length - 2].pattern === "bruteforce") return; // merge adjacent bruteforce via a longer span instead
      const g = fact(l) * prod + (l > 1 ? MIN_SUBMATCH ** (l - 1) : 0);
      for (const [l2, st] of opt[k]) if (l2 <= l && st.g <= g) return;
      opt[k].set(l, { g, prod, seq });
    };
    for (let k = 0; k < n; k++) {
      for (const m of byEnd[k]) consider(m);
      for (let i = 0; i <= k; i++) consider(bruteforce(i, k, pw));
    }
    let best = null;
    for (const st of opt[n - 1].values()) if (!best || st.g < best.g) best = st;
    return result(pw, best.g, best.seq, inner);
  }
  const DISPLAY = {
    online_throttled: ["Online, rate-limited (100/hour)", 100 / 3600],
    online: ["Online, unthrottled (10/s)", 10],
    offline_slow: ["Offline, slow hash e.g. bcrypt (10k/s)", 1e4],
    offline_fast: ["Offline, fast hash e.g. MD5 on GPUs (10¹⁰/s)", 1e10],
  };
  function duration(s) {
    if (s < 1) return "instant";
    const u = [["second", 60], ["minute", 60], ["hour", 24], ["day", 30.44], ["month", 12], ["year", 100]];
    let v = s;
    for (const [name, k] of u) { if (v < k) { const r = Math.round(v); return `${r} ${name}${r === 1 ? "" : "s"}`; } v /= k; }
    return v < 10 ? `${Math.round(v * 100)} years` : "centuries";
  }
  function result(pw, guesses, seq, inner) {
    guesses = Math.max(1, guesses);
    const log10 = Math.log10(guesses);
    const score = guesses < 1e3 + 5 ? 0 : guesses < 1e6 + 5 ? 1 : guesses < 1e8 + 5 ? 2 : guesses < 1e10 + 5 ? 3 : 4;
    const r = { password: undefined, length: pw.length, guesses, log10: +log10.toFixed(2), bits: +Math.log2(guesses).toFixed(1), score, sequence: seq.map((m) => Object.assign({}, m)) };
    if (inner) return r;
    r.label = ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score];
    r.crack = {}; for (const [k, [label, rate]] of Object.entries(DISPLAY)) r.crack[k] = { label, seconds: guesses / rate / 2, text: duration(guesses / rate / 2) };
    Object.assign(r, feedback(pw, score, seq));
    return r;
  }
  function feedback(pw, score, seq) {
    const sug = []; let warning = "";
    if (!pw) return { warning: "", suggestions: ["Use a few random words, or let the generator pick."] };
    const real = seq.filter((m) => m.pattern !== "bruteforce");
    const big = real.slice().sort((a, b) => (b.j - b.i) - (a.j - a.i))[0];
    if (big) {
      if (big.pattern === "dictionary") {
        if (big.dict === "common passwords") warning = big.rank <= 20 ? "This is a top-20 common password." : big.rank <= 100 ? "This is a top-100 common password." : "This is a very common password.";
        else if (big.dict === "your own details") warning = "It contains your own name / details — attackers try those first.";
        else if (big.dict === "names") warning = "Names and surnames are easy to guess.";
        else warning = seq.length === 1 ? "A single dictionary word is easy to guess." : "";
        if (big.l33t) sug.push("Predictable substitutions like '@' for 'a' don't help much.");
        if (big.reversed) sug.push("Reversed words aren't much harder to guess.");
        if (/^[A-Z]/.test(big.token)) sug.push("Capitalising the first letter doesn't help much.");
      } else if (big.pattern === "keyboard") warning = big.turns === 1 ? "Straight rows of keys are easy to guess." : "Short keyboard patterns are easy to guess.";
      else if (big.pattern === "repeat") warning = big.unit.length === 1 ? 'Repeats like "aaa" are easy to guess.' : 'Repeats like "abcabc" are only slightly harder than "abc".';
      else if (big.pattern === "sequence") warning = "Sequences like abc or 6543 are easy to guess.";
      else if (big.pattern === "date" || big.pattern === "year") { warning = "Dates and years are often personal and easy to guess."; sug.push("Avoid dates and years associated with you."); }
    }
    if (score <= 2) sug.unshift("Add another word or two — uncommon words are better.");
    if (score <= 2 && pw.length < 12) sug.push("Longer is stronger: aim for 14+ characters or 5+ random words.");
    if (score >= 3 && !warning) sug.push("Good. Use it for one account only, stored in a password manager.");
    return { warning, suggestions: W.uniq(sug) };
  }

  /** Character-class entropy for a typed password (the naïve upper bound shown next to the estimate). */
  function poolBits(pw) {
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10; if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    return pool ? +(pw.length * Math.log2(pool)).toFixed(1) : 0;
  }

  W.eng.passgen = { password, passphrase, estimate, poolBits, randInt, duration, SETS, COMMON };
})(typeof window !== "undefined" ? window.W : globalThis.W);
