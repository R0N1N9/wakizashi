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
    if (o.caps) words =