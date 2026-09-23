// ─────────────────────────────────────────────
// how attackers actually guess: lists first, brute force last.
// ─────────────────────────────────────────────

export const GUESSES_PER_SEC = 1e11;

// roughly ordered by real-world popularity
const COMMON = [
  "123456", "password", "123456789", "12345678", "12345", "qwerty",
  "1234567", "111111", "123123", "abc123", "1234567890", "iloveyou",
  "000000", "qwerty123", "1q2w3e", "admin", "letmein", "welcome",
  "monkey", "dragon", "sunshine", "princess", "football", "charlie",
  "aa123456", "donald", "password1", "qwertyuiop", "michael", "shadow",
  "master", "superman", "batman", "trustno1", "hello", "freedom",
  "whatever", "starwars", "login", "passw0rd", "zaq12wsx", "baseball",
  "ninja", "azerty", "solo", "flower", "hottie", "loveme", "jesus",
  "soccer", "killer", "pepper", "cheese", "summer", "ashley", "bailey",
];

// words attackers feed into cracking tools
const WORDS = [
  "love", "life", "home", "work", "time", "year", "name", "king", "queen",
  "baby", "girl", "boy", "man", "woman", "money", "happy", "lucky", "angel",
  "black", "white", "green", "blue", "red", "pink", "orange", "purple",
  "january", "february", "march", "april", "june", "july", "august",
  "september", "october", "november", "december", "monday", "friday",
  "spring", "summer", "autumn", "winter", "school", "college", "student",
  "computer", "internet", "google", "apple", "microsoft", "samsung",
  "phone", "email", "music", "movie", "game", "gamer", "player", "level",
  "coffee", "chocolate", "cookie", "candy", "sugar", "honey", "pizza",
  "dog", "cat", "puppy", "kitten", "tiger", "lion", "bear", "wolf", "fox",
  "star", "moon", "sun", "sky", "cloud", "rain", "snow", "fire", "water",
  "secret", "private", "access", "system", "server", "network", "data",
  "hunter", "ranger", "warrior", "knight", "wizard", "magic", "dream",
  "forever", "always", "never", "friend", "family", "mother", "father",
  "india", "london", "paris", "tokyo", "york", "china", "america",
  "cyber", "hack", "hacker", "code", "coding", "python", "java", "script",
];

// what people substitute to feel clever
const LEET: Record<string, string> = {
  "4": "a", "@": "a", "8": "b", "3": "e", "1": "l", "!": "i",
  "0": "o", "$": "s", "5": "s", "7": "t", "+": "t", "(": "c", "9": "g",
};

const KEY_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

export function unleet(s: string) {
  return s.split("").map((c) => LEET[c] ?? c).join("");
}

export function poolSize(pw: string) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  return pool;
}

export function entropyBits(pw: string) {
  const pool = poolSize(pw);
  if (pool === 0) return 0;
  return pw.length * Math.log2(pool);
}

export type Issue = { title: string; detail: string };

// find the longest run of characters that follow a keyboard row
function keyboardRun(s: string) {
  let best = 0;
  for (const row of KEY_ROWS) {
    for (let i = 0; i < s.length; i++) {
      let len = 1;
      while (i + len < s.length) {
        const a = row.indexOf(s[i + len - 1]);
        const b = row.indexOf(s[i + len]);
        if (a === -1 || b === -1 || Math.abs(a - b) !== 1) break;
        len++;
      }
      if (len >= 3) best = Math.max(best, len);
    }
  }
  return best;
}

// abc / 123 / zyx, forwards or backwards
function sequenceRun(s: string) {
  let best = 0;
  for (let i = 0; i < s.length; i++) {
    let len = 1;
    while (i + len < s.length) {
      const diff = s.charCodeAt(i + len) - s.charCodeAt(i + len - 1);
      if (diff !== 1 && diff !== -1) break;
      len++;
    }
    if (len >= 3) best = Math.max(best, len);
  }
  return best;
}

function repeatRun(s: string) {
  let best = 0;
  for (let i = 0; i < s.length; i++) {
    let len = 1;
    while (i + len < s.length && s[i + len] === s[i]) len++;
    if (len >= 3) best = Math.max(best, len);
  }
  return best;
}

export function analyze(pw: string) {
  const pool = poolSize(pw);
  const bits = entropyBits(pw);
  const issues: Issue[] = [];

  // start from brute force: expected guesses is half the keyspace
  let guesses = Math.pow(2, bits) / 2;

  const lower = pw.toLowerCase();
  const norm = unleet(lower);

  // a pattern replaces brute force over that segment with
  // the much smaller number of guesses the pattern actually costs
  const shrink = (segLen: number, segGuesses: number) => {
    if (pool === 0 || segLen === 0) return;
    guesses = Math.max(segGuesses, (guesses / Math.pow(pool, segLen)) * segGuesses);
  };

  // 1. is it just a famous password?
  const ci = COMMON.indexOf(norm);
  if (ci >= 0) {
    guesses = Math.min(guesses, (ci + 1) * 5);
    issues.push({
      title: "this is on every attacker's list",
      detail: `it sits at roughly position ${ci + 1} in the most-guessed passwords. it is tried first, not last.`,
    });
  }

  // 2. does it contain a dictionary word?
  let word = "";
  for (const w of [...COMMON, ...WORDS]) {
    if (w.length >= 4 && norm.includes(w) && w.length > word.length) word = w;
  }
  if (word && ci < 0) {
    const hasLeet = norm !== lower;
    const hasCaps = pw !== lower && pw !== pw.toUpperCase();
    const rank = [...COMMON, ...WORDS].indexOf(word) + 1;
    shrink(word.length, rank * 4 * (hasLeet ? 8 : 1) * (hasCaps ? 4 : 1));
    issues.push({
      title: `built around the word "${word}"`,
      detail: hasLeet
        ? "swapping letters for symbols doesn't help. cracking tools try every substitution automatically."
        : "wordlist attacks try real words before random characters, so a word costs far less than its length suggests.",
    });
  }

  // 3. keyboard walks
  const kr = keyboardRun(lower);
  if (kr >= 3) {
    shrink(kr, 60 * kr);
    issues.push({
      title: "there's a keyboard pattern in here",
      detail: `${kr} characters in a row follow the shape of the keyboard. these are generated and tried early.`,
    });
  }

  // 4. sequences
  const sr = sequenceRun(lower);
  if (sr >= 3) {
    shrink(sr, 40 * sr);
    issues.push({
      title: "there's a counting sequence in here",
      detail: `${sr} characters run in order. attackers append these to words by default.`,
    });
  }

  // 5. repeats
  const rr = repeatRun(lower);
  if (rr >= 3) {
    shrink(rr, pool * rr);
    issues.push({
      title: "a character repeats",
      detail: `${rr} of the same character in a row adds almost nothing.`,
    });
  }

  // 6. years and dates
  const year = pw.match(/(19|20)\d\d/);
  if (year) {
    shrink(4, 120);
    issues.push({
      title: `"${year[0]}" looks like a year`,
      detail: "birth years and graduation years are a tiny set. there are only about 120 plausible ones.",
    });
  }

  // advisory, no maths change
  if (pw.length > 0 && pw.length < 12) {
    issues.push({
      title: "it's short",
      detail: "length buys more security than symbols do. aim for 16 or more.",
    });
  }

  const effBits = guesses > 0 ? Math.log2(guesses) : 0;
  const seconds = guesses / GUESSES_PER_SEC;

  return { pool, bits, effBits, guesses, seconds, issues };
}

export function verdict(effBits: number) {
  if (effBits < 20) return { label: "terrible", color: "#FF8A8A" };
  if (effBits < 32) return { label: "weak", color: "#FFB86B" };
  if (effBits < 48) return { label: "okay", color: "#FFE066" };
  if (effBits < 64) return { label: "strong", color: "#9FE88D" };
  return { label: "excellent", color: "#6FD5B4" };
}

export function humanTime(seconds: number) {
  if (seconds < 1) return "instantly";
  const steps: [number, string, string][] = [
    [60, "second", "seconds"],
    [60, "minute", "minutes"],
    [24, "hour", "hours"],
    [365, "day", "days"],
    [100, "year", "years"],
    [Infinity, "century", "centuries"],
  ];
  let value = seconds;
  let one = "second";
  let many = "seconds";
  for (const [step, s, p] of steps) {
    one = s;
    many = p;
    if (value < step) break;
    value = value / step;
  }
  if (value > 1e6) return "longer than the universe has existed";
  const n = value < 10 ? Number(value.toFixed(1)) : Math.round(value);
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}