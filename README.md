# password lab

A password strength visualizer that shows you what an attacker sees.

**Live:** https://password-lab-five.vercel.app

Most strength meters count character types and give you a green bar for
adding a `!` to the end. This one models how passwords are actually
cracked, and explains itself while doing it.

---

## What it does

**Entropy scoring.** Calculates the raw keyspace from length and
character pool, then subtracts what patterns give away for free.

**Pattern detection.** Finds dictionary words, leetspeak substitutions,
keyboard walks, counting sequences, repeated characters, and years,
then recalculates the cost of guessing based on what the pattern
actually costs rather than brute force.

**Breach checking.** Queries the Have I Been Pwned database of leaked
passwords without ever transmitting the password.

---

## The interesting part: k-anonymity

Checking a password against a breach database normally means sending the
password to a server. That's a bad trade.

This tool does it without transmitting the password:

1. SHA-1 hash the password in the browser, using the Web Crypto API
2. Send only the **first five hex characters** of that hash
3. The server returns every hash it holds beginning with that prefix,
   typically 400 to 1,000 of them
4. Search that list locally for the remaining 35 characters

The server learns five hex characters, which narrows the space to roughly
one in a million. It never receives the password, and it cannot tell which
of the returned hashes was the one being asked about.

The UI shows the prefix that was sent and how many hashes came back, so the
privacy claim is visible rather than asserted.

```ts
const hash = await sha1Hex(pw);
const prefix = hash.slice(0, 5);
const suffix = hash.slice(5);

const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
// match suffix locally against the returned list
```

---

## Why patterns matter more than symbols

`password123!` looks like 73 bits of entropy if you only count characters
and length. Run it through the analyzer and it's worth about 7.

The difference is that attackers don't guess randomly. They start with
wordlists, apply common mutation rules, and only brute force what's left.
A dictionary word costs roughly its rank in the wordlist, not
`pool^length`.

The scoring reflects that: each detected pattern replaces the brute-force
cost of that segment with the smaller number of guesses the pattern
actually requires.

---

## Running it

```bash
npm install
npm run dev
```

## Built with

React, TypeScript, Vite, Tailwind CSS, the Web Crypto API, and the
Have I Been Pwned range API.

## Notes

No password is stored, logged, or transmitted. The strength analysis runs
entirely in the browser; the only network request is the five-character
hash prefix described above.

Scoring is inspired by the approach behind zxcvbn, implemented from
scratch to understand the model rather than to replace it.
