import { useEffect, useMemo, useRef, useState } from "react";
import { analyze, verdict, humanTime } from "./strength";
import { checkBreach, type BreachResult } from "./breach";

export default function App() {
  const [pw, setPw] = useState("");
  const [show, setShow] = useState(false);
  const [breach, setBreach] = useState<BreachResult>({ state: "idle" });
  const seq = useRef(0);

  const a = useMemo(() => analyze(pw), [pw]);
  const v = verdict(a.effBits);
  const pct = Math.min(100, (a.effBits / 80) * 100);

  // wait until typing stops before asking the API
  useEffect(() => {
    if (!pw) {
      setBreach({ state: "idle" });
      return;
    }
    const mine = ++seq.current;
    setBreach({ state: "checking" });
    const t = setTimeout(async () => {
      const result = await checkBreach(pw);
      if (mine === seq.current) setBreach(result);
    }, 600);
    return () => clearTimeout(t);
  }, [pw]);

  return (
    <main className="min-h-screen px-6 py-16 text-plum">
      <div className="mx-auto max-w-2xl">

        <h1 className="text-5xl font-bold">how strong is it, really?</h1>
        <p className="mt-4 text-lg text-plum/80">
          type a password and watch what a computer sees. nothing you type ever
          leaves this page.
        </p>

        <div className="sticker mt-10 rounded-3xl border-4 border-plum bg-white p-6">
          <label className="block text-sm font-semibold" htmlFor="pw">
            password
          </label>

          <div className="mt-2 flex gap-3">
            <input
              id="pw"
              type={show ? "text" : "password"}
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              placeholder="try something you'd actually use"
              autoComplete="off"
              className="w-full rounded-xl border-4 border-plum px-4 py-3 text-lg outline-none"
            />
            <button
              onClick={() => setShow((s) => !s)}
              className="shrink-0 rounded-xl border-4 border-plum bg-lav px-4 font-semibold"
            >
              {show ? "hide" : "show"}
            </button>
          </div>

          <div className="mt-6 h-5 w-full overflow-hidden rounded-full border-4 border-plum bg-cream">
            <div
              className="h-full transition-all duration-300"
              style={{ width: `${pct}%`, background: v.color }}
            />
          </div>

          {pw && (
            <div className="mt-3 flex items-baseline justify-between">
              <span className="text-2xl font-bold">{v.label}</span>
              <span className="text-sm text-plum/70">
                {a.effBits.toFixed(1)} bits after patterns
              </span>
            </div>
          )}
        </div>

        {pw && breach.state !== "idle" && (
          <div
            className="sticker mt-6 rounded-3xl border-4 border-plum p-6"
            style={{
              background:
                breach.state === "found" ? "#FFDADA" :
                breach.state === "safe" ? "#D9F7EC" : "#FFFFFF",
            }}
          >
            <p className="text-sm font-semibold uppercase tracking-wide text-plum/60">
              real breach data
            </p>

            {breach.state === "checking" && (
              <p className="mt-2 text-xl font-bold">checking…</p>
            )}

            {breach.state === "error" && (
              <p className="mt-2 text-xl font-bold">couldn't reach the service</p>
            )}

            {breach.state === "found" && (
              <>
                <p className="mt-2 text-3xl font-bold">
                  found in {breach.count.toLocaleString()} breaches
                </p>
                <p className="mt-3 text-sm text-plum/75">
                  this exact password is already sitting in public leak
                  databases. attackers try these first. if you use it anywhere,
                  change it.
                </p>
              </>
            )}

            {breach.state === "safe" && (
              <>
                <p className="mt-2 text-3xl font-bold">not in any known breach</p>
                <p className="mt-3 text-sm text-plum/75">
                  it hasn't shown up in the leaks this database covers. that's
                  good, but it doesn't make a weak password strong.
                </p>
              </>
            )}

            {(breach.state === "safe" || breach.state === "found") && (
              <div className="mt-4 rounded-xl border-4 border-plum bg-white/70 p-3 text-sm">
                <p className="font-bold">how this stayed private</p>
                <p className="mt-1 text-plum/75">
                  your password was hashed here in the browser. only the first
                  five characters of that hash —{" "}
                  <code className="font-mono font-bold">{breach.prefix}</code> —
                  were sent. the server returned {breach.compared} hashes
                  starting with those characters, and the match was found on
                  this page. the server never saw your password, and never
                  learned which of those {breach.compared} you were asking about.
                </p>
              </div>
            )}
          </div>
        )}

        {pw && (
          <div className="sticker mt-6 rounded-3xl border-4 border-plum bg-white p-6">
            <p className="text-sm font-semibold uppercase tracking-wide text-plum/60">
              time to crack
            </p>
            <p className="mt-2 text-4xl font-bold">{humanTime(a.seconds)}</p>
            <p className="mt-3 text-sm text-plum/70">
              assuming a leaked database and 100 billion guesses a second offline.
            </p>

            <div className="mt-6 grid grid-cols-3 gap-3 text-sm">
              <div className="rounded-xl border-4 border-plum bg-cream p-3">
                <p className="text-plum/60">length</p>
                <p className="text-xl font-bold">{pw.length}</p>
              </div>
              <div className="rounded-xl border-4 border-plum bg-cream p-3">
                <p className="text-plum/60">pool</p>
                <p className="text-xl font-bold">{a.pool}</p>
              </div>
              <div className="rounded-xl border-4 border-plum bg-cream p-3">
                <p className="text-plum/60">if random</p>
                <p className="text-xl font-bold">{a.bits.toFixed(0)}b</p>
              </div>
            </div>

            {a.bits - a.effBits > 4 && (
              <p className="mt-4 rounded-xl border-4 border-plum bg-peach/50 p-3 text-sm">
                looks like {a.bits.toFixed(0)} bits of randomness, actually worth{" "}
                {a.effBits.toFixed(0)}. the patterns below are why.
              </p>
            )}
          </div>
        )}

        {a.issues.length > 0 && (
          <div className="mt-6 space-y-3">
            {a.issues.map((issue) => (
              <div
                key={issue.title}
                className="sticker-sm rounded-2xl border-4 border-plum bg-white p-4"
              >
                <p className="font-bold">{issue.title}</p>
                <p className="mt-1 text-sm text-plum/75">{issue.detail}</p>
              </div>
            ))}
          </div>
        )}

      </div>
    </main>
  );
}
