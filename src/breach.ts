// Have I Been Pwned range API, using k-anonymity:
// only the first 5 characters of the SHA-1 hash ever leave this browser.

async function sha1Hex(text: string) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export type BreachResult =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "safe"; prefix: string; compared: number }
  | { state: "found"; count: number; prefix: string; compared: number }
  | { state: "error" };

export async function checkBreach(pw: string): Promise<BreachResult> {
  if (!pw) return { state: "idle" };

  try {
    const hash = await sha1Hex(pw);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) return { state: "error" };

    const body = await res.text();
    const lines = body.split("\n");

    for (const line of lines) {
      const [returnedSuffix, countStr] = line.trim().split(":");
      if (returnedSuffix === suffix) {
        return {
          state: "found",
          count: parseInt(countStr, 10),
          prefix,
          compared: lines.length,
        };
      }
    }

    return { state: "safe", prefix, compared: lines.length };
  } catch {
    return { state: "error" };
  }
}
