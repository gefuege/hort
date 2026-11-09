// Checks a running Worker (default: wrangler dev) for the pages of contract §8.1
// and the security headers of §8.3. Usage: node scripts/check-web.mjs [base-url]
// API paths answer from the Worker; locally they fail on jurisdiction("eu") with 500,
// which still carries the headers.
const base = process.argv[2] ?? "http://localhost:8787";
const headers = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
};
const pages = ["/", "/login", "/recover", "/vault", "/devices", "/access", "/r/abc", "/impressum", "/privacy", "/js/app.js"];

let failed = false;
for (const path of [...pages, "/api/v1/nope"]) {
  const res = await fetch(base + path);
  const problems = [];
  const api = path.startsWith("/api/");
  if (!api && res.status !== 200) problems.push(`status ${res.status}`);
  if (api && res.status !== 404) problems.push(`status ${res.status}`);
  for (const [name, value] of Object.entries(headers)) if (res.headers.get(name) !== value) problems.push(name);
  if (!res.headers.get("content-security-policy")?.includes("script-src 'self' 'wasm-unsafe-eval';")) problems.push("csp");
  if (!res.headers.get("permissions-policy")?.includes("publickey-credentials-get=(self)")) problems.push("permissions-policy");
  console.log(`${problems.length ? "FAIL" : "ok  "} ${res.status} ${path}${problems.length ? "  " + problems.join(", ") : ""}`);
  if (problems.length) failed = true;
}
process.exit(failed ? 1 : 0);
