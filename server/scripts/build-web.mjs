// Builds the browser app (web/) into public/js/app.js. Wrangler runs this
// before `wrangler dev` and `wrangler deploy` (build.command in wrangler.jsonc).
// The vendored Argon2id build must match its pinned SHA-256, or nothing is built.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { build } from "esbuild";

// hash-wasm 4.12.0, dist/argon2.umd.min.js from the npm tarball, renamed to .cjs so the bundler treats the UMD as CommonJS
// (integrity sha512-+/2B2rYLb48I/evdOIhP+K/DD2ca2fgBjp6O+GBEnCDk2e4rpeXIK8GvIyRPjTezgmWn9gmKwkQjjx6BtqDHVQ==).
const VENDORED = {
  "web/vendor/hash-wasm/argon2.umd.min.cjs": "dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094",
};

for (const [file, expected] of Object.entries(VENDORED)) {
  const actual = createHash("sha256").update(readFileSync(new URL(`../${file}`, import.meta.url))).digest("hex");
  if (actual !== expected) {
    console.error(`${file}: SHA-256 ${actual} does not match the pinned ${expected}`);
    process.exit(1);
  }
}

await build({
  entryPoints: ["web/app.ts"],
  outfile: "public/js/app.js",
  bundle: true,
  format: "esm",
  target: "es2022",
  legalComments: "inline",
  logLevel: "warning",
});
console.log("built public/js/app.js; vendored Argon2id hash ok");
