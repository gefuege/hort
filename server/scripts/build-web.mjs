// Builds the browser app (web/) into public/js/app.js and the agent guide
// public/self-host.md from docs/self-hosting.md. Wrangler runs this before
// `wrangler dev` and `wrangler deploy` (build.command in wrangler.jsonc).
// The vendored Argon2id build must match its pinned SHA-256, or nothing is built.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
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
// hort.pm/self-host.md: the self-hosting guide, addressed to an agent that sets Hort up for its user.
const AGENT_INTRO = `# Self-host Hort: instructions for an agent

You are setting up a Hort server for your user. Follow the guide below step by step and run the commands yourself where you can.

Ask your user, never guess:

- to run \`npx wrangler login\` themselves; it signs in to their Cloudflare account in the browser;
- whether to use their own domain (which one) or a \`workers.dev\` address;
- whether registration should be invite-only. If yes, they type a long random value into \`npx wrangler secret put ADMIN_TOKEN\` and set \`HORT_ADMIN_TOKEN\` in their own shell for \`hort invite create\`. Never ask for the value in the chat;
- to run \`hort init --server <address>\` in their own terminal: they set the passphrase there and keep the printed Emergency Kit. Never ask for either.

Verify:

- \`npm test\` passes in \`server/\` before you deploy;
- after \`npx wrangler deploy\`, the server address shows the Hort page in a browser;
- after \`hort init\`, \`hort status\` names the new server and \`hort sync\` succeeds.

Source of the guide: https://github.com/gefuege/hort/blob/main/docs/self-hosting.md

---

`;
writeFileSync(new URL("../public/self-host.md", import.meta.url), AGENT_INTRO + readFileSync(new URL("../../docs/self-hosting.md", import.meta.url), "utf8"));
console.log("built public/js/app.js and public/self-host.md; vendored Argon2id hash ok");
