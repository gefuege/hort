# hort-api

Sync backend of Hort 1.0: a Cloudflare Worker with one SQLite Durable Object per account, placed in the EU jurisdiction. The server stores ciphertext and public keys only; it never sees secret names, values, the passphrase, the Secret Key or the vault key.

The byte formats are fixed by `../spec/vectors/` (see its README). The tests check the server code against those vectors.

## Endpoints

All paths start with `/api/v1`. Signed requests carry `Hort-Account` (lowercase account ID), `Hort-Device` (lowercase hex device ID, or `ak` for the account key), `Hort-Timestamp` (Unix seconds, at most 300 s off) and `Hort-Signature` (base64 Ed25519 over the `hort/v4/req` message). Binary values in JSON are standard base64, device IDs lowercase hex.

| Method and path | Auth | Body → response |
|---|---|---|
| `POST /accounts` | AK, plus `Hort-Registration-Token` while `REGISTRATION_TOKEN` is set | `{account_id, ak_pub, slot: {id: "passphrase", version, bytes, ak_sig}, device: {id, pub, name}}` → 201 `{devices_version}`; a replay with the same AK → 200 |
| `GET /accounts/{id}/slot` | none | → `{ak_pub, slot: {id, version, bytes, ak_sig}}` |
| `POST /devices` | AK | `{device_id, pub, name}` → 201 `{devices_version}`; a replay → 200; a revoked ID → 409 |
| `GET /devices` | device or session | → `{devices: [{id, name, created_at, last_seen_at, revoked_at}], passkeys: [{id, prf, created_at, last_used_at, revoked_at}], devices_version}`; a session also gets `last_visit_at` (its previous call, `null` the first time) and moves it to now |
| `DELETE /devices/{id}` | device, or session + CSRF | `id` is a device ID (16 bytes hex) or a passkey ID (64 hex) → `{devices_version}`; revoking a passkey deletes its slot and ends its sessions |
| `PUT /slots/passphrase` | AK | `{version, bytes, ak_sig}` → `{version}`; the version must be higher than the stored one |

Revisions (contract §6.3, §6.6). The server stores each revision as an opaque envelope `ct` (nonce, AES-256-GCM ciphertext and tag under a key only devices hold) and orders them by `seq`, which is transport only.

| Method and path | Auth | Body → response |
|---|---|---|
| `POST /revisions` | device, or session + `Hort-CSRF` | `{revisions: [{id, ct}]}` (1 to 500, `ct` 28 bytes to 64 KiB, body at most 4 MiB) → `{accepted: [id], duplicate: [id]}`; an ID already stored is `duplicate` whatever its `ct`, an ID repeated in the body counts once; a session push stores no `from_device` |
| `GET /revisions?after=SEQ[&limit=N]` | device or session | → `{revisions: [{seq, id, ct}], cursor, more, devices_version, slot_version}`, oldest first; `slot_version` is the stored version of the passphrase slot; `limit` 1 to 500 (default 500); a page also ends after 4 MiB of `ct` but holds at least one revision; `cursor` is the last `seq` returned, or `after` for an empty page; any other query → 400 |

Per account at most 50,000 revisions and 64 MiB of `ct`; a push beyond that → 413 and stores nothing. A push counts against the write rate limit, a pull does not. The CLI splits larger pushes by count and size, so one max-size envelope (about 87 KiB as base64) fits a push although other endpoints cap bodies at 64 KiB.

Agent requests (contract §6.3, §7). The server holds only `meta_ct` and revision envelopes, never a name, description or value. `meta_ct` and `ct` are standard base64 of at least 28 bytes (nonce plus GCM tag); `meta_ct` is at most 16 KiB, an envelope at most 64 KiB.

| Method and path | Auth | Body → response |
|---|---|---|
| `POST /requests` | device | `{id, meta_ct}` (`id`: 16 bytes lowercase hex, chosen by the client) → 201 `{status: "pending"}`; the request expires 24 h after creation. A replay with the same `meta_ct` → 200 `{status}` (the current state); the same `id` with a different `meta_ct` → 409; more than 50 pending → 429 |
| `GET /requests/{id}` | device or session | → `{status, meta_ct, revision_ids}`; `revision_ids` is `[]` unless `fulfilled`; unknown ID or ID of another account → 404 |
| `GET /requests?status=pending` | device or session | → `{requests: [{id, meta_ct, created_at}]}`, at most 50, oldest first; any other query → 400 |
| `POST /requests/{id}/decline` | device, or session + CSRF | → `{status: "declined"}`; repeating it → 200; `fulfilled` or `expired` → 409 |
| `POST /requests/{id}/fulfill` | session + CSRF only | `{revisions: [{id, ct}]}` (1 to 500, body at most 256 KiB) → `{accepted: [id], duplicate: [id]}` |

`status` is `pending`, `fulfilled`, `declined` or `expired`. Expiry is lazy: every request operation first marks pending requests past `expires_at` as `expired`, so an expired request frees its pending slot and is never listed. Create and decline count against the write rate limit; reads do not.

Fulfill inserts the revisions (an ID already stored is `duplicate`; an ID repeated in the body counts once), sets `fulfilled` and `revision_ids` (each body ID once, in order, stored duplicates included) in one transaction, and works only on a `pending` request (else 409). It counts against the write rate limit of the session.

Passkeys and sessions (contract §5.4, §5.5):

| Method and path | Auth | Body → response |
|---|---|---|
| `POST /webauthn/register/options` | AK, empty body | → WebAuthn creation options (`challenge`, `rp`, `user` with the account ID as user handle, `residentKey` and `userVerification` required, attestation `none`, `excludeCredentials`). The browser adds the PRF extension itself. More than 10 active passkeys → 429 |
| `POST /webauthn/register/verify` | AK | `{response, slot}`: `response` is the registration response JSON, `slot` is `null` (no PRF) or `{version, bytes, ak_sig}` of slot `passkey:<cred-hash>` → 201 `{id, prf, devices_version}`; the same credential again → 409 |
| `POST /webauthn/login/options` | none, rate-limited | → `{challenge, rpId, userVerification, timeout}` for a discoverable-credential `get()` |
| `POST /webauthn/login/verify` | none, rate-limited | authentication response JSON → `{account_id, ak_pub, credential_id, slot}` (`slot` is `null` without PRF) and `Set-Cookie: __Host-hort` |
| `DELETE /session` | session + CSRF | → 204; ends the session, deletes its unlock key and clears the cookie |
| `PUT /session/unlock-key` | session + CSRF | `{ttl}` with `ttl` 900, 3600, 28800 or 604800 → `{key, expires_at}`: a new unlock key of 32 random bytes that replaces the session's previous one and expires at min(now + `ttl`, session end); another `ttl` → 400 |
| `GET /session/unlock-key` | session | → `{key, expires_at}` while the key and the session are valid, else 404; like every session request it extends both |
| `DELETE /session/unlock-key` | session + CSRF | → 204; deletes the session's unlock key (lock now) |

- A challenge lives in its own `Challenge` Durable Object for five minutes and is consumed by its first use. Its binding is `login`, or `register:<account ID>` for the account whose AK signed the options call, so a challenge works only for the ceremony and account it was issued for. A discoverable login starts before the account is known, which is why challenges do not live in the account DO.
- Verification uses `@simplewebauthn/server` with origin and rpId from the request URL (`https://hort.pm` and `hort.pm` in production), user verification required and a strictly increasing `sign_count` once the authenticator reports one. The passkey slot must carry `slot_params` = canon(`"hort/v4/passkey\n"`, SHA-256(credential ID)) and an `ak_sig` over `passkey:<hex of that hash>` and its version (`../spec/vectors/passkey-slot.json`).
- The session cookie is `__Host-hort=<account ID>.<32 random bytes, base64url>; Max-Age=2592000; Path=/; Secure; HttpOnly; SameSite=Strict`. The account DO stores only SHA-256 of the token. Every session request the server accepts extends the session to 7 days from then, at most to 30 days after sign-in; the cookie's `Max-Age` is those 30 days, and the server alone decides when the session ends. "CSRF" above means the request carries `Hort-CSRF: 1` and an `Origin` equal to the site origin. A request with `Hort-Signature` is always treated as signed, never as a session. A session request may name the account in `Hort-Account`; when that differs from the cookie's account, every session endpoint except `DELETE /session` answers 409 `signed in to a different account`. The web app sends it with every session call, so a tab that unlocked one vault never reads from or writes to another account's session. Without the header the cookie alone decides.
- Unlock key: the web app wraps the vault key with it in browser storage, so a reload or a new tab reopens the vault until the lock time the user picked has passed without use (see `app.ts` below). The entry `{key, ttl, expires_at}` lives in the account DO's key-value storage under `unlock:<token_hash>`, next to the SQL tables and outside the schema. Every session request the server accepts, including `GET /session/unlock-key`, moves `expires_at` to min(now + `ttl`, session end); a key that has expired stays expired, and an entry written before S6.12 has no `ttl` and is not extended. It is handed out only to its own valid session; signing out deletes it, and a session that expired or ended with a revoked passkey makes it unreachable, because `GET` checks the session first. A `PUT` also drops the keys of ended sessions.

`slot.bytes` is `slot_bytes` from the vectors: `canon("hort/v4/slot-bytes\n", slot_params, wrap_nonce, wrapped_vk)`. The server stores a slot only if `ak_sig` verifies against the account's `ak_pub`.

Errors are an HTTP status and one plain-text line. Rate limits (fixed windows, per Durable Object `RateLimiter`): 5 account creations per hour per IP, 10 slot fetches per minute per IP and account, 60 writes per minute per device (AK and sessions count as one device each), 30 passkey login calls per minute per IP. They answer 429 with `Retry-After`.

### Schema

The account DO schema is contract §6.5 plus three additions from S6.2: `passkeys.id` (hex SHA-256 of the credential ID, the passkey ID in `/devices`), `account.devices_seen_at` (for `last_visit_at`) and the table `sessions (token_hash, credential_id, created_at, expires_at)`. No account DO existed in production when they were added, so there is no migration. Once accounts exist, a schema change needs one. Wrangler migration `v2` adds the `Challenge` class.

## Develop

```bash
npm ci
npm test            # Worker tests inside workerd, browser code (test-web/) under Node
npm run typecheck   # worker-configuration.d.ts, tsc for the Worker and for web/
npm run build       # web/ → public/js/app.js; wrangler dev and deploy run it themselves
```

The Worker tests drive registration and login with a software authenticator (`test/passkey.ts`, ES256, attestation `none`). The browser tests run every vector and reduction fixture of `../spec/vectors/` against `web/vault-core.ts`. They run under Node, because workerd refuses to compile WebAssembly at runtime.

Local workerd does not implement Durable Object jurisdictions and throws on `jurisdiction("eu")`. The tests record those calls instead (`test/setup.ts`), so the EU placement itself is only effective on Cloudflare. The same limit applies to `wrangler dev` without `--remote`.

### Go CLI against a local Worker

`wrangler dev --remote` no longer supports Durable Objects (it answers 500 with that message), so the CLI integration test runs against local workerd. `wrangler.dev.jsonc` serves the production code through `test/dev-entry.ts`, which lets `jurisdiction("eu")` return the plain namespace as `test/setup.ts` does; it has its own Worker name and no route. Never deploy it.

```bash
npx wrangler dev -c wrangler.dev.jsonc --port 8788 --persist-to "$(mktemp -d)"
# from the repo root, in a second shell:
HORT_TEST_SERVER=http://localhost:8788 go test ./internal/cli -run TestServerSync -count=1 -v
```

The CLI speaks https only; the test puts a local TLS proxy in front of the Worker, which also simulates a refused push and a lost push answer. A fresh `--persist-to` directory resets the rate limits (locally every request shares the IP bucket `unknown`).

## Web app and landing page

The same Worker serves hort.pm. `wrangler.jsonc` sets `run_worker_first: ["/api/*"]`; every other path is a static asset from `public/`:

- `index.html`, `impressum.html`, `privacy.html`, `style.css`, `fonts/`, `img/`: the landing page and legal pages (design B · Phosphor, self-hosted fonts under OFL, no third-party requests).
- `login.html`, `recover.html`, `devices.html`, `vault.html` and `r.html` (served for `/r/<id>` through `_redirects`) load `js/app.js`, the bundle of `web/` (see below).
- `_headers` carries the security headers for assets. Cloudflare does not apply that file to Worker responses, so `src/entry.ts` sets the same list on `/api/*`; `test/web.test.ts` keeps both identical. The CSP allows `script-src 'self' 'wasm-unsafe-eval'` for the Argon2id WASM and loads nothing from another origin.

### Browser code (`web/`)

- `vault-core.ts`: key derivation, 2SKD with NFC and Argon2id, passkey KEK, slot wrap and unwrap with `ak_sig`, revision and request-meta envelopes, AK request signing, Secret Key and account ID parsing, reduction with nanosecond times, the Append rule and the write rules of contract §3.4. Byte encodings come from `src/wire.ts`, which the Worker uses too. `/vault` and `/r/<id>` build on this module.
- `request-view.ts`: `/r/<id>` (contract §7.3). Without an unlocked vault and a passkey session it embeds the passkey sign-in and shows the request after unlock, with no URL parameter and no storage of its own. It decrypts `meta_ct`, pulls the revisions of that secret, shows whether a value exists for the exact `(field, env, context)` but never the value, and on submit builds a `set` revision (Append rule against a fresh delta pull) plus a `describe` revision when the description is missing or differs, sealed and sent with `POST /requests/{id}/fulfill`. Decline posts `/decline`; fulfilled, declined and expired requests only show their status.
- `app.ts`: `/login`, `/recover`, `/devices` and `/vault` as one app, and the routing for `/r/<id>`. Links between them swap the view without a page load, so an unlocked vault stays unlocked. Browser storage holds the non-secret account ID (`device-memory.ts`, localStorage key `hort.account`, see PRF login), the theme choice (`hort.theme`), the lock time and, while it runs, the wrapped vault key (`unlock-memory.ts`, see Lock time). Derived keys are non-extractable `CryptoKey`s. New passphrase: `/recover` takes the Secret Key from the unlocked kit, or asks for it (check symbol verified) after a passkey unlock, and writes a new AK-signed passphrase slot at `slot_version`+1 (`newPassphraseSlot`) through `PUT /slots/passphrase`. A Secret Key that is not the account's cannot be detected; the passphrase slot then opens with nobody, and the passkeys still unlock.
- `vault-view.ts`: `/vault`. It needs an unlocked vault and a passkey session, because `GET /revisions` accepts a session or a device signature, not an AK signature. The first visit in a tab pulls every revision from cursor 0, later visits and every write pull deltas first. Writes run through `validateWrite` and the Append rule against the entry in memory, then `POST /revisions`. A 401 or 409 replaces the view with the sign-in prompt. Values reach the DOM only on Show (hidden again after 30 s); Copy tries to clear the clipboard 30 s later and, if the browser refuses that write, again on the next pointer or key press in the tab.
- PRF login: the PRF eval salt depends on the account ID, which a discoverable `get()` reveals only afterwards. Deliberate exception to "nothing in browser storage" (decided by the owner): after a successful passkey login the browser remembers the account ID (never VK, keys, session or values), and the next login evaluates the PRF in the same `get()` prompt. On a device that does not know the account yet (first login, or storage unavailable), `/login` asks for the passkey a second time and says so; sign-out offers to forget the device, which deletes the ID, and a login of another account replaces it. After `/recover` in the same tab, one prompt does both. `privacy.html` states this.
- Lock time (S6.10): a select in the top nav, localStorage `hort.lock` = `immediately`, `15m`, `1h` (default), `8h` or `1w` (S6.12: counted from the last use; the labels say "idle"). After every unlock with a session of the remembered account, and when the lock time changes, the app gets a fresh key K from `PUT /session/unlock-key` and stores `{account, nonce, ct}` in `hort.unlock`, with `ct` = AES-256-GCM(K, VK) and AAD `"hort/web/unlock\n"` || account ID; K is imported non-extractable and its bytes are zeroed. On page start a stored blob that matches the remembered account is opened with K from `GET /session/unlock-key` (sent with `Hort-Account`), and the app starts unlocked and signed in. 401, 404, 409 or a failed decryption delete the blob; so do sign-out, `immediately` (which also calls `DELETE /session/unlock-key`) and any session refusal while the app runs. Leaving a page only wipes memory. Threat model: the server never sees VK, and neither K nor the blob alone opens it. Someone who can run script on the origin or read this browser's storage while the session cookie is valid gets VK until the lock time has passed without use, at most until the session ends; with `immediately` nothing is kept and every reload asks for the passkey again.
- `esbuild` (pinned) bundles `web/app.ts` to `public/js/app.js` (ignored by git). No framework, no runtime dependency.
- Argon2id: `web/vendor/hash-wasm/argon2.umd.min.cjs` is `dist/argon2.umd.min.js` of [hash-wasm](https://github.com/Daninet/hash-wasm) 4.12.0 (MIT, Dani Biró, `LICENSE` next to it), taken from the npm tarball (integrity `sha512-+/2B2rYLb48I/evdOIhP+K/DD2ca2fgBjp6O+GBEnCDk2e4rpeXIK8GvIyRPjTezgmWn9gmKwkQjjx6BtqDHVQ==`) and renamed to `.cjs` so the bundler treats the UMD as CommonJS. The WASM is embedded in that file. `scripts/build-web.mjs` refuses to build unless its SHA-256 is `dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094`. To update it, take the file from a new tarball, check its integrity, and change both the file and the pinned hash in one commit.

`npm run check:web [base-url]` requests the pages and `/api/v1/nope` of a running Worker (default `http://localhost:8787` from `npx wrangler dev`) and checks status and headers.

### Switch hort.pm from hort-site to hort-api

The assets-only Worker `hort-site` (formerly `site/`) holds the custom domain `hort.pm` today, and a domain can only be bound to one Worker.

1. `npm ci && npm test && npm run typecheck` in `server/`.
2. In the Cloudflare dashboard, remove the custom domain `hort.pm` from the Worker `hort-site` (Workers & Pages, hort-site, Settings, Domains & Routes). The landing page is down from here until step 3 finishes.
3. `cd server && npx wrangler deploy`. This binds `hort.pm` to `hort-api` and uploads `public/`.
4. `npm run check:web https://hort.pm`, then open `/` and `/vault` in a browser.
5. Delete the Worker `hort-site` once `hort.pm` is confirmed.

Rollback before step 5: remove the domain from `hort-api` and bind it to `hort-site` again.

## Self-host

```bash
npx wrangler deploy
npx wrangler secret put REGISTRATION_TOKEN   # optional: invite-only registration
```

Replace the `routes` entry in `wrangler.jsonc` with your own domain or remove it to use the `workers.dev` address.

Without `REGISTRATION_TOKEN`, anyone can create an account. Point the CLI at your Worker with `--server`.
