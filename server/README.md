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
| `GET /devices` | device | → `{devices: [{id, name, created_at, last_seen_at, revoked_at}], devices_version}`; passkeys follow with S6.2 |
| `DELETE /devices/{id}` | device | → `{devices_version}` |
| `PUT /slots/passphrase` | AK | `{version, bytes, ak_sig}` → `{version}`; the version must be higher than the stored one |

Agent requests (contract §6.3, §7). The server holds only `meta_ct` and revision envelopes, never a name, description or value. `meta_ct` and `ct` are standard base64 of at least 28 bytes (nonce plus GCM tag); `meta_ct` is at most 16 KiB, an envelope at most 64 KiB.

| Method and path | Auth | Body → response |
|---|---|---|
| `POST /requests` | device | `{id, meta_ct}` (`id`: 16 bytes lowercase hex, chosen by the client) → 201 `{status: "pending"}`; the request expires 24 h after creation. A replay with the same `meta_ct` → 200 `{status}` (the current state); the same `id` with a different `meta_ct` → 409; more than 50 pending → 429 |
| `GET /requests/{id}` | device | → `{status, meta_ct, revision_ids}`; `revision_ids` is `[]` unless `fulfilled`; unknown ID or ID of another account → 404 |
| `GET /requests?status=pending` | device | → `{requests: [{id, meta_ct, created_at}]}`, at most 50, oldest first; any other query → 400 |
| `POST /requests/{id}/decline` | device | → `{status: "declined"}`; repeating it → 200; `fulfilled` or `expired` → 409 |
| `POST /requests/{id}/fulfill` | passkey session + `Hort-CSRF` | `{revisions: [{id, ct}]}` (1 to 500) → `{accepted: [id], duplicate: [id]}` |

`status` is `pending`, `fulfilled`, `declined` or `expired`. Expiry is lazy: every request operation first marks pending requests past `expires_at` as `expired`, so an expired request frees its pending slot and is never listed. Create and decline count against the write rate limit; reads do not.

Fulfill is implemented as the Durable Object method `Account.fulfillRequest(id, body)` and tested there, but the HTTP route answers 401 until S6.2 adds the passkey session and the `Hort-CSRF` check; the method takes no signature, so only a Worker route that has authenticated the session may call it, and that route also applies the write rate limit. The method inserts the revisions (an ID already stored is `duplicate`; an ID repeated in the body counts once), sets `fulfilled` and `revision_ids` (each body ID once, in order, stored duplicates included) in one transaction, and works only on a `pending` request (else 409). The session branches of `GET` and `decline` follow with S6.2 as well.

`slot.bytes` is `slot_bytes` from the vectors: `canon("hort/v4/slot-bytes\n", slot_params, wrap_nonce, wrapped_vk)`. The server stores a slot only if `ak_sig` verifies against the account's `ak_pub`.

Errors are an HTTP status and one plain-text line. Rate limits (fixed windows, per Durable Object `RateLimiter`): 5 account creations per hour per IP, 10 slot fetches per minute per IP and account, 60 writes per minute per device. They answer 429 with `Retry-After`.

## Develop

```bash
npm ci
npm test            # Vitest inside workerd (@cloudflare/vitest-plugin)
npm run typecheck   # generates worker-configuration.d.ts, then tsc --noEmit
```

Local workerd does not implement Durable Object jurisdictions and throws on `jurisdiction("eu")`. The tests record those calls instead (`test/setup.ts`), so the EU placement itself is only effective on Cloudflare. The same limit applies to `wrangler dev` without `--remote`.

## Web app and landing page

The same Worker serves hort.pm. `wrangler.jsonc` sets `run_worker_first: ["/api/*"]`; every other path is a static asset from `public/`:

- `index.html`, `impressum.html`, `privacy.html`, `style.css`, `fonts/`, `img/`: the landing page and legal pages (design B · Phosphor, self-hosted fonts under OFL, no third-party requests).
- `login.html`, `vault.html`, `recover.html`, `devices.html` and `r.html` (served for `/r/<id>` through `_redirects`): the web app shell with layout, navigation and a one-sentence placeholder per page. The functions follow with S6.2 to S6.4.
- `_headers` carries the security headers for assets. Cloudflare does not apply that file to Worker responses, so `src/entry.ts` sets the same list on `/api/*`; `test/web.test.ts` keeps both identical. The CSP allows `script-src 'self' 'wasm-unsafe-eval'` for the Argon2id WASM and loads nothing from another origin.

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
