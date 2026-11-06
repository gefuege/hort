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

`slot.bytes` is `slot_bytes` from the vectors: `canon("hort/v4/slot-bytes\n", slot_params, wrap_nonce, wrapped_vk)`. The server stores a slot only if `ak_sig` verifies against the account's `ak_pub`.

Errors are an HTTP status and one plain-text line. Rate limits (fixed windows, per Durable Object `RateLimiter`): 5 account creations per hour per IP, 10 slot fetches per minute per IP and account, 60 writes per minute per device. They answer 429 with `Retry-After`.

## Develop

```bash
npm ci
npm test            # Vitest inside workerd (@cloudflare/vitest-plugin)
npm run typecheck   # generates worker-configuration.d.ts, then tsc --noEmit
```

Local workerd does not implement Durable Object jurisdictions and throws on `jurisdiction("eu")`. The tests record those calls instead (`test/setup.ts`), so the EU placement itself is only effective on Cloudflare. The same limit applies to `wrangler dev` without `--remote`.

## Self-host

```bash
npx wrangler deploy
npx wrangler secret put REGISTRATION_TOKEN   # optional: invite-only registration
```

Without `REGISTRATION_TOKEN`, anyone can create an account. Point the CLI at your Worker with `--server`.
