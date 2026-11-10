# Hort v4 test vectors

Shared vectors that bind the Go CLI, the Cloudflare Worker and the browser to
the same bytes. The Go reference test generates them from production code in
`internal/vault` (`keys.go`, `secretkey.go`, `revisions.go`):

```bash
go test ./internal/vault/ -run TestVectors -update   # regenerate
go test ./internal/vault/ -run TestVectors           # verify byte for byte
```

Never edit these files by hand. A changed byte means a changed contract.

## Conventions

- Byte values are lowercase hex in fields ending in `_hex`. Wire values that
  travel as base64 (`envelope_base64`, `meta_ct_base64`, `hort_signature`) use
  standard base64 with padding (RFC 4648 §4).
- Integers inside `canon()` are big-endian: `u32` for lengths and Argon2id
  `t`/`m`, `u8` for `p`, `u64` for `slot_version` and timestamps.
- IDs (account, revision, request, device, share) go into `canon()` as their decoded
  16 bytes, never as hex text. Strings go in as UTF-8.
- AES-256-GCM: 12-byte nonce and 16-byte tag, appended to the ciphertext.
  Nonces are fixed in the vectors and random in production.
- Inputs are fixed bytes, derived as `SHA-256("hort/vectors/<label>/<i>")`
  only for convenience. The files carry the bytes themselves.
- Argon2id parameter sets marked `"test_params_only": true` (t=1, m=256 KiB,
  p=1) exist only for fast browser tests. Production uses t=3, m=65536 KiB, p=4.

## Files

| File | Contract | Contents |
|---|---|---|
| `canon.json` | §2.1 | `canon(tag, f1..fn) = tag ‖ u32be(len f1) ‖ f1 ‖ …`: tag only, one empty field, several fields including an empty one, the real passphrase `slot_params`. `hort/v4/test\n` is a test-only tag. |
| `keys.json` | §2.1 | `FK`, `RK`, `AKs` = HKDF-SHA256(ikm=VK, salt=account_id, info=`hort/v4/file` / `hort/v4/revision` / `hort/v4/account-auth`, 32 bytes); `ak_public_hex` = Ed25519 public key from seed `AKs`. |
| `kek.json` | §2.2 | Passphrase 2SKD: `A` = Argon2id(NFC(passphrase), slot_salt, t, m, p, 32); `S` = HKDF(secret_key, account_id, `hort/v4/secret-key`); `KEK` = HKDF(A XOR S, slot_salt, `hort/v4/kek`). One vector at production parameters, two at test parameters: the NFC and the NFD spelling of the same passphrase give the same KEK. Passkey: `prf_eval_salt` = SHA-256(`"hort/v4/prf\n"` ‖ account_id), plain concatenation; `KEK` = HKDF(PRF output, account_id, `hort/v4/kek-passkey`). |
| `slot.json` | §2.2, §2.3, Rev 2.1 pt. 2 | Passphrase slot with `slot_id` = `"passphrase"`, `slot_version` = 7, KEK from the production vector in `kek.json`. `slot_params` = canon(`"hort/v4/argon\n"`, salt, u32 t, u32 m, u8 p); `aad` = canon(`"hort/v4/slot\n"`, account_id, slot_id, u64 slot_version, slot_params); `wrapped_vk` = ciphertext ‖ tag (48 bytes); `slot_bytes` = canon(`"hort/v4/slot-bytes\n"`, slot_params, wrap_nonce, wrapped_vk); `ak_sig` = Ed25519_AK(canon(`"hort/v4/slot-sig\n"`, account_id, slot_id, u64 slot_version, slot_bytes)). |
| `passkey-slot.json` | §2.2 | Passkey slot, `slot_version` = 1, KEK from the PRF output in `kek.json`. `cred_hash` = SHA-256(credential ID); `slot_id` = `"passkey:"` ‖ lowercase hex(`cred_hash`); `slot_params` = canon(`"hort/v4/passkey\n"`, cred_hash). AAD, `wrapped_vk`, `slot_bytes` and `ak_sig` follow `slot.json`. |
| `envelope.json` | §6.4 | `envelope` = nonce(12) ‖ AES-256-GCM(RK, plaintext, aad = canon(`"hort/v4/rev\n"`, account_id, revision id bytes)). Cases: default field, named field with env and context, describe, delete-entry, imported revision without a time (`recorded_at: null`). |
| `request.json` | §7.2 step 3, §6.2 | `meta_ct` = nonce(12) ‖ AES-256-GCM(RK, meta JSON, aad = canon(`"hort/v4/req-meta\n"`, account_id, request id bytes)). Signature message = canon(`"hort/v4/req\n"`, account_id, device field, METHOD, PATH_WITH_QUERY, u64 timestamp, SHA-256(exact body bytes)); one device-key POST with a body, one AK GET with a query and an empty body. |
| `secret-key.json` | §2.5, §2.6 | Secret Keys (zero, all 0xff, all symbols `1`, fixture) as data symbols, check symbol and display form; parse variants (lowercase, spaces, no separators, without `H4`, `O` for `0`, `I`/`l` for `1`); mistyped cases (data symbol, check symbol, missing symbol, `U`); account IDs. |
| `share.json` | share by link | `normalize`: recipient names to their one form: NFKC, lowercase per code point (U+0130 → `i` U+0307), `ς` → `σ`, `ß` and `ẞ` → `ss`, NFKC, runs of Unicode White_Space collapsed to one space and trimmed; cases cover umlauts (NFC and NFD), ß, İ, ı, Σ/ς, whitespace, fullwidth letters and a whitespace-only name (empty, refused by key derivation). `keys`: `A` = Argon2id(UTF-8 normalized name, salt = share ID bytes, t, m, p, 32); `K` = HKDF(A XOR link key, share ID bytes, `hort/v4/share`); `enc` = HKDF(K, share ID bytes, `hort/v4/share-enc`); `token` = HKDF(K, share ID bytes, `hort/v4/share-token`); `token_hash` = SHA-256(token). One vector at production parameters, two at test parameters (two spellings of one name, same keys). `ct`: nonce(12) ‖ AES-256-GCM(enc, JSON `{name, description, fields: [{field, value}]}`, aad = canon(`"hort/v4/share-ct\n"`, share ID bytes)). `meta`: nonce(12) ‖ AES-256-GCM(RK, JSON `{name, recipient, fields: [field]}`, aad = canon(`"hort/v4/share-meta\n"`, account_id, share ID bytes)). `link`: valid and refused share links. |
| `reduction.json` | §3.1–§3.3 | `reduce`: revisions in arrival order with the expected history order, values by (field, lookup key), description, visibility and read resolution. `append`: the Append stamp for a given `now`. |

## Binding encoding decisions

These points are open or ambiguous in the contract and are fixed here.

1. **Separate tag for request metadata (Kopf decision).** `meta_ct` uses AAD tag
   `hort/v4/req-meta\n`. The request signature keeps `hort/v4/req\n`. The
   contract (§7.2 step 3) named `hort/v4/req\n` for both, which would mix two
   domains.
2. **`slot_bytes`** = canon(`"hort/v4/slot-bytes\n"`, slot_params, wrap_nonce,
   wrapped_vk). The local file and the server compute it the same way, so one
   `ak_sig` verifies in both places. account_id, slot_id and slot_version are
   already in the signed message and are not repeated.
3. **Envelope and meta layout:** nonce(12) ‖ ciphertext ‖ tag, in that order,
   base64 on the wire. Decryption takes the revision ID or request ID from the
   transport (`{id, ct}`), and the opened revision must carry that same ID.
4. **Base32 bit order (Secret Key and account ID):** 16 bytes, most significant
   bit first, give 26 symbols. The 26th symbol holds the last 3 data bits
   followed by 2 zero bits. A decoder rejects nonzero padding bits.
5. **Check symbol:** `alphabet[SHA-256("hort/v4/sk-check\n" ‖ key)[0] >> 3]`,
   meaning the top 5 bits of the first hash byte.
6. **Secret Key parsing:** ASCII case-insensitive (no Unicode case folding).
   Dashes and spaces are ignored, `I` and `L` read as `1`, `O` as `0`. The `H4`
   prefix is optional: after normalization, 29 symbols starting with `H4` or 27
   symbols without it. Every failure (length, character, padding bits, check
   symbol) is the single error `Secret Key mistyped`.
7. **Account ID parsing** uses the same normalization, with exactly 26 symbols
   and no check symbol. The display form is lowercase.
8. **Request signature fields:** the device field is the decoded 16-byte device
   ID, or the 2 ASCII bytes `ak` for AK-signed requests (`Hort-Device: ak`).
   `Hort-Account` carries the lowercase account ID form, while the signed
   message carries the raw 16 bytes. The timestamp is Unix seconds as u64.
9. **JSON inside envelopes is not canonical.** Readers accept any valid JSON
   with the documented members; writers do not need to reproduce Go's bytes.
   To reproduce a vector, encrypt the given `plaintext` bytes. A revision omits
   `field` when it is empty, and readers treat a missing `field` as `""`.
   `RequestMeta` always carries all five members.
10. **`recorded_at`** is RFC 3339 UTC with up to 9 fractional digits; Go writes
    it with trailing zeros trimmed (`2026-01-01T00:00:05.000000001Z`).
    Implementations compare times at **nanosecond precision**: a JavaScript
    `Date` (milliseconds) is not enough, because the Append rule adds 1 ns.
11. **Reduction details pinned by the fixtures:** IDs tie-break as ascending
    lowercase hex strings, which matches byte order. `describe` makes an entry
    visible unless a later-ordered `delete-entry` hid it, and only `set` revives
    a deleted entry. The values map keys on (field, lookup key). Resolution with
    an empty env or context means `*`, and it never leaves the requested field.
12. **Passkey slot encoding (S6.2):** the contract's "credential-ID hash" is
    SHA-256 over the raw credential ID bytes. The server derives `slot_id` from
    the credential it verified and accepts a passkey slot only when
    `slot_params` carries that same hash.

13. **Share link:** `https://<origin>/s/<share ID>#<link key>`. The share ID is 16 bytes lowercase hex, the link key 32 random bytes as unpadded base64url (43 symbols, canonical form only). A parser accepts only `https`, no user info, no query, the path `/s/<id>` and that fragment; the API of the share is under the link's origin.
14. **Recipient name:** the owner and the recipient derive keys from the normalized name (`normalize` above). Go uses `unicode.ToLower` per rune with U+0130 → `i` U+0307, which equals JavaScript's `toLowerCase` per code point; both use their own Unicode tables, so code points added in a later Unicode version than both know may differ. A name that normalizes to nothing derives no keys. Shares always use production Argon2id parameters.
15. **Share plaintext:** `fields` holds at least one entry, field names unique, each `""` (the default field) or matching the field rule of §3.4; `name` is not empty. Readers reject anything else. `meta.recipient` is the name as the owner typed it, `meta.fields` the shared field names. Writers always write every member.
16. **Access token on the wire:** the owner sends `token_hash` (standard base64) on create; the recipient sends the token in `Hort-Share-Token` (standard base64). The link key and the name never travel.

## Argon2id

The vectors come from `golang.org/x/crypto/argon2` (RFC 9106, version 0x13).
The browser WASM build (`server/web/vendor/`) reproduces `argon_output_hex`;
`server/test-web/vault-core.test.ts` and `server/test-web/share-core.test.ts` check it.
