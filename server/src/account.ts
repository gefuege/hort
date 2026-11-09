import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { DurableObject } from "cloudflare:workers";
import { consumeChallenge, issueChallenge } from "./challenge";
import { asObject, fail, json, parseObject } from "./http";
import { rateLimit } from "./rate-limiter";
import {
  accountIdDecode,
  b64Decode,
  b64Encode,
  b64urlDecode,
  b64urlEncode,
  ed25519Verify,
  hexDecode,
  hexEncode,
  isEd25519PublicKey,
  isPasskeySlotBytes,
  isPassphraseSlotBytes,
  sha256,
  slotSigMessage,
  verifyRequest,
  type Signed,
} from "./wire";

// Contract §6.5, plus passkeys.id, account.devices_seen_at and sessions (S6.2,
// see README "Schema"). Created together with the account, so a slot fetch
// for an unknown account ID leaves no storage behind.
const SCHEMA = `
CREATE TABLE account   (id TEXT PRIMARY KEY, ak_pub BLOB NOT NULL, created_at INTEGER NOT NULL,
                        devices_version INTEGER NOT NULL DEFAULT 0, devices_seen_at INTEGER);
CREATE TABLE devices   (id TEXT PRIMARY KEY, pub BLOB NOT NULL, name TEXT NOT NULL,
                        created_at INTEGER NOT NULL, last_seen_at INTEGER, revoked_at INTEGER);
CREATE TABLE slots     (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('passphrase','passkey')),
                        version INTEGER NOT NULL, blob BLOB NOT NULL, ak_sig BLOB NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE passkeys  (credential_id BLOB PRIMARY KEY, id TEXT NOT NULL UNIQUE, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL,
                        slot_id TEXT REFERENCES slots(id), created_at INTEGER NOT NULL,
                        last_used_at INTEGER, revoked_at INTEGER);
CREATE TABLE revisions (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, ct BLOB NOT NULL,
                        from_device TEXT, received_at INTEGER NOT NULL);
CREATE TABLE requests  (id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK (status IN ('pending','fulfilled','declined','expired')),
                        meta_ct BLOB NOT NULL, from_device TEXT NOT NULL, created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL, revision_ids TEXT);
CREATE TABLE sessions  (token_hash TEXT PRIMARY KEY, credential_id BLOB NOT NULL, created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL);
`;

// Contract §6.6.
const MAX_ACTIVE_DEVICES = 20;
const MAX_ACTIVE_PASSKEYS = 10;
const PASSKEY_LIMIT = `passkey limit reached (${MAX_ACTIVE_PASSKEYS} active passkeys); revoke one first`;
// A session ends 7 days after its last use, at the latest 30 days after sign-in.
const SESSION_IDLE_SECONDS = 7 * 24 * 60 * 60;
const SESSION_MAX_SECONDS = 30 * 24 * 60 * 60;
export const SESSION_COOKIE = "__Host-hort";
const SESSION_EXPIRED = "session expired or signed out; sign in with your passkey again";
const PASSPHRASE_SLOT = "passphrase";
const MAX_PENDING_REQUESTS = 50;
const MAX_ENVELOPE_BYTES = 64 * 1024;
const MAX_META_BYTES = 16 * 1024; // name <= 128 B plus description and parts; far below an envelope
const MIN_CT_BYTES = 28; // nonce(12) + GCM tag(16)
const MAX_PUSH_REVISIONS = 500; // also the most rows per pull page
const MAX_PAGE_CT_BYTES = 4 * 1024 * 1024; // keeps a pull page response near 5.5 MB of base64
const MAX_ACCOUNT_REVISIONS = 50_000;
const MAX_ACCOUNT_CT_BYTES = 64 * 1024 * 1024;
const REQUEST_TTL_SECONDS = 24 * 60 * 60;
// Lock times the web app offers, counted from the last use: 15 min, 1 h, 8 h, 1 week.
const UNLOCK_KEY_TTLS = [900, 3600, 28800, 604800];
const UNLOCK_KEY_PREFIX = "unlock:";
const NO_UNLOCK_KEY = "no unlock key for this session";

type AccountRow = { id: string; ak_pub: ArrayBuffer; devices_version: number };
type DeviceRow = { id: string; pub: ArrayBuffer; name: string; created_at: number; last_seen_at: number | null; revoked_at: number | null };
type SlotRow = { version: number; blob: ArrayBuffer; ak_sig: ArrayBuffer };
type Slot = { version: number; bytes: Uint8Array; akSig: Uint8Array };
type Device = { id: string; pub: Uint8Array; name: string };
type PasskeyRow = { credential_id: ArrayBuffer; id: string; public_key: ArrayBuffer; sign_count: number; slot_id: string | null;
  created_at: number; last_used_at: number | null; revoked_at: number | null };

// A browser session: the account from the cookie and SHA-256 of its token,
// after the Worker checked Hort-CSRF and Origin for state-changing calls.
export type SessionAuth = { accountId: string; session: string };
type Auth = Signed | SessionAuth;
// WebAuthn relying party, taken from the request URL the Worker serves.
export type RelyingParty = { origin: string; id: string };
// A session's unlock key in the DO key-value store under unlock:<token_hash>.
// Entries written before the lock time slid carry no ttl and do not slide.
type UnlockKey = { key: string; ttl?: number; expires_at: number };
type RequestRow = { id: string; status: string; meta_ct: ArrayBuffer; from_device: string; created_at: number; revision_ids: string | null };

const now = () => Math.floor(Date.now() / 1000);

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function deviceName(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const len = new TextEncoder().encode(v).length;
  return len >= 1 && len <= 64 && !/[\u0000-\u001f\u007f]/.test(v) ? v : null;
}

async function parseDevice(id: unknown, pub: unknown, name: unknown): Promise<Device | string> {
  if (typeof id !== "string" || !hexDecode(id, 16)) return "device ID must be 16 bytes of lowercase hex";
  const key = typeof pub === "string" ? b64Decode(pub) : null;
  if (!key || !(await isEd25519PublicKey(key))) return "device key must be a base64 Ed25519 public key";
  const n = deviceName(name);
  if (n === null) return "device name must be 1 to 64 bytes without control characters";
  return { id, pub: key, name: n };
}

// Parses {version, bytes, ak_sig} of a slot, checks the encoding of its kind
// and verifies ak_sig over slot_id and slot_version.
async function parseSlot(
  obj: Record<string, unknown>,
  accountId: string,
  akPub: Uint8Array,
  slotId: string,
  validBytes: (bytes: Uint8Array) => boolean,
): Promise<Slot | string> {
  const version = obj.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) return "slot version must be a positive integer";
  const bytes = typeof obj.bytes === "string" ? b64Decode(obj.bytes) : null;
  if (!bytes || !validBytes(bytes)) return `slot bytes are not a ${slotId === PASSPHRASE_SLOT ? "passphrase" : "passkey"} slot encoding for this slot`;
  const akSig = typeof obj.ak_sig === "string" ? b64Decode(obj.ak_sig) : null;
  if (!akSig || akSig.length !== 64) return "slot ak_sig must be a base64 Ed25519 signature";
  const msg = slotSigMessage(accountIdDecode(accountId)!, slotId, version, bytes);
  if (!(await ed25519Verify(akPub, akSig, msg))) return "slot ak_sig does not verify against the account key";
  return { version, bytes, akSig };
}

// Decodes a base64 ciphertext field within [MIN_CT_BYTES, max].
function ciphertext(v: unknown, max: number): Uint8Array | null {
  const bytes = typeof v === "string" ? b64Decode(v) : null;
  return bytes && bytes.length >= MIN_CT_BYTES && bytes.length <= max ? bytes : null;
}

// Parses {revisions: [{id, ct}]} with 1 to MAX_PUSH_REVISIONS entries. An ID
// repeated in the body counts once, with its first ct.
function parseRevisions(body: Uint8Array): Map<string, Uint8Array> | Response {
  const parsed = parseObject(body, ["revisions"]);
  const list = parsed && Array.isArray(parsed.revisions) ? parsed.revisions : null;
  if (!list || list.length < 1 || list.length > MAX_PUSH_REVISIONS) {
    return fail(400, `body must be {revisions: [{id, ct}]} with 1 to ${MAX_PUSH_REVISIONS} revisions`);
  }
  const revisions = new Map<string, Uint8Array>();
  for (const item of list) {
    const o = asObject(item, ["id", "ct"]);
    if (!o || typeof o.id !== "string" || !hexDecode(o.id, 16)) return fail(400, "revision ID must be 16 bytes of lowercase hex");
    const ct = typeof o.ct === "string" ? b64Decode(o.ct) : null;
    if (!ct || ct.length < MIN_CT_BYTES) return fail(400, `revision ct must be base64 of at least ${MIN_CT_BYTES} bytes`);
    if (ct.length > MAX_ENVELOPE_BYTES) return fail(413, "revision envelope exceeds 64 KiB");
    if (!revisions.has(o.id)) revisions.set(o.id, ct);
  }
  return revisions;
}

export class Account extends DurableObject<Env> {
  private get sql() {
    return this.ctx.storage.sql;
  }

  private account(): AccountRow | null {
    const created = this.sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'account'").toArray().length > 0;
    if (!created) return null;
    return this.sql.exec<AccountRow>("SELECT id, ak_pub, devices_version FROM account").toArray()[0] ?? null;
  }

  private device(id: string): DeviceRow | null {
    return this.sql.exec<DeviceRow>("SELECT * FROM devices WHERE id = ?", id).toArray()[0] ?? null;
  }

  private bumpDevicesVersion(): number {
    return this.sql.exec<{ v: number }>("UPDATE account SET devices_version = devices_version + 1 RETURNING devices_version AS v").one().v;
  }

  // Checks a session and counts this request as its use: a valid session
  // slides to SESSION_IDLE_SECONDS from now, capped at SESSION_MAX_SECONDS
  // after sign-in, and its unlock key slides to its ttl from now, capped at
  // the session end. An expired unlock key stays expired.
  private useSession(tokenHash: string): boolean {
    const t = now();
    const row = this.sql.exec<{ e: number }>(
      "UPDATE sessions SET expires_at = min(?, created_at + ?) WHERE token_hash = ? AND expires_at > ? RETURNING expires_at AS e",
      t + SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS, tokenHash, t,
    ).toArray()[0];
    if (!row) return false;
    const name = UNLOCK_KEY_PREFIX + tokenHash;
    const entry = this.ctx.storage.kv.get<UnlockKey>(name);
    if (entry?.ttl !== undefined && entry.expires_at > t) this.ctx.storage.kv.put(name, { ...entry, expires_at: Math.min(t + entry.ttl, row.e) });
    return true;
  }

  // Verifies a session, or the signature against the account key ("ak") or
  // the device key; applies the write rate limit and rejects revoked devices
  // and ended sessions. These checks run after the last await, so a caller
  // that continues without awaiting acts on current state.
  private async authenticate(req: Auth, write: boolean): Promise<{ account: AccountRow } | Response> {
    const account = this.account();
    if ("session" in req) {
      if (!account || account.id !== req.accountId) return fail(401, SESSION_EXPIRED);
      if (write) {
        const limited = await rateLimit(this.env, "write", `${req.accountId}:session`);
        if (limited) return limited;
      }
      if (!this.useSession(req.session)) return fail(401, SESSION_EXPIRED);
      return { account };
    }
    if (!account || account.id !== req.accountId) return fail(404, "account not found");
    const pub = req.device === "ak" ? account.ak_pub : this.device(req.device)?.pub;
    if (!pub) return fail(401, "unknown device");
    if (!(await verifyRequest(req, new Uint8Array(pub)))) return fail(401, "invalid request signature");
    if (write) {
      const limited = await rateLimit(this.env, "write", `${req.accountId}:${req.device}`);
      if (limited) return limited;
    }
    if (req.device !== "ak") {
      const device = this.device(req.device);
      if (!device || device.revoked_at !== null) return fail(403, "device revoked");
      this.sql.exec("UPDATE devices SET last_seen_at = ? WHERE id = ?", now(), req.device);
    }
    return { account };
  }

  // POST /api/v1/accounts (contract §5.1). The Worker has checked the
  // registration token and the creation rate limit.
  async createAccount(req: Signed): Promise<Response> {
    const body = parseObject(req.body, ["account_id", "ak_pub", "slot", "device"]);
    if (!body) return fail(400, "body must be {account_id, ak_pub, slot, device}");
    if (body.account_id !== req.accountId) return fail(400, "account_id does not match Hort-Account");
    const akPub = typeof body.ak_pub === "string" ? b64Decode(body.ak_pub) : null;
    if (!akPub || !(await isEd25519PublicKey(akPub))) return fail(400, "ak_pub must be a base64 Ed25519 public key");
    if (!(await verifyRequest(req, akPub))) return fail(401, "invalid request signature");

    const slotObj = asObject(body.slot, ["id", "version", "bytes", "ak_sig"]);
    if (!slotObj || slotObj.id !== PASSPHRASE_SLOT) return fail(400, 'slot must be {id: "passphrase", version, bytes, ak_sig}');
    const slot = await parseSlot(slotObj, req.accountId, akPub, PASSPHRASE_SLOT, isPassphraseSlotBytes);
    if (typeof slot === "string") return fail(400, slot);
    const devObj = asObject(body.device, ["id", "pub", "name"]);
    if (!devObj) return fail(400, "device must be {id, pub, name}");
    const device = await parseDevice(devObj.id, devObj.pub, devObj.name);
    if (typeof device === "string") return fail(400, device);

    // No await below: check and insert are one atomic step.
    const existing = this.account();
    if (existing) {
      // A replay by the holder of the same AK is idempotent.
      if (equal(new Uint8Array(existing.ak_pub), akPub)) return json(200, { devices_version: existing.devices_version });
      return fail(409, "account already exists");
    }
    const t = now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(SCHEMA);
      this.sql.exec("INSERT INTO account (id, ak_pub, created_at, devices_version) VALUES (?, ?, ?, 1)", req.accountId, akPub, t);
      this.sql.exec("INSERT INTO devices (id, pub, name, created_at) VALUES (?, ?, ?, ?)", device.id, device.pub, device.name, t);
      this.sql.exec(
        "INSERT INTO slots (id, kind, version, blob, ak_sig, updated_at) VALUES (?, 'passphrase', ?, ?, ?, ?)",
        PASSPHRASE_SLOT, slot.version, slot.bytes, slot.akSig, t,
      );
    });
    return json(201, { devices_version: 1 });
  }

  // GET /api/v1/accounts/{id}/slot: unauthenticated (owner decision G1/Q15).
  async getSlot(): Promise<Response> {
    const account = this.account();
    if (!account) return fail(404, "account not found");
    const slot = this.sql.exec<SlotRow>("SELECT version, blob, ak_sig FROM slots WHERE id = ?", PASSPHRASE_SLOT).one();
    return json(200, {
      ak_pub: b64Encode(new Uint8Array(account.ak_pub)),
      slot: {
        id: PASSPHRASE_SLOT,
        version: slot.version,
        bytes: b64Encode(new Uint8Array(slot.blob)),
        ak_sig: b64Encode(new Uint8Array(slot.ak_sig)),
      },
    });
  }

  // POST /api/v1/devices, AK-signed (contract §5.3).
  async enrollDevice(req: Signed): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    const body = parseObject(req.body, ["device_id", "pub", "name"]);
    if (!body) return fail(400, "body must be {device_id, pub, name}");
    const device = await parseDevice(body.device_id, body.pub, body.name);
    if (typeof device === "string") return fail(400, device);

    // No await below.
    const existing = this.device(device.id);
    if (existing) {
      if (existing.revoked_at !== null) return fail(409, "device was revoked; enroll with a new device ID");
      if (!equal(new Uint8Array(existing.pub), device.pub)) return fail(409, "device ID is enrolled with a different key");
      return json(200, { devices_version: this.account()!.devices_version });
    }
    const active = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM devices WHERE revoked_at IS NULL").one().n;
    if (active >= MAX_ACTIVE_DEVICES) return fail(429, `device limit reached (${MAX_ACTIVE_DEVICES} active devices); revoke one first`);
    const version = this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO devices (id, pub, name, created_at) VALUES (?, ?, ?, ?)", device.id, device.pub, device.name, now());
      return this.bumpDevicesVersion();
    });
    return json(201, { devices_version: version });
  }

  // GET /api/v1/devices, device-signed or session: devices and passkeys. A
  // session also gets last_visit_at, the time of the previous session call,
  // for the security notices on /devices, and moves it to now.
  async listDevices(req: Auth): Promise<Response> {
    const auth = await this.authenticate(req, false);
    if (auth instanceof Response) return auth;
    const devices = this.sql
      .exec<DeviceRow>("SELECT id, name, created_at, last_seen_at, revoked_at FROM devices ORDER BY created_at, id")
      .toArray()
      .map(({ id, name, created_at, last_seen_at, revoked_at }) => ({ id, name, created_at, last_seen_at, revoked_at }));
    const passkeys = this.sql
      .exec<PasskeyRow>("SELECT id, slot_id, created_at, last_used_at, revoked_at FROM passkeys ORDER BY created_at, id")
      .toArray()
      .map(({ id, slot_id, created_at, last_used_at, revoked_at }) => ({ id, prf: slot_id !== null, created_at, last_used_at, revoked_at }));
    const body: Record<string, unknown> = { devices, passkeys, devices_version: auth.account.devices_version };
    if ("session" in req) {
      body.last_visit_at = this.sql.exec<{ t: number | null }>("SELECT devices_seen_at AS t FROM account").one().t;
      this.sql.exec("UPDATE account SET devices_seen_at = ?", now());
    }
    return json(200, body);
  }

  // DELETE /api/v1/devices/{id}, device-signed or session. A 64-hex ID names a
  // passkey: revoking it deletes its slot and ends its sessions. Revoking
  // twice is idempotent.
  async revokeDevice(req: Auth, id: string): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    if (id.length === 64) return this.revokePasskey(id);
    if (!("session" in req) && id === req.device) return fail(409, "a device cannot revoke itself");
    const device = this.device(id);
    if (!device) return fail(404, "device not found");
    if (device.revoked_at !== null) return json(200, { devices_version: this.account()!.devices_version });
    const version = this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE devices SET revoked_at = ? WHERE id = ?", now(), id);
      return this.bumpDevicesVersion();
    });
    return json(200, { devices_version: version });
  }

  private revokePasskey(id: string): Response {
    const passkey = this.sql.exec<PasskeyRow>("SELECT credential_id, slot_id, revoked_at FROM passkeys WHERE id = ?", id).toArray()[0];
    if (!passkey) return fail(404, "passkey not found");
    if (passkey.revoked_at !== null) return json(200, { devices_version: this.account()!.devices_version });
    const version = this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE passkeys SET revoked_at = ?, slot_id = NULL WHERE id = ?", now(), id);
      if (passkey.slot_id) this.sql.exec("DELETE FROM slots WHERE id = ?", passkey.slot_id);
      for (const { token_hash } of this.sql.exec<{ token_hash: string }>("SELECT token_hash FROM sessions WHERE credential_id = ?", passkey.credential_id)) {
        this.ctx.storage.kv.delete(UNLOCK_KEY_PREFIX + token_hash);
      }
      this.sql.exec("DELETE FROM sessions WHERE credential_id = ?", passkey.credential_id);
      return this.bumpDevicesVersion();
    });
    return json(200, { devices_version: version });
  }

  private activePasskeys(): number {
    return this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM passkeys WHERE revoked_at IS NULL").one().n;
  }

  // POST /api/v1/webauthn/register/options, AK-signed with an empty body
  // (contract §5.4). The browser adds the PRF extension itself, because it
  // derives the eval salt from the account ID.
  async registerOptions(req: Signed, rp: RelyingParty): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    if (req.body.length !== 0) return fail(400, "body must be empty");
    if (this.activePasskeys() >= MAX_ACTIVE_PASSKEYS) return fail(429, PASSKEY_LIMIT);
    const challenge = await issueChallenge(this.env, `register:${req.accountId}`);
    const exclude = this.sql
      .exec<{ credential_id: ArrayBuffer }>("SELECT credential_id FROM passkeys WHERE revoked_at IS NULL")
      .toArray()
      .map((r) => ({ type: "public-key", id: b64urlEncode(new Uint8Array(r.credential_id)) }));
    return json(200, {
      challenge,
      rp: { id: rp.id, name: "Hort" },
      user: { id: b64urlEncode(accountIdDecode(req.accountId)!), name: req.accountId, displayName: `Hort ${req.accountId}` },
      pubKeyCredParams: [-8, -7, -257].map((alg) => ({ type: "public-key", alg })),
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
      excludeCredentials: exclude,
      timeout: 300_000,
    });
  }

  // POST /api/v1/webauthn/register/verify {response, slot}, AK-signed. The
  // challenge must come from register/options of the same account. slot is
  // null for a passkey without PRF; otherwise it must be the passkey slot of
  // the verified credential, signed by AK.
  async registerVerify(req: Signed, rp: RelyingParty): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    const body = parseObject(req.body, ["response", "slot"]);
    if (!body) return fail(400, "body must be {response, slot}");
    let info;
    try {
      const result = await verifyRegistrationResponse({
        response: body.response as RegistrationResponseJSON,
        expectedChallenge: (c) => consumeChallenge(this.env, c, `register:${req.accountId}`),
        expectedOrigin: rp.origin,
        expectedRPID: rp.id,
        requireUserVerification: true,
      });
      if (!result.verified) return fail(400, "passkey registration did not verify");
      info = result.registrationInfo;
    } catch (err) {
      return fail(400, `passkey registration did not verify: ${(err as Error).message}`);
    }
    const credentialId = b64urlDecode(info.credential.id);
    if (!credentialId) return fail(400, "invalid credential ID");
    const credHash = await sha256(credentialId);
    const id = hexEncode(credHash);
    const slotId = `passkey:${id}`;
    let slot: Slot | null = null;
    if (body.slot !== null) {
      const obj = asObject(body.slot, ["version", "bytes", "ak_sig"]);
      if (!obj) return fail(400, "slot must be null or {version, bytes, ak_sig}");
      const parsed = await parseSlot(obj, req.accountId, new Uint8Array(auth.account.ak_pub), slotId, (b) => isPasskeySlotBytes(b, credHash));
      if (typeof parsed === "string") return fail(400, parsed);
      slot = parsed;
    }

    // No await below: limit, uniqueness and inserts are one atomic step.
    if (this.sql.exec("SELECT 1 FROM passkeys WHERE credential_id = ?", credentialId).toArray().length) return fail(409, "passkey is already registered");
    if (this.activePasskeys() >= MAX_ACTIVE_PASSKEYS) return fail(429, PASSKEY_LIMIT);
    const t = now();
    const version = this.ctx.storage.transactionSync(() => {
      if (slot) {
        this.sql.exec(
          "INSERT INTO slots (id, kind, version, blob, ak_sig, updated_at) VALUES (?, 'passkey', ?, ?, ?, ?)",
          slotId, slot.version, slot.bytes, slot.akSig, t,
        );
      }
      this.sql.exec(
        "INSERT INTO passkeys (credential_id, id, public_key, sign_count, slot_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        credentialId, id, info.credential.publicKey, info.credential.counter, slot ? slotId : null, t,
      );
      return this.bumpDevicesVersion();
    });
    return json(201, { id, prf: slot !== null, devices_version: version });
  }

  // POST /api/v1/webauthn/login/verify (contract §5.4). The Worker routed by
  // the user handle and rate-limited the call. Verifies origin, rpId, UV,
  // signature and sign_count, consumes the login challenge, then opens a
  // 12 h session and returns the passkey slot, if any.
  async loginVerify(response: AuthenticationResponseJSON, rp: RelyingParty): Promise<Response> {
    const account = this.account();
    const credentialId = typeof response.id === "string" ? b64urlDecode(response.id) : null;
    const row = account && credentialId
      ? this.sql.exec<PasskeyRow>("SELECT * FROM passkeys WHERE credential_id = ?", credentialId).toArray()[0]
      : undefined;
    if (!account || !credentialId || !row || row.revoked_at !== null) return fail(401, "passkey not recognized or revoked");
    let newCounter: number;
    try {
      const result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: (c) => consumeChallenge(this.env, c, "login"),
        expectedOrigin: rp.origin,
        expectedRPID: rp.id,
        credential: { id: response.id, publicKey: new Uint8Array(row.public_key), counter: row.sign_count },
        requireUserVerification: true,
      });
      if (!result.verified) return fail(401, "passkey sign-in did not verify");
      newCounter = result.authenticationInfo.newCounter;
    } catch (err) {
      return fail(401, `passkey sign-in did not verify: ${(err as Error).message}`);
    }
    const token = crypto.getRandomValues(new Uint8Array(32));
    const tokenHash = hexEncode(await sha256(token));

    // No await below. The passkey may have been revoked or used meanwhile.
    const current = this.sql.exec<PasskeyRow>("SELECT revoked_at, slot_id, sign_count FROM passkeys WHERE credential_id = ?", credentialId).one();
    if (current.revoked_at !== null) return fail(401, "passkey not recognized or revoked");
    if ((newCounter > 0 || current.sign_count > 0) && newCounter <= current.sign_count) return fail(401, "passkey signature counter did not increase");
    const t = now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE credential_id = ?", newCounter, t, credentialId);
      this.sql.exec("DELETE FROM sessions WHERE expires_at <= ?", t);
      this.sql.exec("INSERT INTO sessions (token_hash, credential_id, created_at, expires_at) VALUES (?, ?, ?, ?)", tokenHash, credentialId, t, t + SESSION_IDLE_SECONDS);
    });
    const slot = current.slot_id ? this.sql.exec<SlotRow>("SELECT version, blob, ak_sig FROM slots WHERE id = ?", current.slot_id).one() : null;
    const res = json(200, {
      account_id: account.id,
      ak_pub: b64Encode(new Uint8Array(account.ak_pub)),
      credential_id: response.id,
      slot: slot && {
        id: current.slot_id,
        version: slot.version,
        bytes: b64Encode(new Uint8Array(slot.blob)),
        ak_sig: b64Encode(new Uint8Array(slot.ak_sig)),
      },
    });
    res.headers.set("Set-Cookie", `${SESSION_COOKIE}=${account.id}.${b64urlEncode(token)}; Max-Age=${SESSION_MAX_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Strict`);
    return res;
  }

  // DELETE /api/v1/session: sign out. The Worker clears the cookie.
  async logout(req: SessionAuth): Promise<Response> {
    if (this.account()?.id === req.accountId) {
      this.sql.exec("DELETE FROM sessions WHERE token_hash = ?", req.session);
      this.ctx.storage.kv.delete(UNLOCK_KEY_PREFIX + req.session);
    }
    return new Response(null, { status: 204 });
  }

  // PUT /api/v1/session/unlock-key {ttl}, session + CSRF. Creates or replaces
  // the session's unlock key: 32 random bytes the web app wraps the vault key
  // with in browser storage. It expires ttl seconds after the session's last
  // use (useSession), at the latest with the session. Keys of ended sessions
  // are dropped here.
  async putUnlockKey(req: SessionAuth, body: Uint8Array): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    const ttl = parseObject(body, ["ttl"])?.ttl;
    if (typeof ttl !== "number" || !UNLOCK_KEY_TTLS.includes(ttl)) return fail(400, "body must be {ttl} with ttl 900, 3600, 28800 or 604800");
    const t = now();
    const live = new Set(this.sql.exec<{ token_hash: string }>("SELECT token_hash FROM sessions WHERE expires_at > ?", t).toArray().map((r) => r.token_hash));
    const kv = this.ctx.storage.kv;
    const ended = [...kv.list({ prefix: UNLOCK_KEY_PREFIX })].map(([name]) => name).filter((name) => !live.has(name.slice(UNLOCK_KEY_PREFIX.length)));
    for (const name of ended) kv.delete(name);
    const sessionEnd = this.sql.exec<{ e: number }>("SELECT expires_at AS e FROM sessions WHERE token_hash = ?", req.session).one().e;
    const entry: UnlockKey = { key: b64Encode(crypto.getRandomValues(new Uint8Array(32))), ttl, expires_at: Math.min(t + ttl, sessionEnd) };
    kv.put(UNLOCK_KEY_PREFIX + req.session, entry);
    return json(200, { key: entry.key, expires_at: entry.expires_at });
  }

  // GET /api/v1/session/unlock-key, session: the unlock key while it and the
  // session are valid, else 404. Like every session request it slides both.
  async getUnlockKey(req: SessionAuth): Promise<Response> {
    const auth = await this.authenticate(req, false);
    if (auth instanceof Response) return auth;
    const name = UNLOCK_KEY_PREFIX + req.session;
    const entry = this.ctx.storage.kv.get<UnlockKey>(name);
    if (!entry) return fail(404, NO_UNLOCK_KEY);
    if (entry.expires_at <= now()) {
      this.ctx.storage.kv.delete(name);
      return fail(404, NO_UNLOCK_KEY);
    }
    return json(200, { key: entry.key, expires_at: entry.expires_at });
  }

  // DELETE /api/v1/session/unlock-key, session + CSRF: lock now. Like sign-out
  // it touches only the cookie's own session, so an ended session may call it.
  async deleteUnlockKey(req: SessionAuth): Promise<Response> {
    if (this.account()?.id === req.accountId) this.ctx.storage.kv.delete(UNLOCK_KEY_PREFIX + req.session);
    return new Response(null, { status: 204 });
  }

  // PUT /api/v1/slots/{slot_id}, AK-signed (contract §2.2, §6.3).
  async putSlot(req: Signed, slotId: string): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    if (slotId !== PASSPHRASE_SLOT) return fail(404, "slot not found");
    const body = parseObject(req.body, ["version", "bytes", "ak_sig"]);
    if (!body) return fail(400, "body must be {version, bytes, ak_sig}");
    const slot = await parseSlot(body, req.accountId, new Uint8Array(auth.account.ak_pub), PASSPHRASE_SLOT, isPassphraseSlotBytes);
    if (typeof slot === "string") return fail(400, slot);

    // No await below: version check and update are one atomic step.
    const stored = this.sql.exec<{ version: number }>("SELECT version FROM slots WHERE id = ?", PASSPHRASE_SLOT).one().version;
    if (slot.version <= stored) return fail(409, `slot version ${slot.version} is not higher than the stored version ${stored}`);
    this.sql.exec(
      "UPDATE slots SET version = ?, blob = ?, ak_sig = ?, updated_at = ? WHERE id = ?",
      slot.version, slot.bytes, slot.akSig, now(), PASSPHRASE_SLOT,
    );
    return json(200, { version: slot.version });
  }

  // Lazy expiry (contract §7.2): a pending request past expires_at becomes
  // expired the first time any request operation touches the account.
  private expireDue(): void {
    this.sql.exec("UPDATE requests SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?", now());
  }

  private request(id: string): RequestRow | null {
    return this.sql.exec<RequestRow>("SELECT id, status, meta_ct, from_device, created_at, revision_ids FROM requests WHERE id = ?", id).toArray()[0] ?? null;
  }

  // POST /api/v1/requests, device-signed (contract §6.3, §7.2 step 3).
  async createRequest(req: Signed): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    const body = parseObject(req.body, ["id", "meta_ct"]);
    if (!body) return fail(400, "body must be {id, meta_ct}");
    if (typeof body.id !== "string" || !hexDecode(body.id, 16)) return fail(400, "request ID must be 16 bytes of lowercase hex");
    const meta = ciphertext(body.meta_ct, MAX_META_BYTES);
    if (!meta) return fail(400, `meta_ct must be base64 of ${MIN_CT_BYTES} to ${MAX_META_BYTES} bytes`);

    // No await below: expiry, checks and insert are one atomic step.
    this.expireDue();
    const existing = this.request(body.id);
    if (existing) {
      if (!equal(new Uint8Array(existing.meta_ct), meta)) return fail(409, "request ID exists with different content");
      return json(200, { status: existing.status });
    }
    const pending = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM requests WHERE status = 'pending'").one().n;
    if (pending >= MAX_PENDING_REQUESTS) return fail(429, `too many pending requests (${MAX_PENDING_REQUESTS}); decline or wait for expiry`);
    const t = now();
    this.sql.exec(
      "INSERT INTO requests (id, status, meta_ct, from_device, created_at, expires_at) VALUES (?, 'pending', ?, ?, ?, ?)",
      body.id, meta, req.device, t, t + REQUEST_TTL_SECONDS,
    );
    return json(201, { status: "pending" });
  }

  // GET /api/v1/requests/{id}, device-signed.
  async getRequest(req: Auth, id: string): Promise<Response> {
    const auth = await this.authenticate(req, false);
    if (auth instanceof Response) return auth;
    this.expireDue();
    const r = this.request(id);
    if (!r) return fail(404, "request not found");
    return json(200, {
      status: r.status,
      meta_ct: b64Encode(new Uint8Array(r.meta_ct)),
      revision_ids: r.revision_ids ? (JSON.parse(r.revision_ids) as string[]) : [],
    });
  }

  // GET /api/v1/requests?status=pending, device-signed; oldest first.
  async listPendingRequests(req: Auth): Promise<Response> {
    const auth = await this.authenticate(req, false);
    if (auth instanceof Response) return auth;
    this.expireDue();
    const requests = this.sql
      .exec<RequestRow>("SELECT id, meta_ct, created_at FROM requests WHERE status = 'pending' ORDER BY created_at, id LIMIT ?", MAX_PENDING_REQUESTS)
      .toArray()
      .map((r) => ({ id: r.id, meta_ct: b64Encode(new Uint8Array(r.meta_ct)), created_at: r.created_at }));
    return json(200, { requests });
  }

  // POST /api/v1/requests/{id}/decline, device-signed. Declining twice is idempotent.
  async declineRequest(req: Auth, id: string): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    this.expireDue();
    const r = this.request(id);
    if (!r) return fail(404, "request not found");
    if (r.status === "declined") return json(200, { status: "declined" });
    if (r.status !== "pending") return fail(409, `request is ${r.status}`);
    this.sql.exec("UPDATE requests SET status = 'declined' WHERE id = ?", id);
    return json(200, { status: "declined" });
  }

  // Inserts the revisions whose ID is not stored yet and returns the split,
  // or a 413 when the account limits would be exceeded. Synchronous, so a
  // caller runs it inside one atomic step with its own checks.
  private storeRevisions(revisions: Map<string, Uint8Array>, fromDevice: string | null): { accepted: string[]; duplicate: string[] } | Response {
    const ids = [...revisions.keys()];
    const stored = new Set(
      this.sql.exec<{ id: string }>(`SELECT id FROM revisions WHERE id IN (${ids.map(() => "?").join(",")})`, ...ids)
        .toArray().map((row) => row.id),
    );
    const fresh = [...revisions].filter(([rid]) => !stored.has(rid));
    const totals = this.sql.exec<{ n: number; bytes: number }>("SELECT count(*) AS n, coalesce(sum(length(ct)), 0) AS bytes FROM revisions").one();
    const freshBytes = fresh.reduce((sum, [, ct]) => sum + ct.length, 0);
    if (totals.n + fresh.length > MAX_ACCOUNT_REVISIONS || totals.bytes + freshBytes > MAX_ACCOUNT_CT_BYTES) {
      return fail(413, "account revision storage limit reached");
    }
    const t = now();
    for (const [rid, ct] of fresh) {
      this.sql.exec("INSERT INTO revisions (id, ct, from_device, received_at) VALUES (?, ?, ?, ?)", rid, ct, fromDevice, t);
    }
    return { accepted: fresh.map(([rid]) => rid), duplicate: ids.filter((rid) => stored.has(rid)) };
  }

  // POST /api/v1/revisions {revisions:[{id, ct}]}, device-signed or session
  // (the Worker checked Hort-CSRF and Origin) (contract §6.3, §6.6). An ID
  // already stored is a duplicate whatever its ct: the server cannot tell
  // envelopes apart, and the same ID with other content can only come from a
  // bug, which the pulling client reports. A session push records no device.
  async pushRevisions(req: Auth, body: Uint8Array): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    const revisions = parseRevisions(body);
    if (revisions instanceof Response) return revisions;
    // No await below: limit check and inserts are one atomic step.
    const fromDevice = "session" in req ? null : req.device;
    const result = this.ctx.storage.transactionSync(() => this.storeRevisions(revisions, fromDevice));
    if (result instanceof Response) return result;
    return json(200, result);
  }

  // GET /api/v1/revisions?after=SEQ&limit=N, device-signed or session
  // (contract §6.3, §6.6). A page ends at `limit` rows or MAX_PAGE_CT_BYTES of ct, whichever
  // comes first, and always holds at least one row when one exists. slot_version
  // tells a device when to fetch a newer passphrase slot.
  async listRevisions(req: Auth, after: number, limit: number): Promise<Response> {
    const auth = await this.authenticate(req, false);
    if (auth instanceof Response) return auth;
    const revisions: { seq: number; id: string; ct: string }[] = [];
    let bytes = 0;
    let cursor = after;
    for (const row of this.sql.exec<{ seq: number; id: string; ct: ArrayBuffer }>("SELECT seq, id, ct FROM revisions WHERE seq > ? ORDER BY seq LIMIT ?", after, limit)) {
      if (revisions.length > 0 && bytes + row.ct.byteLength > MAX_PAGE_CT_BYTES) break;
      bytes += row.ct.byteLength;
      revisions.push({ seq: row.seq, id: row.id, ct: b64Encode(new Uint8Array(row.ct)) });
      cursor = row.seq;
    }
    const more = this.sql.exec<{ n: number }>("SELECT count(*) AS n FROM (SELECT 1 FROM revisions WHERE seq > ? LIMIT 1)", cursor).one().n > 0;
    const slotVersion = this.sql.exec<{ version: number }>("SELECT version FROM slots WHERE id = ?", PASSPHRASE_SLOT).one().version;
    return json(200, { revisions, cursor, more, devices_version: auth.account.devices_version, slot_version: slotVersion });
  }

  // POST /api/v1/requests/{id}/fulfill {revisions:[{id, ct}]} (contract §7.3),
  // session only; the Worker checked Hort-CSRF and Origin. Revisions and
  // status change in one transaction. Revisions already stored (by ID) count
  // as duplicates.
  async fulfillRequest(req: SessionAuth, id: string, body: Uint8Array): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    const revisions = parseRevisions(body);
    if (revisions instanceof Response) return revisions;

    // No await below: state check and writes are one atomic step.
    if (!this.useSession(req.session)) return fail(401, SESSION_EXPIRED);
    this.expireDue();
    const r = this.request(id);
    if (!r) return fail(404, "request not found");
    if (r.status !== "pending") return fail(409, `request is ${r.status}`);
    const result = this.ctx.storage.transactionSync(() => {
      const stored = this.storeRevisions(revisions, null);
      if (stored instanceof Response) return stored;
      this.sql.exec("UPDATE requests SET status = 'fulfilled', revision_ids = ? WHERE id = ?", JSON.stringify([...revisions.keys()]), id);
      return stored;
    });
    if (result instanceof Response) return result;
    return json(200, result);
  }
}
