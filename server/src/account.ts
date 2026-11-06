import { DurableObject } from "cloudflare:workers";
import { asObject, fail, json, parseObject } from "./http";
import { rateLimit } from "./rate-limiter";
import {
  accountIdDecode,
  b64Decode,
  b64Encode,
  ed25519Verify,
  hexDecode,
  isEd25519PublicKey,
  isPassphraseSlotBytes,
  slotSigMessage,
  verifyRequest,
  type Signed,
} from "./wire";

// Contract §6.5. Created together with the account, so a slot fetch for an
// unknown account ID leaves no storage behind.
const SCHEMA = `
CREATE TABLE account   (id TEXT PRIMARY KEY, ak_pub BLOB NOT NULL, created_at INTEGER NOT NULL,
                        devices_version INTEGER NOT NULL DEFAULT 0);
CREATE TABLE devices   (id TEXT PRIMARY KEY, pub BLOB NOT NULL, name TEXT NOT NULL,
                        created_at INTEGER NOT NULL, last_seen_at INTEGER, revoked_at INTEGER);
CREATE TABLE slots     (id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('passphrase','passkey')),
                        version INTEGER NOT NULL, blob BLOB NOT NULL, ak_sig BLOB NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE passkeys  (credential_id BLOB PRIMARY KEY, public_key BLOB NOT NULL, sign_count INTEGER NOT NULL,
                        slot_id TEXT REFERENCES slots(id), created_at INTEGER NOT NULL,
                        last_used_at INTEGER, revoked_at INTEGER);
CREATE TABLE revisions (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, ct BLOB NOT NULL,
                        from_device TEXT, received_at INTEGER NOT NULL);
CREATE TABLE requests  (id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK (status IN ('pending','fulfilled','declined','expired')),
                        meta_ct BLOB NOT NULL, from_device TEXT NOT NULL, created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL, revision_ids TEXT);
`;

// Contract §6.6.
const MAX_ACTIVE_DEVICES = 20;
const PASSPHRASE_SLOT = "passphrase";
const MAX_PENDING_REQUESTS = 50;
const MAX_ENVELOPE_BYTES = 64 * 1024;
const MAX_META_BYTES = 16 * 1024; // name <= 128 B plus description and parts; far below an envelope
const MIN_CT_BYTES = 28; // nonce(12) + GCM tag(16)
const MAX_PUSH_REVISIONS = 500;
const MAX_ACCOUNT_REVISIONS = 50_000;
const MAX_ACCOUNT_CT_BYTES = 64 * 1024 * 1024;
const REQUEST_TTL_SECONDS = 24 * 60 * 60;

type AccountRow = { id: string; ak_pub: ArrayBuffer; devices_version: number };
type DeviceRow = { id: string; pub: ArrayBuffer; name: string; created_at: number; last_seen_at: number | null; revoked_at: number | null };
type SlotRow = { version: number; blob: ArrayBuffer; ak_sig: ArrayBuffer };
type Slot = { version: number; bytes: Uint8Array; akSig: Uint8Array };
type Device = { id: string; pub: Uint8Array; name: string };
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

// Parses {version, bytes, ak_sig} of a passphrase slot and verifies ak_sig.
async function parseSlot(obj: Record<string, unknown>, accountId: string, akPub: Uint8Array): Promise<Slot | string> {
  const version = obj.version;
  if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1) return "slot version must be a positive integer";
  const bytes = typeof obj.bytes === "string" ? b64Decode(obj.bytes) : null;
  if (!bytes || !isPassphraseSlotBytes(bytes)) return "slot bytes are not a passphrase slot encoding";
  const akSig = typeof obj.ak_sig === "string" ? b64Decode(obj.ak_sig) : null;
  if (!akSig || akSig.length !== 64) return "slot ak_sig must be a base64 Ed25519 signature";
  const msg = slotSigMessage(accountIdDecode(accountId)!, PASSPHRASE_SLOT, version, bytes);
  if (!(await ed25519Verify(akPub, akSig, msg))) return "slot ak_sig does not verify against the account key";
  return { version, bytes, akSig };
}

// Decodes a base64 ciphertext field within [MIN_CT_BYTES, max].
function ciphertext(v: unknown, max: number): Uint8Array | null {
  const bytes = typeof v === "string" ? b64Decode(v) : null;
  return bytes && bytes.length >= MIN_CT_BYTES && bytes.length <= max ? bytes : null;
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

  // Verifies the signature against the account key ("ak") or the device key,
  // applies the write rate limit and rejects revoked devices. The revocation
  // check runs after the last await, so a caller that continues without
  // awaiting acts on current device state.
  private async authenticate(req: Signed, write: boolean): Promise<{ account: AccountRow } | Response> {
    const account = this.account();
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
    const slot = await parseSlot(slotObj, req.accountId, akPub);
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

  // GET /api/v1/devices, device-signed.
  async listDevices(req: Signed): Promise<Response> {
    const auth = await this.authenticate(req, false);
    if (auth instanceof Response) return auth;
    const devices = this.sql
      .exec<DeviceRow>("SELECT id, name, created_at, last_seen_at, revoked_at FROM devices ORDER BY created_at, id")
      .toArray()
      .map(({ id, name, created_at, last_seen_at, revoked_at }) => ({ id, name, created_at, last_seen_at, revoked_at }));
    return json(200, { devices, devices_version: this.account()!.devices_version });
  }

  // DELETE /api/v1/devices/{id}, device-signed. Revoking twice is idempotent.
  async revokeDevice(req: Signed, id: string): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    if (id === req.device) return fail(409, "a device cannot revoke itself");
    const device = this.device(id);
    if (!device) return fail(404, "device not found");
    if (device.revoked_at !== null) return json(200, { devices_version: this.account()!.devices_version });
    const version = this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE devices SET revoked_at = ? WHERE id = ?", now(), id);
      return this.bumpDevicesVersion();
    });
    return json(200, { devices_version: version });
  }

  // PUT /api/v1/slots/{slot_id}, AK-signed (contract §2.2, §6.3).
  async putSlot(req: Signed, slotId: string): Promise<Response> {
    const auth = await this.authenticate(req, true);
    if (auth instanceof Response) return auth;
    if (slotId !== PASSPHRASE_SLOT) return fail(404, "slot not found");
    const body = parseObject(req.body, ["version", "bytes", "ak_sig"]);
    if (!body) return fail(400, "body must be {version, bytes, ak_sig}");
    const slot = await parseSlot(body, req.accountId, new Uint8Array(auth.account.ak_pub));
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
  async getRequest(req: Signed, id: string): Promise<Response> {
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
  async listPendingRequests(req: Signed): Promise<Response> {
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
  async declineRequest(req: Signed, id: string): Promise<Response> {
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

  // POST /api/v1/requests/{id}/fulfill {revisions:[{id, ct}]} (contract §7.3).
  // Called by the Worker only after a passkey session and Hort-CSRF check
  // (S6.2), so it takes no signature. Revisions and status change in one
  // transaction. Revisions already stored (by ID) count as duplicates.
  async fulfillRequest(id: string, body: Uint8Array): Promise<Response> {
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

    // No await below: state check and writes are one atomic step.
    if (!this.account()) return fail(404, "account not found");
    this.expireDue();
    const r = this.request(id);
    if (!r) return fail(404, "request not found");
    if (r.status !== "pending") return fail(409, `request is ${r.status}`);
    const stored = new Set(
      this.sql.exec<{ id: string }>(`SELECT id FROM revisions WHERE id IN (${[...revisions.keys()].map(() => "?").join(",")})`, ...revisions.keys())
        .toArray().map((row) => row.id),
    );
    const fresh = [...revisions].filter(([rid]) => !stored.has(rid));
    const totals = this.sql.exec<{ n: number; bytes: number }>("SELECT count(*) AS n, coalesce(sum(length(ct)), 0) AS bytes FROM revisions").one();
    const freshBytes = fresh.reduce((sum, [, ct]) => sum + ct.length, 0);
    if (totals.n + fresh.length > MAX_ACCOUNT_REVISIONS || totals.bytes + freshBytes > MAX_ACCOUNT_CT_BYTES) {
      return fail(413, "account revision storage limit reached");
    }
    const t = now();
    this.ctx.storage.transactionSync(() => {
      for (const [rid, ct] of fresh) {
        this.sql.exec("INSERT INTO revisions (id, ct, from_device, received_at) VALUES (?, ?, NULL, ?)", rid, ct, t);
      }
      this.sql.exec("UPDATE requests SET status = 'fulfilled', revision_ids = ? WHERE id = ?", JSON.stringify([...revisions.keys()]), id);
    });
    return json(200, { accepted: fresh.map(([rid]) => rid), duplicate: [...stored] });
  }
}
