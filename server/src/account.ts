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

type AccountRow = { id: string; ak_pub: ArrayBuffer; devices_version: number };
type DeviceRow = { id: string; pub: ArrayBuffer; name: string; created_at: number; last_seen_at: number | null; revoked_at: number | null };
type SlotRow = { version: number; blob: ArrayBuffer; ak_sig: ArrayBuffer };
type Slot = { version: number; bytes: Uint8Array; akSig: Uint8Array };
type Device = { id: string; pub: Uint8Array; name: string };

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
}
