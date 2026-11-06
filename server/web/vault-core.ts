// vault-core: the browser side of the Hort v4 format (contract §2, §3, §6).
// spec/vectors is the byte authority; test-web/vault-core.test.ts runs every
// vector and reduction fixture against this module. Byte encodings shared with
// the Worker come from src/wire.ts, so both sides use one implementation.
import { argon2id } from "./argon2";
import {
  accountIdDecode,
  accountIdEncode,
  b64urlDecode,
  canon,
  concat,
  hexDecode,
  hexEncode,
  requestMessage,
  sha256,
  slotSigMessage,
  str,
  u32,
  u64,
  uncanon,
} from "../src/wire";

const utf8 = new TextEncoder();
const NONCE = 12;
const TAG = 16;

export type ArgonParams = { t: number; m: number; p: number };
export const PRODUCTION_ARGON: ArgonParams = { t: 3, m: 65536, p: 4 };
export const PASSPHRASE_SLOT = "passphrase";

// ---------------------------------------------------------------------------
// Key derivation (§2.1, §2.2)

export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: str(info) as BufferSource }, key, 256));
}

const PKCS8_ED25519 = hexDecode("302e020100300506032b657004220420", 16)!;

// Imports an Ed25519 seed as a non-extractable signing key plus its public key.
// WebCrypto exposes the public key only through an export, so a short-lived
// extractable copy yields it and is dropped.
export async function ed25519FromSeed(seed: Uint8Array): Promise<{ key: CryptoKey; pub: Uint8Array }> {
  const pkcs8 = concat([PKCS8_ED25519, seed]);
  const tmp = await crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", tmp)) as JsonWebKey;
  const key = await crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, { name: "Ed25519" }, false, ["sign"]);
  pkcs8.fill(0);
  return { key, pub: b64urlDecode(jwk.x!)! };
}

// TypeScript's DOM lib types BufferSource as ArrayBuffer-backed only; the byte
// helpers return plain Uint8Array, so WebCrypto arguments carry a cast.
const gcm = (iv: Uint8Array, aad: Uint8Array): AesGcmParams => ({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource });

async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export type AccountKeys = {
  accountId: Uint8Array;
  rk: CryptoKey; // revision and request envelopes
  ak: CryptoKey; // account auth key (Ed25519, sign)
  akPub: Uint8Array;
};

export async function deriveAccountKeys(vk: Uint8Array, accountId: Uint8Array): Promise<AccountKeys> {
  const rk = await hkdf(vk, accountId, "hort/v4/revision");
  const aks = await hkdf(vk, accountId, "hort/v4/account-auth");
  const { key, pub } = await ed25519FromSeed(aks);
  const keys = { accountId, rk: await aesKey(rk), ak: key, akPub: pub };
  rk.fill(0);
  aks.fill(0);
  return keys;
}

export async function argonOutput(passphrase: string, salt: Uint8Array, p: ArgonParams): Promise<Uint8Array> {
  return argon2id(utf8.encode(passphrase.normalize("NFC")), salt, p);
}

export async function passphraseKEKBytes(
  passphrase: string,
  secretKey: Uint8Array,
  accountId: Uint8Array,
  salt: Uint8Array,
  p: ArgonParams,
): Promise<Uint8Array> {
  const a = await argonOutput(passphrase, salt, p);
  const s = await hkdf(secretKey, accountId, "hort/v4/secret-key");
  for (let i = 0; i < a.length; i++) a[i] ^= s[i];
  const kek = await hkdf(a, salt, "hort/v4/kek");
  a.fill(0);
  s.fill(0);
  return kek;
}

export async function prfEvalSalt(accountId: Uint8Array): Promise<Uint8Array> {
  return sha256(concat([str("hort/v4/prf\n"), accountId]));
}

export async function passkeyKEKBytes(prf: Uint8Array, accountId: Uint8Array): Promise<Uint8Array> {
  if (prf.length !== 32) throw new Error("PRF output must be 32 bytes");
  return hkdf(prf, accountId, "hort/v4/kek-passkey");
}

// ---------------------------------------------------------------------------
// Slots (§2.2, spec/vectors slot.json and passkey-slot.json)

export function argonSlotParams(salt: Uint8Array, p: ArgonParams): Uint8Array {
  return canon("hort/v4/argon\n", salt, u32(p.t), u32(p.m), new Uint8Array([p.p]));
}

export async function passkeySlot(credentialId: Uint8Array): Promise<{ id: string; params: Uint8Array }> {
  const hash = await sha256(credentialId);
  return { id: "passkey:" + hexEncode(hash), params: canon("hort/v4/passkey\n", hash) };
}

function slotAAD(accountId: Uint8Array, slotId: string, version: number, params: Uint8Array): Uint8Array {
  return canon("hort/v4/slot\n", accountId, str(slotId), u64(version), params);
}

export type SlotRecord = { version: number; bytes: Uint8Array; akSig: Uint8Array };

// Wraps VK into slot_bytes and signs them with AK.
export async function wrapSlot(
  kek: Uint8Array,
  vk: Uint8Array,
  keys: AccountKeys,
  slotId: string,
  version: number,
  params: Uint8Array,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(NONCE)),
): Promise<SlotRecord> {
  const aad = slotAAD(keys.accountId, slotId, version, params);
  const wrapped = new Uint8Array(
    await crypto.subtle.encrypt(gcm(nonce, aad), await aesKey(kek), vk as BufferSource),
  );
  const bytes = canon("hort/v4/slot-bytes\n", params, nonce, wrapped);
  const akSig = await signAK(keys, slotSigMessage(keys.accountId, slotId, version, bytes));
  return { version, bytes, akSig };
}

export type ParsedSlot = { params: Uint8Array; nonce: Uint8Array; wrapped: Uint8Array };

export function parseSlotBytes(bytes: Uint8Array): ParsedSlot | null {
  const f = uncanon("hort/v4/slot-bytes\n", bytes, 3);
  if (!f || f[1].length !== NONCE || f[2].length !== 32 + TAG) return null;
  return { params: f[0], nonce: f[1], wrapped: f[2] };
}

// Argon2id parameters of a passphrase slot, within the bounds the Go parser
// applies to untrusted headers (internal/vault/format.go).
export function parseArgonParams(params: Uint8Array): { salt: Uint8Array; argon: ArgonParams } | null {
  const f = uncanon("hort/v4/argon\n", params, 4);
  if (!f || f[0].length !== 32 || f[1].length !== 4 || f[2].length !== 4 || f[3].length !== 1) return null;
  const dv = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(0);
  const argon = { t: dv(f[1]), m: dv(f[2]), p: f[3][0] };
  if (argon.t < 1 || argon.t > 3 || argon.p < 1 || argon.p > 4 || argon.m < 8 * argon.p || argon.m > 65536) return null;
  return { salt: f[0], argon };
}

export async function unwrapSlot(kek: Uint8Array, accountId: Uint8Array, slotId: string, version: number, slot: ParsedSlot): Promise<Uint8Array> {
  try {
    const aad = slotAAD(accountId, slotId, version, slot.params);
    const vk = new Uint8Array(
      await crypto.subtle.decrypt(gcm(slot.nonce, aad), await aesKey(kek), slot.wrapped as BufferSource),
    );
    if (vk.length !== 32) throw new Error();
    return vk;
  } catch {
    throw new Error("slot does not open — wrong key or corrupted slot");
  }
}

// After unwrapping, the derived AK must match the account's ak_pub and sign
// the slot (§5.3 step 4); a server cannot hand out a slot of its own making.
export async function verifySlotAuthority(keys: AccountKeys, akPub: Uint8Array, slotId: string, slot: SlotRecord): Promise<boolean> {
  if (hexEncode(keys.akPub) !== hexEncode(akPub)) return false;
  const pub = await crypto.subtle.importKey("raw", akPub as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, pub, slot.akSig as BufferSource, slotSigMessage(keys.accountId, slotId, slot.version, slot.bytes) as BufferSource);
}

export async function signAK(keys: AccountKeys, msg: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, keys.ak, msg as BufferSource));
}

// Hort-* headers of an AK-signed request (§6.2).
export async function akHeaders(
  keys: AccountKeys,
  method: string,
  pathWithQuery: string,
  body: Uint8Array,
  timestamp = Math.floor(Date.now() / 1000),
): Promise<Record<string, string>> {
  const msg = await requestMessage(keys.accountId, str("ak"), method, pathWithQuery, timestamp, body);
  const sig = await signAK(keys, msg);
  let bin = "";
  for (const x of sig) bin += String.fromCharCode(x);
  return {
    "Hort-Account": accountIdEncode(keys.accountId),
    "Hort-Device": "ak",
    "Hort-Timestamp": String(timestamp),
    "Hort-Signature": btoa(bin),
  };
}

// ---------------------------------------------------------------------------
// Secret Key and account ID text forms (§2.5, §2.6)

export const SECRET_KEY_MISTYPED = "Secret Key mistyped";

function normalizeCrockford(s: string): string {
  let out = "";
  for (const ch of s) {
    let c = ch >= "a" && ch <= "z" ? ch.toUpperCase() : ch;
    if (c === "-" || c === " ") continue;
    if (c === "I" || c === "L") c = "1";
    if (c === "O") c = "0";
    out += c;
  }
  return out;
}

async function checkSymbol(key: Uint8Array): Promise<string> {
  const sum = await sha256(concat([str("hort/v4/sk-check\n"), key]));
  return "0123456789ABCDEFGHJKMNPQRSTVWXYZ"[sum[0] >> 3];
}

export async function formatSecretKey(key: Uint8Array): Promise<string> {
  const d = accountIdEncode(key).toUpperCase();
  return ["H4", d.slice(0, 6), d.slice(6, 11), d.slice(11, 16), d.slice(16, 21), d.slice(21, 26), await checkSymbol(key)].join("-");
}

export async function parseSecretKey(input: string): Promise<Uint8Array> {
  let n = normalizeCrockford(input);
  if (n.length === 29 && n.startsWith("H4")) n = n.slice(2);
  if (n.length !== 27) throw new Error(SECRET_KEY_MISTYPED);
  const key = accountIdDecode(n.slice(0, 26).toLowerCase());
  if (!key || n[26] !== (await checkSymbol(key))) throw new Error(SECRET_KEY_MISTYPED);
  return key;
}

export function parseAccountId(input: string): Uint8Array | null {
  return accountIdDecode(normalizeCrockford(input).toLowerCase());
}

// ---------------------------------------------------------------------------
// Revisions (§3.1) and times at nanosecond precision (vectors README pt. 10)

export type Op = "set" | "delete" | "delete-entry" | "describe";
export type Revision = {
  id: string;
  recordedAt: bigint | null; // Unix nanoseconds, UTC; null for imported v1 history
  op: Op;
  field: string;
  key: string;
  value: string;
};

const TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]00:00)$/;

export function parseTime(s: string): bigint | null {
  const m = TIME.exec(s);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, se);
  const check = new Date(ms);
  if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d || h > 23 || mi > 59 || se > 59) return null;
  return BigInt(ms) * 1_000_000n + BigInt((m[7] ?? "").padEnd(9, "0"));
}

// RFC 3339 with trailing zeros trimmed, as Go's time.RFC3339Nano writes it.
export function formatTime(ns: bigint): string {
  const sec = ns / 1_000_000_000n - (ns % 1_000_000_000n < 0n ? 1n : 0n);
  const frac = ns - sec * 1_000_000_000n;
  const base = new Date(Number(sec) * 1000).toISOString().slice(0, 19);
  const digits = frac === 0n ? "" : "." + frac.toString().padStart(9, "0").replace(/0+$/, "");
  return `${base}${digits}Z`;
}

export const nowNs = () => BigInt(Date.now()) * 1_000_000n;

const ID = /^[0-9a-f]{32}$/;
const FIELD = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function newId(): string {
  return hexEncode(crypto.getRandomValues(new Uint8Array(16)));
}

function revisionJSON(r: Revision): Record<string, unknown> {
  const o: Record<string, unknown> = { id: r.id, recorded_at: r.recordedAt === null ? null : formatTime(r.recordedAt), op: r.op };
  if (r.field !== "") o.field = r.field;
  o.key = r.key;
  o.value = r.value;
  return o;
}

export function envelopePlaintext(name: string, r: Revision): Uint8Array {
  return utf8.encode(JSON.stringify({ name, revision: revisionJSON(r) }));
}

function exactKeys(o: unknown, required: string[], optional: string[] = []): o is Record<string, unknown> {
  if (typeof o !== "object" || o === null || Array.isArray(o)) return false;
  const keys = Object.keys(o);
  return required.every((k) => keys.includes(k)) && keys.every((k) => required.includes(k) || optional.includes(k));
}

// Decoding rules of §3.4: accepts everything a v3 vault can hold.
function decodeRevision(o: unknown): Revision | string {
  if (!exactKeys(o, ["id", "recorded_at", "op", "key", "value"], ["field"])) return "revision members do not match";
  const { id, recorded_at, op, key, value } = o;
  const field = o.field ?? "";
  if (typeof id !== "string" || !ID.test(id)) return "invalid revision ID";
  if (typeof key !== "string" || typeof value !== "string" || typeof field !== "string") return "invalid revision members";
  let recordedAt: bigint | null = null;
  if (recorded_at !== null) {
    if (typeof recorded_at !== "string" || (recordedAt = parseTime(recorded_at)) === null) return "revision time must be UTC";
  }
  if (field !== "" && !FIELD.test(field)) return "invalid field";
  switch (op) {
    case "set":
      break;
    case "delete":
      if (value !== "") return "invalid delete";
      break;
    case "delete-entry":
      if (key !== "" || value !== "") return "invalid entry deletion";
      break;
    case "describe":
      if (key !== "") return "invalid description";
      break;
    default:
      return "unknown revision operation";
  }
  return { id, recordedAt, op, field, key, value };
}

async function seal(key: CryptoKey, plaintext: Uint8Array, aad: Uint8Array, nonce: Uint8Array): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt(gcm(nonce, aad), key, plaintext as BufferSource);
  return concat([nonce, new Uint8Array(ct)]);
}

async function open(key: CryptoKey, envelope: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  if (envelope.length < NONCE + TAG) throw new Error("envelope too short");
  const pt = await crypto.subtle.decrypt(gcm(envelope.subarray(0, NONCE), aad), key, envelope.subarray(NONCE) as BufferSource);
  return new Uint8Array(pt);
}

const revAAD = (accountId: Uint8Array, id: string) => canon("hort/v4/rev\n", accountId, hexDecode(id, 16)!);

export async function sealRevision(
  keys: AccountKeys,
  name: string,
  r: Revision,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(NONCE)),
): Promise<Uint8Array> {
  if (!ID.test(r.id)) throw new Error("invalid revision ID");
  return seal(keys.rk, envelopePlaintext(name, r), revAAD(keys.accountId, r.id), nonce);
}

// Opens an envelope received as {id, ct}; the sealed revision must carry that
// same ID. Throws for anything that fails decoding, so the caller skips it.
export async function openRevision(keys: AccountKeys, id: string, envelope: Uint8Array): Promise<{ name: string; revision: Revision }> {
  if (!ID.test(id)) throw new Error("invalid revision ID");
  const pt = await open(keys.rk, envelope, revAAD(keys.accountId, id));
  const o: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(pt));
  if (!exactKeys(o, ["name", "revision"]) || typeof o.name !== "string" || o.name === "") throw new Error(`revision ${id}: invalid envelope`);
  const r = decodeRevision(o.revision);
  if (typeof r === "string") throw new Error(`revision ${id}: ${r}`);
  if (r.id !== id) throw new Error(`revision ${id}: envelope holds revision ${r.id}`);
  return { name: o.name, revision: r };
}

export type RequestMeta = { name: string; description: string; field: string; env: string; context: string };
const META_KEYS = ["name", "description", "field", "env", "context"];

export async function openRequestMeta(keys: AccountKeys, requestId: string, metaCt: Uint8Array): Promise<RequestMeta> {
  if (!ID.test(requestId)) throw new Error("invalid request ID");
  const pt = await open(keys.rk, metaCt, canon("hort/v4/req-meta\n", keys.accountId, hexDecode(requestId, 16)!));
  const o: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(pt));
  if (!exactKeys(o, META_KEYS) || META_KEYS.some((k) => typeof o[k] !== "string")) throw new Error(`request ${requestId}: invalid metadata`);
  return o as RequestMeta;
}

// ---------------------------------------------------------------------------
// Reduction (§3.2, §3.3; internal/vault/revisions.go)

export function history(revisions: Revision[]): Revision[] {
  return [...revisions].sort((a, b) => {
    if (a.recordedAt === null && b.recordedAt !== null) return -1;
    if (a.recordedAt !== null && b.recordedAt === null) return 1;
    if (a.recordedAt !== null && b.recordedAt !== null && a.recordedAt !== b.recordedAt) return a.recordedAt < b.recordedAt ? -1 : 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

export type Current = { values: Map<string, { field: string; key: string; value: string }>; description: string; visible: boolean };

const valueKey = (field: string, key: string) => `${field}\u0000${key}`;

export function current(revisions: Revision[]): Current {
  const values: Current["values"] = new Map();
  let description = "";
  let visible = false;
  let deleted = false;
  for (const r of history(revisions)) {
    switch (r.op) {
      case "set":
        values.set(valueKey(r.field, r.key), { field: r.field, key: r.key, value: r.value });
        visible = true;
        deleted = false;
        break;
      case "delete":
        values.delete(valueKey(r.field, r.key));
        break;
      case "delete-entry":
        values.clear();
        description = "";
        visible = false;
        deleted = true;
        break;
      case "describe":
        description = r.value;
        if (!deleted) visible = true;
        break;
    }
  }
  return { values, description, visible };
}

export function lookupKey(env: string, context: string): string {
  return `${env || "*"}:${context || "*"}`;
}

export function resolve(revisions: Revision[], field: string, env: string, context: string): string | null {
  const { values } = current(revisions);
  for (const key of [lookupKey(env, context), lookupKey(env, "*"), lookupKey("*", "*")]) {
    const v = values.get(valueKey(field, key));
    if (v) return v.value;
  }
  return null;
}

// The Append rule (§3.2): a new revision is stamped behind every revision the
// entry knows, at nanosecond precision.
export function appendStamp(existing: Revision[], now: bigint): bigint {
  let at = now;
  for (const r of existing) if (r.recordedAt !== null && r.recordedAt >= at) at = r.recordedAt + 1n;
  return at;
}

// ---------------------------------------------------------------------------
// Write validation (§3.4 "New writes", Revision 2.1 pt. 3 and 5)

export const MAX_ENVELOPE_BYTES = 64 * 1024;
const MAX_PLAINTEXT_BYTES = MAX_ENVELOPE_BYTES - NONCE - TAG;
const CONTROL_OR_SPACE = /[\s\u0000-\u001f\u007f]/u;

function validKeyPart(part: string): boolean {
  return part !== "" && (part === "*" || (!part.includes("*") && !part.includes(":") && !CONTROL_OR_SPACE.test(part)));
}

// Returns an error message, or null when the write is valid. `delete` and
// `delete-entry` stay allowed on legacy names and keys, so old data can be
// cleaned up.
export function validateWrite(name: string, r: Revision): string | null {
  const cleanup = r.op === "delete" || r.op === "delete-entry";
  if (r.field !== "" && !FIELD.test(r.field)) return "field must match [a-z0-9][a-z0-9._-]{0,63}";
  if ((r.op === "delete-entry" || r.op === "describe") && r.field !== "") return `${r.op} applies to the whole entry, not a field`;
  if (!cleanup) {
    const bytes = utf8.encode(name).length;
    if (bytes < 1 || bytes > 128 || CONTROL_OR_SPACE.test(name) || name.startsWith("-")) {
      return "this name does not meet the rules for new values (1–128 bytes, no whitespace or control characters, no leading -); delete it and re-create the secret under a valid name";
    }
    if (r.op === "set") {
      const colon = r.key.indexOf(":");
      if (colon < 0 || !validKeyPart(r.key.slice(0, colon)) || !validKeyPart(r.key.slice(colon + 1))) {
        return "env and context must not contain ':', whitespace or control characters, and '*' only as the whole part";
      }
    }
  }
  if (envelopePlaintext(name, r).length > MAX_PLAINTEXT_BYTES) return "value is too large for one revision (64 KiB envelope limit)";
  return null;
}

export { accountIdEncode, hexEncode };
