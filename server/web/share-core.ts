// share-core: the browser side of sharing a secret by link. Mirrors
// internal/vault/share.go; spec/vectors/share.json is the byte authority and
// test-web/share-core.test.ts runs every case of it against this module.
import { argon2id } from "./argon2";
import { aesKey, exactKeys, foldKey, hkdf, open, PRODUCTION_ARGON, seal, type AccountKeys, type ArgonParams } from "./vault-core";
import { b64urlDecode, b64urlEncode, canon, hexDecode, sha256 } from "../src/wire";

const utf8 = new TextEncoder();
const ID = /^[0-9a-f]{32}$/;
const FIELD = /^[a-z0-9][a-z0-9._-]{0,63}$/;
// Unicode White_Space, the set Go's unicode.IsSpace tests.
const SPACE = /[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/;

export const SHARE_LINK_KEY_BYTES = 32;

// NFKC, foldKey (lowercase per code point, U+0130 becoming "i" + U+0307),
// ς and σ alike, ß as "ss", NFKC again, whitespace runs collapsed and trimmed.
export function normalizeShareName(name: string): string {
  const lower = foldKey(name.normalize("NFKC"));
  const folded = lower.replace(/ς/g, "σ").replace(/ß/g, "ss").normalize("NFKC");
  return folded.split(SPACE).filter((part) => part !== "").join(" ");
}

export type ShareKeys = {
  enc: CryptoKey; // AES-256-GCM key of the share ciphertext
  token: Uint8Array; // access token the recipient presents (Hort-Share-Token)
  tokenHash: Uint8Array; // SHA-256(token), what the owner sends as token_hash
};

function shareIdBytes(shareId: string): Uint8Array {
  if (!ID.test(shareId)) throw new Error("invalid share ID");
  return hexDecode(shareId, 16)!;
}

// The keys of share shareId for the name the recipient typed. Production
// Argon2id parameters always; other parameters exist for the vectors only.
export async function deriveShareKeys(name: string, linkKey: Uint8Array, shareId: string, argon: ArgonParams = PRODUCTION_ARGON): Promise<ShareKeys> {
  const id = shareIdBytes(shareId);
  if (linkKey.length !== SHARE_LINK_KEY_BYTES) throw new Error("link key must be 32 bytes");
  const normalized = normalizeShareName(name);
  if (normalized === "") throw new Error("name is empty");
  const a = await argon2id(utf8.encode(normalized), id, argon);
  for (let i = 0; i < a.length; i++) a[i] ^= linkKey[i];
  const k = await hkdf(a, id, "hort/v4/share");
  const enc = await hkdf(k, id, "hort/v4/share-enc");
  const token = await hkdf(k, id, "hort/v4/share-token");
  const keys = { enc: await aesKey(enc), token, tokenHash: await sha256(token) };
  a.fill(0);
  k.fill(0);
  enc.fill(0);
  return keys;
}

export type SharedField = { field: string; value: string };
// A share hands values over; a request also asks the recipient to send values
// back once (the answer). A request may carry empty values.
export type ShareKind = "share" | "request";
export type SharedAnswer = { name: string; description: string; fields: SharedField[] };
export type SharedSecret = SharedAnswer & { kind: ShareKind };

// The kind member of a share plaintext or meta: absent in the form of an older
// Hort, which reads as "share". The one place the browser maps that form.
function shareKind(o: Record<string, unknown>): ShareKind | null {
  if (!("kind" in o)) return "share";
  return o.kind === "share" || o.kind === "request" ? o.kind : null;
}

function sharedSecretError(s: SharedAnswer): string | null {
  if (s.name === "") return "shared secret has no name";
  if (s.fields.length === 0) return "shared secret has no fields";
  const seen = new Set<string>();
  for (const f of s.fields) {
    if (f.field !== "" && !FIELD.test(f.field)) return `shared field "${f.field}" is invalid`;
    if (seen.has(f.field)) return `shared field "${f.field}" appears twice`;
    seen.add(f.field);
  }
  return null;
}

const shareAAD = (shareId: string) => canon("hort/v4/share-ct\n", shareIdBytes(shareId));
const answerAAD = (shareId: string) => canon("hort/v4/share-answer\n", shareIdBytes(shareId));

async function sealShared(keys: ShareKeys, aad: Uint8Array, s: SharedAnswer, extra: { kind?: ShareKind }, nonce: Uint8Array): Promise<Uint8Array> {
  const error = sharedSecretError(s);
  if (error) throw new Error(error);
  const plaintext = { name: s.name, description: s.description, fields: s.fields.map((f) => ({ field: f.field, value: f.value })), ...extra };
  return seal(keys.enc, utf8.encode(JSON.stringify(plaintext)), aad, nonce);
}

// A share (kinded) or an answer; only a share carries a kind.
async function openShared(keys: ShareKeys, shareId: string, ct: Uint8Array, noun: "share" | "answer"): Promise<SharedSecret> {
  const kinded = noun === "share";
  let pt: Uint8Array;
  try {
    pt = await open(keys.enc, ct, kinded ? shareAAD(shareId) : answerAAD(shareId));
  } catch {
    throw new Error(`${noun} does not open`);
  }
  const o: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(pt));
  const what = `${noun} ${shareId}`;
  const invalid = new Error(`${what}: invalid content`);
  const members = ["name", "description", "fields"];
  if (!exactKeys(o, members, kinded ? ["kind"] : [])) throw invalid;
  const kind = shareKind(o);
  if (!kind || typeof o.name !== "string" || typeof o.description !== "string" || !Array.isArray(o.fields)) throw invalid;
  const fields: SharedField[] = [];
  for (const f of o.fields as unknown[]) {
    if (!exactKeys(f, ["field", "value"]) || typeof f.field !== "string" || typeof f.value !== "string") throw invalid;
    fields.push({ field: f.field, value: f.value });
  }
  const s = { name: o.name, description: o.description, fields, kind };
  const error = sharedSecretError(s);
  if (error) throw new Error(`${what}: ${error}`);
  return s;
}

// ct = nonce || AES-256-GCM(enc, JSON {name, description, fields, kind}).
export async function sealShare(
  keys: ShareKeys,
  shareId: string,
  s: SharedSecret,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(12)),
): Promise<Uint8Array> {
  if (s.kind !== "share" && s.kind !== "request") throw new Error(`share kind "${s.kind}" is invalid`);
  return sealShared(keys, shareAAD(shareId), s, { kind: s.kind }, nonce);
}

export async function openShare(keys: ShareKeys, shareId: string, ct: Uint8Array): Promise<SharedSecret> {
  return openShared(keys, shareId, ct, "share");
}

// The recipient's answer to a request: JSON {name, description, fields} under
// the share's enc key, with its own AAD tag.
export async function sealShareAnswer(
  keys: ShareKeys,
  shareId: string,
  a: SharedAnswer,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(12)),
): Promise<Uint8Array> {
  return sealShared(keys, answerAAD(shareId), a, {}, nonce);
}

export async function openShareAnswer(keys: ShareKeys, shareId: string, ct: Uint8Array): Promise<SharedAnswer> {
  const { name, description, fields } = await openShared(keys, shareId, ct, "answer");
  return { name, description, fields };
}

// The owner's view of a share, sealed under RK like request meta: the row's
// env and context, and for a request the link key (unpadded base64url, "" for
// a share), from which the owner derives the share keys to open the answer.
export type ShareMeta = { name: string; recipient: string; fields: string[]; kind: ShareKind; env: string; context: string; linkKey: string };
const META_MEMBERS = ["name", "recipient", "fields"];
const META_KINDED = [...META_MEMBERS, "kind", "env", "context", "link_key"];

const metaAAD = (keys: AccountKeys, shareId: string) => canon("hort/v4/share-meta\n", keys.accountId, shareIdBytes(shareId));

export async function sealShareMeta(
  keys: AccountKeys,
  shareId: string,
  m: ShareMeta,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(12)),
): Promise<Uint8Array> {
  const plaintext = { name: m.name, recipient: m.recipient, fields: m.fields, kind: m.kind, env: m.env, context: m.context, link_key: m.linkKey };
  return seal(keys.rk, utf8.encode(JSON.stringify(plaintext)), metaAAD(keys, shareId), nonce);
}

export async function openShareMeta(keys: AccountKeys, shareId: string, metaCt: Uint8Array): Promise<ShareMeta> {
  const pt = await open(keys.rk, metaCt, metaAAD(keys, shareId));
  const o: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(pt));
  const invalid = new Error(`share ${shareId}: invalid metadata`);
  const older = exactKeys(o, META_MEMBERS);
  if (!older && !exactKeys(o, META_KINDED)) throw invalid;
  const m = o as Record<string, unknown>;
  const kind = shareKind(m);
  const [env, context, linkKey] = older ? ["", "", ""] : [m.env, m.context, m.link_key];
  if (
    !kind || typeof m.name !== "string" || typeof m.recipient !== "string" || !Array.isArray(m.fields) || !m.fields.every((f) => typeof f === "string") ||
    typeof env !== "string" || typeof context !== "string" || typeof linkKey !== "string" ||
    (kind === "share" ? linkKey !== "" : b64urlDecode(linkKey)?.length !== SHARE_LINK_KEY_BYTES)
  ) {
    throw invalid;
  }
  return { name: m.name, recipient: m.recipient, fields: m.fields as string[], kind, env, context, linkKey };
}

// https://<origin>/s/<share ID>#<link key, unpadded base64url>. The key lives
// only in the fragment, which a browser never sends to the server.
export function formatShareLink(origin: string, shareId: string, linkKey: Uint8Array): string {
  shareIdBytes(shareId);
  if (linkKey.length !== SHARE_LINK_KEY_BYTES) throw new Error("link key must be 32 bytes");
  return `${origin}/s/${shareId}#${b64urlEncode(linkKey)}`;
}

export function parseShareLink(link: string): { origin: string; shareId: string; linkKey: Uint8Array } | null {
  let u: URL;
  try {
    u = new URL(link);
  } catch {
    return null;
  }
  const m = /^\/s\/([0-9a-f]{32})$/.exec(u.pathname);
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || link.includes("?") || !m) return null;
  const key = b64urlDecode(u.hash.slice(1));
  if (!key || key.length !== SHARE_LINK_KEY_BYTES) return null;
  return { origin: u.origin, shareId: m[1], linkKey: key };
}
