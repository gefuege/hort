// Byte-level encodings shared with the Go CLI and the browser.
// spec/vectors/README.md is the authority for every function here.

const utf8 = new TextEncoder();

export function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

export function u64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

export function str(s: string): Uint8Array {
  return utf8.encode(s);
}

// canon(tag, f1..fn) = tag || u32be(len f1) || f1 || ... (contract §2.1)
export function canon(tag: string, ...fields: Uint8Array[]): Uint8Array {
  return concat([str(tag), ...fields.flatMap((f) => [u32(f.length), f])]);
}

// Splits a canon() encoding with the given tag into exactly `count` fields.
export function uncanon(tag: string, bytes: Uint8Array, count: number): Uint8Array[] | null {
  const t = str(tag);
  if (bytes.length < t.length || !t.every((b, i) => bytes[i] === b)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fields: Uint8Array[] = [];
  let at = t.length;
  while (at < bytes.length) {
    if (at + 4 > bytes.length) return null;
    const len = view.getUint32(at);
    at += 4;
    if (at + len > bytes.length) return null;
    fields.push(bytes.subarray(at, at + len));
    at += len;
  }
  return fields.length === count ? fields : null;
}

export function hexEncode(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// Lowercase hex of exactly `bytes` bytes, as used for device IDs.
export function hexDecode(s: string, bytes: number): Uint8Array | null {
  if (s.length !== bytes * 2 || !/^[0-9a-f]*$/.test(s)) return null;
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function b64Encode(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

// Standard base64 with padding (RFC 4648 §4), canonical form only.
export function b64Decode(s: string): Uint8Array | null {
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const bin = atob(s);
  const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return b64Encode(out) === s ? out : null;
}

export function b64urlEncode(b: Uint8Array): string {
  return b64Encode(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Unpadded base64url (RFC 4648 §5), canonical form only, as WebAuthn uses it.
export function b64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const out = b64Decode(std + "=".repeat((4 - (std.length % 4)) % 4));
  return out && b64urlEncode(out) === s ? out : null;
}

const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

// 16 bytes, most significant bit first, 26 lowercase symbols (vectors README pt. 4).
export function accountIdEncode(b: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const x of b) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CROCKFORD[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += CROCKFORD[(acc << (5 - bits)) & 31];
  return out;
}

// The server accepts only the canonical lowercase form, so one account has
// exactly one Durable Object name. Nonzero padding bits fail the round trip.
export function accountIdDecode(s: string): Uint8Array | null {
  if (s.length !== 26) return null;
  const out = new Uint8Array(16);
  let acc = 0;
  let bits = 0;
  let n = 0;
  for (const c of s) {
    const v = CROCKFORD.indexOf(c);
    if (v < 0) return null;
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (n < 16) out[n++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  return accountIdEncode(out) === s ? out : null;
}

export async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

// Ed25519 verification; a malformed key or signature counts as invalid.
export async function ed25519Verify(pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): Promise<boolean> {
  if (pub.length !== 32 || sig.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  } catch {
    return false;
  }
}

export async function isEd25519PublicKey(pub: Uint8Array): Promise<boolean> {
  if (pub.length !== 32) return false;
  try {
    await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return true;
  } catch {
    return false;
  }
}

// Signed request message (contract §6.2, vectors README pt. 8). `device` is
// the decoded 16-byte device ID or the ASCII bytes "ak".
export async function requestMessage(
  accountId: Uint8Array,
  device: Uint8Array,
  method: string,
  pathWithQuery: string,
  timestamp: number,
  body: Uint8Array,
): Promise<Uint8Array> {
  return canon("hort/v4/req\n", accountId, device, str(method), str(pathWithQuery), u64(timestamp), await sha256(body));
}

// A request whose signature headers passed the stateless checks in the Worker.
export interface Signed {
  accountId: string; // canonical lowercase Crockford form
  device: string; // "ak" or a lowercase hex device ID
  method: string;
  pathWithQuery: string;
  timestamp: number;
  signature: Uint8Array;
  body: Uint8Array; // the exact bytes sent
}

export async function verifyRequest(req: Signed, pub: Uint8Array): Promise<boolean> {
  const accountId = accountIdDecode(req.accountId);
  const device = req.device === "ak" ? str("ak") : hexDecode(req.device, 16);
  if (!accountId || !device) return false;
  const msg = await requestMessage(accountId, device, req.method, req.pathWithQuery, req.timestamp, req.body);
  return ed25519Verify(pub, req.signature, msg);
}

// Message under a slot's ak_sig (contract §2.2, vectors slot.json).
export function slotSigMessage(accountId: Uint8Array, slotId: string, version: number, slotBytes: Uint8Array): Uint8Array {
  return canon("hort/v4/slot-sig\n", accountId, str(slotId), u64(version), slotBytes);
}

// Structural check of a passphrase slot:
// canon("hort/v4/slot-bytes\n", canon("hort/v4/argon\n", salt[32], u32 t, u32 m, u8 p), wrap_nonce[12], wrapped_vk[48]).
export function isPassphraseSlotBytes(bytes: Uint8Array): boolean {
  const outer = uncanon("hort/v4/slot-bytes\n", bytes, 3);
  if (!outer || outer[1].length !== 12 || outer[2].length !== 48) return false;
  const argon = uncanon("hort/v4/argon\n", outer[0], 4);
  return !!argon && argon[0].length === 32 && argon[1].length === 4 && argon[2].length === 4 && argon[3].length === 1;
}

// Structural check of a passkey slot whose slot_params name credHash
// (spec/vectors/passkey-slot.json): slot_params = canon("hort/v4/passkey\n", cred_hash).
export function isPasskeySlotBytes(bytes: Uint8Array, credHash: Uint8Array): boolean {
  const outer = uncanon("hort/v4/slot-bytes\n", bytes, 3);
  if (!outer || outer[1].length !== 12 || outer[2].length !== 48) return false;
  const params = uncanon("hort/v4/passkey\n", outer[0], 1);
  return !!params && params[0].length === credHash.length && params[0].every((x, i) => x === credHash[i]);
}
