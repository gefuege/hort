// Keeps an unlocked vault across reloads and new tabs for the lock time the
// user picks, counted from the last use. Browser storage holds the vault key
// only wrapped with the session's unlock key K, which the server hands out
// while the session and K are valid (GET /api/v1/session/unlock-key). The
// server alone tracks when K expires: each session request moves it. The server never sees the vault
// key; the stored blob alone and K alone open nothing. Every storage access is
// guarded: without usable storage the vault locks on reload as before.
import { b64Decode, b64Encode, concat, str } from "../src/wire";
import { accountIdEncode } from "./vault-core";

export const LOCK_KEY = "hort.lock";
export const UNLOCK_KEY = "hort.unlock";

export const LOCK_CHOICES = ["immediately", "15m", "1h", "8h", "1w"] as const;
export type LockAfter = (typeof LOCK_CHOICES)[number];
export const LOCK_TTL: Record<Exclude<LockAfter, "immediately">, number> = { "15m": 900, "1h": 3600, "8h": 28800, "1w": 604800 };
export const LOCK_LABEL: Record<LockAfter, string> = {
  immediately: "immediately",
  "15m": "after 15 min idle",
  "1h": "after 1 h idle",
  "8h": "after 8 h idle",
  "1w": "after 1 week idle",
};

// The vault key wrapped with K: AES-256-GCM, AAD = "hort/web/unlock\n" || account ID.
export type WrappedUnlock = { account: string; nonce: string; ct: string };

type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function browserStore(): Store | null {
  try {
    return localStorage;
  } catch {
    return null;
  }
}

export function lockSetting(store: Store | null = browserStore()): LockAfter {
  try {
    const v = store?.getItem(LOCK_KEY);
    return (LOCK_CHOICES as readonly string[]).includes(v ?? "") ? (v as LockAfter) : "1h";
  } catch {
    return "1h";
  }
}

export function setLockSetting(choice: LockAfter, store: Store | null = browserStore()): void {
  try {
    store?.setItem(LOCK_KEY, choice);
  } catch {
    // the choice holds for this page only
  }
}

const aad = (accountId: Uint8Array) => concat([str("hort/web/unlock\n"), accountId]);

// Imports K as a non-extractable key and zeroes the given bytes.
async function importK(k: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey("raw", k as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
  } finally {
    k.fill(0);
  }
}

export async function wrapVaultKey(k: Uint8Array, accountId: Uint8Array, vk: Uint8Array): Promise<WrappedUnlock> {
  const key = await importK(k);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad(accountId) as BufferSource }, key, vk as BufferSource));
  return { account: accountIdEncode(accountId), nonce: b64Encode(nonce), ct: b64Encode(ct) };
}

// Throws when K, the account or the blob do not match.
export async function unwrapVaultKey(k: Uint8Array, accountId: Uint8Array, w: WrappedUnlock): Promise<Uint8Array> {
  const key = await importK(k);
  const nonce = b64Decode(w.nonce);
  const ct = b64Decode(w.ct);
  if (!nonce || nonce.length !== 12 || !ct) throw new Error("stored unlock is malformed");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad(accountId) as BufferSource }, key, ct as BufferSource));
}

export function storedUnlock(store: Store | null = browserStore()): WrappedUnlock | null {
  try {
    const v = JSON.parse(store?.getItem(UNLOCK_KEY) ?? "null") as WrappedUnlock | null;
    return v && typeof v.account === "string" && typeof v.nonce === "string" && typeof v.ct === "string" ? { account: v.account, nonce: v.nonce, ct: v.ct } : null;
  } catch {
    return null;
  }
}

export function storeUnlock(w: WrappedUnlock, store: Store | null = browserStore()): void {
  try {
    store?.setItem(UNLOCK_KEY, JSON.stringify(w));
  } catch {
    // the vault locks on reload
  }
}

export function dropUnlock(store: Store | null = browserStore()): void {
  try {
    store?.removeItem(UNLOCK_KEY);
  } catch {
    // nothing stored
  }
}
