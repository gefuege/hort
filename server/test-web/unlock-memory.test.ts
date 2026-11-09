// The vault key kept in browser storage, wrapped with the session's unlock key.
import { describe, expect, it } from "vitest";
import { b64Decode, b64Encode } from "../src/wire";
import { accountIdEncode } from "../web/vault-core";
import { dropUnlock, LOCK_KEY, LOCK_TTL, lockSetting, setLockSetting, storedUnlock, storeUnlock, UNLOCK_KEY, unwrapVaultKey, wrapVaultKey } from "../web/unlock-memory";

const memory = () => {
  const m = new Map<string, string>();
  return Object.assign(m, { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) });
};
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

describe("unlock memory", () => {
  it("round-trips the vault key, zeroes K and stores no plaintext", async () => {
    const account = random(16);
    const vk = random(32);
    const k = random(32);
    const kCopy = k.slice();
    const w = await wrapVaultKey(k, account, vk);
    expect(k.every((b) => b === 0)).toBe(true);
    expect(w.account).toBe(accountIdEncode(account));
    expect(JSON.stringify(w)).not.toContain(b64Encode(vk));
    expect(await unwrapVaultKey(kCopy.slice(), account, w)).toEqual(vk);
  });

  it("fails for another account, another K or a changed blob", async () => {
    const account = random(16);
    const vk = random(32);
    const k = random(32);
    const w = await wrapVaultKey(k.slice(), account, vk);
    await expect(unwrapVaultKey(k.slice(), random(16), w)).rejects.toThrow();
    await expect(unwrapVaultKey(random(32), account, w)).rejects.toThrow();
    const ct = b64Decode(w.ct)!;
    ct[0] ^= 1;
    await expect(unwrapVaultKey(k.slice(), account, { ...w, ct: b64Encode(ct) })).rejects.toThrow();
  });

  it("stores, reads and drops the blob, and defaults the lock time to 1 h", async () => {
    const store = memory();
    expect(lockSetting(store)).toBe("1h");
    setLockSetting("immediately", store);
    expect(lockSetting(store)).toBe("immediately");
    setLockSetting("1w", store);
    expect(lockSetting(store)).toBe("1w");
    expect(LOCK_TTL["1w"]).toBe(604800);
    store.set(LOCK_KEY, "forever");
    expect(lockSetting(store)).toBe("1h");

    expect(storedUnlock(store)).toBeNull();
    const w = await wrapVaultKey(random(32), random(16), random(32));
    storeUnlock(w, store);
    expect(storedUnlock(store)).toEqual(w);
    // A blob stored before the lock time slid still opens; its expires_at is ignored.
    store.set(UNLOCK_KEY, JSON.stringify({ ...w, expires_at: 1 }));
    expect(storedUnlock(store)).toEqual(w);
    store.set(UNLOCK_KEY, "{not json");
    expect(storedUnlock(store)).toBeNull();
    storeUnlock(w, store);
    dropUnlock(store);
    expect(store.has(UNLOCK_KEY)).toBe(false);
  });
});
