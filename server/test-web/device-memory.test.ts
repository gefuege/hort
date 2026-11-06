// The account ID that a browser remembers to shorten the passkey login.
import { describe, expect, it } from "vitest";
import { accountIdEncode } from "../web/vault-core";
import { ACCOUNT_KEY, forgetDevice, rememberAccount, rememberedAccount } from "../web/device-memory";

const memory = () => {
  const m = new Map<string, string>();
  return Object.assign(m, { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) });
};
const blocked = () => {
  throw new Error("blocked");
};
const throwing = { getItem: blocked, setItem: blocked, removeItem: blocked };
const id = () => accountIdEncode(crypto.getRandomValues(new Uint8Array(16)));

describe("device memory", () => {
  it("remembers only the account ID, and a later account replaces it", () => {
    const store = memory();
    expect(rememberedAccount(store)).toBeNull();
    const first = id();
    expect(rememberAccount(first, store)).toBe(true);
    expect(accountIdEncode(rememberedAccount(store)!)).toBe(first);
    const second = id();
    rememberAccount(second, store);
    expect(accountIdEncode(rememberedAccount(store)!)).toBe(second);
    expect([...store.keys()]).toEqual([ACCOUNT_KEY]);
    expect(store.get(ACCOUNT_KEY)).toBe(second);
  });

  it("forgets the device", () => {
    const store = memory();
    rememberAccount(id(), store);
    forgetDevice(store);
    expect(rememberedAccount(store)).toBeNull();
    expect(store.size).toBe(0);
  });

  it("ignores a malformed stored value and refuses to store one", () => {
    const store = memory();
    store.set(ACCOUNT_KEY, "not-an-account");
    expect(rememberedAccount(store)).toBeNull();
    expect(rememberAccount("not-an-account", store)).toBe(false);
    expect(store.get(ACCOUNT_KEY)).toBe("not-an-account");
  });

  it("falls back quietly when storage is missing or throws", () => {
    for (const store of [null, throwing]) {
      expect(rememberedAccount(store)).toBeNull();
      expect(rememberAccount(id(), store)).toBe(false);
      expect(() => forgetDevice(store)).not.toThrow();
    }
  });
});
