// The account ID this browser remembers, which is not secret.
// The PRF eval salt depends on it, so a remembered ID lets /login evaluate the
// PRF in the first passkey prompt. The wrapped vault key is unlock-memory.ts.
// Every access is guarded: without usable storage the login takes two prompts.
import { accountIdEncode, parseAccountId } from "./vault-core";

export const ACCOUNT_KEY = "hort.account";

type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function browserStore(): Store | null {
  try {
    return localStorage;
  } catch {
    return null;
  }
}

export function rememberedAccount(store: Store | null = browserStore()): Uint8Array | null {
  try {
    const stored = store?.getItem(ACCOUNT_KEY);
    return stored ? parseAccountId(stored) : null;
  } catch {
    return null;
  }
}

// Replaces any remembered ID, so the last account that signed in wins.
export function rememberAccount(accountId: string, store: Store | null = browserStore()): boolean {
  try {
    const parsed = parseAccountId(accountId);
    if (!store || !parsed) return false;
    store.setItem(ACCOUNT_KEY, accountIdEncode(parsed));
    return true;
  } catch {
    return false;
  }
}

export function forgetDevice(store: Store | null = browserStore()): void {
  try {
    store?.removeItem(ACCOUNT_KEY);
  } catch {
    // nothing to forget
  }
}
