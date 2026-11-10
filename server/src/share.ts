import { DurableObject } from "cloudflare:workers";

// Where a share lives: one instance per share ID, holding only the share ID,
// the owning account ID and the expiry. A recipient knows the share ID but not
// the account, so the Worker looks the account up here and never shows it.
// The share itself (ciphertext, token hash, tries, state) lives in the account
// DO, so the try count and every state change stay one atomic step there. The
// expiry stored here is authoritative: the account DO's record copies it, and
// at that time the alarm has the account DO delete this share by ID, then
// deletes the pointer, so nothing of the share remains.
type Pointer = { share: string; account: string; expires: number };

export class Share extends DurableObject<Env> {
  // Binds the share ID to its account on first use and returns the expiry the
  // share must carry: the one already stored for this account, or expiresAt
  // for a new pointer. null when another account holds the ID or the pointer
  // has expired.
  bind(share: string, account: string, expiresAt: number): number | null {
    const p = this.ctx.storage.kv.get<Pointer>("p");
    if (p) return p.account === account && Date.now() < p.expires * 1000 ? p.expires : null;
    this.ctx.storage.kv.put("p", { share, account, expires: expiresAt });
    this.ctx.storage.setAlarm(expiresAt * 1000);
    return expiresAt;
  }

  // The owning account while the share has not expired.
  account(): string | null {
    const p = this.ctx.storage.kv.get<Pointer>("p");
    return p && Date.now() < p.expires * 1000 ? p.account : null;
  }

  async alarm(): Promise<void> {
    const p = this.ctx.storage.kv.get<Pointer>("p");
    if (p) await this.env.ACCOUNT.jurisdiction("eu").getByName(p.account).expireShare(p.share);
    await this.ctx.storage.deleteAll();
  }
}

export const shareStub = (env: Env, share: string) => env.SHARE.jurisdiction("eu").getByName(share);
