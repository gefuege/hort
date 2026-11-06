import { DurableObject } from "cloudflare:workers";
import { b64urlEncode } from "./wire";

// WebAuthn challenges (contract §5.4, §6.5): one instance per challenge, five
// minutes, consumed once. A discoverable login starts before the account is
// known, so challenges cannot live in the account DO. The binding names what
// the challenge may be used for: "login" or "register:<account ID>" for the
// account whose AK signed the options request.
const TTL_MS = 5 * 60 * 1000;

export class Challenge extends DurableObject {
  issue(binding: string): void {
    const expires = Date.now() + TTL_MS;
    this.ctx.storage.kv.put("c", { binding, expires });
    this.ctx.storage.setAlarm(expires);
  }

  consume(binding: string): boolean {
    const c = this.ctx.storage.kv.get<{ binding: string; expires: number }>("c");
    if (!c) return false;
    this.ctx.storage.kv.delete("c");
    return c.binding === binding && Date.now() < c.expires;
  }

  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

const stub = (env: Env, challenge: string) => env.CHALLENGE.jurisdiction("eu").getByName(challenge);

export async function issueChallenge(env: Env, binding: string): Promise<string> {
  const challenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  await stub(env, challenge).issue(binding);
  return challenge;
}

export async function consumeChallenge(env: Env, challenge: string, binding: string): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) return false;
  return stub(env, challenge).consume(binding);
}
