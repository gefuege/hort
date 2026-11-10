// Entry of wrangler.dev.jsonc for local integration runs of the Go CLI.
// Local workerd throws on namespace.jurisdiction(); as in test/setup.ts the
// call returns the plain namespace here, so everything except the EU
// placement runs the production Worker code unchanged.
import { env } from "cloudflare:workers";
import worker from "../src/entry";

export { Account, Challenge, Invitations, RateLimiter, Share } from "../src/entry";

for (const ns of [env.ACCOUNT, env.RATE_LIMITER, env.CHALLENGE, env.SHARE, env.INVITATIONS]) {
  Object.getPrototypeOf(ns).jurisdiction = function (this: DurableObjectNamespace) {
    return this;
  };
}

export default worker;
