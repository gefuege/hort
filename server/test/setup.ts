import { env } from "cloudflare:workers";

// Local workerd throws "Jurisdiction restrictions are not implemented" for
// namespace.jurisdiction(). Production code always calls jurisdiction("eu");
// the tests record each call and continue on the plain namespace.
export const jurisdictionCalls: string[] = [];

for (const ns of [env.ACCOUNT, env.RATE_LIMITER, env.CHALLENGE]) {
  Object.getPrototypeOf(ns).jurisdiction = function (this: DurableObjectNamespace, j: string) {
    jurisdictionCalls.push(j);
    return this;
  };
}
