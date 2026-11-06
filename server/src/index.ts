import { fail } from "./http";
import { rateLimit } from "./rate-limiter";
import { accountIdDecode, b64Decode, hexDecode, type Signed } from "./wire";

export { Account } from "./account";
export { RateLimiter } from "./rate-limiter";

// Contract §6.2 and §6.6.
const MAX_CLOCK_SKEW_SECONDS = 300;
const MAX_BODY_BYTES = 64 * 1024;

type Bindings = Env & { REGISTRATION_TOKEN?: string };

function accountStub(env: Env, accountId: string) {
  return env.ACCOUNT.jurisdiction("eu").getByName(accountId);
}

// Rate-limit key: IPv4 as is, IPv6 reduced to its /64 so rotating addresses
// inside one allocation shares a bucket. IPv4-mapped IPv6 counts as IPv4.
function clientIp(request: Request): string {
  const raw = request.headers.get("CF-Connecting-IP");
  if (!raw) return "unknown";
  const ip = raw.toLowerCase();
  if (!ip.includes(":")) return ip;
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return mapped[1];
  const [head, tail, extra] = ip.split("::");
  if (extra !== undefined) return ip;
  const groups = (part: string) => (part ? part.split(":") : []);
  const front = groups(head);
  const back = groups(tail ?? "");
  const all = tail === undefined ? front : [...front, ...Array<string>(Math.max(0, 8 - front.length - back.length)).fill("0"), ...back];
  if (all.length < 4 || all.some((g, i) => i < 4 && !/^[0-9a-f]{1,4}$/.test(g))) return ip;
  return `${all.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(":")}::/64`;
}

// Reads at most MAX_BODY_BYTES from the stream and cancels it beyond that.
async function readBody(request: Request): Promise<Uint8Array | null> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

// Stateless checks of the signature headers (contract §6.2) and reading the
// exact body bytes. Key lookup and verification happen in the account DO.
async function readSigned(request: Request, url: URL, kind: "ak" | "device"): Promise<Signed | Response> {
  const h = request.headers;
  const accountId = h.get("Hort-Account") ?? "";
  if (!accountIdDecode(accountId)) return fail(400, "invalid Hort-Account header");
  const device = h.get("Hort-Device") ?? "";
  if (kind === "ak" && device !== "ak") return fail(401, "this endpoint requires an account key signature (Hort-Device: ak)");
  if (kind === "device" && !hexDecode(device, 16)) return fail(401, "this endpoint requires a device signature");
  const ts = h.get("Hort-Timestamp") ?? "";
  if (!/^[0-9]{1,12}$/.test(ts)) return fail(400, "invalid Hort-Timestamp header");
  const timestamp = Number(ts);
  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS) {
    return fail(401, "request timestamp is more than 300 s off the server clock; check the device clock");
  }
  const signature = b64Decode(h.get("Hort-Signature") ?? "");
  if (!signature || signature.length !== 64) return fail(400, "invalid Hort-Signature header");
  if (Number(h.get("Content-Length") ?? 0) > MAX_BODY_BYTES) return fail(413, "request body exceeds 64 KiB");
  const body = await readBody(request);
  if (!body) return fail(413, "request body exceeds 64 KiB");
  return { accountId, device, method: request.method, pathWithQuery: url.pathname + url.search, timestamp, signature, body };
}

async function route(request: Request, env: Bindings): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  let m: RegExpMatchArray | null;

  if (path === "/api/v1/accounts") {
    if (method !== "POST") return fail(405, "method not allowed");
    if (env.REGISTRATION_TOKEN) {
      const token = request.headers.get("Hort-Registration-Token");
      if (!token) return fail(403, "registration is invite-only; a registration token is required");
      if (!(await constantTimeEqual(token, env.REGISTRATION_TOKEN))) return fail(403, "invalid registration token");
    }
    const req = await readSigned(request, url, "ak");
    if (req instanceof Response) return req;
    const limited = await rateLimit(env, "create", clientIp(request));
    if (limited) return limited;
    return accountStub(env, req.accountId).createAccount(req);
  }

  if ((m = path.match(/^\/api\/v1\/accounts\/([^/]+)\/slot$/))) {
    if (method !== "GET") return fail(405, "method not allowed");
    const accountId = m[1];
    if (!accountIdDecode(accountId)) return fail(404, "account not found");
    const limited = await rateLimit(env, "slot", `${clientIp(request)}:${accountId}`);
    if (limited) return limited;
    return accountStub(env, accountId).getSlot();
  }

  if (path === "/api/v1/devices") {
    if (method === "POST") {
      const req = await readSigned(request, url, "ak");
      if (req instanceof Response) return req;
      return accountStub(env, req.accountId).enrollDevice(req);
    }
    if (method === "GET") {
      const req = await readSigned(request, url, "device");
      if (req instanceof Response) return req;
      return accountStub(env, req.accountId).listDevices(req);
    }
    return fail(405, "method not allowed");
  }

  if ((m = path.match(/^\/api\/v1\/devices\/([^/]+)$/))) {
    if (method !== "DELETE") return fail(405, "method not allowed");
    const id = m[1];
    if (!hexDecode(id, 16)) return fail(404, "device not found");
    const req = await readSigned(request, url, "device");
    if (req instanceof Response) return req;
    return accountStub(env, req.accountId).revokeDevice(req, id);
  }

  if ((m = path.match(/^\/api\/v1\/slots\/([^/]+)$/))) {
    if (method !== "PUT") return fail(405, "method not allowed");
    const req = await readSigned(request, url, "ak");
    if (req instanceof Response) return req;
    return accountStub(env, req.accountId).putSlot(req, m[1]);
  }

  if (path === "/api/v1/requests") {
    if (method === "POST") {
      const req = await readSigned(request, url, "device");
      if (req instanceof Response) return req;
      return accountStub(env, req.accountId).createRequest(req);
    }
    if (method === "GET") {
      if (url.search !== "?status=pending") return fail(400, "only ?status=pending is supported");
      const req = await readSigned(request, url, "device");
      if (req instanceof Response) return req;
      return accountStub(env, req.accountId).listPendingRequests(req);
    }
    return fail(405, "method not allowed");
  }

  if ((m = path.match(/^\/api\/v1\/requests\/([^/]+)$/))) {
    if (method !== "GET") return fail(405, "method not allowed");
    if (!hexDecode(m[1], 16)) return fail(404, "request not found");
    const req = await readSigned(request, url, "device");
    if (req instanceof Response) return req;
    return accountStub(env, req.accountId).getRequest(req, m[1]);
  }

  if ((m = path.match(/^\/api\/v1\/requests\/([^/]+)\/(decline|fulfill)$/))) {
    if (method !== "POST") return fail(405, "method not allowed");
    if (!hexDecode(m[1], 16)) return fail(404, "request not found");
    // Fulfill needs a passkey session plus Hort-CSRF (contract §6.3), which S6.2 adds.
    if (m[2] === "fulfill") return fail(401, "fulfilling a request requires a passkey session");
    const req = await readSigned(request, url, "device");
    if (req instanceof Response) return req;
    return accountStub(env, req.accountId).declineRequest(req, m[1]);
  }

  return fail(404, "not found");
}

export default {
  async fetch(request, env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (err) {
      console.error(err);
      return fail(500, "internal error");
    }
  },
} satisfies ExportedHandler<Bindings>;
