// Passkey registration and login (contract §5.4, §6.3) and the session
// branches of the devices and requests endpoints (§5.5).
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { accountIdDecode, b64Decode, b64Encode, hexEncode, sha256, uncanon } from "../src/wire";
import { call, created, enroll, listDevices, newKey, random, randomFixture, randomIp, type Fixture } from "./helpers";
import {
  Authenticator,
  cookieOf,
  kekFromPRF,
  login,
  loginChallenge,
  passkeySlot,
  post,
  registerOptions,
  registerPasskey,
  registerVerify,
  session,
  sessionFetch,
} from "./passkey";

afterEach(() => vi.useRealTimers());

type LoginBody = { account_id: string; ak_pub: string; credential_id: string; slot: { id: string; version: number; bytes: string; ak_sig: string } | null };
type Listing = { passkeys: { id: string; prf: boolean; revoked_at: number | null; last_used_at: number | null }[]; devices: { id: string; revoked_at: number | null }[]; devices_version: number; last_visit_at?: number | null };

const passkeyId = async (a: Authenticator) => hexEncode(await sha256(a.credentialId));

describe("passkey registration", () => {
  it("stores a PRF passkey with its slot; login returns the slot and the PRF output unwraps VK", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create();
    const prf = random(32);
    const vk = random(32);
    const slot = await passkeySlot(f, a, prf, vk);
    const res = await registerPasskey(f, a, slot.json);
    expect(res.status, await res.clone().text()).toBe(201);
    expect(await res.json()).toEqual({ id: await passkeyId(a), prf: true, devices_version: 2 });

    const signedIn = await login(f, a);
    expect(signedIn.status, await signedIn.clone().text()).toBe(200);
    const body = (await signedIn.json()) as LoginBody;
    expect(body).toEqual({ account_id: f.account, ak_pub: b64Encode(f.ak.pub), credential_id: a.id, slot: { id: slot.slotId, ...slot.json } });

    // The browser side: KEK from PRF, unwrap with the slot AAD (vault-core does this in test-web).
    const bytes = b64Decode(body.slot!.bytes)!;
    const [params, nonce, wrapped] = uncanon("hort/v4/slot-bytes\n", bytes, 3)!;
    const { canon, str, u64 } = await import("../src/wire");
    const aad = canon("hort/v4/slot\n", accountIdDecode(f.account)!, str(body.slot!.id), u64(body.slot!.version), params);
    const kek = await kekFromPRF(prf, accountIdDecode(f.account)!);
    const opened = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, kek, wrapped));
    expect(hexEncode(opened)).toBe(hexEncode(vk));
  });

  it("stores a passkey without PRF for sign-in only; login returns no slot", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create();
    const res = await registerPasskey(f, a);
    expect(await res.json()).toMatchObject({ prf: false });
    const body = (await (await login(f, a)).json()) as LoginBody;
    expect(body.slot).toBeNull();
    const listing = (await (await listDevices(f)).json()) as Listing;
    expect(listing.passkeys).toEqual([expect.objectContaining({ id: await passkeyId(a), prf: false, revoked_at: null })]);
  });

  it("requires the AK signature for options and verify", async () => {
    const f = await created(await randomFixture());
    const other = await newKey();
    expect((await registerOptions(f, other)).status).toBe(401);
    const options = (await (await registerOptions(f)).json()) as { challenge: string; user: { id: string }; authenticatorSelection: unknown };
    expect(options.user.id).toBe(b64Encode(accountIdDecode(f.account)!).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
    expect(options.authenticatorSelection).toEqual({ residentKey: "required", requireResidentKey: true, userVerification: "required" });
    const a = await Authenticator.create();
    expect((await registerVerify(f, { response: await a.register(options.challenge), slot: null }, other)).status).toBe(401);
    const byDevice = await call({ account: f.account, device: f.deviceId, key: f.device, method: "POST", path: "/api/v1/webauthn/register/options" });
    expect(byDevice.status).toBe(401);
  });

  it("binds the challenge to the account and to one use, and expires it after 5 minutes", async () => {
    const f = await created(await randomFixture());
    const g = await created(await randomFixture());
    const a = await Authenticator.create();
    const { challenge } = (await (await registerOptions(g)).json()) as { challenge: string };
    expect((await registerVerify(f, { response: await a.register(challenge), slot: null })).status).toBe(400);
    // Consumed by the failed attempt; g cannot use it either.
    expect((await registerVerify(g, { response: await a.register(challenge), slot: null })).status).toBe(400);

    const fresh = (await (await registerOptions(f)).json()) as { challenge: string };
    vi.useFakeTimers({ now: Date.now() + 5 * 60 * 1000 + 1000, toFake: ["Date"] });
    expect((await registerVerify(f, { response: await a.register(fresh.challenge), slot: null })).status).toBe(400);
    vi.useRealTimers();
    expect((await registerPasskey(f, a)).status).toBe(201);
  });

  it("rejects a wrong origin, a missing user verification and a slot that is not this credential's", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create();
    const challenge = async () => ((await (await registerOptions(f)).json()) as { challenge: string }).challenge;
    expect((await registerVerify(f, { response: await a.register(await challenge(), { origin: "https://evil.test" }), slot: null })).status).toBe(400);
    expect((await registerVerify(f, { response: await a.register(await challenge(), { uv: false }), slot: null })).status).toBe(400);

    const otherCred = await Authenticator.create();
    const foreign = await passkeySlot(f, otherCred, random(32), random(32));
    const res = await registerVerify(f, { response: await a.register(await challenge()), slot: foreign.json });
    expect(res.status).toBe(400);
    expect(await res.text()).toMatch(/passkey slot encoding/);
    const ownSlot = await passkeySlot(f, a, random(32), random(32));
    const badSig = { ...ownSlot.json, ak_sig: b64Encode(random(64)) };
    expect((await registerVerify(f, { response: await a.register(await challenge()), slot: badSig })).status).toBe(400);
    const badVersion = { ...ownSlot.json, version: 2 }; // ak_sig covers version 1
    expect((await registerVerify(f, { response: await a.register(await challenge()), slot: badVersion })).status).toBe(400);
    expect((await (await listDevices(f)).json() as Listing).passkeys).toEqual([]);
  });

  it("refuses the same credential twice and caps active passkeys at 10", async () => {
    const f = await created(await randomFixture());
    const first = await Authenticator.create();
    expect((await registerPasskey(f, first)).status).toBe(201);
    expect((await registerPasskey(f, first)).status).toBe(409);
    for (let i = 1; i < 10; i++) expect((await registerPasskey(f, await Authenticator.create())).status).toBe(201);
    expect((await registerOptions(f)).status).toBe(429);
    // Revoking one frees a place.
    const cookie = await (async () => cookieOf(await login(f, first)))();
    expect((await sessionFetch(cookie, "DELETE", `/api/v1/devices/${await passkeyId(first)}`)).status).toBe(200);
    expect((await registerPasskey(f, await Authenticator.create())).status).toBe(201);
  });
});

const DAY = 24 * 60 * 60 * 1000;

describe("passkey login", () => {
  it("sets the __Host-hort session cookie with the contract attributes", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create();
    await registerPasskey(f, a);
    const res = await login(f, a);
    const cookie = res.headers.get("Set-Cookie")!;
    expect(cookie).toMatch(new RegExp(`^__Host-hort=${f.account}\\.[A-Za-z0-9_-]{43}; Max-Age=2592000; Path=/; Secure; HttpOnly; SameSite=Strict$`));
    const listing = (await (await sessionFetch(cookieOf(res), "GET", "/api/v1/devices")).json()) as Listing;
    expect(listing.passkeys[0].last_used_at).toBeTypeOf("number");
    // The DO keeps only the token hash.
    const token = cookieOf(res).split(".")[1];
    const stored = await runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) =>
      state.storage.sql.exec<{ token_hash: string }>("SELECT token_hash FROM sessions").toArray());
    expect(stored.map((r) => r.token_hash)).not.toContain(token);
    expect(stored).toHaveLength(1);
  });

  it("refuses a replayed assertion, an expired challenge, a wrong origin, missing UV and an unknown passkey", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create();
    await registerPasskey(f, a);
    const handle = accountIdDecode(f.account)!;
    const assertion = await a.assert(await loginChallenge(), handle);
    expect((await post("/api/v1/webauthn/login/verify", assertion)).status).toBe(200);
    expect((await post("/api/v1/webauthn/login/verify", assertion)).status).toBe(401);

    const late = await a.assert(await loginChallenge(), handle);
    vi.useFakeTimers({ now: Date.now() + 5 * 60 * 1000 + 1000, toFake: ["Date"] });
    expect((await post("/api/v1/webauthn/login/verify", late)).status).toBe(401);
    vi.useRealTimers();

    expect((await login(f, a, { origin: "https://evil.test" })).status).toBe(401);
    expect((await login(f, a, { uv: false })).status).toBe(401);
    expect((await login(f, await Authenticator.create())).status).toBe(401);
    // A register challenge does not sign in.
    const { challenge } = (await (await registerOptions(f)).json()) as { challenge: string };
    expect((await post("/api/v1/webauthn/login/verify", await a.assert(challenge, handle))).status).toBe(401);
  });

  it("requires an increasing signature counter once the authenticator uses one", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create(5);
    await registerPasskey(f, a);
    expect((await login(f, a, { counter: 6 })).status).toBe(200);
    expect((await login(f, a, { counter: 6 })).status).toBe(401);
    expect((await login(f, a, { counter: 3 })).status).toBe(401);
    expect((await login(f, a, { counter: 7 })).status).toBe(200);
  });

  it("limits login calls to 30 per minute per IP", async () => {
    const ip = randomIp();
    for (let i = 0; i < 30; i++) expect((await post("/api/v1/webauthn/login/options", undefined, {}, ip)).status).toBe(200);
    const res = await post("/api/v1/webauthn/login/options", undefined, {}, ip);
    expect(res.status).toBe(429);
    expect((await post("/api/v1/webauthn/login/verify", {}, {}, ip)).status).toBe(429);
  });

  it("signs out: the session ends and the cookie is cleared", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    expect((await sessionFetch(cookie, "DELETE", "/api/v1/session", undefined, { "Hort-CSRF": "" })).status).toBe(403);
    const res = await sessionFetch(cookie, "DELETE", "/api/v1/session");
    expect(res.status).toBe(204);
    expect(res.headers.get("Set-Cookie")).toBe("__Host-hort=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict");
    expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status).toBe(401);
  });

  it("does not accept a session token for another account or a session that expired", async () => {
    const f = await created(await randomFixture());
    const g = await created(await randomFixture());
    const cookie = await session(f);
    const forged = cookie.replace(f.account, g.account);
    expect((await sessionFetch(forged, "GET", "/api/v1/devices")).status).toBe(401);
    vi.useFakeTimers({ now: Date.now() + 7 * DAY + 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status).toBe(401);
  });

  it("slides the session 7 days from each use, at most 30 days after sign-in", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const start = Date.now();
    // Used every 6 days: still valid on day 24, well past the first 7 days.
    for (const day of [6, 12, 18, 24]) {
      vi.useFakeTimers({ now: start + day * DAY, toFake: ["Date"] });
      expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status, `day ${day}`).toBe(200);
    }
    vi.useFakeTimers({ now: start + 30 * DAY - 5000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status).toBe(200);
    // Continuous use does not pass the 30-day cap.
    vi.useFakeTimers({ now: start + 30 * DAY + 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status).toBe(401);
  });
});

describe("session branches", () => {
  it("lists devices and passkeys with the previous visit time", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const first = (await (await sessionFetch(cookie, "GET", "/api/v1/devices")).json()) as Listing;
    expect(first.last_visit_at).toBeNull();
    expect(first.devices.map((d) => d.id)).toEqual([f.deviceId]);
    expect(first.passkeys).toHaveLength(1);
    const second = (await (await sessionFetch(cookie, "GET", "/api/v1/devices")).json()) as Listing;
    expect(second.last_visit_at).toBeTypeOf("number");
    // A device-signed listing carries no visit marker.
    expect((await (await listDevices(f)).json()) as Listing).not.toHaveProperty("last_visit_at");
  });

  it("revokes a device and a passkey with Hort-CSRF and the site origin only", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create();
    const prfSlot = await passkeySlot(f, a, random(32), random(32));
    expect((await registerPasskey(f, a, prfSlot.json)).status).toBe(201);
    const cookie = cookieOf(await login(f, a));
    const other = await enroll(f);
    const path = `/api/v1/devices/${other.id}`;
    expect((await sessionFetch(cookie, "DELETE", path, undefined, { "Hort-CSRF": "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "DELETE", path, undefined, { Origin: "https://evil.test" })).status).toBe(403);
    expect((await sessionFetch(cookie, "DELETE", path, undefined, { Origin: "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "DELETE", path)).status).toBe(200);
    expect((await listDevices(f, other.id, other.key)).status).toBe(403);

    // Revoking the passkey deletes its slot and ends its sessions; it no longer signs in.
    const id = await passkeyId(a);
    expect((await sessionFetch(cookie, "DELETE", `/api/v1/devices/${id}`)).status).toBe(200);
    expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status).toBe(401);
    expect((await login(f, a)).status).toBe(401);
    const slots = await runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) =>
      state.storage.sql.exec<{ id: string }>("SELECT id FROM slots").toArray().map((r) => r.id));
    expect(slots).toEqual(["passphrase"]);
    const listing = (await (await listDevices(f)).json()) as Listing;
    expect(listing.passkeys[0]).toMatchObject({ id, prf: false });
    expect(listing.passkeys[0].revoked_at).toBeTypeOf("number");
  });

  it("reads, lists and declines requests with a session", async () => {
    const f: Fixture = await created(await randomFixture());
    const cookie = await session(f);
    const id = hexEncode(random(16));
    const metaCt = b64Encode(random(60));
    const created_ = await call({ account: f.account, device: f.deviceId, key: f.device, method: "POST", path: "/api/v1/requests", body: JSON.stringify({ id, meta_ct: metaCt }) });
    expect(created_.status).toBe(201);
    expect(await (await sessionFetch(cookie, "GET", "/api/v1/requests?status=pending")).json()).toEqual({
      requests: [{ id, meta_ct: metaCt, created_at: expect.any(Number) }],
    });
    expect(await (await sessionFetch(cookie, "GET", `/api/v1/requests/${id}`)).json()).toEqual({ status: "pending", meta_ct: metaCt, revision_ids: [] });
    expect((await sessionFetch(cookie, "POST", `/api/v1/requests/${id}/decline`, undefined, { "Hort-CSRF": "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "POST", `/api/v1/requests/${id}/decline`)).status).toBe(200);
    expect(((await (await sessionFetch(cookie, "GET", `/api/v1/requests/${id}`)).json()) as { status: string }).status).toBe("declined");
    // Without a cookie or signature the branches answer 401.
    expect((await sessionFetch("", "GET", "/api/v1/requests?status=pending")).status).toBe(401);
  });
});
