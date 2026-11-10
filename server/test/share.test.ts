// Shares by link (README "Shares"): owner endpoints, recipient endpoints,
// tries, end states, expiry and limits.
import { env, exports } from "cloudflare:workers";
import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Share as SharePointer } from "../src/share";
import { b64Encode, hexEncode, sha256 } from "../src/wire";
import { call, created, random, randomFixture, randomIp, type Fixture } from "./helpers";
import { session, sessionFetch } from "./passkey";

const GONE = "this link no longer opens\n";

type Share = { id: string; token: Uint8Array; body: Record<string, unknown> };

async function newShare(over: Record<string, unknown> = {}): Promise<Share> {
  const id = hexEncode(random(16));
  const token = random(32);
  const body = { id, expires_in: 86400, ct: b64Encode(random(200)), meta_ct: b64Encode(random(60)), token_hash: b64Encode(await sha256(token)), ...over };
  return { id, token, body };
}

const create = (f: Fixture, body: unknown) =>
  call({ account: f.account, device: f.deviceId, key: f.device, method: "POST", path: "/api/v1/shares", body: JSON.stringify(body) });
const list = async (f: Fixture) => {
  const res = await call({ account: f.account, device: f.deviceId, key: f.device, method: "GET", path: "/api/v1/shares" });
  expect(res.status).toBe(200);
  return ((await res.json()) as { shares: { id: string; state: string; meta_ct: string; created_at: number; expires_at: number }[] }).shares;
};
const revoke = (f: Fixture, id: string) =>
  call({ account: f.account, device: f.deviceId, key: f.device, method: "POST", path: `/api/v1/shares/${id}/revoke` });
const open = (id: string, token: Uint8Array, ip = randomIp()) =>
  exports.default.fetch(new Request(`https://hort.test/api/v1/shares/${id}/open`, { method: "POST", headers: { "Hort-Share-Token": b64Encode(token), "CF-Connecting-IP": ip } }));
const take = (id: string, token: Uint8Array, ip = randomIp()) =>
  exports.default.fetch(new Request(`https://hort.test/api/v1/shares/${id}`, { method: "DELETE", headers: { "Hort-Share-Token": b64Encode(token), "CF-Connecting-IP": ip } }));
const stored = (f: Fixture, id: string) =>
  runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) => ({
    record: state.storage.kv.get<{ state: string; tries: number }>(`share:${id}`),
    ct: state.storage.kv.get(`share-ct:${id}`),
  }));

async function expectGone(res: Response) {
  expect(res.status).toBe(404);
  expect(await res.text()).toBe(GONE);
}

async function openShare(): Promise<{ f: Fixture; s: Share }> {
  const f = await created(await randomFixture());
  const s = await newShare();
  expect((await create(f, s.body)).status).toBe(201);
  return { f, s };
}

describe("shares", () => {
  afterEach(() => vi.useRealTimers());

  it("creates, lists and opens a share with the right token; the answer names no account", async () => {
    const { f, s } = await openShare();
    const [row] = await list(f);
    expect(row).toMatchObject({ id: s.id, state: "open", meta_ct: s.body.meta_ct });
    expect(row.expires_at - row.created_at).toBe(86400);
    const res = await open(s.id, s.token);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ ct: s.body.ct });
    expect(text).not.toContain(f.account);
    expect([...res.headers.values()].join(" ")).not.toContain(f.account);
    // Opening does not end the share.
    expect((await open(s.id, s.token)).status).toBe(200);
  });

  it("creates with a session only with Hort-CSRF and the site origin", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const s = await newShare();
    expect((await sessionFetch(cookie, "POST", "/api/v1/shares", s.body, { "Hort-CSRF": "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "POST", "/api/v1/shares", s.body, { Origin: "https://evil.test" })).status).toBe(403);
    expect((await sessionFetch(cookie, "POST", "/api/v1/shares", s.body)).status).toBe(201);
    const res = await sessionFetch(cookie, "GET", "/api/v1/shares");
    expect(((await res.json()) as { shares: { id: string }[] }).shares.map((x) => x.id)).toEqual([s.id]);
    const revokePath = `/api/v1/shares/${s.id}/revoke`;
    expect((await sessionFetch(cookie, "POST", revokePath, undefined, { "Hort-CSRF": "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "POST", revokePath, undefined, { Origin: "https://evil.test" })).status).toBe(403);
    expect((await stored(f, s.id)).record?.state).toBe("open");
    expect((await sessionFetch(cookie, "POST", revokePath)).status).toBe(200);
  });

  it("treats a replay of create as idempotent, also after the share ended, and refuses other content", async () => {
    const { f, s } = await openShare();
    const replay = await create(f, s.body);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toMatchObject({ state: "open" });
    expect((await create(f, { ...s.body, meta_ct: b64Encode(random(60)) })).status).toBe(409);
    expect((await take(s.id, s.token)).status).toBe(204);
    const after = await create(f, s.body);
    expect(after.status).toBe(200);
    expect(await after.json()).toMatchObject({ state: "taken" });
    expect((await stored(f, s.id)).ct).toBeUndefined();
    await expectGone(await open(s.id, s.token));
  });

  it("refuses another account's create under a taken share ID", async () => {
    const { s } = await openShare();
    const g = await created(await randomFixture());
    const res = await create(g, s.body);
    expect(res.status).toBe(409);
    expect(await list(g)).toEqual([]);
  });

  it("lets only the owning account list and revoke", async () => {
    const { f, s } = await openShare();
    const g = await created(await randomFixture());
    expect(await list(g)).toEqual([]);
    expect((await revoke(g, s.id)).status).toBe(404);
    expect((await list(f))[0].state).toBe("open");
    expect((await open(s.id, s.token)).status).toBe(200);
  });

  it("counts wrong tokens and destroys the share at the fifth, deleting the ciphertext", async () => {
    const { f, s } = await openShare();
    const wrong = random(32);
    for (let left = 4; left >= 1; left--) {
      const res = left % 2 ? await take(s.id, wrong) : await open(s.id, wrong);
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ tries_left: left });
    }
    expect((await stored(f, s.id)).record?.tries).toBe(4);
    await expectGone(await open(s.id, wrong));
    expect(await stored(f, s.id)).toEqual({ record: expect.objectContaining({ state: "destroyed" }), ct: undefined });
    await expectGone(await open(s.id, s.token));
    expect((await list(f))[0].state).toBe("destroyed");
    expect((await revoke(f, s.id)).status).toBe(409);
  });

  it("counts concurrent wrong tokens atomically", async () => {
    const { f, s } = await openShare();
    const results = await Promise.all(Array.from({ length: 8 }, () => open(s.id, random(32))));
    expect(results.filter((r) => r.status === 403)).toHaveLength(4);
    expect(results.filter((r) => r.status === 404)).toHaveLength(4);
    expect((await stored(f, s.id)).record?.state).toBe("destroyed");
  });

  it("takes a share: the ciphertext is deleted and the owner sees taken", async () => {
    const { f, s } = await openShare();
    expect((await take(s.id, s.token)).status).toBe(204);
    expect(await stored(f, s.id)).toEqual({ record: expect.objectContaining({ state: "taken" }), ct: undefined });
    await expectGone(await open(s.id, s.token));
    await expectGone(await take(s.id, s.token));
    expect((await list(f))[0].state).toBe("taken");
    expect((await revoke(f, s.id)).status).toBe(409);
  });

  it("revokes idempotently and deletes the ciphertext", async () => {
    const { f, s } = await openShare();
    for (let i = 0; i < 2; i++) {
      const res = await revoke(f, s.id);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ state: "revoked" });
    }
    expect(await stored(f, s.id)).toEqual({ record: expect.objectContaining({ state: "revoked" }), ct: undefined });
    await expectGone(await open(s.id, s.token));
    expect((await revoke(f, "0".repeat(32))).status).toBe(404);
  });

  it("answers unknown, malformed, ended and expired shares identically", async () => {
    const answers: Response[] = [await open(hexEncode(random(16)), random(32)), await open("not-an-id", random(32)), await take(hexEncode(random(16)), random(32))];
    const taken = await openShare();
    await take(taken.s.id, taken.s.token);
    answers.push(await open(taken.s.id, taken.s.token));
    const revoked = await openShare();
    await revoke(revoked.f, revoked.s.id);
    answers.push(await open(revoked.s.id, revoked.s.token));
    const destroyed = await openShare();
    for (let i = 0; i < 5; i++) await open(destroyed.s.id, random(32));
    answers.push(await open(destroyed.s.id, destroyed.s.token));
    const expired = await openShare();
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 86400 * 1000 });
    answers.push(await open(expired.s.id, expired.s.token));
    for (const res of answers) {
      expect(res.status).toBe(404);
      expect(await res.text()).toBe(GONE);
      expect([...res.headers].sort()).toEqual([...answers[0].headers].sort());
    }
  });

  it("expires: the share is gone for the recipient and the owner, and the alarm deletes everything", async () => {
    const { f, s } = await openShare();
    const ended = await newShare({ expires_in: 3600 });
    expect((await create(f, ended.body)).status).toBe(201);
    await revoke(f, ended.id);
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 3600 * 1000 });
    expect((await list(f)).map((x) => x.id)).toEqual([s.id]);
    expect(await stored(f, ended.id)).toEqual({ record: undefined, ct: undefined });
    vi.setSystemTime(Date.now() + 23 * 3600 * 1000);
    expect(await runDurableObjectAlarm(env.SHARE.getByName(s.id))).toBe(true);
    expect(await stored(f, s.id)).toEqual({ record: undefined, ct: undefined });
    expect(await runInDurableObject(env.SHARE.getByName(s.id), (_i, state) => [...state.storage.kv.list()])).toEqual([]);
    await expectGone(await open(s.id, s.token));
    expect(await list(f)).toEqual([]);
  });

  it("deletes the share at its alarm even when the account DO's clock has not reached the expiry", async () => {
    const { f, s } = await openShare();
    // Date is not advanced: the account DO sees the share as unexpired.
    expect(await runDurableObjectAlarm(env.SHARE.getByName(s.id))).toBe(true);
    expect(await stored(f, s.id)).toEqual({ record: undefined, ct: undefined });
    await expectGone(await open(s.id, s.token));
    expect(await list(f)).toEqual([]);
  });

  it("keeps the expiry of an earlier bind when a create under the same ID is retried", async () => {
    const f = await created(await randomFixture());
    const s = await newShare();
    // A first attempt bound the pointer and then failed before the insert.
    const first = Math.floor(Date.now() / 1000) + 3600;
    await runInDurableObject(env.SHARE.getByName(s.id), (share: SharePointer) => share.bind(s.id, f.account, first));
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 600 * 1000 });
    const res = await create(f, s.body);
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ state: "open", expires_at: first });
    expect((await list(f))[0].expires_at).toBe(first);
    vi.setSystemTime(first * 1000);
    await expectGone(await open(s.id, s.token));
    expect(await runDurableObjectAlarm(env.SHARE.getByName(s.id))).toBe(true);
    expect(await stored(f, s.id)).toEqual({ record: undefined, ct: undefined });
  });

  it("refuses a create under an expired pointer that the alarm has not deleted yet", async () => {
    const f = await created(await randomFixture());
    const s = await newShare();
    const first = Math.floor(Date.now() / 1000) + 3600;
    await runInDurableObject(env.SHARE.getByName(s.id), (share: SharePointer) => share.bind(s.id, f.account, first));
    vi.useFakeTimers({ toFake: ["Date"], now: first * 1000 });
    expect((await create(f, s.body)).status).toBe(409);
    expect(await stored(f, s.id)).toEqual({ record: undefined, ct: undefined });
  });

  it("allows 50 open shares; ended shares free the slot and a replay still answers", async () => {
    const f = await created(await randomFixture());
    const shares: Share[] = [];
    for (let i = 0; i < 50; i++) {
      const s = await newShare();
      shares.push(s);
      expect((await create(f, s.body)).status).toBe(201);
    }
    const extra = await newShare();
    expect((await create(f, extra.body)).status).toBe(429);
    expect((await create(f, shares[0].body)).status).toBe(200);
    await revoke(f, shares[0].id);
    expect((await create(f, extra.body)).status).toBe(201);
  }, 60_000);

  it("validates create bodies: expiry, sizes and the token hash", async () => {
    const f = await created(await randomFixture());
    for (const over of [
      { expires_in: 7200 },
      { expires_in: "86400" },
      { ct: b64Encode(new Uint8Array(64 * 1024 + 1)) },
      { ct: b64Encode(random(27)) },
      { meta_ct: b64Encode(random(16 * 1024 + 1)) },
      { token_hash: b64Encode(random(31)) },
      { id: "ABCDEF".padEnd(32, "0") },
    ]) {
      const s = await newShare(over);
      expect((await create(f, s.body)).status, JSON.stringify(Object.keys(over))).toBe(400);
    }
    const { id: _id, ...missing } = (await newShare()).body;
    expect((await create(f, missing)).status).toBe(400);
    for (const expires_in of [3600, 86400, 604800]) expect((await create(f, (await newShare({ expires_in })).body)).status).toBe(201);
    expect((await create(f, (await newShare({ ct: b64Encode(random(64 * 1024)) })).body)).status).toBe(201);
    expect(await list(f)).toHaveLength(4);
  });

  it("requires a device signature or a session for owner endpoints", async () => {
    const { f, s } = await openShare();
    const anon = await exports.default.fetch(new Request("https://hort.test/api/v1/shares", { headers: { "CF-Connecting-IP": randomIp() } }));
    expect(anon.status).toBe(401);
    const ak = await call({ account: f.account, device: "ak", key: f.ak, method: "POST", path: `/api/v1/shares/${s.id}/revoke` });
    expect(ak.status).toBe(401);
  });

  it("rejects a missing or malformed token before any lookup", async () => {
    const { s } = await openShare();
    const res = await exports.default.fetch(new Request(`https://hort.test/api/v1/shares/${s.id}/open`, { method: "POST", headers: { "CF-Connecting-IP": randomIp() } }));
    expect(res.status).toBe(400);
    expect((await open(s.id, random(31))).status).toBe(400);
    expect((await exports.default.fetch(new Request(`https://hort.test/api/v1/shares/${s.id}/open`, { method: "GET" }))).status).toBe(405);
  });

  it("limits recipient calls to 30 per minute per IP", async () => {
    const ip = randomIp();
    for (let i = 0; i < 30; i++) expect((await open(hexEncode(random(16)), random(32), ip)).status).toBe(404);
    const limited = await take(hexEncode(random(16)), random(32), ip);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toBeTruthy();
  });
});
