// The web app's unlock key per session: PUT/GET/DELETE /api/v1/session/unlock-key.
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { b64Decode, hexEncode, sha256 } from "../src/wire";
import { created, randomFixture } from "./helpers";
import { Authenticator, cookieOf, login, registerPasskey, session, sessionFetch } from "./passkey";

afterEach(() => vi.useRealTimers());

const PATH = "/api/v1/session/unlock-key";
type Key = { key: string; expires_at: number };
const nowS = () => Math.floor(Date.now() / 1000);
const DAY = 24 * 60 * 60 * 1000;
const kvKeys = (account: string) =>
  runInDurableObject(env.ACCOUNT.getByName(account), (_i, state) => [...state.storage.kv.list({ prefix: "unlock:" })].map(([k]) => k));
const tables = (account: string) =>
  runInDurableObject(env.ACCOUNT.getByName(account), (_i, state) =>
    state.storage.sql.exec<{ name: string }>("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name <> 'sqlite_sequence' ORDER BY name").toArray().map((r) => r.name));

describe("unlock key", () => {
  it("is never cached and goes with a revoked passkey", async () => {
    const f = await created(await randomFixture());
    const a = await Authenticator.create();
    expect((await registerPasskey(f, a)).status).toBe(201);
    const cookie = cookieOf(await login(f, a));
    const put = await sessionFetch(cookie, "PUT", PATH, { ttl: 3600 });
    expect(put.headers.get("Cache-Control")).toBe("no-store");
    const got = await sessionFetch(cookie, "GET", PATH);
    expect(got.status).toBe(200);
    expect(got.headers.get("Cache-Control")).toBe("no-store");

    // Revoked from a second session: the first session's key leaves storage with it.
    const other = await session(f);
    const id = hexEncode(await sha256(a.credentialId));
    expect((await sessionFetch(other, "DELETE", `/api/v1/devices/${id}`)).status).toBe(200);
    expect(await kvKeys(f.account)).toEqual([]);
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(401);
  });

  it("creates, reads, replaces and deletes the key of the session, without a schema change", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);

    const put = await sessionFetch(cookie, "PUT", PATH, { ttl: 3600 });
    expect(put.status).toBe(200);
    const first = (await put.json()) as Key;
    expect(b64Decode(first.key)!.length).toBe(32);
    expect(first.expires_at - nowS()).toBeGreaterThan(3590);
    expect(first.expires_at - nowS()).toBeLessThanOrEqual(3600);

    const got = await sessionFetch(cookie, "GET", PATH);
    expect(got.status).toBe(200);
    expect(await got.json()).toEqual(first);

    const second = (await (await sessionFetch(cookie, "PUT", PATH, { ttl: 900 })).json()) as Key;
    expect(second.key).not.toBe(first.key);
    expect(second.expires_at - nowS()).toBeLessThanOrEqual(900);
    expect(await (await sessionFetch(cookie, "GET", PATH)).json()).toEqual(second);
    expect(await kvKeys(f.account)).toHaveLength(1);

    expect((await sessionFetch(cookie, "DELETE", PATH)).status).toBe(204);
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);
    expect(await kvKeys(f.account)).toEqual([]);
    expect(await tables(f.account)).toEqual(["account", "devices", "passkeys", "requests", "revisions", "sessions", "slots"]);
  });

  it("slides with each session request and expires after the ttl without use", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const start = Date.now();
    await sessionFetch(cookie, "PUT", PATH, { ttl: 900 });
    // A session request 10 min later moves the key's end to 15 min from then.
    vi.useFakeTimers({ now: start + 600 * 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status).toBe(200);
    vi.useFakeTimers({ now: start + 1200 * 1000, toFake: ["Date"] });
    const got = (await (await sessionFetch(cookie, "GET", PATH)).json()) as Key;
    expect(got.expires_at).toBe(nowS() + 900);
    // 15 min without use: gone.
    vi.useFakeTimers({ now: start + 2101 * 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);
    expect(await kvKeys(f.account)).toEqual([]);
  });

  it("does not come back once expired", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const start = Date.now();
    await sessionFetch(cookie, "PUT", PATH, { ttl: 900 });
    vi.useFakeTimers({ now: start + 901 * 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", "/api/v1/devices")).status).toBe(200);
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);
  });

  it("offers 1 week and never outlives the session, which ends 30 days after sign-in", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const start = Date.now();
    const week = (await (await sessionFetch(cookie, "PUT", PATH, { ttl: 604800 })).json()) as Key;
    expect(week.expires_at).toBe(nowS() + 604800);
    // Used every 6 days the key lives on, but ends with the session on day 30.
    for (const day of [6, 12, 18]) {
      vi.useFakeTimers({ now: start + day * DAY, toFake: ["Date"] });
      const got = (await (await sessionFetch(cookie, "GET", PATH)).json()) as Key;
      expect(got.expires_at, `day ${day}`).toBe(nowS() + 604800);
    }
    // On day 24 a week would pass the session's end on day 30.
    vi.useFakeTimers({ now: start + 24 * DAY, toFake: ["Date"] });
    const capped = (await (await sessionFetch(cookie, "GET", PATH)).json()) as Key;
    expect(capped.expires_at).toBeLessThanOrEqual(Math.floor(start / 1000) + 30 * 86400);
    expect(capped.expires_at).toBeGreaterThan(Math.floor(start / 1000) + 30 * 86400 - 5);
    vi.useFakeTimers({ now: start + 30 * DAY + 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(401);
  });

  it("ends with a session left idle for 7 days", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const start = Date.now();
    await sessionFetch(cookie, "PUT", PATH, { ttl: 604800 });
    vi.useFakeTimers({ now: start + 7 * DAY + 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(401);
  });

  it("leaves a key stored without ttl unextended", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    const start = Date.now();
    await sessionFetch(cookie, "PUT", PATH, { ttl: 3600 });
    const end = nowS() + 3600;
    await runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) => {
      const [[name, entry]] = [...state.storage.kv.list<{ key: string; ttl: number; expires_at: number }>({ prefix: "unlock:" })];
      state.storage.kv.put(name, { key: entry.key, expires_at: end });
    });
    vi.useFakeTimers({ now: start + 1800 * 1000, toFake: ["Date"] });
    expect(((await (await sessionFetch(cookie, "GET", PATH)).json()) as Key).expires_at).toBe(end);
    vi.useFakeTimers({ now: start + 3601 * 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);
  });

  it("is gone after sign-out, and keys of ended sessions are dropped on the next PUT", async () => {
    const f = await created(await randomFixture());
    const a = await session(f);
    const b = await session(f);
    await sessionFetch(a, "PUT", PATH, { ttl: 3600 });
    await sessionFetch(b, "PUT", PATH, { ttl: 3600 });
    expect(await kvKeys(f.account)).toHaveLength(2);
    expect((await sessionFetch(a, "DELETE", "/api/v1/session")).status).toBe(204);
    expect(await kvKeys(f.account)).toHaveLength(1);
    expect((await sessionFetch(a, "GET", PATH)).status).toBe(401);
    expect((await sessionFetch(b, "GET", PATH)).status).toBe(200);
  });

  it("refuses without a session, without CSRF, from another origin and for another account", async () => {
    const f = await created(await randomFixture());
    const g = await created(await randomFixture());
    const cookie = await session(f);
    expect((await sessionFetch("", "GET", PATH)).status).toBe(401);
    expect((await sessionFetch("", "PUT", PATH, { ttl: 900 })).status).toBe(401);
    expect((await sessionFetch(cookie, "PUT", PATH, { ttl: 900 }, { "Hort-CSRF": "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "PUT", PATH, { ttl: 900 }, { Origin: "https://evil.test" })).status).toBe(403);
    await sessionFetch(cookie, "PUT", PATH, { ttl: 900 });
    expect((await sessionFetch(cookie, "DELETE", PATH, undefined, { "Hort-CSRF": "" })).status).toBe(403);
    const asG = { "Hort-Account": g.account };
    expect((await sessionFetch(cookie, "GET", PATH, undefined, asG)).status).toBe(409);
    expect((await sessionFetch(cookie, "PUT", PATH, { ttl: 900 }, asG)).status).toBe(409);
    expect((await sessionFetch(cookie, "DELETE", PATH, undefined, asG)).status).toBe(409);
    expect((await sessionFetch(cookie, "GET", PATH, undefined, { "Hort-Account": f.account })).status).toBe(200);
    // A cookie with another account's ID names that account's DO, where the token is unknown.
    expect((await sessionFetch(cookie.replace(f.account, g.account), "GET", PATH)).status).toBe(401);
    expect((await sessionFetch(cookie, "POST", PATH, { ttl: 900 })).status).toBe(405);
  });

  it("accepts only the offered lock times", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    for (const body of [{ ttl: 60 }, { ttl: 86400 }, { ttl: 2592000 }, { ttl: "900" }, { ttl: 900, extra: 1 }, {}]) {
      expect((await sessionFetch(cookie, "PUT", PATH, body)).status, JSON.stringify(body)).toBe(400);
    }
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);
  });
});
