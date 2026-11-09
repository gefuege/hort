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

  it("expires after the ttl and never outlives the session", async () => {
    const f = await created(await randomFixture());
    const cookie = await session(f);
    await sessionFetch(cookie, "PUT", PATH, { ttl: 900 });
    vi.useFakeTimers({ now: Date.now() + 901 * 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);
    expect(await kvKeys(f.account)).toEqual([]);
    vi.useRealTimers();

    // 8 h asked 11.5 h into the 12 h session: it ends with the session.
    vi.useFakeTimers({ now: Date.now() + 11.5 * 3600 * 1000, toFake: ["Date"] });
    const late = (await (await sessionFetch(cookie, "PUT", PATH, { ttl: 28800 })).json()) as Key;
    expect(late.expires_at - nowS()).toBeLessThanOrEqual(1800);
    vi.useFakeTimers({ now: Date.now() + 1801 * 1000, toFake: ["Date"] });
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(401);
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
    for (const body of [{ ttl: 60 }, { ttl: 86400 }, { ttl: "900" }, { ttl: 900, extra: 1 }, {}]) {
      expect((await sessionFetch(cookie, "PUT", PATH, body)).status, JSON.stringify(body)).toBe(400);
    }
    expect((await sessionFetch(cookie, "GET", PATH)).status).toBe(404);
  });
});
