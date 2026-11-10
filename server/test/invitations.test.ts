import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { INVITE_INVALID } from "../src/invitations";
import { accountIdDecode, hexDecode, sha256 } from "../src/wire";
import { createCall, newKey, makeSlot, randomFixture, randomIp, signedRequest, type Fixture } from "./helpers";

// The test Worker runs without ADMIN_TOKEN (open registration); these calls
// pass it, as a server with invitations does.
const ADMIN = "synthetic-admin-token";
const withAdmin = { ...env, ADMIN_TOKEN: ADMIN } as Env;
const fetchAdmin = (req: Request) => worker.fetch(req as Parameters<typeof worker.fetch>[0], withAdmin);

const admin = (method: string, path: string, token: string | null = ADMIN) =>
  fetchAdmin(
    new Request(`https://hort.test/api/v1${path}`, {
      method,
      headers: { "CF-Connecting-IP": randomIp(), ...(token === null ? {} : { "Hort-Admin-Token": token }) },
    }),
  );

async function invite(): Promise<{ id: string; code: string }> {
  const res = await admin("POST", "/invitations");
  expect(res.status).toBe(201);
  return res.json();
}

async function register(f: Fixture, code?: string): Promise<Response> {
  return fetchAdmin(await signedRequest(createCall(f, { headers: code === undefined ? {} : { "Hort-Invite": code } })));
}

type Listed = { id: string; created_at: number; used_at: number | null; account_id: string | null };
async function listed(id: string): Promise<Listed | undefined> {
  const res = await admin("GET", "/invitations");
  expect(res.status).toBe(200);
  const body = (await res.json()) as { invitations: Listed[] };
  expect(JSON.stringify(body)).not.toMatch(/code/);
  return body.invitations.find((i) => i.id === id);
}

describe("operator API", () => {
  it("refuses calls without or with a wrong admin token", async () => {
    for (const token of [null, "nope", ""]) {
      expect((await admin("POST", "/invitations", token)).status).toBe(403);
      expect((await admin("GET", "/invitations", token)).status).toBe(403);
      expect((await admin("POST", "/invitations/00000000/revoke", token)).status).toBe(403);
    }
  });

  it("has no invitations on a server without ADMIN_TOKEN", async () => {
    const res = await worker.fetch(
      new Request("https://hort.test/api/v1/invitations", { headers: { "Hort-Admin-Token": ADMIN, "CF-Connecting-IP": randomIp() } }) as Parameters<typeof worker.fetch>[0],
      env,
    );
    expect(res.status).toBe(404);
  });

  it("creates a 128-bit code, lists it as open without the code, and revokes it", async () => {
    const { id, code } = await invite();
    expect(id).toMatch(/^[0-9a-f]{8}$/);
    expect(code).toMatch(/^[0-9a-f]{32}$/);
    expect(await listed(id)).toEqual({ id, created_at: expect.any(Number), used_at: null, account_id: null });
    expect((await admin("POST", `/invitations/${id}/revoke`)).status).toBe(200);
    expect(await listed(id)).toBeUndefined();
    expect((await admin("POST", `/invitations/${id}/revoke`)).status).toBe(404);
  });

  it("rate-limits operator calls per IP", async () => {
    const ip = randomIp();
    const req = () => fetchAdmin(new Request("https://hort.test/api/v1/invitations", { headers: { "Hort-Admin-Token": "nope", "CF-Connecting-IP": ip } }));
    for (let i = 0; i < 30; i++) expect((await req()).status).toBe(403);
    expect((await req()).status).toBe(429);
  });
});

describe("registration with ADMIN_TOKEN", () => {
  it("needs a code", async () => {
    const res = await register(await randomFixture());
    expect(res.status).toBe(403);
    expect(await res.text()).toMatch(/needs an invitation; run hort sync --invite CODE/);
  });

  it("refuses a wrong or malformed code", async () => {
    for (const code of ["0".repeat(32), "not-a-code"]) {
      const res = await register(await randomFixture(), code);
      expect(res.status).toBe(403);
      expect(await res.text()).toBe(INVITE_INVALID + "\n");
    }
  });

  it("registers with a valid code once, binds it to the account, and lets the same account replay", async () => {
    const { id, code } = await invite();
    const f = await randomFixture();
    expect((await register(f, code)).status).toBe(201);
    expect(await listed(id)).toEqual({ id, created_at: expect.any(Number), used_at: expect.any(Number), account_id: f.account });

    expect((await register(f, code)).status).toBe(200);

    const other = await register(await randomFixture(), code);
    expect(other.status).toBe(403);
    expect(await other.text()).toBe(INVITE_INVALID + "\n");
    expect((await admin("POST", `/invitations/${id}/revoke`)).status).toBe(409);
  });

  it("refuses a revoked code", async () => {
    const { id, code } = await invite();
    expect((await admin("POST", `/invitations/${id}/revoke`)).status).toBe(200);
    const res = await register(await randomFixture(), code);
    expect(res.status).toBe(403);
    expect(await res.text()).toBe(INVITE_INVALID + "\n");
  });

  it("does not spend a code on a request with a bad signature", async () => {
    const { id, code } = await invite();
    const f = await randomFixture();
    const res = await fetchAdmin(await signedRequest(createCall(f, { key: await newKey(), headers: { "Hort-Invite": code } })));
    expect(res.status).toBe(401);
    expect((await listed(id))?.used_at).toBeNull();
    expect((await register(f, code)).status).toBe(201);
  });

  it("refuses an existing account ID with another AK without spending the code", async () => {
    const first = await invite();
    const f = await randomFixture();
    expect((await register(f, first.code)).status).toBe(201);
    const { id, code } = await invite();
    const ak = await newKey();
    const res = await register({ ...f, ak, slot: await makeSlot(accountIdDecode(f.account)!, ak, 1) }, code);
    expect(res.status).toBe(409);
    expect((await listed(id))?.used_at).toBeNull();
  });

  it("binds the code to the first account: that account again, never another one", async () => {
    const { code } = await invite();
    const stub = env.INVITATIONS.getByName("invitations");
    const hash = await sha256(hexDecode(code, 16)!);
    expect(await stub.consume(hash, "account-a")).toBe(true);
    expect(await stub.consume(hash, "account-a")).toBe(true);
    expect(await stub.consume(hash, "account-b")).toBe(false);
  });
});
