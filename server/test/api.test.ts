import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import keyVectors from "../../spec/vectors/keys.json";
import slotVectors from "../../spec/vectors/slot.json";
import worker from "../src/index";
import { jurisdictionCalls } from "./setup";
import {
  TOKEN,
  hex,
  random,
  nowSeconds,
  randomIp,
  keyFromSeed,
  newKey,
  sign,
  signedRequest,
  call,
  makeSlot,
  slotJson,
  createBody,
  createCall,
  vectorFixture,
  randomFixture,
  created,
  enroll,
  listDevices,
  fetchSlot,
  putSlot,
  type Call,
  type Fixture,
  type Key,
  type Slot,
} from "./helpers";
import { session, sessionFetch } from "./passkey";
import {
  accountIdDecode,
  accountIdEncode,
  b64Encode,
  canon,
  concat,
  hexDecode,
  hexEncode,
  requestMessage,
  slotSigMessage,
  str,
  u32,
} from "../src/wire";

describe("POST /api/v1/accounts", () => {
  it("creates an account from the vector slot and AK, and a replay is idempotent", async () => {
    const f = await vectorFixture();
    const res = await call(createCall(f));
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ devices_version: 1 });
    const replay = await call(createCall(f));
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual({ devices_version: 1 });
  });

  it("refuses an existing account ID with a different AK", async () => {
    const f = await created(await randomFixture());
    const other = await newKey();
    const g = { ...f, ak: other, slot: await makeSlot(accountIdDecode(f.account)!, other, 1) };
    const res = await call(createCall(g));
    expect(res.status).toBe(409);
    expect(await res.text()).toBe("account already exists\n");
  });

  it("requires the registration token while it is set", async () => {
    const f = await randomFixture();
    const missing = await call(createCall(f, { headers: {} }));
    expect(missing.status).toBe(403);
    expect(await missing.text()).toBe("registration is invite-only; a registration token is required\n");
    const wrong = await call(createCall(f, { headers: { "Hort-Registration-Token": "nope" } }));
    expect(wrong.status).toBe(403);
    expect(await wrong.text()).toBe("invalid registration token\n");
  });

  it("is open without a configured registration token", async () => {
    const f = await randomFixture();
    const req = await signedRequest(createCall(f, { headers: {} }));
    const res = await worker.fetch(req as Parameters<typeof worker.fetch>[0], { ...env, REGISTRATION_TOKEN: undefined } as Env);
    expect(res.status).toBe(201);
  });

  it("rejects a request not signed by the posted AK", async () => {
    const f = await randomFixture();
    const res = await call(createCall(f, { key: await newKey() }));
    expect(res.status).toBe(401);
  });

  it("rejects a slot whose ak_sig does not verify", async () => {
    const f = await randomFixture();
    f.slot = { ...f.slot, akSig: await sign(await newKey(), slotSigMessage(accountIdDecode(f.account)!, "passphrase", 1, f.slot.bytes)) };
    const res = await call(createCall(f));
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("slot ak_sig does not verify against the account key\n");
  });

  it("rejects Hort-Device other than ak", async () => {
    const f = await randomFixture();
    const res = await call(createCall(f, { device: f.deviceId }));
    expect(res.status).toBe(401);
  });

  it("limits account creation to 5 per hour per IP", async () => {
    const ip = randomIp();
    for (let i = 0; i < 5; i++) {
      const res = await call(createCall(await randomFixture(), { headers: { "Hort-Registration-Token": TOKEN, "CF-Connecting-IP": ip } }));
      expect(res.status).toBe(201);
    }
    const res = await call(createCall(await randomFixture(), { headers: { "Hort-Registration-Token": TOKEN, "CF-Connecting-IP": ip } }));
    expect(res.status).toBe(429);
    expect(Number(res.headers.get("Retry-After"))).toBeGreaterThan(3500);
  });
});

describe("input boundary", () => {
  it("rejects a body over 64 KiB without Content-Length", async () => {
    const f = await randomFixture();
    const big = new Uint8Array(64 * 1024 + 1);
    const stream = new ReadableStream({ start(c) { c.enqueue(big.subarray(0, 40000)); c.enqueue(big.subarray(40000)); c.close(); } });
    const req = await signedRequest(createCall(f));
    const chunked = new Request(req.url, { method: "POST", headers: req.headers, body: stream, duplex: "half" } as RequestInit);
    expect(chunked.headers.get("Content-Length")).toBeNull();
    const res = await exports.default.fetch(chunked);
    expect(res.status).toBe(413);
  });
});

describe("GET /api/v1/accounts/{id}/slot", () => {
  it("returns the passphrase slot, version, ak_sig and ak_pub without authentication", async () => {
    // Storage is shared within this file: the vector account may already exist (200) or not (201).
    const f = await vectorFixture();
    expect([200, 201]).toContain((await call(createCall(f))).status);
    const res = await fetchSlot(f.account);
    expect(res.status).toBe(200);
    const v = slotVectors.vectors[0];
    expect(await res.json()).toEqual({
      ak_pub: b64Encode(hex(v.ak_public_hex)),
      slot: { id: "passphrase", version: 7, bytes: b64Encode(hex(v.slot_bytes_hex)), ak_sig: b64Encode(hex(v.ak_sig_hex)) },
    });
  });

  it("answers 404 for an unknown or malformed account ID", async () => {
    expect((await fetchSlot(accountIdEncode(random(16)))).status).toBe(404);
    expect((await fetchSlot("not-an-account")).status).toBe(404);
  });

  it("limits fetches to 10 per minute per IP and account", async () => {
    const f = await created(await randomFixture());
    const ip = randomIp();
    for (let i = 0; i < 10; i++) expect((await fetchSlot(f.account, ip)).status).toBe(200);
    const limited = await fetchSlot(f.account, ip);
    expect(limited.status).toBe(429);
    expect(limited.headers.get("Retry-After")).toMatch(/^[1-9][0-9]*$/);
    expect((await fetchSlot(f.account, randomIp())).status).toBe(200);
    const g = await created(await randomFixture());
    expect((await fetchSlot(g.account, ip)).status).toBe(200);
  });
});

describe("rate-limit key", () => {
  it("shares one slot bucket per IPv6 /64 and separates other prefixes", async () => {
    const f = await created(await randomFixture());
    const p = hexEncode(random(4)).replace(/(.{4})(.{4})/, "$1:$2");
    // Ten fetches in one /64, varying spelling, case and interface identifier.
    const same = [`${p}:1:2::1`, `${p}:0001:0002:aaaa:bbbb:cccc:dddd`.toUpperCase(), `${p}:1:2:3:4:5:6`, `${p}:1:2::9`, `${p}:1:2::a`];
    for (let i = 0; i < 10; i++) expect((await fetchSlot(f.account, same[i % same.length])).status).toBe(200);
    expect((await fetchSlot(f.account, `${p}:1:2::ff`)).status).toBe(429);
    expect((await fetchSlot(f.account, `${p}:1:3::1`)).status).toBe(200);
  });
});

describe("devices", () => {
  it("enrolls, lists and revokes devices and bumps devices_version", async () => {
    const f = await created(await randomFixture());
    const second = await enroll(f);
    expect(second.res.status).toBe(201);
    expect(await second.res.json()).toEqual({ devices_version: 2 });

    const list = await listDevices(f);
    expect(list.status).toBe(200);
    const body = (await list.json()) as { devices: { id: string; name: string; revoked_at: number | null; last_seen_at: number | null }[]; devices_version: number };
    expect(body.devices_version).toBe(2);
    expect(body.devices.map((d) => d.id).sort()).toEqual([f.deviceId, second.id].sort());
    expect(body.devices.find((d) => d.id === f.deviceId)!.last_seen_at).not.toBeNull();

    const revoke = await call({ account: f.account, device: f.deviceId, key: f.device, method: "DELETE", path: `/api/v1/devices/${second.id}` });
    expect(revoke.status).toBe(200);
    expect(await revoke.json()).toEqual({ devices_version: 3 });
    const again = await call({ account: f.account, device: f.deviceId, key: f.device, method: "DELETE", path: `/api/v1/devices/${second.id}` });
    expect(await again.json()).toEqual({ devices_version: 3 });
    const unknown = await call({ account: f.account, device: f.deviceId, key: f.device, method: "DELETE", path: `/api/v1/devices/${hexEncode(random(16))}` });
    expect(unknown.status).toBe(404);
  });

  it("rejects a device revoking itself and keeps it active", async () => {
    const f = await created(await randomFixture());
    const res = await call({ account: f.account, device: f.deviceId, key: f.device, method: "DELETE", path: `/api/v1/devices/${f.deviceId}` });
    expect(res.status).toBe(409);
    expect(await res.text()).toBe("a device cannot revoke itself\n");
    expect((await listDevices(f)).status).toBe(200);
  });

  it("treats an enrollment replay as idempotent", async () => {
    const f = await created(await randomFixture());
    const { id, key, res } = await enroll(f);
    expect(res.status).toBe(201);
    const body = JSON.stringify({ device_id: id, pub: b64Encode(key.pub), name: "linux-zz99" });
    const replay = await call({ account: f.account, device: "ak", key: f.ak, method: "POST", path: "/api/v1/devices", body });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual({ devices_version: 2 });
  });

  it("rejects a revoked device, also when it is enrolled again", async () => {
    const f = await created(await randomFixture());
    const second = await enroll(f);
    await call({ account: f.account, device: f.deviceId, key: f.device, method: "DELETE", path: `/api/v1/devices/${second.id}` });

    const asRevoked = await listDevices(f, second.id, second.key);
    expect(asRevoked.status).toBe(403);
    expect(await asRevoked.text()).toBe("device revoked\n");
    const revokeOther = await call({ account: f.account, device: second.id, key: second.key, method: "DELETE", path: `/api/v1/devices/${f.deviceId}` });
    expect(revokeOther.status).toBe(403);

    const body = JSON.stringify({ device_id: second.id, pub: b64Encode(second.key.pub), name: "linux-zz99" });
    const reEnroll = await call({ account: f.account, device: "ak", key: f.ak, method: "POST", path: "/api/v1/devices", body });
    expect(reEnroll.status).toBe(409);
    expect(await reEnroll.text()).toBe("device was revoked; enroll with a new device ID\n");
  });

  it("requires the AK for enrollment and a device key for listing", async () => {
    const f = await created(await randomFixture());
    const body = JSON.stringify({ device_id: hexEncode(random(16)), pub: b64Encode((await newKey()).pub), name: "x" });
    const byDevice = await call({ account: f.account, device: f.deviceId, key: f.device, method: "POST", path: "/api/v1/devices", body });
    expect(byDevice.status).toBe(401);
    const byAk = await call({ account: f.account, device: "ak", key: f.ak, method: "GET", path: "/api/v1/devices" });
    expect(byAk.status).toBe(401);
  });

  it("caps active devices at 20", async () => {
    const f = await created(await randomFixture());
    for (let i = 0; i < 19; i++) expect((await enroll(f)).res.status).toBe(201);
    const over = await enroll(f);
    expect(over.res.status).toBe(429);
  });
});

describe("request signatures", () => {
  it("rejects a wrong signature and a body that differs from the signed bytes", async () => {
    const f = await created(await randomFixture());
    expect((await listDevices(f, f.deviceId, await newKey())).status).toBe(401);
    const second = await enroll(f);
    const res = await call({
      account: f.account, device: f.deviceId, key: f.device, method: "DELETE",
      path: `/api/v1/devices/${second.id}`, body: "", tamperBody: "{}",
    });
    expect(res.status).toBe(401);
    expect(await res.text()).toBe("invalid request signature\n");
  });

  it("rejects timestamps more than 300 s off and accepts 299 s", async () => {
    const f = await created(await randomFixture());
    for (const skew of [-301, 301, -100000]) {
      const res = await call({ account: f.account, device: f.deviceId, key: f.device, method: "GET", path: "/api/v1/devices", ts: nowSeconds() + skew });
      expect(res.status, `skew ${skew}`).toBe(401);
    }
    for (const skew of [-299, 299]) {
      const res = await call({ account: f.account, device: f.deviceId, key: f.device, method: "GET", path: "/api/v1/devices", ts: nowSeconds() + skew });
      expect(res.status, `skew ${skew}`).toBe(200);
    }
  });

  it("rejects malformed signature headers", async () => {
    const f = await created(await randomFixture());
    const req = await signedRequest({ account: f.account, device: f.deviceId, key: f.device, method: "GET", path: "/api/v1/devices" });
    const bad = new Request(req, { headers: new Headers(req.headers) });
    bad.headers.set("Hort-Signature", "AAAA");
    expect((await exports.default.fetch(bad)).status).toBe(400);
  });

  it("keeps accounts isolated", async () => {
    const a = await created(await randomFixture());
    const b = await created(await randomFixture());
    // A's device and A's AK sign for account B.
    const byDevice = await call({ account: b.account, device: a.deviceId, key: a.device, method: "GET", path: "/api/v1/devices" });
    expect(byDevice.status).toBe(401);
    expect(await byDevice.text()).toBe("unknown device\n");
    const slot = await makeSlot(accountIdDecode(b.account)!, a.ak, 2);
    expect((await putSlot(b, slot, a.ak)).status).toBe(401);
    // B's own state is unchanged and separate.
    const res = (await (await fetchSlot(b.account)).json()) as { ak_pub: string; slot: { version: number } };
    expect(res.ak_pub).toBe(b64Encode(b.ak.pub));
    expect(res.slot.version).toBe(1);
    const listA = (await (await listDevices(a)).json()) as { devices: { id: string }[] };
    expect(listA.devices.map((d) => d.id)).toEqual([a.deviceId]);
  });

  it("requests the EU jurisdiction for every Durable Object it reaches", async () => {
    jurisdictionCalls.length = 0;
    const f = await created(await randomFixture());
    await fetchSlot(f.account);
    await enroll(f);
    // create: rate limiter + account; slot: rate limiter + account; enroll: account + write limiter.
    expect(jurisdictionCalls).toEqual(["eu", "eu", "eu", "eu", "eu", "eu"]);
  });
});

describe("PUT /api/v1/slots/passphrase", () => {
  it("stores a higher slot_version and rejects equal or lower versions", async () => {
    const f = await randomFixture();
    const id = accountIdDecode(f.account)!;
    f.slot = await makeSlot(id, f.ak, 7);
    await created(f);
    const next = await makeSlot(id, f.ak, 8);
    const res = await putSlot(f, next);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ version: 8 });
    const fetched = (await (await fetchSlot(f.account)).json()) as { slot: { version: number; bytes: string } };
    expect(fetched.slot).toMatchObject({ version: 8, bytes: b64Encode(next.bytes) });

    const equal = await putSlot(f, await makeSlot(id, f.ak, 8));
    expect(equal.status).toBe(409);
    expect(await equal.text()).toBe("slot version 8 is not higher than the stored version 8\n");
    expect((await putSlot(f, await makeSlot(id, f.ak, 3))).status).toBe(409);
  });

  it("rejects an invalid ak_sig", async () => {
    const f = await created(await randomFixture());
    const id = accountIdDecode(f.account)!;
    const forged = await makeSlot(id, await newKey(), 2);
    const res = await putSlot(f, forged);
    expect(res.status).toBe(400);
    expect(await res.text()).toBe("slot ak_sig does not verify against the account key\n");
    // A valid signature for another version does not carry over.
    const signedFor2 = await makeSlot(id, f.ak, 2);
    expect((await putSlot(f, { ...signedFor2, version: 3 })).status).toBe(400);
  });

  it("requires the AK signature", async () => {
    const f = await created(await randomFixture());
    const slot = await makeSlot(accountIdDecode(f.account)!, f.ak, 2);
    const byDevice = await call({ account: f.account, device: f.deviceId, key: f.device, method: "PUT", path: "/api/v1/slots/passphrase", body: JSON.stringify(slotJson(slot)) });
    expect(byDevice.status).toBe(401);
    expect((await putSlot(f, slot, await newKey())).status).toBe(401);
  });
});

// Requests (contract §6.3, §7.2, §7.3).
const metaCt = () => b64Encode(random(60));
const rid = () => hexEncode(random(16));
const revision = () => ({ id: rid(), ct: b64Encode(random(80)) });

const createRequest = (f: Fixture, body: unknown, deviceId = f.deviceId, key = f.device) =>
  call({ account: f.account, device: deviceId, key, method: "POST", path: "/api/v1/requests", body: JSON.stringify(body) });
const getRequest = (f: Fixture, id: string, deviceId = f.deviceId, key = f.device) =>
  call({ account: f.account, device: deviceId, key, method: "GET", path: `/api/v1/requests/${id}` });
const listPending = (f: Fixture) =>
  call({ account: f.account, device: f.deviceId, key: f.device, method: "GET", path: "/api/v1/requests?status=pending" });
const declineRequest = (f: Fixture, id: string, deviceId = f.deviceId, key = f.device) =>
  call({ account: f.account, device: deviceId, key, method: "POST", path: `/api/v1/requests/${id}/decline` });
// Fulfil runs over HTTP with a passkey session, one per fixture.
const sessions = new WeakMap<Fixture, Promise<string>>();
const fulfill = async (f: Fixture, id: string, body: unknown) => {
  if (!sessions.has(f)) sessions.set(f, session(f));
  return sessionFetch(await sessions.get(f)!, "POST", `/api/v1/requests/${id}/fulfill`, body);
};

type Info = { status: string; meta_ct: string; revision_ids: string[] };
const info = async (f: Fixture, id: string) => (await (await getRequest(f, id)).json()) as Info;
const pendingIds = async (f: Fixture) => ((await (await listPending(f)).json()) as { requests: { id: string }[] }).requests.map((r) => r.id);

describe("requests", () => {
  afterEach(() => vi.useRealTimers());

  it("creates a request, a replay is idempotent and different content conflicts", async () => {
    const f = await created(await randomFixture());
    const id = rid();
    const meta = metaCt();
    const res = await createRequest(f, { id, meta_ct: meta });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ status: "pending" });
    const replay = await createRequest(f, { id, meta_ct: meta });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual({ status: "pending" });
    expect((await createRequest(f, { id, meta_ct: metaCt() })).status).toBe(409);
    expect(await info(f, id)).toEqual({ status: "pending", meta_ct: meta, revision_ids: [] });
  });

  it("rejects malformed create bodies and bounds meta_ct", async () => {
    const f = await created(await randomFixture());
    for (const body of [
      { id: "ABC", meta_ct: metaCt() },
      { id: rid(), meta_ct: "!!" },
      { id: rid(), meta_ct: b64Encode(random(10)) },
      { id: rid(), meta_ct: b64Encode(random(16 * 1024 + 1)) },
      { id: rid() },
      { id: rid(), meta_ct: metaCt(), extra: 1 },
    ]) {
      expect((await createRequest(f, body)).status).toBe(400);
    }
    expect((await createRequest(f, { id: rid(), meta_ct: b64Encode(random(16 * 1024)) })).status).toBe(201);
  });

  it("allows at most 50 pending requests; a replay and freed slots still work", async () => {
    const f = await created(await randomFixture());
    const first = { id: rid(), meta_ct: metaCt() };
    expect((await createRequest(f, first)).status).toBe(201);
    for (let i = 1; i < 50; i++) expect((await createRequest(f, { id: rid(), meta_ct: metaCt() })).status).toBe(201);
    const over = await createRequest(f, { id: rid(), meta_ct: metaCt() });
    expect(over.status).toBe(429);
    expect(await over.text()).toBe("too many pending requests (50); decline or wait for expiry\n");
    expect((await createRequest(f, first)).status).toBe(200);
    expect((await declineRequest(f, first.id)).status).toBe(200);
    expect((await createRequest(f, { id: rid(), meta_ct: metaCt() })).status).toBe(201);
  });

  it("gets a request and answers 404 for an unknown or malformed ID", async () => {
    const f = await created(await randomFixture());
    expect((await getRequest(f, rid())).status).toBe(404);
    expect((await getRequest(f, "nothex")).status).toBe(404);
  });

  it("lists pending requests only, oldest first, and requires status=pending", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    const b = { id: rid(), meta_ct: metaCt() };
    await createRequest(f, a);
    await createRequest(f, b);
    await declineRequest(f, b.id);
    const body = (await (await listPending(f)).json()) as { requests: unknown[] };
    expect(body.requests).toEqual([{ id: a.id, meta_ct: a.meta_ct, created_at: expect.any(Number) }]);
    const other = await call({ account: f.account, device: f.deviceId, key: f.device, method: "GET", path: "/api/v1/requests?status=done" });
    expect(other.status).toBe(400);
  });

  it("expires a pending request lazily after 24 h", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    await createRequest(f, a);
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 24 * 3600 * 1000 - 5000 });
    expect((await info(f, a.id)).status).toBe("pending");
    vi.setSystemTime(Date.now() + 5000);
    expect((await info(f, a.id)).status).toBe("expired");
    expect(await pendingIds(f)).toEqual([]);
    const replay = await createRequest(f, a);
    expect(await replay.json()).toEqual({ status: "expired" });
    expect((await declineRequest(f, a.id)).status).toBe(409);
    expect((await fulfill(f, a.id, { revisions: [revision()] })).status).toBe(409);
  });

  it("excludes expired requests from the list and frees pending capacity", async () => {
    const f = await created(await randomFixture());
    for (let i = 0; i < 50; i++) await createRequest(f, { id: rid(), meta_ct: metaCt() });
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 24 * 3600 * 1000 });
    expect(await pendingIds(f)).toEqual([]);
    expect((await createRequest(f, { id: rid(), meta_ct: metaCt() })).status).toBe(201);
  });

  it("declines idempotently and refuses a non-pending state", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    await createRequest(f, a);
    const res = await declineRequest(f, a.id);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "declined" });
    expect((await declineRequest(f, a.id)).status).toBe(200);
    expect((await info(f, a.id)).status).toBe("declined");
    expect((await fulfill(f, a.id, { revisions: [revision()] })).status).toBe(409);

    const b = { id: rid(), meta_ct: metaCt() };
    await createRequest(f, b);
    expect((await fulfill(f, b.id, { revisions: [revision()] })).status).toBe(200);
    const late = await declineRequest(f, b.id);
    expect(late.status).toBe(409);
    expect(await late.text()).toBe("request is fulfilled\n");
    expect((await declineRequest(f, rid())).status).toBe(404);
  });

  it("fulfills atomically: revisions, status and revision_ids together, with dedupe", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    const b = { id: rid(), meta_ct: metaCt() };
    await createRequest(f, a);
    await createRequest(f, b);
    const r1 = revision();
    const r2 = revision();
    const res = await fulfill(f, a.id, { revisions: [r1, r2, r1] });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ accepted: [r1.id, r2.id], duplicate: [] });
    expect(await info(f, a.id)).toMatchObject({ status: "fulfilled", revision_ids: [r1.id, r2.id] });
    expect((await fulfill(f, a.id, { revisions: [revision()] })).status).toBe(409);

    const r3 = revision();
    const res2 = await fulfill(f, b.id, { revisions: [r2, r3] });
    expect(await res2.json()).toEqual({ accepted: [r3.id], duplicate: [r2.id] });
    expect((await info(f, b.id)).revision_ids).toEqual([r2.id, r3.id]);

    const rows = await runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) =>
      state.storage.sql.exec<{ id: string; from_device: string | null }>("SELECT id, from_device FROM revisions ORDER BY seq").toArray());
    expect(rows).toEqual([{ id: r1.id, from_device: null }, { id: r2.id, from_device: null }, { id: r3.id, from_device: null }]);
  });

  it("validates fulfill input and leaves the request pending on failure", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    await createRequest(f, a);
    for (const body of [
      { revisions: [] },
      { revisions: [{ id: "x", ct: revision().ct }] },
      { revisions: [{ id: rid(), ct: "!!" }] },
      { revisions: [{ id: rid() }] },
      { revisions: Array.from({ length: 501 }, revision) },
      { revisions: [revision()], extra: 1 },
    ]) {
      expect((await fulfill(f, a.id, body)).status).toBe(400);
    }
    const big = await fulfill(f, a.id, { revisions: [revision(), { id: rid(), ct: b64Encode(new Uint8Array(64 * 1024 + 1)) }] });
    expect(big.status).toBe(413);
    expect((await info(f, a.id)).status).toBe("pending");
    const rows = await runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) =>
      state.storage.sql.exec<{ n: number }>("SELECT count(*) AS n FROM revisions").one().n);
    expect(rows).toBe(0);
    expect((await fulfill(f, rid(), { revisions: [revision()] })).status).toBe(404);
    expect((await fulfill(f, a.id, { revisions: [{ id: rid(), ct: b64Encode(new Uint8Array(64 * 1024)) }] })).status).toBe(200);
  });

  it("fulfills only with a session, Hort-CSRF and the site origin, never with a device signature", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    await createRequest(f, a);
    const body = { revisions: [revision()] };
    const res = await call({ account: f.account, device: f.deviceId, key: f.device, method: "POST", path: `/api/v1/requests/${a.id}/fulfill`, body: JSON.stringify(body) });
    expect(res.status).toBe(401);
    const cookie = await session(f);
    const path = `/api/v1/requests/${a.id}/fulfill`;
    expect((await sessionFetch(cookie, "POST", path, body, { "Hort-CSRF": "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "POST", path, body, { Origin: "https://evil.test" })).status).toBe(403);
    expect((await sessionFetch("", "POST", path, body)).status).toBe(401);
    expect((await info(f, a.id)).status).toBe("pending");
    const big = await sessionFetch(cookie, "POST", path, { revisions: [{ id: rid(), ct: b64Encode(new Uint8Array(200 * 1024)) }] });
    expect(big.status).toBe(413);
    expect((await sessionFetch(cookie, "POST", path, body)).status).toBe(200);
    expect((await info(f, a.id)).status).toBe("fulfilled");
  });

  it("isolates accounts: another account's request ID is 404 and untouched", async () => {
    const a = await created(await randomFixture());
    const b = await created(await randomFixture());
    const req = { id: rid(), meta_ct: metaCt() };
    await createRequest(a, req);
    expect((await getRequest(b, req.id)).status).toBe(404);
    expect((await declineRequest(b, req.id)).status).toBe(404);
    expect((await fulfill(b, req.id, { revisions: [revision()] })).status).toBe(404);
    expect(await pendingIds(b)).toEqual([]);
    expect((await info(a, req.id)).status).toBe("pending");
    expect((await getRequest(b, req.id, a.deviceId, a.device)).status).toBe(401);
  });

  it("rejects wrong signatures, AK signatures and revoked devices", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    expect((await createRequest(f, a, f.deviceId, await newKey())).status).toBe(401);
    expect((await createRequest(f, a, "ak", f.ak)).status).toBe(401);
    await createRequest(f, a);
    expect((await getRequest(f, a.id, f.deviceId, await newKey())).status).toBe(401);
    expect((await declineRequest(f, a.id, f.deviceId, await newKey())).status).toBe(401);
    const second = await enroll(f);
    await call({ account: f.account, device: f.deviceId, key: f.device, method: "DELETE", path: `/api/v1/devices/${second.id}` });
    expect((await getRequest(f, a.id, second.id, second.key)).status).toBe(403);
  });

  it("applies the write rate limit to create and decline but not to reads", async () => {
    const f = await created(await randomFixture());
    const a = { id: rid(), meta_ct: metaCt() };
    expect((await createRequest(f, a)).status).toBe(201);
    for (let i = 0; i < 70; i++) expect((await getRequest(f, a.id)).status).toBe(200);
    let limited = 0;
    for (let i = 0; i < 70; i++) if ((await declineRequest(f, a.id)).status === 429) limited++;
    expect(limited).toBeGreaterThan(0);
  });
});

// Revisions (contract §6.3, §6.6).
type Page = { revisions: { seq: number; id: string; ct: string }[]; cursor: number; more: boolean; devices_version: number };
const push = (f: Fixture, revisions: unknown, deviceId = f.deviceId, key = f.device) =>
  call({ account: f.account, device: deviceId, key, method: "POST", path: "/api/v1/revisions", body: JSON.stringify({ revisions }) });
const pull = (f: Fixture, query: string, deviceId = f.deviceId, key = f.device) =>
  call({ account: f.account, device: deviceId, key, method: "GET", path: `/api/v1/revisions${query}` });
const page = async (f: Fixture, query: string) => {
  const res = await pull(f, query);
  expect(res.status, await res.clone().text()).toBe(200);
  return (await res.json()) as Page;
};
const fill = (f: Fixture, rows: number, ctBytes: number) =>
  runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) => {
    for (let i = 0; i < rows; i++) {
      state.storage.sql.exec("INSERT INTO revisions (id, ct, from_device, received_at) VALUES (?, ?, NULL, 0)", rid(), new Uint8Array(ctBytes));
    }
  });

describe("revisions", () => {
  it("pushes with dedupe by ID and pulls by cursor with more", async () => {
    const f = await created(await randomFixture());
    const [r1, r2, r3] = [revision(), revision(), revision()];
    const first = await push(f, [r1, r2, r1]);
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ accepted: [r1.id, r2.id], duplicate: [] });
    // The same ID with other content is a duplicate: the server cannot judge envelopes.
    const second = await push(f, [{ id: r2.id, ct: r3.ct }, r3]);
    expect(await second.json()).toEqual({ accepted: [r3.id], duplicate: [r2.id] });

    const all = await page(f, "?after=0");
    expect(all.revisions.map((r) => [r.id, r.ct])).toEqual([[r1.id, r1.ct], [r2.id, r2.ct], [r3.id, r3.ct]]);
    expect(all.more).toBe(false);
    expect(all.cursor).toBe(all.revisions[2].seq);
    expect(all.devices_version).toBe(1);

    const p1 = await page(f, "?after=0&limit=2");
    expect(p1.revisions.map((r) => r.id)).toEqual([r1.id, r2.id]);
    expect(p1.more).toBe(true);
    const p2 = await page(f, `?after=${p1.cursor}&limit=2`);
    expect(p2.revisions.map((r) => r.id)).toEqual([r3.id]);
    expect(p2.more).toBe(false);
    expect(await page(f, `?after=${p2.cursor}`)).toMatchObject({ revisions: [], cursor: p2.cursor, more: false });

    const other = await enroll(f);
    expect((await pull(f, "?after=0", other.id, other.key)).status).toBe(200);
    expect((await page(f, "?after=0")).devices_version).toBe(2);
    const from = await runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) =>
      state.storage.sql.exec<{ from_device: string }>("SELECT from_device FROM revisions ORDER BY seq").toArray().map((r) => r.from_device));
    expect(from).toEqual([f.deviceId, f.deviceId, f.deviceId]);
  });

  it("validates push bodies, envelope size and the pull query", async () => {
    const f = await created(await randomFixture());
    const invalid = [[], [{ id: "x", ct: revision().ct }], [{ id: rid(), ct: "!!" }], [{ id: rid(), ct: b64Encode(random(27)) }], [{ id: rid() }], Array.from({ length: 501 }, revision)];
    for (const revisions of invalid) expect((await push(f, revisions)).status).toBe(400);
    expect((await push(f, [revision(), { id: rid(), ct: b64Encode(new Uint8Array(64 * 1024 + 1)) }])).status).toBe(413);
    // One envelope at the 64 KiB limit is larger than the 64 KiB body limit of other endpoints.
    const max = { id: rid(), ct: b64Encode(new Uint8Array(64 * 1024)) };
    expect(await (await push(f, [max])).json()).toEqual({ accepted: [max.id], duplicate: [] });
    const tooBig = await push(f, Array.from({ length: 49 }, () => ({ id: rid(), ct: b64Encode(new Uint8Array(64 * 1024)) })));
    expect(tooBig.status).toBe(413);
    expect(await tooBig.text()).toBe("request body exceeds 4096 KiB\n");
    for (const q of ["", "?after=-1", "?after=01", "?after=1&limit=0", "?after=1&limit=501", "?limit=5", "?after=1&x=2", "?after=abc"]) {
      expect((await pull(f, q)).status, q).toBe(400);
    }
    expect((await page(f, "?after=0")).revisions.map((r) => r.id)).toEqual([max.id]);
  });

  it("ends a page at 4 MiB of ct but always returns one row", async () => {
    const f = await created(await randomFixture());
    await fill(f, 3, 1_500_000);
    const p1 = await page(f, "?after=0");
    expect(p1.revisions.length).toBe(2);
    expect(p1.more).toBe(true);
    const p2 = await page(f, `?after=${p1.cursor}`);
    expect(p2.revisions.length).toBe(1);
    expect(p2.more).toBe(false);
  });

  it("enforces 50,000 revisions per account", async () => {
    const f = await created(await randomFixture());
    await fill(f, 49_999, 28);
    const over = await push(f, [revision(), revision()]);
    expect(over.status).toBe(413);
    expect(await over.text()).toBe("account revision storage limit reached\n");
    expect((await push(f, [revision()])).status).toBe(200);
  });

  it("enforces 64 MiB of ct per account", async () => {
    const f = await created(await randomFixture());
    const row = 1_900_000;
    const rows = Math.floor((64 * 1024 * 1024) / row);
    await fill(f, rows, row);
    await fill(f, 1, 64 * 1024 * 1024 - rows * row - 100);
    expect((await push(f, [{ id: rid(), ct: b64Encode(random(101)) }])).status).toBe(413);
    expect((await push(f, [{ id: rid(), ct: b64Encode(random(100)) }])).status).toBe(200);
  });

  it("pulls and pushes with a passkey session; a session push needs Hort-CSRF and the site origin", async () => {
    const f = await created(await randomFixture());
    const r1 = revision();
    await push(f, [r1]);
    const cookie = await session(f);
    const pulled = await sessionFetch(cookie, "GET", "/api/v1/revisions?after=0");
    expect(pulled.status).toBe(200);
    expect(((await pulled.json()) as Page).revisions.map((r) => [r.id, r.ct])).toEqual([[r1.id, r1.ct]]);

    const r2 = revision();
    expect((await sessionFetch(cookie, "POST", "/api/v1/revisions", { revisions: [r2] }, { "Hort-CSRF": "" })).status).toBe(403);
    expect((await sessionFetch(cookie, "POST", "/api/v1/revisions", { revisions: [r2] }, { Origin: "https://evil.test" })).status).toBe(403);
    expect((await sessionFetch("", "POST", "/api/v1/revisions", { revisions: [r2] })).status).toBe(401);
    expect((await sessionFetch("", "GET", "/api/v1/revisions?after=0")).status).toBe(401);
    expect((await page(f, "?after=0")).revisions.map((r) => r.id)).toEqual([r1.id]);

    const pushed = await sessionFetch(cookie, "POST", "/api/v1/revisions", { revisions: [r2, r1] });
    expect(pushed.status).toBe(200);
    expect(await pushed.json()).toEqual({ accepted: [r2.id], duplicate: [r1.id] });
    const from = await runInDurableObject(env.ACCOUNT.getByName(f.account), (_i, state) =>
      state.storage.sql.exec<{ from_device: string | null }>("SELECT from_device FROM revisions ORDER BY seq").toArray().map((r) => r.from_device));
    expect(from).toEqual([f.deviceId, null]);
  });

  it("isolates accounts and rejects foreign, revoked and AK signatures", async () => {
    const a = await created(await randomFixture());
    const b = await created(await randomFixture());
    const r = revision();
    await push(a, [r]);
    expect((await page(b, "?after=0")).revisions).toEqual([]);
    expect(await (await push(b, [r])).json()).toEqual({ accepted: [r.id], duplicate: [] }); // no dedupe across accounts
    expect((await pull(b, "?after=0", a.deviceId, a.device)).status).toBe(401);
    expect((await push(a, [revision()], a.deviceId, await newKey())).status).toBe(401);
    expect((await push(a, [revision()], "ak", a.ak)).status).toBe(401);
    const second = await enroll(a);
    await call({ account: a.account, device: a.deviceId, key: a.device, method: "DELETE", path: `/api/v1/devices/${second.id}` });
    expect((await push(a, [revision()], second.id, second.key)).status).toBe(403);
    expect((await pull(a, "?after=0", second.id, second.key)).status).toBe(403);
  });
});
