import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import keyVectors from "../../spec/vectors/keys.json";
import slotVectors from "../../spec/vectors/slot.json";
import worker from "../src/index";
import { jurisdictionCalls } from "./setup";
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

const TOKEN = "test-registration-token";
const hex = (s: string) => hexDecode(s, s.length / 2)!;
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const nowSeconds = () => Math.floor(Date.now() / 1000);
const randomIp = () => `10.${random(3).join(".")}`;

type Key = { priv: CryptoKey; pub: Uint8Array };

async function keyFromSeed(seed: Uint8Array): Promise<Key> {
  const pkcs8 = concat([hex("302e020100300506032b657004220420"), seed]);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", priv)) as JsonWebKey;
  const pub = Uint8Array.from(atob(jwk.x!.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  return { priv, pub };
}

const newKey = () => keyFromSeed(random(32));

async function sign(key: Key, msg: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.priv, msg));
}

type Call = {
  account: string;
  device: string; // "ak" or hex device ID
  key: Key;
  method: string;
  path: string;
  body?: string;
  ts?: number;
  headers?: Record<string, string>;
  tamperBody?: string; // sent instead of the signed body
};

async function signedRequest(c: Call): Promise<Request> {
  const body = c.body ?? "";
  const ts = c.ts ?? nowSeconds();
  const device = c.device === "ak" ? str("ak") : hex(c.device);
  const msg = await requestMessage(accountIdDecode(c.account)!, device, c.method, c.path, ts, str(body));
  return new Request(`https://hort.test${c.path}`, {
    method: c.method,
    body: c.method === "GET" ? undefined : (c.tamperBody ?? body),
    headers: {
      "Hort-Account": c.account,
      "Hort-Device": c.device,
      "Hort-Timestamp": String(ts),
      "Hort-Signature": b64Encode(await sign(c.key, msg)),
      "CF-Connecting-IP": randomIp(),
      ...c.headers,
    },
  });
}

async function call(c: Call): Promise<Response> {
  return exports.default.fetch(await signedRequest(c));
}

type Slot = { version: number; bytes: Uint8Array; akSig: Uint8Array };

async function makeSlot(accountId: Uint8Array, ak: Key, version: number): Promise<Slot> {
  const params = canon("hort/v4/argon\n", random(32), u32(3), u32(65536), new Uint8Array([4]));
  const bytes = canon("hort/v4/slot-bytes\n", params, random(12), random(48));
  return { version, bytes, akSig: await sign(ak, slotSigMessage(accountId, "passphrase", version, bytes)) };
}

const slotJson = (s: Slot) => ({ version: s.version, bytes: b64Encode(s.bytes), ak_sig: b64Encode(s.akSig) });

type Fixture = { account: string; ak: Key; deviceId: string; device: Key; slot: Slot };

function createBody(f: Fixture): string {
  return JSON.stringify({
    account_id: f.account,
    ak_pub: b64Encode(f.ak.pub),
    slot: { id: "passphrase", ...slotJson(f.slot) },
    device: { id: f.deviceId, pub: b64Encode(f.device.pub), name: "macos-ab12" },
  });
}

function createCall(f: Fixture, extra: Partial<Call> = {}): Call {
  return {
    account: f.account,
    device: "ak",
    key: f.ak,
    method: "POST",
    path: "/api/v1/accounts",
    body: createBody(f),
    headers: { "Hort-Registration-Token": TOKEN },
    ...extra,
  };
}

// The account from the shared vectors: real AK, real slot and ak_sig.
async function vectorFixture(): Promise<Fixture> {
  const v = slotVectors.vectors[0];
  const ak = await keyFromSeed(hex(keyVectors.vectors[0].aks_hex));
  expect(hexEncode(ak.pub)).toBe(v.ak_public_hex);
  return {
    account: accountIdEncode(hex(v.account_id_hex)),
    ak,
    deviceId: hexEncode(random(16)),
    device: await newKey(),
    slot: { version: v.slot_version, bytes: hex(v.slot_bytes_hex), akSig: hex(v.ak_sig_hex) },
  };
}

async function randomFixture(): Promise<Fixture> {
  const id = random(16);
  const ak = await newKey();
  return { account: accountIdEncode(id), ak, deviceId: hexEncode(random(16)), device: await newKey(), slot: await makeSlot(id, ak, 1) };
}

async function created(f: Fixture): Promise<Fixture> {
  const res = await call(createCall(f));
  expect(res.status, await res.clone().text()).toBe(201);
  return f;
}

async function enroll(f: Fixture): Promise<{ id: string; key: Key; res: Response }> {
  const id = hexEncode(random(16));
  const key = await newKey();
  const body = JSON.stringify({ device_id: id, pub: b64Encode(key.pub), name: "linux-zz99" });
  const res = await call({ account: f.account, device: "ak", key: f.ak, method: "POST", path: "/api/v1/devices", body });
  return { id, key, res };
}

const listDevices = (f: Fixture, deviceId = f.deviceId, key = f.device) =>
  call({ account: f.account, device: deviceId, key, method: "GET", path: "/api/v1/devices" });

const fetchSlot = (account: string, ip = randomIp()) =>
  exports.default.fetch(new Request(`https://hort.test/api/v1/accounts/${account}/slot`, { headers: { "CF-Connecting-IP": ip } }));

const putSlot = (f: Fixture, slot: Slot, key = f.ak, account = f.account) =>
  call({ account, device: "ak", key, method: "PUT", path: "/api/v1/slots/passphrase", body: JSON.stringify(slotJson(slot)) });

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
