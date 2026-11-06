// Shared fixtures for the Worker tests: signed requests, accounts, devices.
import { exports } from "cloudflare:workers";
import { expect } from "vitest";
import keyVectors from "../../spec/vectors/keys.json";
import slotVectors from "../../spec/vectors/slot.json";
import { accountIdEncode, b64Encode, canon, concat, hexDecode, hexEncode, requestMessage, slotSigMessage, str, u32, accountIdDecode } from "../src/wire";

export const TOKEN = "test-registration-token";
export const hex = (s: string) => hexDecode(s, s.length / 2)!;
export const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
export const nowSeconds = () => Math.floor(Date.now() / 1000);
export const randomIp = () => `10.${random(3).join(".")}`;

export type Key = { priv: CryptoKey; pub: Uint8Array };

export async function keyFromSeed(seed: Uint8Array): Promise<Key> {
  const pkcs8 = concat([hex("302e020100300506032b657004220420"), seed]);
  const priv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  const jwk = (await crypto.subtle.exportKey("jwk", priv)) as JsonWebKey;
  const pub = Uint8Array.from(atob(jwk.x!.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  return { priv, pub };
}

export const newKey = () => keyFromSeed(random(32));

export async function sign(key: Key, msg: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.priv, msg));
}

export type Call = {
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

export async function signedRequest(c: Call): Promise<Request> {
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

export async function call(c: Call): Promise<Response> {
  return exports.default.fetch(await signedRequest(c));
}

export type Slot = { version: number; bytes: Uint8Array; akSig: Uint8Array };

export async function makeSlot(accountId: Uint8Array, ak: Key, version: number): Promise<Slot> {
  const params = canon("hort/v4/argon\n", random(32), u32(3), u32(65536), new Uint8Array([4]));
  const bytes = canon("hort/v4/slot-bytes\n", params, random(12), random(48));
  return { version, bytes, akSig: await sign(ak, slotSigMessage(accountId, "passphrase", version, bytes)) };
}

export const slotJson = (s: Slot) => ({ version: s.version, bytes: b64Encode(s.bytes), ak_sig: b64Encode(s.akSig) });

export type Fixture = { account: string; ak: Key; deviceId: string; device: Key; slot: Slot };

export function createBody(f: Fixture): string {
  return JSON.stringify({
    account_id: f.account,
    ak_pub: b64Encode(f.ak.pub),
    slot: { id: "passphrase", ...slotJson(f.slot) },
    device: { id: f.deviceId, pub: b64Encode(f.device.pub), name: "macos-ab12" },
  });
}

export function createCall(f: Fixture, extra: Partial<Call> = {}): Call {
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
export async function vectorFixture(): Promise<Fixture> {
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

export async function randomFixture(): Promise<Fixture> {
  const id = random(16);
  const ak = await newKey();
  return { account: accountIdEncode(id), ak, deviceId: hexEncode(random(16)), device: await newKey(), slot: await makeSlot(id, ak, 1) };
}

export async function created(f: Fixture): Promise<Fixture> {
  const res = await call(createCall(f));
  expect(res.status, await res.clone().text()).toBe(201);
  return f;
}

export async function enroll(f: Fixture): Promise<{ id: string; key: Key; res: Response }> {
  const id = hexEncode(random(16));
  const key = await newKey();
  const body = JSON.stringify({ device_id: id, pub: b64Encode(key.pub), name: "linux-zz99" });
  const res = await call({ account: f.account, device: "ak", key: f.ak, method: "POST", path: "/api/v1/devices", body });
  return { id, key, res };
}

export const listDevices = (f: Fixture, deviceId = f.deviceId, key = f.device) =>
  call({ account: f.account, device: deviceId, key, method: "GET", path: "/api/v1/devices" });

export const fetchSlot = (account: string, ip = randomIp()) =>
  exports.default.fetch(new Request(`https://hort.test/api/v1/accounts/${account}/slot`, { headers: { "CF-Connecting-IP": ip } }));

export const putSlot = (f: Fixture, slot: Slot, key = f.ak, account = f.account) =>
  call({ account, device: "ak", key, method: "PUT", path: "/api/v1/slots/passphrase", body: JSON.stringify(slotJson(slot)) });
