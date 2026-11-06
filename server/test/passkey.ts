// A software WebAuthn authenticator (ES256, attestation "none") and session
// helpers for the Worker tests.
import { exports } from "cloudflare:workers";
import { expect } from "vitest";
import { accountIdDecode, b64Encode, b64urlEncode, canon, concat, hexEncode, sha256, slotSigMessage, str, u64 } from "../src/wire";
import { call, randomIp, sign, type Fixture } from "./helpers";

export const ORIGIN = "https://hort.test";
const RP_ID = "hort.test";

// Minimal CBOR encoder for the attestation object and COSE key.
function cbor(v: unknown): Uint8Array {
  const head = (major: number, n: number) =>
    n < 24 ? new Uint8Array([(major << 5) | n]) : n < 256 ? new Uint8Array([(major << 5) | 24, n]) : new Uint8Array([(major << 5) | 25, n >> 8, n & 255]);
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") return concat([head(3, str(v).length), str(v)]);
  if (v instanceof Uint8Array) return concat([head(2, v.length), v]);
  if (v instanceof Map) return concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error("unsupported CBOR value");
}

// ECDSA P-256 signature from WebCrypto (r || s) to the DER form WebAuthn uses.
function der(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.subarray(i);
    return concat([new Uint8Array([2, v.length + (v[0] & 0x80 ? 1 : 0)]), v[0] & 0x80 ? new Uint8Array([0]) : new Uint8Array(), v]);
  };
  const body = concat([int(raw.subarray(0, 32)), int(raw.subarray(32))]);
  return concat([new Uint8Array([0x30, body.length]), body]);
}

const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

export class Authenticator {
  counter = 0;
  private constructor(
    readonly credentialId: Uint8Array,
    private readonly key: CryptoKeyPair,
    private readonly cose: Uint8Array,
  ) {}

  static async create(counter = 0): Promise<Authenticator> {
    const key = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", key.publicKey)) as ArrayBuffer);
    const cose = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, raw.subarray(1, 33)], [-3, raw.subarray(33)]]));
    const a = new Authenticator(crypto.getRandomValues(new Uint8Array(20)), key, cose);
    a.counter = counter;
    return a;
  }

  get id(): string {
    return b64urlEncode(this.credentialId);
  }

  private async authData(flags: number, attested: boolean): Promise<Uint8Array> {
    const count = new Uint8Array(4);
    new DataView(count.buffer).setUint32(0, this.counter);
    const parts = [await sha256(str(RP_ID)), new Uint8Array([flags]), count];
    if (attested) parts.push(new Uint8Array(16), new Uint8Array([0, this.credentialId.length]), this.credentialId, this.cose);
    return concat(parts);
  }

  async register(challenge: string, o: { origin?: string; uv?: boolean } = {}) {
    const clientData = str(JSON.stringify({ type: "webauthn.create", challenge, origin: o.origin ?? ORIGIN, crossOrigin: false }));
    const authData = await this.authData(UP | AT | (o.uv === false ? 0 : UV), true);
    const attestation = cbor(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      response: { clientDataJSON: b64urlEncode(clientData), attestationObject: b64urlEncode(attestation), transports: ["internal"] },
      clientExtensionResults: {},
    };
  }

  async assert(challenge: string, userHandle: Uint8Array, o: { origin?: string; uv?: boolean; counter?: number } = {}) {
    this.counter = o.counter ?? (this.counter === 0 ? 0 : this.counter + 1);
    const clientData = str(JSON.stringify({ type: "webauthn.get", challenge, origin: o.origin ?? ORIGIN, crossOrigin: false }));
    const authData = await this.authData(UP | (o.uv === false ? 0 : UV), false);
    const raw = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.key.privateKey, concat([authData, await sha256(clientData)])),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      response: {
        clientDataJSON: b64urlEncode(clientData),
        authenticatorData: b64urlEncode(authData),
        signature: b64urlEncode(der(raw)),
        userHandle: b64urlEncode(userHandle),
      },
      clientExtensionResults: {},
    };
  }
}

// A passkey slot as the browser builds it, from a simulated PRF output.
export async function passkeySlot(f: Fixture, a: Authenticator, prf: Uint8Array, vk: Uint8Array, version = 1) {
  const accountId = accountIdDecode(f.account)!;
  const hash = await sha256(a.credentialId);
  const slotId = `passkey:${hexEncode(hash)}`;
  const params = canon("hort/v4/passkey\n", hash);
  const kek = await kekFromPRF(prf, accountId);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = canon("hort/v4/slot\n", accountId, str(slotId), u64(version), params);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, kek, vk));
  const bytes = canon("hort/v4/slot-bytes\n", params, nonce, wrapped);
  const akSig = await sign(f.ak, slotSigMessage(accountId, slotId, version, bytes));
  return { slotId, json: { version, bytes: b64Encode(bytes), ak_sig: b64Encode(akSig) } };
}

export async function kekFromPRF(prf: Uint8Array, accountId: Uint8Array): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: accountId, info: str("hort/v4/kek-passkey") },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export const registerOptions = (f: Fixture, key = f.ak) =>
  call({ account: f.account, device: "ak", key, method: "POST", path: "/api/v1/webauthn/register/options" });

export const registerVerify = (f: Fixture, body: unknown, key = f.ak) =>
  call({ account: f.account, device: "ak", key, method: "POST", path: "/api/v1/webauthn/register/verify", body: JSON.stringify(body) });

export async function registerPasskey(f: Fixture, a: Authenticator, slot: unknown = null): Promise<Response> {
  const options = await registerOptions(f);
  expect(options.status, await options.clone().text()).toBe(200);
  const { challenge } = (await options.json()) as { challenge: string };
  return registerVerify(f, { response: await a.register(challenge), slot });
}

export const post = (path: string, body?: unknown, headers: Record<string, string> = {}, ip = randomIp()) =>
  exports.default.fetch(
    new Request(ORIGIN + path, {
      method: "POST",
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: { "CF-Connecting-IP": ip, ...headers },
    }),
  );

export async function loginChallenge(ip = randomIp()): Promise<string> {
  const res = await post("/api/v1/webauthn/login/options", undefined, {}, ip);
  expect(res.status).toBe(200);
  return ((await res.json()) as { challenge: string }).challenge;
}

export async function login(f: Fixture, a: Authenticator, o: { origin?: string; uv?: boolean; counter?: number } = {}): Promise<Response> {
  const assertion = await a.assert(await loginChallenge(), accountIdDecode(f.account)!, o);
  return post("/api/v1/webauthn/login/verify", assertion);
}

export function cookieOf(res: Response): string {
  return res.headers.get("Set-Cookie")!.split(";")[0];
}

// Registers a passkey without PRF and signs in with it; returns the cookie.
export async function session(f: Fixture): Promise<string> {
  const a = await Authenticator.create();
  expect((await registerPasskey(f, a)).status).toBe(201);
  const res = await login(f, a);
  expect(res.status, await res.clone().text()).toBe(200);
  return cookieOf(res);
}

// A browser call with the session cookie; writes carry Hort-CSRF and Origin.
export function sessionFetch(cookie: string, method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<Response> {
  const write = method !== "GET";
  return exports.default.fetch(
    new Request(ORIGIN + path, {
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: { Cookie: cookie, "CF-Connecting-IP": randomIp(), ...(write ? { "Hort-CSRF": "1", Origin: ORIGIN } : {}), ...headers },
    }),
  );
}
