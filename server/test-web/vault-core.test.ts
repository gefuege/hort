// vault-core against every vector and reduction fixture in spec/vectors.
import { describe, expect, it } from "vitest";
import envelopeVectors from "../../spec/vectors/envelope.json";
import foldVectors from "../../spec/vectors/fold.json";
import kekVectors from "../../spec/vectors/kek.json";
import keyVectors from "../../spec/vectors/keys.json";
import passkeySlotVectors from "../../spec/vectors/passkey-slot.json";
import reductionVectors from "../../spec/vectors/reduction.json";
import requestVectors from "../../spec/vectors/request.json";
import secretKeyVectors from "../../spec/vectors/secret-key.json";
import slotVectors from "../../spec/vectors/slot.json";
import { b64Decode, hexDecode, hexEncode, requestMessage, str } from "../src/wire";
import {
  akHeaders,
  appendStamp,
  argonOutput,
  argonSlotParams,
  current,
  deriveAccountKeys,
  entries,
  entryOf,
  foldKey,
  ed25519FromSeed,
  envelopePlaintext,
  formatSecretKey,
  formatTime,
  history,
  hkdf,
  lookupKey,
  openRequestMeta,
  newPassphraseSlot,
  openRevision,
  parseAccountId,
  PASSPHRASE_SLOT,
  parseArgonParams,
  parseSecretKey,
  parseSlotBytes,
  parseTime,
  passkeyKEKBytes,
  passkeySlot,
  passphraseKEKBytes,
  prfEvalSalt,
  resolve,
  sealRevision,
  spelling,
  unwrapSlot,
  validateWrite,
  verifySlotAuthority,
  wrapSlot,
  type Revision,
} from "../web/vault-core";

const hex = (s: string) => hexDecode(s, s.length / 2)!;

type RevJSON = { id: string; recorded_at: string | null; op: string; field?: string; key: string; value: string };
const rev = (r: RevJSON): Revision => ({
  id: r.id,
  recordedAt: r.recorded_at === null ? null : parseTime(r.recorded_at),
  op: r.op as Revision["op"],
  field: r.field ?? "",
  key: r.key,
  value: r.value,
});

describe("keys.json", () => {
  for (const v of keyVectors.vectors) {
    it("derives FK, RK, AKs and the AK public key", async () => {
      const vk = hex(v.vk_hex);
      const id = hex(v.account_id_hex);
      expect(hexEncode(await hkdf(vk, id, "hort/v4/file"))).toBe(v.fk_hex);
      expect(hexEncode(await hkdf(vk, id, "hort/v4/revision"))).toBe(v.rk_hex);
      expect(hexEncode(await hkdf(vk, id, "hort/v4/account-auth"))).toBe(v.aks_hex);
      expect(hexEncode((await ed25519FromSeed(hex(v.aks_hex))).pub)).toBe(v.ak_public_hex);
      const keys = await deriveAccountKeys(vk, id);
      expect(hexEncode(keys.akPub)).toBe(v.ak_public_hex);
      expect(keys.rk.extractable).toBe(false);
      expect(keys.ak.extractable).toBe(false);
    });
  }
});

describe("kek.json", () => {
  for (const v of kekVectors.vectors.passphrase) {
    it(`passphrase: ${v.name}`, async () => {
      const pass = new TextDecoder().decode(hex(v.passphrase_utf8_hex));
      const argon = { t: v.argon.t, m: v.argon.m_kib, p: v.argon.p };
      expect(hexEncode(await argonOutput(pass, hex(v.slot_salt_hex), argon))).toBe(v.argon_output_hex);
      expect(hexEncode(await hkdf(hex(v.secret_key_hex), hex(v.account_id_hex), "hort/v4/secret-key"))).toBe(v.secret_key_half_hex);
      const kek = await passphraseKEKBytes(pass, hex(v.secret_key_hex), hex(v.account_id_hex), hex(v.slot_salt_hex), argon);
      expect(hexEncode(kek)).toBe(v.kek_hex);
    }, 30_000);
  }
  for (const v of kekVectors.vectors.passkey) {
    it("passkey", async () => {
      expect(hexEncode(await prfEvalSalt(hex(v.account_id_hex)))).toBe(v.prf_eval_salt_hex);
      expect(hexEncode(await passkeyKEKBytes(hex(v.prf_output_hex), hex(v.account_id_hex)))).toBe(v.kek_hex);
    });
  }
});

describe("slot.json and passkey-slot.json", () => {
  const cases = [
    ...slotVectors.vectors.map((v) => ({ ...v, params: () => argonSlotParams(hex(v.slot_salt_hex), { t: v.argon.t, m: v.argon.m_kib, p: v.argon.p }) })),
    ...passkeySlotVectors.vectors.map((v) => ({
      ...v,
      params: () => hex(v.slot_params_hex),
    })),
  ];
  for (const v of cases) {
    it(`slot ${v.slot_id.slice(0, 20)} v${v.slot_version}: wrap, slot_bytes, ak_sig, unwrap`, async () => {
      const id = hex(v.account_id_hex);
      const keys = await deriveAccountKeys(hex(v.vk_hex), id);
      const params = v.params();
      expect(hexEncode(params)).toBe(v.slot_params_hex);
      const slot = await wrapSlot(hex(v.kek_hex), hex(v.vk_hex), keys, v.slot_id, v.slot_version, params, hex(v.wrap_nonce_hex));
      expect(hexEncode(slot.bytes)).toBe(v.slot_bytes_hex);
      expect(hexEncode(slot.akSig)).toBe(v.ak_sig_hex); // Ed25519 is deterministic
      const parsed = parseSlotBytes(slot.bytes)!;
      expect(hexEncode(parsed.wrapped)).toBe(v.wrapped_vk_hex);
      expect(hexEncode(await unwrapSlot(hex(v.kek_hex), id, v.slot_id, v.slot_version, parsed))).toBe(v.vk_hex);
      await expect(unwrapSlot(hex(v.kek_hex), id, v.slot_id, v.slot_version + 1, parsed)).rejects.toThrow("slot does not open");
      expect(await verifySlotAuthority(keys, hex(v.ak_public_hex), v.slot_id, slot)).toBe(true);
      expect(await verifySlotAuthority(keys, hex(v.ak_public_hex), v.slot_id, { ...slot, version: slot.version + 1 })).toBe(false);
    });
  }
  it("passkey slot_id and slot_params from the credential ID", async () => {
    const v = passkeySlotVectors.vectors[0];
    const { id, params } = await passkeySlot(hex(v.credential_id_hex));
    expect(id).toBe(v.slot_id);
    expect(id).toBe(`passkey:${v.cred_hash_hex}`);
    expect(hexEncode(params)).toBe(v.slot_params_hex);
    expect(hexEncode(await passkeyKEKBytes(hex(v.prf_output_hex), hex(v.account_id_hex)))).toBe(v.kek_hex);
  });
  it("parses Argon2id parameters within the CLI bounds only", () => {
    const v = slotVectors.vectors[0];
    expect(parseArgonParams(hex(v.slot_params_hex))).toEqual({ salt: hex(v.slot_salt_hex), argon: { t: 3, m: 65536, p: 4 } });
    const salt = hex(v.slot_salt_hex);
    expect(parseArgonParams(argonSlotParams(salt, { t: 4, m: 65536, p: 4 }))).toBeNull();
    expect(parseArgonParams(argonSlotParams(salt, { t: 3, m: 65537, p: 4 }))).toBeNull();
    expect(parseArgonParams(argonSlotParams(salt, { t: 3, m: 31, p: 4 }))).toBeNull();
    expect(parseArgonParams(argonSlotParams(salt, { t: 1, m: 256, p: 1 }))).not.toBeNull();
  });
});

describe("envelope.json", () => {
  for (const v of envelopeVectors.vectors) {
    it(v.name, async () => {
      const keys = await deriveAccountKeys(hex(keyVectors.vectors[0].vk_hex), hex(v.account_id_hex));
      const r = rev(v.revision);
      expect(new TextDecoder().decode(envelopePlaintext(v.entry_name, r))).toBe(v.plaintext);
      const env = await sealRevision(keys, v.entry_name, r, hex(v.nonce_hex));
      expect(hexEncode(env)).toBe(v.envelope_hex);
      const opened = await openRevision(keys, v.revision.id, b64Decode(v.envelope_base64)!);
      expect(opened.name).toBe(v.entry_name);
      expect(opened.revision).toEqual(r);
      await expect(openRevision(keys, "00000000000000000000000000000063", env)).rejects.toThrow();
    });
  }
  it("rejects envelopes that fail the decoding rules", async () => {
    const keys = await deriveAccountKeys(hex(keyVectors.vectors[0].vk_hex), hex(keyVectors.vectors[0].account_id_hex));
    const id = "000000000000000000000000000000aa";
    const sealRaw = async (json: string) => {
      const { canon } = await import("../src/wire");
      const nonce = new Uint8Array(12);
      const aad = canon("hort/v4/rev\n", keys.accountId, hex(id));
      const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad as BufferSource }, keys.rk, str(json) as BufferSource);
      return new Uint8Array([...nonce, ...new Uint8Array(ct)]);
    };
    const r = (o: object) => JSON.stringify({ name: "n", revision: { id, recorded_at: "2026-01-01T00:00:00Z", op: "set", key: "*:*", value: "v", ...o } });
    await expect(openRevision(keys, id, await sealRaw(r({ recorded_at: "2026-01-01T01:00:00+01:00" })))).rejects.toThrow("UTC");
    await expect(openRevision(keys, id, await sealRaw(r({ op: "delete", value: "x" })))).rejects.toThrow("invalid delete");
    await expect(openRevision(keys, id, await sealRaw(r({ extra: 1 })))).rejects.toThrow("members");
    await expect(openRevision(keys, id, await sealRaw(r({ field: "Bad" })))).rejects.toThrow("field");
    await expect(openRevision(keys, id, await sealRaw(r({ id: "000000000000000000000000000000bb" })))).rejects.toThrow("envelope holds");
    // A legacy name with whitespace and a v3 key stay readable.
    const legacy = JSON.stringify({ name: "legacy name", revision: { id, recorded_at: null, op: "set", key: "a b:*", value: "v" } });
    expect((await openRevision(keys, id, await sealRaw(legacy))).name).toBe("legacy name");
  });
});

describe("request.json", () => {
  for (const v of requestVectors.vectors.meta) {
    it(`meta ${v.request_id}`, async () => {
      const keys = await deriveAccountKeys(hex(keyVectors.vectors[0].vk_hex), hex(v.account_id_hex));
      expect(await openRequestMeta(keys, v.request_id, b64Decode(v.meta_ct_base64)!)).toEqual(v.meta);
      await expect(openRequestMeta(keys, "00".repeat(16), hex(v.meta_ct_hex))).rejects.toThrow();
    });
  }
  it("AK request signature verifies under the vector message scheme", async () => {
    const v = requestVectors.vectors.signature.find((s) => s.hort_device === "ak")!;
    const keys = await deriveAccountKeys(hex(keyVectors.vectors[0].vk_hex), hex(v.account_id_hex));
    const h = await akHeaders(keys, v.method, v.path_with_query, str(v.body), v.timestamp);
    expect(h).toEqual({ "Hort-Account": v.hort_account, "Hort-Device": "ak", "Hort-Timestamp": String(v.timestamp), "Hort-Signature": v.hort_signature });
    const msg = await requestMessage(keys.accountId, str("ak"), v.method, v.path_with_query, v.timestamp, str(v.body));
    expect(hexEncode(msg)).toBe(v.message_hex);
  });
});

describe("secret-key.json", () => {
  for (const v of secretKeyVectors.vectors.secret_keys) {
    it(`format ${v.name}`, async () => {
      expect(await formatSecretKey(hex(v.secret_key_hex))).toBe(v.display);
      expect(hexEncode(await parseSecretKey(v.display))).toBe(v.secret_key_hex);
    });
  }
  for (const v of secretKeyVectors.vectors.parse) {
    it(`parse ${v.name}`, async () => {
      if ("error" in v && v.error) await expect(parseSecretKey(v.input)).rejects.toThrow(v.error);
      else expect(hexEncode(await parseSecretKey(v.input))).toBe((v as { secret_key_hex: string }).secret_key_hex);
    });
  }
  for (const v of secretKeyVectors.vectors.account_ids) {
    it(`account ID ${v.display}`, () => {
      expect(hexEncode(parseAccountId(v.display)!)).toBe(v.account_id_hex);
      expect(hexEncode(parseAccountId(v.display.toUpperCase().replace(/0/g, "O"))!)).toBe(v.account_id_hex);
    });
  }
});

describe("reduction.json", () => {
  for (const v of reductionVectors.vectors.reduce) {
    it(`reduce: ${v.name}`, () => {
      const revs = v.revisions.map(rev);
      expect(history(revs).map((r) => r.id)).toEqual(v.history_ids);
      const c = current(revs);
      expect([...c.values.values()].sort((a, b) => (a.field + a.key < b.field + b.key ? -1 : 1))).toEqual(
        [...v.values].sort((a, b) => (a.field + a.key < b.field + b.key ? -1 : 1)),
      );
      expect(c.description).toBe(v.description);
      expect(c.visible).toBe(v.visible);
      for (const q of v.resolve) expect(resolve(revs, q.field, q.env, q.context), JSON.stringify(q)).toBe(q.value);
    });
  }
  for (const v of reductionVectors.vectors.append) {
    it(`append: ${v.name}`, () => {
      expect(formatTime(appendStamp(v.existing.map(rev), parseTime(v.now)!))).toBe(v.recorded_at);
    });
  }
  it("times keep nanoseconds through parse and format", () => {
    for (const s of ["2026-01-01T00:20:00.500000001Z", "2026-11-06T10:00:00Z", "1999-12-31T23:59:59.1Z"]) expect(formatTime(parseTime(s)!)).toBe(s);
    expect(parseTime("2026-02-30T00:00:00Z")).toBeNull();
    expect(parseTime("2026-01-01T00:00:00")).toBeNull();
  });
});

describe("fold.json", () => {
  it("folds as Go does", () => {
    for (const v of foldVectors.vectors.fold) {
      expect(foldKey(v.input), v.name).toBe(v.folded);
      expect(foldKey(v.folded), v.name).toBe(v.folded);
    }
  });
  const { stored, entries: want, resolve: queries, spell } = foldVectors.vectors.reduce;
  const vault = (list: typeof stored) => {
    const m = new Map<string, Revision[]>();
    for (const s of list) m.set(s.name, [...(m.get(s.name) ?? []), rev(s.revision)]);
    return m;
  };
  const byKey = (a: { field: string; key: string }, b: { field: string; key: string }) => (a.field + "\u0000" + a.key < b.field + "\u0000" + b.key ? -1 : 1);
  for (const list of [stored, [...stored].reverse()]) {
    it(`reduce: entries, display spellings, values and history (${list === stored ? "arrival" : "reversed"} order)`, () => {
      const got = [...entries(vault(list))].sort(([a], [b]) => (a < b ? -1 : 1));
      expect(got.map(([name]) => name)).toEqual(want.map((e) => e.name));
      got.forEach(([, revs], i) => {
        expect(history(revs).map((r) => r.id)).toEqual(want[i].history_ids);
        const c = current(revs);
        expect([...c.values.values()].sort(byKey)).toEqual([...want[i].values].sort(byKey));
        expect(c.description).toBe(want[i].description);
        expect(c.visible).toBe(want[i].visible);
      });
    });
  }
  it("reduce: resolve and write spelling", () => {
    const m = vault(stored);
    for (const q of queries) expect(resolve(entryOf(m, q.name).revisions, q.field, q.env, q.context), JSON.stringify(q)).toBe(q.value);
    for (const q of spell) {
      const e = entryOf(m, q.name);
      expect({ name: e.name, ...spelling(e.revisions, q.field, lookupKey(q.env, q.context)) }, JSON.stringify(q)).toEqual({ name: q.write_name, field: q.write_field, key: q.write_key });
    }
  });
});

describe("write validation (§3.4)", () => {
  const r = (o: Partial<Revision>): Revision => ({ id: "00".repeat(16), recordedAt: 0n, op: "set", field: "", key: "*:*", value: "v", ...o });
  it("accepts valid writes", () => {
    expect(validateWrite("github-token", r({}))).toBeNull();
    expect(validateWrite("db", r({ field: "password", key: "prod:heine" }))).toBeNull();
    expect(validateWrite("db", r({ op: "describe", key: "", value: "Postgres" }))).toBeNull();
  });
  it("rejects names, fields, keys and sizes outside the write rules", () => {
    expect(validateWrite("has space", r({}))).toMatch(/delete it and re-create/);
    expect(validateWrite("-flag", r({}))).not.toBeNull();
    expect(validateWrite("x".repeat(129), r({}))).not.toBeNull();
    expect(validateWrite("ok", r({ field: "Upper" }))).not.toBeNull();
    expect(validateWrite("ok", r({ op: "describe", field: "f", key: "" }))).not.toBeNull();
    expect(validateWrite("ok", r({ key: "a:b:c" }))).not.toBeNull();
    expect(validateWrite("ok", r({ key: "pr*d:*" }))).not.toBeNull();
    expect(validateWrite("ok", r({ key: "prod :*" }))).not.toBeNull();
    expect(validateWrite("ok", r({ value: "x".repeat(64 * 1024) }))).toMatch(/too large/);
  });
  it("rejects C1 control characters in names and key parts", () => {
    expect(validateWrite("na\u0085me", r({}))).not.toBeNull();
    expect(validateWrite("ok", r({ key: "pr\u009fod:*" }))).not.toBeNull();
  });
  it("rejects a revision shape no decoder accepts", () => {
    expect(validateWrite("ok", r({ op: "delete", key: "*:*", value: "v" }))).toBe("invalid delete");
    expect(validateWrite("ok", r({ op: "delete-entry", key: "*:*", value: "" }))).toBe("invalid entry deletion");
  });
  it("allows delete and delete-entry on legacy names and keys", () => {
    expect(validateWrite("legacy name", r({ op: "delete-entry", key: "", value: "" }))).toBeNull();
    expect(validateWrite("legacy name", r({ op: "delete", key: "a b:*", value: "" }))).toBeNull();
  });
});

describe("newPassphraseSlot", () => {
  it("writes version+1 with a valid ak_sig that the Secret Key and new passphrase open", async () => {
    const accountId = crypto.getRandomValues(new Uint8Array(16));
    const vk = crypto.getRandomValues(new Uint8Array(32));
    const secretKey = crypto.getRandomValues(new Uint8Array(32));
    const keys = await deriveAccountKeys(vk, accountId);
    const argon = { t: 1, m: 256, p: 1 };
    const slot = await newPassphraseSlot(keys, vk, secretKey, "new passphrase", 4, argon);
    expect(slot.version).toBe(5);
    expect(await verifySlotAuthority(keys, keys.akPub, PASSPHRASE_SLOT, slot)).toBe(true);
    expect(await verifySlotAuthority(keys, keys.akPub, PASSPHRASE_SLOT, { ...slot, version: 6 })).toBe(false);

    const parsed = parseSlotBytes(slot.bytes)!;
    const params = parseArgonParams(parsed.params)!;
    expect(params.argon).toEqual(argon);
    const open = async (pass: string, key: Uint8Array) =>
      unwrapSlot(await passphraseKEKBytes(pass, key, accountId, params.salt, params.argon), accountId, PASSPHRASE_SLOT, slot.version, parsed);
    expect(hexEncode(await open("new passphrase", secretKey))).toBe(hexEncode(vk));
    await expect(open("old passphrase", secretKey)).rejects.toThrow("slot does not open");
    await expect(open("new passphrase", crypto.getRandomValues(new Uint8Array(32)))).rejects.toThrow("slot does not open");
  });
});
