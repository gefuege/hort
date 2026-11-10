// share-core against every case of spec/vectors/share.json.
import { describe, expect, it } from "vitest";
import keyVectors from "../../spec/vectors/keys.json";
import shareVectors from "../../spec/vectors/share.json";
import { argon2id } from "../web/argon2";
import {
  deriveShareKeys,
  formatShareLink,
  normalizeShareName,
  openShare,
  openShareMeta,
  parseShareLink,
  sealShare,
  sealShareMeta,
  type SharedSecret,
} from "../web/share-core";
import { deriveAccountKeys } from "../web/vault-core";
import { b64Encode, hexDecode, hexEncode, str } from "../src/wire";

const hex = (s: string) => hexDecode(s, s.length / 2)!;
const { normalize, keys, ct, meta, link } = shareVectors.vectors;

describe("share.json", () => {
  it("normalizes names as Go does", () => {
    for (const v of normalize) {
      expect(normalizeShareName(v.input), v.name).toBe(v.normalized);
      expect(normalizeShareName(v.normalized), v.name).toBe(v.normalized);
    }
  });

  it("derives Argon2id output, token and token hash; the encryption key reproduces the ciphertext", async () => {
    for (const v of keys) {
      expect(hexEncode(str(normalizeShareName(v.input))), v.name).toBe(v.normalized_utf8_hex);
      const a = await argon2id(hex(v.normalized_utf8_hex), hex(v.share_id), { t: v.argon.t, m: v.argon.m_kib, p: v.argon.p });
      expect(hexEncode(a), v.name).toBe(v.argon_output_hex);
      const k = await deriveShareKeys(v.input, hex(v.link_key_hex), v.share_id, { t: v.argon.t, m: v.argon.m_kib, p: v.argon.p });
      expect(hexEncode(k.token), v.name).toBe(v.token_hex);
      expect(b64Encode(k.token), v.name).toBe(v.token_base64);
      expect(hexEncode(k.tokenHash), v.name).toBe(v.token_hash_hex);
      expect(b64Encode(k.tokenHash), v.name).toBe(v.token_hash_base64);
      if (v.enc_key_hex === ct[0].enc_key_hex) {
        expect(hexEncode(await sealShare(k, ct[0].share_id, ct[0].secret, hex(ct[0].nonce_hex)))).toBe(ct[0].ct_hex);
      }
    }
  }, 60_000);

  it("rejects an empty name and a link key of the wrong size", async () => {
    const v = keys[1];
    const argon = { t: v.argon.t, m: v.argon.m_kib, p: v.argon.p };
    await expect(deriveShareKeys(" \t ", hex(v.link_key_hex), v.share_id, argon)).rejects.toThrow("name is empty");
    await expect(deriveShareKeys(v.input, new Uint8Array(31), v.share_id, argon)).rejects.toThrow("link key");
  });

  it("seals the vector plaintexts to the vector ciphertexts and opens them", async () => {
    const v = keys[1];
    const k = await deriveShareKeys(v.input, hex(v.link_key_hex), v.share_id, { t: v.argon.t, m: v.argon.m_kib, p: v.argon.p });
    for (const c of ct) {
      expect(c.enc_key_hex).toBe(v.enc_key_hex);
      const sealed = await sealShare(k, c.share_id, c.secret, hex(c.nonce_hex));
      expect(hexEncode(sealed), c.name).toBe(c.ct_hex);
      expect(b64Encode(sealed), c.name).toBe(c.ct_base64);
      expect(await openShare(k, c.share_id, hex(c.ct_hex))).toEqual(c.secret);
      await expect(openShare(k, "0".repeat(31) + "1", hex(c.ct_hex))).rejects.toThrow("share does not open");
    }
    const other = await deriveShareKeys("someone else", hex(v.link_key_hex), v.share_id, { t: v.argon.t, m: v.argon.m_kib, p: v.argon.p });
    await expect(openShare(other, ct[0].share_id, hex(ct[0].ct_hex))).rejects.toThrow("share does not open");
    const invalid: SharedSecret[] = [
      { name: "db", description: "", fields: [] },
      { name: "", description: "", fields: [{ field: "", value: "v" }] },
      { name: "db", description: "", fields: [{ field: "user", value: "a" }, { field: "user", value: "b" }] },
      { name: "db", description: "", fields: [{ field: "User", value: "a" }] },
    ];
    for (const s of invalid) await expect(sealShare(k, ct[0].share_id, s)).rejects.toThrow();
  });

  it("seals and opens the owner's share meta under RK", async () => {
    const m = meta[0];
    const ak = await deriveAccountKeys(hex(keyVectors.vectors[0].vk_hex), hex(m.account_id_hex));
    const sealed = await sealShareMeta(ak, m.share_id, m.meta, hex(m.nonce_hex));
    expect(hexEncode(sealed)).toBe(m.meta_ct_hex);
    expect(b64Encode(sealed)).toBe(m.meta_ct_base64);
    expect(await openShareMeta(ak, m.share_id, hex(m.meta_ct_hex))).toEqual(m.meta);
  });

  it("parses and formats share links", () => {
    for (const v of link) {
      const parsed = parseShareLink(v.link);
      if (v.error) {
        expect(parsed, v.name).toBeNull();
        continue;
      }
      expect(parsed, v.name).not.toBeNull();
      expect(parsed!.origin, v.name).toBe(v.origin);
      expect(parsed!.shareId, v.name).toBe(v.share_id);
      expect(hexEncode(parsed!.linkKey), v.name).toBe(v.link_key_hex);
      expect(formatShareLink(v.origin!, v.share_id!, hex(v.link_key_hex!)), v.name).toBe(v.link);
    }
  });
});
