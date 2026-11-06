import { describe, expect, it } from "vitest";
import canonVectors from "../../spec/vectors/canon.json";
import requestVectors from "../../spec/vectors/request.json";
import secretKeyVectors from "../../spec/vectors/secret-key.json";
import slotVectors from "../../spec/vectors/slot.json";
import {
  accountIdDecode,
  accountIdEncode,
  b64Decode,
  canon,
  ed25519Verify,
  hexDecode,
  hexEncode,
  isPassphraseSlotBytes,
  slotSigMessage,
  str,
  verifyRequest,
} from "../src/wire";

const hex = (s: string) => {
  const b = hexDecode(s, s.length / 2);
  if (!b) throw new Error(`bad hex ${s}`);
  return b;
};

describe("canon (spec/vectors/canon.json)", () => {
  for (const v of canonVectors.vectors) {
    it(v.name, () => {
      expect(hexEncode(canon(v.tag, ...v.fields_hex.map(hex)))).toBe(v.output_hex);
    });
  }
});

describe("account ID (spec/vectors/secret-key.json)", () => {
  for (const v of secretKeyVectors.vectors.account_ids) {
    it(v.display, () => {
      expect(accountIdEncode(hex(v.account_id_hex))).toBe(v.display);
      expect(hexEncode(accountIdDecode(v.display)!)).toBe(v.account_id_hex);
    });
  }
  it("rejects non-canonical forms", () => {
    expect(accountIdDecode("0AXXW4GW3H5SEW31C7CMZEM3HM")).toBeNull();
    expect(accountIdDecode("0axxw4gw3h5sew31c7cmzem3hn")).toBeNull(); // nonzero padding bits
    expect(accountIdDecode("0axxw4gw3h5sew31c7cmzem3h")).toBeNull();
    expect(accountIdDecode("0axxw4gw3h5sew31c7cmzem3hu")).toBeNull();
  });
});

describe("request signature (spec/vectors/request.json)", () => {
  for (const v of requestVectors.vectors.signature) {
    it(v.name, async () => {
      const req = {
        accountId: v.hort_account,
        device: v.hort_device,
        method: v.method,
        pathWithQuery: v.path_with_query,
        timestamp: v.timestamp,
        signature: b64Decode(v.hort_signature)!,
        body: str(v.body),
      };
      expect(hexEncode(req.signature)).toBe(v.signature_hex);
      const pub = hex(v.public_key_hex);
      expect(await verifyRequest(req, pub)).toBe(true);
      expect(await ed25519Verify(pub, req.signature, hex(v.message_hex))).toBe(true);
      // Any change to a signed field breaks the signature.
      expect(await verifyRequest({ ...req, pathWithQuery: v.path_with_query + "x" }, pub)).toBe(false);
      expect(await verifyRequest({ ...req, timestamp: v.timestamp + 1 }, pub)).toBe(false);
      expect(await verifyRequest({ ...req, body: str(v.body + " ") }, pub)).toBe(false);
    });
  }
});

describe("slot ak_sig (spec/vectors/slot.json)", () => {
  for (const v of slotVectors.vectors) {
    it(`slot ${v.slot_id} v${v.slot_version}`, async () => {
      const slotBytes = hex(v.slot_bytes_hex);
      expect(isPassphraseSlotBytes(slotBytes)).toBe(true);
      const msg = slotSigMessage(hex(v.account_id_hex), v.slot_id, v.slot_version, slotBytes);
      expect(hexEncode(msg)).toBe(v.sig_message_hex);
      expect(await ed25519Verify(hex(v.ak_public_hex), hex(v.ak_sig_hex), msg)).toBe(true);
      const older = slotSigMessage(hex(v.account_id_hex), v.slot_id, v.slot_version - 1, slotBytes);
      expect(await ed25519Verify(hex(v.ak_public_hex), hex(v.ak_sig_hex), older)).toBe(false);
    });
  }
});
