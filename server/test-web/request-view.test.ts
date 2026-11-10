// /r/<id>: the one write that answers a request, for a request of several
// fields and for the single-field form an older Hort creates.
import { describe, expect, it } from "vitest";
import requestVectors from "../../spec/vectors/request.json";
import keyVectors from "../../spec/vectors/keys.json";
import { b64Decode, hexDecode } from "../src/wire";
import { fulfill, type Host } from "../web/request-view";
import { current, deriveAccountKeys, openRequestMeta, openRevision, resolve, type Revision } from "../web/vault-core";

const hex = (s: string) => hexDecode(s, s.length / 2)!;

// Records every call; answers fulfill with 200.
function fakeServer() {
  const calls: { method: string; path: string; body?: string }[] = [];
  const host: Pick<Host, "api" | "ok"> = {
    async api(method, path, o) {
      calls.push({ method, path, body: o?.body });
      return Response.json({ accepted: [], duplicate: [] });
    },
    async ok<T>(res: Response) {
      return (await res.json()) as T;
    },
  };
  return { host, calls };
}

async function vectorRequest(i: number) {
  const v = requestVectors.vectors.meta[i];
  const keys = await deriveAccountKeys(hex(keyVectors.vectors[0].vk_hex), hex(v.account_id_hex));
  return { keys, id: v.request_id, meta: await openRequestMeta(keys, v.request_id, b64Decode(v.meta_ct_base64)!) };
}

async function sent(keys: Awaited<ReturnType<typeof deriveAccountKeys>>, body: string) {
  const { revisions } = JSON.parse(body) as { revisions: { id: string; ct: string }[] };
  return Promise.all(revisions.map(async (r) => openRevision(keys, r.id, b64Decode(r.ct)!)));
}

describe("request-view fulfill", () => {
  it("stores every field of a request in one write", async () => {
    const { keys, id, meta } = await vectorRequest(0);
    expect(meta.fields).toEqual(["client_id", "secret"]);
    const { host, calls } = fakeServer();
    await fulfill(host, keys, id, meta, new Map(), ["cid-1", "sec-1"]);
    expect(calls.map((c) => [c.method, c.path])).toEqual([["POST", `/api/v1/requests/${id}/fulfill`]]);
    const opened = await sent(keys, calls[0].body!);
    const revisions: Revision[] = opened.map((o) => o.revision);
    expect(opened.every((o) => o.name === "stripe")).toBe(true);
    expect(revisions.map((r) => [r.op, r.field, r.key])).toEqual([["set", "client_id", "prod:*"], ["set", "secret", "prod:*"], ["describe", "", ""]]);
    expect(resolve(revisions, "client_id", "prod", "")).toBe("cid-1");
    expect(resolve(revisions, "SECRET", "prod", "")).toBe("sec-1");
    expect(current(revisions).description).toBe("Payments for the shop");
  });

  it("answers a single-field request of an older Hort", async () => {
    const { keys, id, meta } = await vectorRequest(1);
    expect(meta.fields).toEqual([""]);
    const { host, calls } = fakeServer();
    await fulfill(host, keys, id, meta, new Map(), ["key-1"]);
    const revisions = (await sent(keys, calls[0].body!)).map((o) => o.revision);
    expect(revisions.map((r) => [r.op, r.field, r.key])).toEqual([["set", "", "prod:*"], ["describe", "", ""]]);
    expect(resolve(revisions, "", "prod", "")).toBe("key-1");
  });

  it("sends nothing when a value breaks the write rules", async () => {
    const { keys, id, meta } = await vectorRequest(0);
    const { host, calls } = fakeServer();
    await expect(fulfill(host, keys, id, meta, new Map(), ["ok", "x".repeat(70_000)])).rejects.toThrow();
    expect(calls).toEqual([]);
  });
});
