// Sharing by link through the functions the console uses: the sender's panel
// (fields, create, state on the row, revoke) and the recipient page (open,
// wrong name, delete, save to the vault), against a fake server that keeps
// the server's rules: token hash only, five tries, one answer for ended shares.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { b64Encode, sha256 } from "../src/wire";
import { parseShareLink } from "../web/share-core";
import { answerShared, deleteShared, GONE, openShared, saveShared, send as realSend, SHARE_PATH, type Send } from "../web/share-view";
import { current, deriveAccountKeys, type Revision } from "../web/vault-core";
import { createShare, forgetVault, ownShares, pull, revokeShare, rows, shareAnswer, shareFields, shareTag, takeAnswer, write, type Host } from "../web/vault-view";

async function unlockedVault() {
  const accountId = crypto.getRandomValues(new Uint8Array(16));
  return { accountId, keys: await deriveAccountKeys(crypto.getRandomValues(new Uint8Array(32)), accountId) };
}

type Stored = { state: string; kind: string; ct: string | null; answer: string | null; meta_ct: string; token_hash: string; tries: number; expires_at: number };

// POST/GET /revisions, POST/GET /shares, revoke and GET answer for the owner;
// open, DELETE and POST answer for the recipient.
function fakeServer() {
  const revisions: { seq: number; id: string; ct: string }[] = [];
  const shares = new Map<string, Stored>();
  const bodies: string[] = [];
  const host: Pick<Host, "api" | "ok"> = {
    async api(method, path, o) {
      if (o?.body) bodies.push(o.body);
      if (path === "/api/v1/shares" && method === "POST") {
        const b = JSON.parse(o!.body!) as { id: string; expires_in: number; ct: string; meta_ct: string; token_hash: string; kind: string };
        expect(Object.keys(b).sort()).toEqual(["ct", "expires_in", "id", "kind", "meta_ct", "token_hash"]);
        shares.set(b.id, { state: "open", kind: b.kind, ct: b.ct, answer: null, meta_ct: b.meta_ct, token_hash: b.token_hash, tries: 0, expires_at: Math.floor(Date.now() / 1000) + b.expires_in });
        return Response.json({ state: "open" }, { status: 201 });
      }
      if (path === "/api/v1/shares") return Response.json({ shares: [...shares].map(([id, s]) => ({ id, state: s.state, meta_ct: s.meta_ct, created_at: 0, expires_at: s.expires_at })) });
      const revoke = /^\/api\/v1\/shares\/([0-9a-f]{32})\/revoke$/.exec(path);
      if (revoke) {
        const s = shares.get(revoke[1])!;
        if (s.state !== "open" && s.state !== "revoked" && s.state !== "answered") return new Response(`share is ${s.state}`, { status: 409 });
        const state = s.state === "answered" ? "closed" : "revoked";
        Object.assign(s, { state, ct: null, answer: null });
        return Response.json({ state });
      }
      const answer = /^\/api\/v1\/shares\/([0-9a-f]{32})\/answer$/.exec(path);
      if (answer) {
        const s = shares.get(answer[1])!;
        if (s.state !== "answered") return new Response(`share is ${s.state}`, { status: 409 });
        return Response.json({ ct: s.answer });
      }
      if (method === "POST") {
        const { revisions: pushed } = JSON.parse(o!.body!) as { revisions: { id: string; ct: string }[] };
        for (const r of pushed) revisions.push({ seq: revisions.length + 1, ...r });
        return Response.json({ accepted: pushed.map((r) => r.id), duplicate: [] });
      }
      const after = Number(new URL(path, "https://hort.test").searchParams.get("after"));
      const page = revisions.filter((r) => r.seq > after);
      return Response.json({ revisions: page, cursor: page.at(-1)?.seq ?? after, more: false });
    },
    async ok<T>(res: Response) {
      if (!res.ok) throw new Error(await res.text());
      return (res.status === 204 ? undefined : await res.json()) as T;
    },
  };
  const paths: string[] = [];
  const send: Send = async (method, path, token, body) => {
    paths.push(path);
    const m = /^\/api\/v1\/shares\/([0-9a-f]{32})(\/open|\/answer)?$/.exec(path)!;
    const s = shares.get(m[1]);
    if (!s || s.state !== "open") return new Response("this link no longer opens", { status: 404 });
    if (btoa(String.fromCharCode(...(await sha256(token)))) !== s.token_hash) {
      if (++s.tries >= 5) {
        Object.assign(s, { state: "destroyed", ct: null });
        return new Response("this link no longer opens", { status: 404 });
      }
      return Response.json({ tries_left: 5 - s.tries }, { status: 403 });
    }
    if (method === "DELETE") {
      Object.assign(s, { state: "taken", ct: null });
      return new Response(null, { status: 204 });
    }
    if (m[2] === "/answer") {
      if (s.kind !== "request") return new Response("this link no longer opens", { status: 404 });
      Object.assign(s, { state: "answered", ct: null, answer: (JSON.parse(body!) as { ct: string }).ct });
      return new Response(null, { status: 204 });
    }
    return Response.json({ ct: s.ct });
  };
  return { host, send, shares, bodies, paths };
}

const rev = (op: Revision["op"], field: string, key: string, value: string, at: bigint): Revision => ({ id: crypto.randomUUID().replace(/-/g, ""), recordedAt: at, op, field, key, value });

beforeEach(forgetVault);

describe("share panel", () => {
  it("shares every field with the value the row's env and context resolve to", () => {
    const entry = [rev("set", "user", "*:*", "app", 1n), rev("set", "password", "*:*", "pw-any", 2n), rev("set", "password", "prod:*", "pw-prod", 3n), rev("set", "token", "dev:*", "dev-only", 4n)];
    expect(shareFields(entry, "prod", "eu")).toEqual([
      { field: "password", value: "pw-prod" },
      { field: "user", value: "app" },
    ]);
    expect(shareFields(entry, "", "")).toEqual([
      { field: "password", value: "pw-any" },
      { field: "user", value: "app" },
    ]);
    expect(shareFields([rev("set", "", "*:*", "v", 1n)], "", "")).toEqual([{ field: "", value: "v" }]);
  });

  it("offers share only on rows whose env and context resolve a value, so a parent without default values has none", () => {
    // Only prod values: the parent row (env and context any) resolves nothing, the child rows do.
    const entry = [rev("set", "password", "prod:*", "pw", 1n), rev("set", "user", "prod:*", "app", 2n)];
    const listed = rows(new Map([["db", entry]]), "").rows;
    const offered = listed.map((r) => [r.kind, shareFields(entry, r.env, r.context).length > 0]);
    expect(offered).toEqual([
      ["parent", false],
      ["child", true],
      ["child", true],
    ]);
  });

  it("shows the time left while open, how it ended after, and nothing from the expiry on", () => {
    const now = 1_000_000;
    const at = (state: string, left: number) => shareTag({ state, recipient: "Lars", expiresAt: now + left, kind: "share" }, now);
    expect(at("open", 86400 - 60)).toBe("shared → Lars · 23h");
    expect(at("open", 604800)).toBe("shared → Lars · 7d");
    expect(at("open", 59 * 60 + 30)).toBe("shared → Lars · 59m");
    expect(at("open", 20)).toBe("shared → Lars · 1m");
    expect(at("taken", 100)).toBe("shared → Lars · picked up");
    expect(at("revoked", 100)).toBe("shared → Lars · revoked");
    expect(at("destroyed", 100)).toBe("shared → Lars · destroyed");
    for (const state of ["open", "taken", "revoked", "destroyed"]) expect(at(state, 0)).toBeNull();
    const asked = (state: string) => shareTag({ state, recipient: "Lars", expiresAt: now + 86400 - 60, kind: "request" }, now);
    expect(asked("open")).toBe("requested → Lars · 23h");
    expect(asked("answered")).toBe("requested → Lars · answered");
    expect(asked("taken")).toBe("requested → Lars · declined");
    expect(asked("closed")).toBe("requested → Lars · closed");
  });
});

describe("share link end to end", () => {
  const secret = { name: "db", description: "staging database", fields: [{ field: "password", value: "s3cret" }, { field: "user", value: "app" }], kind: "share" as const };

  it("creates a link the right name opens, keeps the key off the server, and lists the share for the owner", async () => {
    const u = await unlockedVault();
    const { host, send, bodies, paths } = fakeServer();
    const link = await createShare(host, u, "https://hort.test", secret, "  Lars  Müller ", 86400);
    const parsed = parseShareLink(link)!;
    expect(SHARE_PATH.test(new URL(link).pathname)).toBe(true);
    const fragment = new URL(link).hash.slice(1);
    for (const b of bodies) expect(b).not.toContain(fragment);

    const owned = await ownShares(host, u);
    expect(owned.get("db")).toEqual([{ id: parsed.shareId, state: "open", name: "db", recipient: "Lars  Müller", expiresAt: expect.any(Number), kind: "share", env: "", context: "", linkKey: "" }]);

    const opened = await openShared(send, parsed.shareId, parsed.linkKey, "lars müller");
    expect(opened.kind).toBe("secret");
    if (opened.kind !== "secret") return;
    expect(opened.secret).toEqual(secret);
    for (const p of paths) expect(p).not.toContain(fragment);

    expect(await answerShared(send, parsed.shareId, opened.keys, opened.secret)).toBe(false);
    expect(await deleteShared(send, parsed.shareId, opened.keys.token)).toBe(true);
    expect((await ownShares(host, u)).get("db")![0].state).toBe("taken");
    expect(await openShared(send, parsed.shareId, parsed.linkKey, "Lars Müller")).toEqual({ kind: "gone" });
    expect(GONE).toBe("This link no longer opens. Ask the sender for a new one.");
  }, 60_000);

  it("counts wrong names down and answers the fifth like an ended link", async () => {
    const u = await unlockedVault();
    const { host, send } = fakeServer();
    const { shareId, linkKey } = parseShareLink(await createShare(host, u, "https://hort.test", secret, "Lars", 3600))!;
    const left = [];
    for (let i = 0; i < 4; i++) {
      const r = await openShared(send, shareId, linkKey, `Eve ${i}`);
      left.push(r.kind === "wrong" ? r.triesLeft : r.kind);
    }
    expect(left).toEqual([4, 3, 2, 1]);
    expect(await openShared(send, shareId, linkKey, "Eve")).toEqual({ kind: "gone" });
    expect(await openShared(send, shareId, linkKey, "Lars")).toEqual({ kind: "gone" });
    expect((await ownShares(host, u)).get("db")![0].state).toBe("destroyed");
  }, 120_000);

  it("revokes an open share, after which the link no longer opens", async () => {
    const u = await unlockedVault();
    const { host, send } = fakeServer();
    const { shareId, linkKey } = parseShareLink(await createShare(host, u, "https://hort.test", secret, "Lars", 604800))!;
    await revokeShare(host, shareId);
    expect((await ownShares(host, u)).get("db")![0].state).toBe("revoked");
    expect(await openShared(send, shareId, linkKey, "Lars")).toEqual({ kind: "gone" });
  }, 60_000);
});

describe("request by link end to end", () => {
  it("asks for values, takes one answer, and writes the taken values to the row in one write before ending the request", async () => {
    const u = await unlockedVault();
    const { host, send, shares, bodies } = fakeServer();
    await write(host, u, "stripe", [{ op: "set", field: "client_id", key: "prod:*", value: "pk_old" }]);
    const asked = { name: "stripe", description: "Payments", fields: [{ field: "client_id", value: "pk_old" }, { field: "secret", value: "" }], kind: "request" as const };
    const link = await createShare(host, u, "https://hort.test", asked, "Lars", 86400, { env: "prod", context: "" });
    const { shareId, linkKey } = parseShareLink(link)!;
    const fragment = new URL(link).hash.slice(1);
    for (const b of bodies) expect(b).not.toContain(fragment);
    expect(shares.get(shareId)!.kind).toBe("request");

    const opened = await openShared(send, shareId, linkKey, "lars");
    if (opened.kind !== "secret") throw new Error(opened.kind);
    expect(opened.secret).toEqual(asked);
    const answer = { name: "stripe", description: "Payments", fields: [{ field: "client_id", value: "pk_new" }, { field: "secret", value: "sk_new\nline 2" }] };
    expect(await answerShared(send, shareId, opened.keys, answer)).toBe(true);
    expect(shares.get(shareId)).toMatchObject({ state: "answered", ct: null });
    // answered ends the link for the recipient.
    expect(await answerShared(send, shareId, opened.keys, answer)).toBe(false);
    expect(await openShared(send, shareId, linkKey, "Lars")).toEqual({ kind: "gone" });

    const [own] = (await ownShares(host, u)).get("stripe")!;
    expect(own).toMatchObject({ state: "answered", kind: "request", env: "prod", context: "" });
    expect(own.linkKey).toBe(fragment);
    expect(await shareAnswer(host, own)).toEqual(answer);

    const before = bodies.length;
    await takeAnswer(host, u, own, [{ field: "client_id", value: "pk_new" }, { field: "secret", value: "sk_new\nline 2" }], null);
    const writes = bodies.slice(before).filter((b) => b.includes('"revisions"'));
    expect(writes).toHaveLength(1);
    expect((JSON.parse(writes[0]) as { revisions: unknown[] }).revisions).toHaveLength(2);
    expect(shares.get(shareId)).toMatchObject({ state: "closed", answer: null });
    forgetVault();
    const v = await pull(host, u);
    expect([...current(v.entries.get("stripe")!).values.values()].sort((a, b) => (a.field < b.field ? -1 : 1))).toEqual([
      { field: "client_id", key: "prod:*", value: "pk_new" },
      { field: "secret", key: "prod:*", value: "sk_new\nline 2" },
    ]);
  }, 60_000);

  it("ends a declined review without writing", async () => {
    const u = await unlockedVault();
    const { host, send, shares, bodies } = fakeServer();
    const asked = { name: "new-api", description: "", fields: [{ field: "", value: "" }], kind: "request" as const };
    const { shareId, linkKey } = parseShareLink(await createShare(host, u, "https://hort.test", asked, "Lars", 3600))!;
    const opened = await openShared(send, shareId, linkKey, "Lars");
    if (opened.kind !== "secret") throw new Error(opened.kind);
    await answerShared(send, shareId, opened.keys, { ...asked, fields: [{ field: "", value: "k" }] });
    const before = bodies.length;
    await takeAnswer(host, u, { id: shareId, name: "new-api", env: "", context: "" }, [], null);
    expect(bodies.slice(before).filter((b) => b.includes('"revisions"'))).toEqual([]);
    expect(shares.get(shareId)!.state).toBe("closed");
  }, 60_000);
});

describe("recipient requests", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("send no cookies and no header but the access token", async () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);
    const token = crypto.getRandomValues(new Uint8Array(32));
    await realSend("DELETE", "/api/v1/shares/00112233445566778899aabbccddeeff", token);
    expect(fetch.mock.calls).toEqual([["/api/v1/shares/00112233445566778899aabbccddeeff", { method: "DELETE", headers: { "Hort-Share-Token": b64Encode(token) }, credentials: "omit" }]]);
    await realSend("POST", "/api/v1/shares/00112233445566778899aabbccddeeff/answer", token, '{"ct":"x"}');
    expect(fetch.mock.calls[1]).toEqual(["/api/v1/shares/00112233445566778899aabbccddeeff/answer", { method: "POST", headers: { "Hort-Share-Token": b64Encode(token) }, credentials: "omit", body: '{"ct":"x"}' }]);
  });
});

describe("save to my vault", () => {
  it("saves the fields as default values with the description, and never overwrites an existing secret", async () => {
    const u = await unlockedVault();
    const { host } = fakeServer();
    await write(host, u, "db", [{ op: "set", field: "", key: "*:*", value: "mine" }]);
    const shared = { name: "db", description: "staging database", fields: [{ field: "password", value: "s3cret" }, { field: "user", value: "app" }], kind: "share" as const };
    await expect(saveShared(host, u, "db", shared)).rejects.toThrow("Your vault has a secret named db already. Pick another name.");
    await expect(saveShared(host, u, "DB", shared)).rejects.toThrow("Your vault has a secret named db already. Pick another name.");
    await saveShared(host, u, "db-staging", shared);
    forgetVault();
    const v = await pull(host, u);
    expect([...current(v.entries.get("db")!).values.values()]).toEqual([{ field: "", key: "*:*", value: "mine" }]);
    const saved = current(v.entries.get("db-staging")!);
    expect(saved.description).toBe("staging database");
    expect([...saved.values.values()].sort((a, b) => (a.field < b.field ? -1 : 1))).toEqual([
      { field: "password", key: "*:*", value: "s3cret" },
      { field: "user", key: "*:*", value: "app" },
    ]);
  });
});
