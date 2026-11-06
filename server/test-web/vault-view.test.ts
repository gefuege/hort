// The /vault data path against a fake server: refused sessions, and a write
// that a fresh pull (another tab) reads back.
import { beforeEach, describe, expect, it } from "vitest";
import { b64Decode } from "../src/wire";
import { current, deriveAccountKeys, resolve } from "../web/vault-core";
import { forgetVault, pull, SignInRequired, write, type Host } from "../web/vault-view";

async function unlockedVault() {
  const accountId = crypto.getRandomValues(new Uint8Array(16));
  return { accountId, keys: await deriveAccountKeys(crypto.getRandomValues(new Uint8Array(32)), accountId) };
}

// Stores pushed envelopes and serves them as pages, like POST/GET /revisions.
function fakeServer(refuse?: number) {
  const rows: { seq: number; id: string; ct: string }[] = [];
  const host: Pick<Host, "api" | "ok"> = {
    async api(method, path, o) {
      if (refuse) return new Response("refused", { status: refuse });
      if (method === "POST") {
        const { revisions } = JSON.parse(o!.body!) as { revisions: { id: string; ct: string }[] };
        for (const r of revisions) rows.push({ seq: rows.length + 1, ...r });
        return Response.json({ accepted: revisions.map((r) => r.id), duplicate: [] });
      }
      const after = Number(new URL(path, "https://hort.test").searchParams.get("after"));
      const page = rows.filter((r) => r.seq > after);
      return Response.json({ revisions: page, cursor: page.at(-1)?.seq ?? after, more: false });
    },
    async ok<T>(res: Response) {
      if (!res.ok) throw new Error(await res.text());
      return (await res.json()) as T;
    },
  };
  return { host, rows };
}

beforeEach(forgetVault);

describe("vault-view", () => {
  it("turns 401 and 409 into a sign-in prompt and writes nothing", async () => {
    const u = await unlockedVault();
    for (const status of [401, 409]) {
      forgetVault();
      await expect(pull(fakeServer(status).host, u)).rejects.toBeInstanceOf(SignInRequired);
      await expect(write(fakeServer(status).host, u, "db", [{ op: "set", field: "", key: "*:*", value: "v" }])).rejects.toBeInstanceOf(SignInRequired);
    }
    await expect(pull(fakeServer(409).host, u)).rejects.toThrow("signed in to a different account");
  });

  it("writes set and describe with the Append rule and reads them back in a fresh pull", async () => {
    const u = await unlockedVault();
    const { host, rows } = fakeServer();
    await write(host, u, "api", [{ op: "set", field: "token", key: "prod:*", value: "" }]);
    await write(host, u, "api", [
      { op: "set", field: "token", key: "prod:*", value: "second" },
      { op: "describe", field: "", key: "", value: "API token" },
    ]);
    expect(rows.length).toBe(3);
    expect(rows.every((r) => b64Decode(r.ct) !== null)).toBe(true);

    forgetVault(); // another tab: full pull from cursor 0
    const v = await pull(host, u);
    const revisions = v.entries.get("api")!;
    expect(resolve(revisions, "token", "prod", "")).toBe("second");
    expect(current(revisions).description).toBe("API token");
    const times = revisions.map((r) => r.recordedAt!);
    expect(times[1] > times[0] && times[2] > times[1]).toBe(true);
  });

  it("refuses an invalid write before anything is sent", async () => {
    const u = await unlockedVault();
    const { host, rows } = fakeServer();
    await expect(write(host, u, "has space", [{ op: "set", field: "", key: "*:*", value: "v" }])).rejects.toThrow("does not meet the rules");
    await expect(write(host, u, "db", [{ op: "set", field: "", key: "a:b:c", value: "v" }])).rejects.toThrow("env and context");
    expect(rows).toEqual([]);
  });
});
