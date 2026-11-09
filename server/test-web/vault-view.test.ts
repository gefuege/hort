// The /vault data path against a fake server (refused sessions, and a write
// that a fresh pull reads back), the per-value rows and filter, and the keys.
import { beforeEach, describe, expect, it } from "vitest";
import { b64Decode } from "../src/wire";
import { current, deriveAccountKeys, resolve, type Op, type Revision } from "../web/vault-core";
import { command, forgetVault, pull, rowLabel, rows, secondsLeft, SignInRequired, write, type Host } from "../web/vault-view";

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

let seq = 0n;
const rev = (op: Op, field = "", key = "", value = ""): Revision => ({ id: `r${++seq}`, recordedAt: seq, op, field, key, value });

describe("vault rows", () => {
  const entries = new Map<string, Revision[]>([
    ["stripe", [rev("set", "secret_key", "prod:tenant-a", "a"), rev("set", "secret_key", "staging:*", "s"), rev("describe", "", "", "Payments")]],
    ["db", [rev("set", "password", "prod:*", "p"), rev("set", "username", "*:*", "u")]],
    ["npm", [rev("set", "", "*:*", "n")]],
    ["notes", [rev("describe", "", "", "only a description")]],
    ["gone", [rev("set", "", "*:*", "x"), rev("delete-entry")]],
  ]);

  it("lists one row per value, the entry's name and description on its first row only", () => {
    const r = rows(entries, "");
    expect(r.secrets).toBe(4);
    expect(r.values).toBe(5);
    expect(r.rows.map(rowLabel)).toEqual(["db password · env prod", "db username", "notes", "npm", "stripe secret_key · env prod · context tenant-a", "stripe secret_key · env staging"]);
    expect(r.rows.map((x) => x.first)).toEqual([true, false, true, true, true, false]);
    expect(r.rows.find((x) => x.name === "notes")!.value).toBeNull();
  });

  it("matches individual values by their field, env or context, and every value by the entry's name or description", () => {
    expect(rows(entries, "prod").rows.map(rowLabel)).toEqual(["db password · env prod", "stripe secret_key · env prod · context tenant-a"]);
    expect(rows(entries, "payments staging").rows.map(rowLabel)).toEqual(["stripe secret_key · env staging"]);
    expect(rows(entries, "DB").rows).toHaveLength(2);
    expect(rows(entries, "default").rows.map(rowLabel)).toEqual(["npm"]);
    const tenant = rows(entries, "tenant-a").rows;
    expect(tenant.map((x) => [x.name, x.first])).toEqual([["stripe", true]]);
    expect(rows(entries, "nothing-like-this").rows).toEqual([]);
  });
});

describe("vault keys", () => {
  it("maps keys by focus: list shortcuts, filter hand-off, editor typing, inline confirm", () => {
    expect(["/", "ArrowDown", "ArrowUp", "Enter", "c", "e", "d", "n", "r"].map((k) => command(k, "list", false))).toEqual(["filter", "down", "up", "show", "copy", "edit", "delete", "new", "refresh"]);
    expect(command("x", "list", false)).toBeNull();
    expect(command("ArrowDown", "filter", false)).toBe("first");
    expect(command("Enter", "filter", false)).toBe("first");
    expect(command("n", "filter", false)).toBeNull();
    expect(command("c", "editor", false)).toBeNull();
    expect(command("Enter", "button", false)).toBeNull();
    expect(command("c", "button", false)).toBe("copy");
    expect([command("y", "list", true), command("n", "list", true), command("c", "list", true)]).toEqual(["yes", "no", null]);
    for (const focus of ["list", "filter", "editor", "button"] as const) expect(command("Escape", focus, true)).toBe("close");
  });
});

describe("secondsLeft", () => {
  it("counts down to a deadline from the clock, not from ticks", () => {
    expect(secondsLeft(30_000, 0)).toBe(30);
    expect(secondsLeft(30_000, 29_001)).toBe(1);
    expect(secondsLeft(30_000, 30_000)).toBe(0);
    expect(secondsLeft(30_000, 95_000)).toBe(0);
  });
});
