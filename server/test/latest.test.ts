import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import npmPackage from "../../npm/package.json";
import { call, createCall, fetchSlot, randomFixture, randomIp } from "./helpers";

const get = (path: string) => exports.default.fetch(new Request(`https://hort.test${path}`, { headers: { "CF-Connecting-IP": randomIp() } }));

describe("Hort-Latest header", () => {
  it("names the npm package version on a successful /api/* answer", async () => {
    const f = await randomFixture();
    expect((await call(createCall(f))).status).toBe(201);
    const res = await fetchSlot(f.account);
    expect(res.status).toBe(200);
    expect(res.headers.get("Hort-Latest")).toBe(npmPackage.version);
  });

  it("names it on a failing /api/* answer too", async () => {
    const res = await get("/api/v1/nope");
    expect(res.status).toBe(404);
    expect(res.headers.get("Hort-Latest")).toBe(npmPackage.version);
  });
});
