/// <reference types="vite/client" />
import { describe, expect, it } from "vitest";
import headersFile from "../public/_headers?raw";
import { SECURITY_HEADERS } from "../src/entry";

const pages = import.meta.glob("../public/**/*.{html,css}", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

describe("security headers (contract §8.3)", () => {
  it("static asset headers match the API headers", () => {
    const block = headersFile.split("\n\n")[0].split("\n").slice(1);
    const fromFile = Object.fromEntries(block.map((l: string) => [l.slice(0, l.indexOf(":")).trim(), l.slice(l.indexOf(":") + 1).trim()]));
    expect(fromFile).toEqual(SECURITY_HEADERS);
  });

  it("the CSP allows scripts from self and WebAssembly compilation only", () => {
    expect(SECURITY_HEADERS["Content-Security-Policy"]).toContain("script-src 'self' 'wasm-unsafe-eval';");
  });
});

describe("assets", () => {
  it("load nothing from another origin", () => {
    const files = Object.entries(pages);
    expect(files.length).toBeGreaterThan(5);
    // Outbound links (<a href>) are fine; every other reference must be same-origin.
    const loaded = /(?:<(?:link|script|img|iframe|source)\b[^>]*?\s(?:src|href)=|url\(|@import\s+)["']?(?:https?:)?\/\/([^/"')\s]+)/gi;
    for (const [file, text] of files) {
      for (const m of text.matchAll(loaded)) expect(m[1], `${file}: ${m[0]}`).toBe("hort.pm");
      expect(text, file).not.toMatch(/<script\b/i);
    }
  });
});
