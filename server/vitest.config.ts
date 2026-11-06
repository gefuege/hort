import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: { bindings: { REGISTRATION_TOKEN: "test-registration-token" } },
          }),
        ],
        test: { name: "worker", include: ["test/**/*.test.ts"], setupFiles: ["./test/setup.ts"] },
      },
      // Browser code. workerd refuses runtime WebAssembly compilation, so the
      // Argon2id WASM runs under Node's WebCrypto and WebAssembly instead.
      { test: { name: "web", include: ["test-web/**/*.test.ts"], environment: "node" } },
    ],
  },
});
