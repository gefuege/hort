import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: { bindings: { REGISTRATION_TOKEN: "test-registration-token" } },
    }),
  ],
  test: { setupFiles: ["./test/setup.ts"] },
});
