import api from "./index";

export { Account } from "./account";
export { RateLimiter } from "./rate-limiter";

// Contract §8.3. Static assets get the same headers from public/_headers
// (Cloudflare does not apply that file to Worker responses); a test keeps
// the two lists identical.
export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy":
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self), clipboard-write=(self)",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
};

export default {
  async fetch(request, env): Promise<Response> {
    const response = await api.fetch(request, env);
    const secured = new Response(response.body, response);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) secured.headers.set(name, value);
    return secured;
  },
} satisfies ExportedHandler<Env>;
