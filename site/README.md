# hort.pm

Static landing page, served by an assets-only Cloudflare Worker (`hort-site`, no Worker script).

- `public/` is the whole site: HTML, `style.css`, self-hosted fonts (OFL, licenses in `public/fonts/`), images.
- `public/_headers` carries the CSP and security headers. The page uses no JavaScript and makes no third-party requests.

Preview: `cd site && npx wrangler dev`, then open the printed local URL.

Deploy: `cd site && npx wrangler deploy` (binds the custom domain `hort.pm`).

Open before going live: `public/impressum.html` and `public/privacy.html` carry TODO markers; the owner supplies the legal data.
