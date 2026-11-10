# Self-hosting Hort

Hort's sync server is one Cloudflare Worker with SQLite Durable Objects. This guide takes you from `git clone` to a CLI that syncs with your own server. The server stores only ciphertext and public keys; running it yourself moves the operator role to you (see the [threat model](https://hort.pm/threat-model)).

## You need

- A Cloudflare account with Workers and Durable Objects (SQLite-backed) available, and Node.js with npm.
- Optional: a domain in that Cloudflare account. Without one you use a `workers.dev` address.
- The Hort CLI ([releases](https://github.com/gefuege/hort/releases) or `npm i -g @s16e/hort`).

## 1. Get the code and install

```bash
git clone https://github.com/gefuege/hort.git
cd hort/server
npm ci
npm test        # optional: Worker tests plus the browser-code tests
```

## 2. Configure `wrangler.jsonc`

The file is `server/wrangler.jsonc`. It already declares the three Durable Object bindings (`ACCOUNT`, `RATE_LIMITER`, `CHALLENGE`) and their migrations; leave those as they are. Change two things:

- `routes`: replace `hort.pm` with your own domain (it keeps `"custom_domain": true`), or delete the `routes` entry and set `"workers_dev": true` to use `https://hort-api.<your-subdomain>.workers.dev`. The shipped file sets `"workers_dev": false`, so deleting `routes` alone leaves the Worker without an address.
- `name`: optional, if `hort-api` is taken in your account.

Accounts are placed in Cloudflare's EU jurisdiction by the code (`jurisdiction("eu")`); there is nothing to configure for that.

## 3. Deploy

```bash
npx wrangler login      # once
npx wrangler deploy     # builds the web app, then uploads the Worker and public/
```

`wrangler deploy` runs `npm run build` itself. The Worker serves the API under `/api/v1`, the landing page and the web app from the same address.

## 4. Optional: invite-only registration

Without the secret `ADMIN_TOKEN` anyone who can reach your server can create accounts. To make registration invite-only, set it:

```bash
npx wrangler secret put ADMIN_TOKEN     # wrangler asks for the value; pick a long random string
```

While it is set, every new account needs a single-use invitation. Create one per person; the operator commands read the secret from `HORT_ADMIN_TOKEN` and need no vault:

```bash
export HORT_ADMIN_TOKEN=...
hort invite create --server https://hort.example.com   # prints the invite link, valid once
hort invite list --server https://hort.example.com     # ID, created, open or used, account ID
hort invite revoke <id> --server https://hort.example.com
```

The link `https://hort.example.com/invite#<code>` opens a page with the install steps and the `hort init --invite <code> --server https://hort.example.com` command. The code sits in the link's fragment, so it never reaches the server's logs; the server stores only its hash. Once an account used it, the code works for no other account.

## 5. Point the CLI at your server

The server URL must be `https`. It is chosen when the vault is created and stored in the vault file's header; there is no `hort sync --server`.

```bash
hort init --server https://hort.example.com    # add --invite <code> if you set ADMIN_TOKEN
```

`hort init` creates the account, prints the Emergency Kit (Secret Key and account ID; keep it apart from the passphrase) and registers the account when the server answers. If the server was unreachable, init warns that the account is not registered yet; `hort sync --invite <code>` registers it later.

```bash
hort sync          # sync now, without time limit
hort status        # shows the server this vault uses
```

Add another device to the same account:

```bash
hort enroll <account-id> --server https://hort.example.com
```

It asks for the Secret Key and the passphrase and refuses if `~/.hort/vault.enc` already exists.

## 6. The web app

Open your server's address in a browser. Passkeys are bound to that domain, so register passkeys on your own server; hort.pm passkeys do not carry over.

## Updating

Pull the new code, run `npm ci` and `npx wrangler deploy` again.
