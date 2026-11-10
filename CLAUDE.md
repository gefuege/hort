# Hort

Local secret store CLI. Go project.

## Build

```bash
go build ./cmd/hort/
```

## Test

```bash
go test ./...
```

## Run

```bash
# Init vault (needs terminal or HORT_PASSPHRASE env var)
HORT_PASSPHRASE="test" ./hort init

# Store and retrieve
./hort set foo --value "bar" --description "test secret"
./hort get foo
./hort set db password --value "pw"   # named field
./hort get db password

# Full help
./hort --help
```

## Structure

- `cmd/hort/main.go` — Entry point, Cobra CLI wiring
- `internal/vault/file.go` — v4 file format: outer envelope, inner content, validation
- `internal/vault/keys.go` — Key derivation, account keys, revision encryption and signatures
- `internal/vault/secretkey.go` — Secret Key and account ID text forms
- `internal/vault/vault.go` — `VaultRef`, init, load/save/update, primary helpers
- `internal/vault/revisions.go` — Revision-only entries and deterministic current-value reduction
- `internal/vault/session.go` — Session key persistence
- `internal/vault/lock.go` — File locks by canonical vault path (concurrent-safe writers)
- `internal/vault/io.go`, `json.go` — Atomic file writes, strict JSON decoding
- `internal/vault/crypto.go`, `format.go`, `v3.go`, `migrate.go` — v3 reader and the one-time v3→v4 migration (`hort migrate`)
- `internal/store/store.go` — Reads and writes on the one local vault
- `internal/cli/commands.go` — Command implementations (direct store access)
- `internal/cli/sync.go` — Sync with the Hort server, enroll, devices; time limit (`syncLimit`) for automatic sync around reads and writes
- `internal/api/` — HTTP client for the sync API
- `internal/mcp/` — `hort mcp`: MCP stdio server with the `request_secret` tool
- `internal/helptext/text.go` — Help text (serves as agent prompt)
- `internal/cli/output.go` — Output formatting (plain/JSON)
- `server/` — Cloudflare Worker `hort-api`: sync API under `/api/*` (TypeScript) and the hort.pm web app and landing page from `server/public/`; see `server/README.md`
- `spec/vectors/` — Shared test vectors; byte authority, see `spec/vectors/README.md`

## Vault

One local vault at `~/.hort/vault.enc`; session key in `~/.hort/.session`, locks under `~/.hort/locks/<path-digest>.lock`.

## Sync

Sync runs through the Hort server (`server/`): hort.pm or a self-hosted one (`docs/self-hosting.md`). The server stores ciphertext only. `hort sync` registers the account on first use (a server with `ADMIN_TOKEN` needs `--invite CODE` on `init` or that first `sync`; its operator creates codes with `hort invite`); `hort enroll` adds a device. Folder sync is removed.

## Release

Tag push triggers the `cli` job in `release.yml` (goreleaser → binaries,
Homebrew formula and Scoop manifest) and `docker.yml` (`ghcr.io/gefuege/hort`).
The version comes from the tag through ldflags (`main.version`); `hort --version`
prints it. The Homebrew tap and Scoop bucket stay under `sebastian-breitzke`
(`HOMEBREW_TAP_TOKEN` is scoped to them). npm publish is manual.

Order: push the tag, wait for the release build, bump `npm/package.json`,
deploy the Worker, publish npm. The Worker states `npm/package.json`'s version
in `Hort-Latest` on every `/api/*` answer; the CLI's update hint compares to it,
so the bump and deploy come after the binaries exist:

```bash
git tag v<version> && git push --tags
# after the release build:
cd npm && npm version <version> --no-git-tag-version   # then commit and push
cd ../server && npm run build && npx wrangler deploy
cd ../npm && npm publish --access=public
```

Package: `@s16e/hort`. Do not automate npm publish via CI.

## Conventions

- Errors on stderr, values on stdout (no decoration)
- Exit code 2 = vault locked
- `HORT_PASSPHRASE` env var bypasses terminal prompt

## Vault contract

Outer and inner versions are 4. v3 and v2 vaults are rejected by normal commands;
`hort migrate` converts v3 to v4 once (v2 must go through Hort 0.4.1 first). Byte authority is `spec/vectors/README.md`. Entries persist
revisions only; descriptions are describe revisions.

`hort history NAME [--json]` explicitly returns revision values.
List, describe and search remain metadata-only. All values use the secret interface.
