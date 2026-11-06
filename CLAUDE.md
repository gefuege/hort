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
- `internal/vault/crypto.go`, `format.go`, `v3.go` — v3 reader only, kept for the coming v3→v4 migration
- `internal/store/store.go` — Reads and writes on the one local vault
- `internal/cli/commands.go` — Command implementations (direct store access)
- `internal/cli/sync.go` — Time limit (`syncLimit`) for automatic sync around reads and writes
- `internal/helptext/text.go` — Help text (serves as agent prompt)
- `internal/cli/output.go` — Output formatting (plain/JSON)
- `server/` — Cloudflare Worker `hort-api`: sync API under `/api/*` (TypeScript) and the hort.pm web app and landing page from `server/public/`; see `server/README.md`
- `spec/vectors/` — Shared test vectors; byte authority, see `spec/vectors/README.md`

## Vault

One local vault at `~/.hort/vault.enc`; session key in `~/.hort/.session`, locks under `~/.hort/locks/<path-digest>.lock`.

## Sync

Sync runs through the Hort server (`server/`) and arrives with Hort 1.0; folder sync is removed.

## Release

Tag push triggers the `cli` job in `release.yml` (goreleaser → binaries +
Homebrew). npm publish is manual:

```bash
git tag v<version> && git push --tags
cd npm && npm version <version> --no-git-tag-version && npm publish --access=public
```

Package: `@s16e/hort`. Do not automate npm publish via CI.

## Conventions

- Errors on stderr, values on stdout (no decoration)
- Exit code 2 = vault locked
- `HORT_PASSPHRASE` env var bypasses terminal prompt

## Vault contract

Outer and inner versions are 4. v3 and v2 vaults are rejected; `hort migrate`
(v3 to v4) follows. Byte authority is `spec/vectors/README.md`. Entries persist
revisions only; descriptions are describe revisions.

`hort history NAME [--json]` explicitly returns revision values.
List, describe and search remain metadata-only. All values use the secret interface.
