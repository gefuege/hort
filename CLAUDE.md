# Hort

Local secret and config store CLI. Go project.

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
./hort --set-secret foo --value "bar" --description "test secret"
./hort --secret foo

# Full help
./hort --help
```

## Structure

- `cmd/hort/main.go` — Entry point, Cobra CLI wiring
- `internal/vault/crypto.go` — AES-256-GCM, Argon2id KDF, v2 format helpers
- `internal/vault/format.go` — v2 header layout + KDF flag byte (raw vs Argon2id)
- `internal/vault/vault.go` — `VaultRef`, load/save/update by ref, primary helpers
- `internal/vault/sources.go` — Mounted-source registry (~/.hort/sources/index.json)
- `internal/vault/session.go` — Per-ref session key persistence
- `internal/vault/lock.go` — Per-ref flock (concurrent-safe writers)
- `internal/store/store.go` — Multi-source merge reads, targeted writes, ambiguity detection
- `internal/cli/commands.go` — Command implementations (direct store access)
- `internal/helptext/text.go` — Help text (serves as agent prompt)
- `internal/cli/output.go` — Output formatting (plain/JSON)

## Sources

Primary vault at `~/.hort/vault.enc` (Argon2id KDF). Any number of mounted
sources registered via `hort source mount --name <n> --path <p> --key-hex <hex>`;
their vault files live wherever the mounter decides, their lock/session files
under `~/.hort/sources/<name>.{lock,session}`. Reads merge across all unlocked
sources. Writes default to primary; `--source <name>` targets a mount. Same
key in multiple sources → ambiguity error with `--source` hint.

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
- Exit code 2 = primary vault locked (mounts that are locked are skipped with a stderr warning)
- `HORT_PASSPHRASE` env var bypasses terminal prompt
- `primary` is a reserved source name; mount names must match `[a-z0-9._-]+` and not start with `-` or `.`
