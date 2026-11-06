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
./hort --set-secret foo --value "bar" --description "test secret"
./hort --secret foo

# Full help
./hort --help
```

## Structure

- `cmd/hort/main.go` — Entry point, Cobra CLI wiring
- `internal/vault/crypto.go` — AES-256-GCM, Argon2id KDF, v3 encryption helpers
- `internal/vault/format.go` — v3 header layout + KDF flag byte (raw vs Argon2id)
- `internal/vault/vault.go` — `VaultRef`, load/save/update by ref, primary helpers
- `internal/vault/revisions.go` — Revision-only entries and deterministic current-value reduction
- `internal/vault/migrate.go` — Explicit, locked v2-to-v3 conversion with encrypted permanent backup
- `internal/vault/sources.go` — Mounted-source registry (~/.hort/sources/index.json), including `sync_file`
- `internal/vault/sync.go` — Sync folder exchange and setup, merge by revision identity
- `internal/vault/session.go` — Per-ref session key persistence
- `internal/vault/lock.go` — File locks by canonical vault path (concurrent-safe writers)
- `internal/store/store.go` — Multi-source merge reads, targeted writes, ambiguity detection
- `internal/cli/commands.go` — Command implementations (direct store access)
- `internal/cli/sync.go` — `hort sync`, `hort sync setup`, time-limited sync around reads and writes
- `internal/helptext/text.go` — Help text (serves as agent prompt)
- `internal/cli/output.go` — Output formatting (plain/JSON)
- `site/` — hort.pm landing page (static assets, assets-only Cloudflare Worker `hort-site`; see `site/README.md`)

## Sources

Primary vault at `~/.hort/vault.enc` (Argon2id KDF). Any number of mounted
sources registered via `hort source mount --name <n> --path <p> --key-hex <hex>`;
their vault files live wherever the mounter decides. Session files remain under
`~/.hort/sources/<name>.session`; locks use `~/.hort/locks/<path-digest>.lock`,
so aliases of the same vault share one lock. Reads merge across all unlocked
sources. Writes default to primary; `--source <name>` targets a mount. Same
key in multiple sources → ambiguity error with `--source` hint.

## Sync

Primary vault only. `hort sync setup --path <dir>` connects a device to an
existing folder that a third-party service replicates; Hort holds no provider
code and never creates the folder or deletes in it. Each device writes a byte
copy of `vault.enc` to its own `hort-<id>.enc`, stored as `sync_file` in
`~/.hort/sources/index.json`. Every regular `hort-*` file in the folder is read,
so conflict copies count; files that fail to decrypt are skipped as unreadable,
files that fail to read (usually not downloaded yet) as pending, both with a warning. Merge is
the union of revisions by identity and writes nothing when no revision is new.
An own file that cannot be read or decrypted is never overwritten.

Reads and writes sync on their own within two seconds (`syncLimit`), `hort sync`
has no limit, `hort status` stays local. Folder I/O runs outside the vault lock.
A new local revision is stamped behind the newest time its entry knows
(`Entry.Append`). All devices share one vault key; there is no adopt step.

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

## Vault contract

Outer and inner versions are 3. Entries persist revisions only; descriptions are
describe revisions. Normal reads and writes reject v2. Unlock may authenticate a
v2 vault so `hort migrate [--source <name>]` can convert exactly one unlocked
source. Never perform an implicit migration. Legacy names shared by secrets and
configs stop conversion before backup or replacement.

`hort history NAME [--source NAME] [--json]` explicitly returns revision values.
List, describe and search remain metadata-only. Config commands, type filters
and config counts were removed; all values use the secret interface.
