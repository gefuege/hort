# Hort

**Local secret store for humans and AI agents.**

<p align="center">
  <img src="hort-logo-transparent.png" alt="Hort Logo" width="400">
</p>

## Why

I work with three AI coding agents daily — Claude Code, Codex, Gemini. All of them need credentials. API tokens, database passwords, tenant IDs, service URLs. Across environments. Across customers.

Here is how that works today: `.env` files scattered across projects. Environment variables that vanish between sessions. Hardcoded values in configs that shouldn't be committed. Or the agent asks you, you paste it in, it forgets, it asks again next session.

None of this is discoverable. An agent can't ask "what secrets are available?" — it has to know upfront or ask you every time. None of it is environment-aware — switching between dev and prod means manual juggling. None of it is secure — plaintext files with credentials sitting in project directories. And none of it works across agents — each tool has its own way of handling credentials, or doesn't handle them at all.

*Hort* — the Nibelungenhort, where the treasure lies — solves this. One encrypted vault, one CLI, all agents, all environments.

## Who uses Hort

**You, on your own machine.** Run `hort init`, set a passphrase, add secrets with `hort -s <name> -v <value>`.

**Your AI coding agents.** Claude Code, Codex, Gemini, Cursor, whatever you run. `hort list` shows them what is available, `hort get <name>` gives them the value, `--json` gives it structured. No more "what's the DB password again?" on every new session. One vault, every agent.

**Your own apps, as a drop-in secret backend.** Instead of reinventing a secrets table, mount an encrypted file into hort at startup:

```bash
# your app on boot
hort source mount --name myapp-prod \
  --path ~/.myapp-prod/secrets.hort.enc \
  --key-hex "$MYAPP_MASTER_KEY_HEX"
```

Your app reads and writes via the same hort CLI that it already uses for shell automation. The moment you do this, **the agents working on that app pick up the same secrets aus einem guss** — no separate credential system per integration, no copy-paste between the app's UI and the agent's context. Your app's `.env`-equivalent and your agent's `hort get` resolve to the same byte.

**Integration code.** Anywhere a script or service needs "this token for dev, that one for prod, a third for the Heine tenant on prod" — the `env + context` fallback chain covers it in one call.

## Install

### npm / npx (cross-platform)

```bash
npx @s16e/hort --help       # Run without installing
npm install -g @s16e/hort   # Install globally
hort init
```

### macOS (Homebrew) — recommended

```bash
brew install sebastian-breitzke/tap/hort && hort init
```

Updates: `brew upgrade hort`

### Linux

```bash
VERSION=$(curl -fsSI -o /dev/null -w '%{redirect_url}' https://github.com/gefuege/hort/releases/latest | grep -oE '[^/]+$') \
  && ARCH=$(uname -m | sed 's/x86_64/amd64/') \
  && curl -fsSL "https://github.com/gefuege/hort/releases/download/${VERSION}/hort_${VERSION#v}_linux_${ARCH}.tar.gz" \
  | tar -xz -C /tmp hort \
  && sudo mv /tmp/hort /usr/local/bin/hort \
  && hort init
```

### Windows (PowerShell)

```powershell
$release = (Invoke-RestMethod -Uri "https://api.github.com/repos/sebastian-breitzke/hort/releases/latest").tag_name
$version = $release.TrimStart("v")
$url = "https://github.com/sebastian-breitzke/hort/releases/download/$release/hort_${version}_windows_amd64.zip"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\hort.zip"
Expand-Archive -Path "$env:TEMP\hort.zip" -DestinationPath "$env:LOCALAPPDATA\hort" -Force
$env:PATH += ";$env:LOCALAPPDATA\hort"
[Environment]::SetEnvironmentVariable("PATH", "$([Environment]::GetEnvironmentVariable('PATH', 'User'));$env:LOCALAPPDATA\hort", "User")
Remove-Item "$env:TEMP\hort.zip"
Write-Host "hort installed" -ForegroundColor Green
hort init
```

### Windows (Scoop)

```powershell
scoop bucket add sebastian-breitzke https://github.com/sebastian-breitzke/scoop-bucket
scoop install hort
hort init
```

### From Source

```bash
go install github.com/sebastian-breitzke/hort/cmd/hort@latest && hort init
```

After `hort init` you'll set a passphrase — that's it. Vault created, session
unlocked, ready to store secrets.

## Usage

### Getting Started

```bash
# Create your vault — you'll set a passphrase
hort init

# Store your first secret
hort set grafana-token --value "glsa_..." --description "Grafana API token"

# Use it
TOKEN=$(hort get grafana-token)
curl -H "Authorization: Bearer $TOKEN" https://monitoring.example.com
```

### Environments

Every entry supports environment-specific values. Without `--env`, the baseline (`*`) is used.

```bash
hort set db-password --value "dev-pass" --description "PostgreSQL password"
hort set db-password --value "prod-pass" --env prod

hort get db-password              # → dev-pass (baseline)
hort get db-password --env prod   # → prod-pass
hort get db-password --env staging # → dev-pass (fallback to baseline)
```

### Contexts

Secrets aren't just per-environment. They can be per-environment *and* per-context. A context is any second dimension: tenant, customer, project.

```bash
hort set tenant-id --value "default-123" --description "SimpleChain tenant ID"
hort set tenant-id --value "prod-123" --env prod
hort set tenant-id --value "heine-456" --env prod --context heine
hort set tenant-id --value "otto-789" --env prod --context otto

hort get tenant-id --env prod --context heine  # → heine-456
hort get tenant-id --env prod --context otto   # → otto-789
hort get tenant-id --env prod                  # → prod-123
hort get tenant-id --env staging               # → default-123 (fallback to *+*)
```

Fallback chain: `env+context → env+* → *+*`. Specific wins, baseline catches the rest.

### Service URLs and other values

Store service URLs, tenant IDs and tokens through the same secret interface:

```bash
hort set api-url --value "https://api.dev.example.com" --description "Base API URL"
hort set api-url --value "https://api.example.com" --env prod
API_URL=$(hort get api-url --env prod)
```

### Fields

An entry can hold several named values. Without a field you use the default field; reads never fall back from a named field to the default field.

```bash
hort set db-login username --value "app"
hort set db-login password --value-stdin
hort get db-login password
```

### Discovery

Agents need to know what's available. Hort makes everything discoverable:

```bash
hort list
# api-url      Base API URL           [env: *, prod]
# tenant-id    SimpleChain tenant ID  [env: *, prod]  [ctx: heine, otto]

hort describe tenant-id
# Name:         tenant-id
# Description:  SimpleChain tenant ID
# Environments: *, prod
# Contexts:     heine, otto

hort list --json   # Machine-readable output
hort describe tenant-id --json
```

### History and migration

`hort history <name> [--source <name>] [--json]` shows all recorded revisions,
including values and deletions. List, search and describe never show values.
New changes record their local UTC time once. Imported legacy values have an
unknown recorded time. Revisions sort by recorded time and then revision ID;
unknown times sort first. A whole-entry deletion hides older values, including
older variants that arrive later. A later set can revive its own scope.

Existing v2 vaults need an explicit conversion after unlocking:

```bash
hort unlock
hort migrate
hort migrate --source myapp-prod
```

Each call converts exactly one unlocked source. Migration combines legacy secrets
and configs into one secret collection and preserves exact keys, values and
descriptions. If a name exists in both legacy collections, migration stops and
reports the names without values. Resolve those collisions with the old CLI
before migrating. The removed config flags have no aliases.

Migration keeps the original encrypted bytes in `<vault>.pre-v3.bak` with mode
0600. Ordinary saves do not overwrite that backup. Normal reads and writes reject
v2 and never migrate automatically. The new outer and inner format versions are
both 3; old binaries cannot read or write v3 vaults. Header fields are
authenticated with the ciphertext.

### Vault Management

```bash
hort init              # Create new vault (set passphrase)
hort init --restore    # Restore with existing passphrase on a new machine
hort unlock            # Unlock vault (passphrase → session key cached)
hort lock              # Lock vault (clear session key)
hort status            # Show vault status, entry counts
```

### Delete

```bash
hort delete tenant-id                          # Delete entire entry
hort delete tenant-id --env prod               # Delete prod override only
hort delete tenant-id --env prod --context heine  # Delete specific env+context
hort delete db-login password                  # Delete one field
```

### Mounted Sources

Hort supports multiple secret sources on top of the primary vault. Use `hort source mount` to register an external encrypted file (e.g. an app's instance-local secret store) as an additional source. Reads merge across every unlocked source with a `[source]` prefix; writes default to the primary vault and require `--source <name>` to target a mount.

```bash
# Register a mounted source (raw 32-byte key, no KDF)
hort source mount --name fachwerk-heine \
  --path ~/.fachwerk-heine/secrets.hort.enc \
  --key-hex "$MY_APP_MASTER_KEY_HEX"

hort source list                         # primary + all registered mounts
hort --list                              # merged entries with [mount] prefixes
hort --set-secret foo --value bar --source fachwerk-heine
hort --secret foo --source fachwerk-heine
hort source unmount --name fachwerk-heine
```

The vault file itself stays on disk between unmounts — unmount only clears the cached key and removes the registry entry. Mount names must be lowercase `a-z0-9._-`. `primary` is reserved.

### Device sync

Hort keeps the primary vault of several devices in step through a folder that
a sync service of your choice, such as iCloud Drive, already replicates. Hort
itself stays offline: it only reads and writes files in that folder.

```bash
# First device
hort sync setup --path ~/path/to/sync-folder

# Second device: same vault, same passphrase
mkdir -p ~/.hort
cp ~/path/to/sync-folder/hort-<id>.enc ~/.hort/vault.enc
hort init --restore
hort sync setup --path ~/path/to/sync-folder

hort sync    # Exchange now and report; reads and writes also do this on their own
```

Each device writes one encrypted copy of its vault into the folder and merges
the revisions of every other copy. The revision with the later time wins, and
the other one stays in `hort history`, whichever device delivers first. Reads
and writes keep working offline; changes travel on the next use with the folder
in reach. A missing or unresponsive folder costs a warning on stderr and a few
seconds at most.

All devices share one passphrase. A vault created separately has a different
key, so `hort sync setup` stops without changing anything. Mounted sources are
not synced.

Migrate a v2 vault before it joins, then bring it to the second device as a copy
of the migrated v3 file plus `hort init --restore`. Two vaults migrated
separately with the same key do merge, but migrated revisions have no recorded
time, so current values can flip to the other device's.

A file the sync service has not downloaded yet cannot be read for a moment. Hort
warns and reads it on a later run; files from other devices never hold up the
own push.

If a device cannot read or decrypt its own file in the folder, it stops pushing
and warns on every use. If that does not clear up, remove that file from the folder by hand and the next run
writes it anew. After a fresh `hort init` the file still holds the old vault, so
keep a copy if you need it.

### Removing an older daemon installation

Hort now accesses vault files directly through the CLI. Before upgrading an
older macOS installation, remove its launchd service. For a user-level install:

```bash
launchctl bootout "gui/$(id -u)/tech.s16e.hort.daemon"
rm -f "$HOME/Library/LaunchAgents/tech.s16e.hort.daemon.plist"
```

For an installation made with `hort daemon install --system`:

```bash
sudo launchctl bootout system/tech.s16e.hort.daemon
sudo rm -f /Library/LaunchDaemons/tech.s16e.hort.daemon.plist
```

If `bootout` reports that the service is not loaded, remove the plist anyway.
After the service has stopped, remove its unused socket and PID file:

```bash
rm -f "$HOME/.hort/daemon.sock" "$HOME/.hort/daemon.pid"
```

Keep `~/.hort/vault.enc`, its backup, and the session/source files. For v2 vaults, run the explicit migration described above. Containers now run individual CLI commands; mount the
vault directory at `/var/lib/hort/.hort` and pass the desired command (for
example `init`, `status --json`, or `--list`).

### Readiness

Apps integrating Hort can use `hort status --json` as a single readiness
check:

```json
{
  "primary": { "unlocked": true, "vault_path":  "/Users/you/.hort/vault.enc",
               "secret_count": 32 },
  "ready": true
}
```

`ready: true` means secrets can be resolved right now; `false` means the app
should ask the user to run `hort unlock`.

## Agent Integration

Hort is agent-first, not agent-compatible. The `--help` output includes an `AGENT INSTRUCTIONS` section — when an agent runs `hort --help`, it learns the full interface in one call.

**How agents use Hort:**

1. `hort --list` — discover available secrets
2. `hort --describe <name>` — see environments and contexts for an entry
3. `hort --secret <name>` — read values
4. Output is raw on stdout, no decoration — safe for `$()` and pipes
5. `--json` flag for structured output when agents prefer to parse
6. Exit code 2 = vault locked → agent asks user to run `hort unlock`

**Automation:** Set `HORT_PASSPHRASE` to skip interactive prompts (CI/CD, scripting):

```bash
export HORT_PASSPHRASE="my-passphrase"
hort init    # no terminal prompt
hort unlock  # no terminal prompt
```

### Claude Code plugin: enter secrets without the chat

The `hort-secrets` plugin lets an agent ask for secrets without seeing them. The agent calls `request_secrets` with name, description and optional env and context per secret. A bar above the prompt shows one field per secret. Enter stores the value through `hort --set-secret --value-stdin`, and the chat only learns the stored name.

```text
/plugin install hort-secrets --marketplace sebastian-breitzke/hort
```

Click the field or press `ctrl+x tab` before typing: text typed into the prompt goes to the chat. The field shows the value in plain text. `hort` must be on the `PATH` of the Claude Code process.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (not found, invalid args) |
| 2 | Vault is locked |

## Implementation Details

### Architecture

```
cmd/hort/main.go            CLI entry point (Cobra)
internal/
├── vault/
│   ├── crypto.go            AES-256-GCM encrypt/decrypt, Argon2id KDF, v3 encryption
│   ├── format.go            v3 header layout + KDF flag
│   ├── vault.go             VaultRef, load/save/update by ref, primary helpers
│   ├── sources.go           Mounted-source registry (~/.hort/sources/index.json)
│   ├── session.go           Per-ref session key persistence
│   └── lock.go              Per-ref flock for concurrent writers
├── store/
│   └── store.go             Multi-source merge reads, targeted writes, ambiguity detection
├── cli/
│   ├── commands.go          Command implementations (direct store access)
│   └── output.go            Output formatting (plain text + JSON)
├── helptext/
│   └── text.go              The `hort --help` string
└── (...)

```

### Encryption

Everything lives in a single file: `~/.hort/vault.enc`.
Writes to the same canonical vault path share a local file lock, including mounted and symlink aliases. Locks live under `~/.hort/locks/`. Every successful update keeps the previous encrypted state in `~/.hort/vault.enc.bak`.

**File format** (binary):

```
[magic:"HRT\x03"][version:1 byte (=3)][kdf:1 byte][salt:32][argon-time:4][argon-memory:4][argon-threads:1][nonce:12][ciphertext+tag:...]
```

`kdf = 0` → Argon2id-derived key (salt + params are meaningful). `kdf = 1` → raw 32-byte key supplied by the mounter (salt/params fields are present but unused). Mounted sources typically use `kdf = 1` so the mounting app's own master key is used directly, no Argon2id pass.

- **Key derivation:** Argon2id (memory-hard, GPU-resistant) with 64 MB memory cost, 3 iterations, 4 threads
- **Encryption:** AES-256-GCM with authenticated encryption (tamper-proof)
- **Salt:** 32 bytes, cryptographically random, generated at vault creation
- **Nonce:** 12 bytes, fresh random nonce on every write

The header (salt + Argon2id params) is unencrypted by design — these are not secrets. The ciphertext is the AES-256-GCM sealed JSON vault body.

### Vault Structure (decrypted)

```json
{
  "version": 3,
  "source_id": "21e9dcc8a5eb4d029bd7410ae905b13b",
  "secrets": {
    "tenant-id": {
      "revisions": [
        {
          "id": "e88fb43536b544158b2c63bd4bbfdc86",
          "recorded_at": "2026-11-02T12:00:00Z",
          "op": "set",
          "key": "*:*",
          "value": "default-123"
        }
      ]
    }
  }
}
```

Each entry stores only revisions: `set`, `delete`, `delete-entry` and `describe`.
Current values and descriptions are reduced on read; there is no persisted
current-value copy. Scoped revisions retain the exact `env:context` key.
`*` is the baseline for either dimension. Source IDs and revision IDs are
random 128-bit identities. Sources remain independent; the same name in several
sources requires disambiguation.

### Session

`hort unlock` derives the encryption key from your passphrase and caches it in `~/.hort/.session` (chmod 600, OS user-owned). The session persists until `hort lock` — no TTL, no daemon.

Subsequent CLI calls read the session key and use it to decrypt the vault on every operation. No in-memory state between calls.

### Security Model

- **Encryption:** AES-256-GCM — authenticated, tamper-proof
- **Key derivation:** Argon2id — memory-hard, resistant to GPU/ASIC attacks
- **Session key:** File-based, chmod 600, scoped to OS user
- **No network:** Zero network access, no telemetry, no phone-home. Hort has no cloud service of its own; device sync only uses a local folder that a third-party service replicates
- **Sync folder:** Holds encrypted vault copies, never plaintext or keys. Header and salt are included, so anyone who reads the folder can attack the passphrase offline: use a long random one. Deleted values stay in the encrypted history there as well
- **Threat model:** Protects against other OS users and casual file access. Root access = game over — accepted for a local development tool
- **Portability:** Same passphrase decrypts the vault on any machine. Copy `vault.enc`, run `hort init --restore`

### Dependencies

| Dependency | Purpose |
|------------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `golang.org/x/crypto` | Argon2id key derivation |
| `golang.org/x/term` | Terminal passphrase input (no echo) |
| Standard library | `crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/json`, `os` |

### Cross-Platform

Single Go binary. No CGO, no system dependencies. Cross-compiles to:

- macOS (amd64, arm64)
- Linux (amd64, arm64)
- Windows (amd64)

GoReleaser builds all targets automatically on GitHub Release.

## Name

**Hort** (German, /hɔʁt/) — the Nibelungenhort, the legendary treasure hoard from Germanic mythology. Where the gold lies. Where your secrets belong.

## License

MIT
