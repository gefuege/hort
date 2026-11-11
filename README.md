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

**You, on your own machine.** Run `hort init`, set a passphrase, store secrets with `hort set <name> --value <value>`.

**Your AI coding agents.** Claude Code, Codex, Gemini, Cursor, whatever you run. `hort list` shows what is available, `hort get <name>` gives the value, `--json` gives it structured. One vault, every agent. When a secret is missing, the agent asks for it through `hort mcp`, and you type the value on hort.pm. It never enters the chat.

**All your devices.** The vault syncs through the Hort server at hort.pm (EU) or one you host yourself. The server stores ciphertext only.

**Integration code.** Anywhere a script or service needs "this token for dev, that one for prod, a third for the Heine tenant on prod", the `env + context` fallback chain covers it in one call.

## Install

### Homebrew (macOS, Linux)

```bash
brew install sebastian-breitzke/tap/hort && hort init
```

Updates: `brew upgrade hort`

### npm / npx (any OS)

```bash
npx @s16e/hort --help       # Run without installing
npm install -g @s16e/hort   # Install globally
hort init
```

### Windows (Scoop)

```powershell
scoop bucket add sebastian-breitzke https://github.com/sebastian-breitzke/scoop-bucket
scoop install hort
hort init
```

### Docker

```bash
docker run --rm -it -v hort-state:/var/lib/hort/.hort ghcr.io/gefuege/hort:latest init
```

The image runs one CLI command per call; the volume holds the vault.

### Linux binary

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
$release = (Invoke-RestMethod -Uri "https://api.github.com/repos/gefuege/hort/releases/latest").tag_name
$version = $release.TrimStart("v")
$url = "https://github.com/gefuege/hort/releases/download/$release/hort_${version}_windows_amd64.zip"
Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\hort.zip"
Expand-Archive -Path "$env:TEMP\hort.zip" -DestinationPath "$env:LOCALAPPDATA\hort" -Force
$env:PATH += ";$env:LOCALAPPDATA\hort"
[Environment]::SetEnvironmentVariable("PATH", "$([Environment]::GetEnvironmentVariable('PATH', 'User'));$env:LOCALAPPDATA\hort", "User")
Remove-Item "$env:TEMP\hort.zip"
hort init
```

### From source

```bash
go install github.com/gefuege/hort/cmd/hort@latest && hort init
```

`hort --version` prints the installed version.

## Getting started

```bash
# Create your vault: account, Secret Key and passphrase
hort init

# Store your first secret
hort set grafana-token --value "glsa_..." --description "Grafana API token"

# Use it
TOKEN=$(hort get grafana-token)
curl -H "Authorization: Bearer $TOKEN" https://monitoring.example.com
```

`hort init` prints your **Emergency Kit** (account ID and Secret Key). Keep it somewhere safe and apart from the passphrase: your vault opens only with passphrase plus Secret Key, and nobody, including us, can recover either. `hort help recovery` lists what can and cannot be recovered.

**Registration.** hort.pm is a private instance, not a public service: creating an account there needs a personal invite link. To sync your own vault, host the server yourself; see [Self-hosting](docs/self-hosting.md). An invite link shows the command to run, `hort init --invite <code>`; if init could not reach the server, `hort sync --invite <code>` registers later. The code works for one account, is only sent while registering and is never stored. Your own server decides its own rule.

## Usage

### Environments

Every entry supports environment-specific values. Without `--env`, the baseline (`*`) is used.

```bash
hort set db-password --value "dev-pass" --description "PostgreSQL password"
hort set db-password --value "prod-pass" --env prod

hort get db-password               # dev-pass (baseline)
hort get db-password --env prod    # prod-pass
hort get db-password --env staging # dev-pass (fallback to baseline)
```

### Contexts

A context is a second dimension next to the environment: tenant, customer, project.

```bash
hort set tenant-id --value "default-123" --description "Tenant ID"
hort set tenant-id --value "prod-123" --env prod
hort set tenant-id --value "heine-456" --env prod --context heine

hort get tenant-id --env prod --context heine  # heine-456
hort get tenant-id --env prod                  # prod-123
hort get tenant-id --env staging               # default-123 (fallback to *+*)
```

Fallback chain: `env+context -> env+* -> *+*`. Specific wins, the baseline catches the rest.

### Named fields

An entry can hold several named values. Without a field you use the default field; a read never falls back from a named field to the default field.

```bash
hort set db-login username --value "app"
hort set db-login password --value-stdin
hort get db-login password
```

### Discovery

```bash
hort list [--json]            # all entries, never values
hort describe tenant-id       # one entry: fields, environments, contexts
hort search stripe            # names, descriptions, fields and scopes
hort status [--json]          # locked or unlocked, account, server, last sync
```

### History and delete

`hort history <name>` shows all recorded revisions, including values and deletions. List, search and describe never show values. A whole-entry deletion hides older values; a later `set` revives its own scope.

```bash
hort delete tenant-id                              # whole entry
hort delete tenant-id --env prod --context heine   # one scoped value
hort delete db-login password                      # one field
```

### Lock and unlock

```bash
hort unlock    # passphrase, plus the Secret Key from ~/.hort/secret-key
hort lock      # clear the session key
hort passphrase  # set a new passphrase, keeping the Secret Key
hort kit       # print the Emergency Kit again
```

## Sync and devices

Sync goes through the Hort server: hort.pm (EU, Cloudflare) or your own. The server stores ciphertext and public keys only. It never sees names, values, passphrase, Secret Key or vault key. Reads sync first and writes sync afterwards, for at most 2 seconds; a failed sync prints one warning and never changes the exit code. Hort works offline.

```bash
hort sync          # sync now, without a time limit; the first run registers the account
```

To add another device, run this on the new machine:

```bash
hort enroll <account-id>     # asks for Secret Key and passphrase, then pulls the vault
hort devices                 # devices and passkeys of this account
hort devices revoke <id>     # end a device's server access
```

Revoking ends server access only. It does not help against someone who already holds your vault key; `hort help recovery` says what does.

## Web app (hort.pm)

Open https://hort.pm/vault to read, copy and set secrets in the browser. Unlock with passphrase plus Secret Key, or with a passkey. The web app is JavaScript served by hort.pm: if you cannot accept that, use only the CLI. See the [threat model](https://hort.pm/threat-model.html) for what Hort does and does not protect against, and the [terms](https://hort.pm/terms.html).

## Agent integration

Hort is agent-first. `hort --help` ends with an `AGENT INSTRUCTIONS` section: an agent that runs it learns the interface in one call.

1. `hort list --json`: discover entries
2. `hort describe <name> --json`: environments, contexts, fields
3. `hort get <name> [<field>]`: the value on stdout, no decoration, safe for `$()` and pipes
4. Exit code 2 means the vault is locked: the agent asks you to run `hort unlock`

### Ask for secrets without the chat (MCP)

`hort mcp` is an MCP server on stdio with one tool, `request_secret`. The agent passes name, description and optionally fields (up to 16 fields of one secret, entered on one page), env and context. You get a link to hort.pm, sign in with a passkey and type the value there. The agent learns only the name and a status (`stored`, `pending`, `declined`, `expired`, `conflict`) and reads the value afterwards with `hort get`. There is no MCP tool that reads values or lists secrets.

```bash
claude mcp add hort -- hort mcp
```

For other MCP clients, register the command `hort mcp` as a stdio server. The vault must be unlocked and registered on the server. `hort mcp --help` has the details.

### Automation

`HORT_PASSPHRASE` and `HORT_SECRET_KEY` replace the passphrase prompt and the Secret Key file (CI, scripting). Without a terminal, `hort init` prints the Emergency Kit and skips the typed-back confirmation.

## Upgrading from Hort 0.4

Hort 1.0 uses a new vault format (v4) with Secret Key and sync through the server. Folder sync is gone. A v3 vault is converted once and locally:

1. On every device, run `hort sync` with Hort 0.4.x so all changes converge.
2. Install Hort 1.0 on one device and run `hort migrate`. It asks for your passphrase, creates the account and Secret Key and keeps every revision. The v3 file stays as `~/.hort/vault.enc.pre-v4.bak`.
3. Run `hort sync` to register the vault on the server, then `hort enroll <account-id>` on your other devices.

A v2 vault must first be migrated with Hort 0.4.1. Mounted sources (`hort source ...`) and the old root flags (`hort --secret`, `hort --list`) no longer exist: use `hort get`, `hort list` and so on. `hort migrate --help` has the details.

If an old macOS installation still has the launchd daemon, remove it:

```bash
launchctl bootout "gui/$(id -u)/tech.s16e.hort.daemon"
rm -f "$HOME/Library/LaunchAgents/tech.s16e.hort.daemon.plist"
rm -f "$HOME/.hort/daemon.sock" "$HOME/.hort/daemon.pid"
```

## Self-hosting

The backend is a Cloudflare Worker in `server/` (see [server/README.md](server/README.md)). The step-by-step guide is [docs/self-hosting.md](docs/self-hosting.md). Point the CLI at your server with `hort init --server <url>`.

## Security model

- **Encryption:** AES-256-GCM, authenticated and tamper-proof. Keys are derived from passphrase plus Secret Key (Argon2id).
- **Zero knowledge server:** the sync server stores ciphertext only.
- **Session key:** file-based in `~/.hort/.session` (mode 0600), scoped to the OS user, until `hort lock`.
- **No telemetry.** The only network traffic is sync with your configured server.
- **Not protected against:** root or malware on an unlocked device; whoever controls the hort.pm deployment when you use the web app; losing both Secret Key and passphrase.

Details: [threat model](https://hort.pm/threat-model.html). Byte-level formats: `spec/vectors/README.md`.

## Development

```bash
go build ./cmd/hort/ && go test ./...
cd server && npm ci && npm run check:web
```

Releases: a pushed `v*` tag builds binaries, Homebrew and Scoop packages with GoReleaser and the Docker image; npm is published by hand (see `AGENTS.md`).

## Name

**Hort** (German, /hɔʁt/) — the Nibelungenhort, the legendary treasure hoard from Germanic mythology. Where the gold lies. Where your secrets belong.

## License

MIT
