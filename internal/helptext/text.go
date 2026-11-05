// Package helptext holds the hort CLI help text.
package helptext

const HelpText = `Hort — Local secret store for humans and AI agents.

USAGE:
  hort <command> [flags]

READ (merged across all unlocked sources):
  hort --secret <name> [--env <env>] [--context <ctx>] [--source <name>]   Get a secret (stdout only)

WRITE (targets --source, defaults to primary):
  hort --set-secret <name> (--value <v> | --value-stdin) [--env <env>] [--context <ctx>] [--description <d>] [--source <name>]

DISCOVER:
  hort <search terms> [--json]           Search names, descriptions and scope metadata
  hort --list                           List entries across all unlocked sources (prefixed with [source])
  hort --describe <name>                 Show entry details (one block per source with a match)
  hort status                            Show primary vault status (locked/unlocked, entry count)

MANAGE:
  hort history <name> [--source <name>] [--json]
                                         Show revision history, including values
  hort migrate [--source <name>]         Convert one unlocked v2 source to v3 explicitly
  hort init [--restore]                  Create new primary vault or restore with existing passphrase
  hort unlock                            Unlock primary vault with passphrase
  hort lock                              Lock primary vault (clears session key)

SYNC (primary vault only, between devices sharing one passphrase):
  hort sync setup --path <dir>           Connect to an existing folder a sync service keeps in step
  hort sync                              Exchange with the folder now and report the result

SOURCES:
  hort source list [--json]              List primary + mounted sources with lock status
  hort source mount --name <n> --path <p> --key-hex <hex> [--kdf raw|argon2id]
                                         Register a mounted source vault and cache its key
  hort source unmount --name <n>         Unmount a source (vault file stays on disk)

DELETE:
  hort --delete <name> [--env <env>] [--context <ctx>] [--source <name>]   Delete entry or override

FLAGS:
  --env <name>          Target environment (default: * baseline)
  --context <name>      Target context, e.g. tenant or customer (default: * baseline)
  --source <name>       Target a specific source. Required for writes into mounted sources,
                        and for disambiguating reads when a name exists in multiple sources.
  --value <value>       Value to store
  --value-stdin         Read the value to store from stdin (keeps secrets out of argv)
  --description <text>  Human-readable description for discovery
  --json                Machine-readable JSON output for --list, --describe, status
  --help                Show this help text

SOURCES EXPLAINED:
  Hort holds exactly one 'primary' vault (~/.hort/vault.enc) plus any number of
  mounted sources registered via 'hort source mount'. Reads merge across every
  unlocked source. Writes default to the primary vault; pass --source <name> to
  target a specific mount.

  Mounted sources are the glue for external apps like Fachwerk: the app carries
  its own 32-byte master key, creates a vault file in its instance work-dir,
  and mounts it at startup. On shutdown it calls 'hort source unmount'.

ENVIRONMENTS AND CONTEXTS:
  Each entry is keyed by env:context. The baseline is *:*. Reads fall back:
    env+context → env+* → *+*

  Example (primary vault):
    hort --set-secret tenant-id --value "default-123"
    hort --set-secret tenant-id --value "heine-prod" --env prod --context heine
    hort --secret tenant-id --env prod --context heine   → heine-prod
    hort --secret tenant-id --env staging                → default-123 (fallback)

AGENT INSTRUCTIONS:
  Hort is designed to be used by AI agents (Claude, Codex, Gemini) as a local
  secret store.

  1. Discovery: Run 'hort --list' to see all available entries with source prefixes.
     Use 'hort --describe <name>' to see environments, contexts, and the source.

  2. Reading: 'hort --secret <name>' returns just the value on stdout — safe for
     piping and $(...) subshells. If a name exists in multiple sources you will
     get an ambiguity error; add '--source <name>' to pick one.

  3. Writing: '--set-secret' writes to the primary vault by
     default. Pipe sensitive values to '--value-stdin' so they never appear in
     process arguments. Pass '--source <name>' to write into a mounted source.

  4. Error handling:
     - Exit code 0: success, value on stdout
     - Exit code 1: general error, message on stderr
     - Exit code 2: primary vault is locked — ask user to run 'hort unlock'

  5. History: 'hort history <name> [--source <name>] [--json]' includes
     values. Use it only when the user requests past values or changes.
     Imported legacy revisions have an unknown recorded time.

  6. Migration: Older v2 vaults require 'hort migrate [--source <name>]'.
     Unlock the source first. Migration keeps an encrypted .pre-v3.bak backup.
     Same-named legacy secrets/configs stop migration; resolve them with the old
     CLI before migrating. Normal reads and writes never migrate implicitly.

  7. Do NOT parse vault files directly. Always use the CLI.
  8. Do NOT store hort output in files or logs.
  9. Use --json with --list and --describe for structured output.

  10. Sync: Once set up, every read and write exchanges with the sync folder on
      its own. A missing or slow folder only prints a warning on stderr; the
      command still runs locally with an unchanged exit code.

EXAMPLES:
  # Read a secret via fallback chain
  TOKEN=$(hort --secret grafana-token --env prod)

  # Mount a Fachwerk instance vault
  hort source mount --name fachwerk-heine-int \
     --path ~/.fachwerk-heine-int/secrets.hort.enc \
     --key-hex "$FACHWERK_SECRETS_MASTER_KEY_HEX"

  # Read merged across primary + all mounts
  hort --list

  # Write into a specific mount
  hort --set-secret telegram-token --value "xxx" --source fachwerk-heine-int
`
