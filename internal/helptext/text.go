// Package helptext holds the hort CLI help text.
package helptext

const HelpText = `Hort — Local secret store for humans and AI agents.

USAGE:
  hort <command> [flags]

READ:
  hort --secret <name> [--env <env>] [--context <ctx>]   Get a secret (stdout only)

WRITE:
  hort --set-secret <name> (--value <v> | --value-stdin) [--env <env>] [--context <ctx>] [--description <d>]

DISCOVER:
  hort <search terms> [--json]           Search names, descriptions and scope metadata
  hort --list                           List all entries
  hort --describe <name>                 Show entry details
  hort status [--json]                   Show local vault status: locked or unlocked, account,
                                         server, registration, device and entry count

MANAGE:
  hort history <name> [--json]           Show revision history, including values
  hort init [--server <url>] [--name <n>]
                                         Create a new vault: account, Secret Key and passphrase.
                                         Prints the Emergency Kit and, on a terminal, waits until
                                         you type the last group of the Secret Key back.
  hort unlock                            Unlock the vault with your passphrase; the Secret Key
                                         comes from ~/.hort/secret-key
  hort lock                              Lock the vault (clears the session key)
  hort kit                               Print the Emergency Kit again (needs an unlocked vault)
  hort passphrase                        Set a new passphrase, keeping the Secret Key

DELETE:
  hort --delete <name> [--env <env>] [--context <ctx>]   Delete entry or override

FLAGS:
  --env <name>          Target environment (default: * baseline)
  --context <name>      Target context, e.g. tenant or customer (default: * baseline)
  --value <value>       Value to store
  --value-stdin         Read the value to store from stdin (keeps secrets out of argv)
  --description <text>  Human-readable description for discovery
  --json                Machine-readable JSON output for --list, --describe, status
  --help                Show this help text

  HORT_PASSPHRASE and HORT_SECRET_KEY replace the passphrase prompt and the
  Secret Key file for automation. Without a terminal, init prints the
  Emergency Kit and skips the typed-back confirmation.

KEYS:
  Your vault opens only with your passphrase plus your Secret Key. The Secret
  Key is stored in ~/.hort/secret-key and printed in the Emergency Kit; Hort
  cannot recover either for you.

  Unlock errors: "Secret Key mistyped" means the Secret Key fails its check
  symbol; "wrong passphrase" means the slot did not open.

ENVIRONMENTS AND CONTEXTS:
  Each entry is keyed by env:context. The baseline is *:*. Reads fall back:
    env+context → env+* → *+*

  Example:
    hort --set-secret tenant-id --value "default-123"
    hort --set-secret tenant-id --value "heine-prod" --env prod --context heine
    hort --secret tenant-id --env prod --context heine   → heine-prod
    hort --secret tenant-id --env staging                → default-123 (fallback)

AGENT INSTRUCTIONS:
  Hort is designed to be used by AI agents (Claude, Codex, Gemini) as a local
  secret store.

  1. Discovery: Run 'hort --list' to see all available entries.
     Use 'hort --describe <name>' to see environments and contexts.

  2. Reading: 'hort --secret <name>' returns just the value on stdout — safe for
     piping and $(...) subshells.

  3. Writing: Pipe sensitive values to '--value-stdin' so they never appear in
     process arguments.

  4. Error handling:
     - Exit code 0: success, value on stdout
     - Exit code 1: general error, message on stderr
     - Exit code 2: vault is locked — ask user to run 'hort unlock'

  5. History: 'hort history <name> [--json]' includes values. Use it only
     when the user requests past values or changes.
     Imported legacy revisions have an unknown recorded time.

  6. Migration: Hort reads and writes only v4 vaults. A v3 vault is rejected
     with a pointer to 'hort migrate'; normal reads and writes never migrate.

  7. Do NOT parse vault files directly. Always use the CLI.
  8. Do NOT store hort output in files or logs.
  9. Use --json with --list and --describe for structured output.

EXAMPLES:
  # Read a secret via fallback chain
  TOKEN=$(hort --secret grafana-token --env prod)

  # Store a value without putting it into process arguments
  printf '%s' "$TOKEN" | hort --set-secret grafana-token --value-stdin --env prod
`
