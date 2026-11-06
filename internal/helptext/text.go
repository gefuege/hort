// Package helptext holds the hort CLI help text.
package helptext

const HelpText = `Hort — Local secret store for humans and AI agents.

USAGE:
  hort <command> [flags]

READ:
  hort get <name> [<field>] [--env <env>] [--context <ctx>]
                                         Print one value (stdout only)

WRITE:
  hort set <name> [<field>] (--value <v> | --value-stdin) [--env <env>] [--context <ctx>]
           [--description <d>]           Store one value

DISCOVER (metadata only, never values):
  hort list [--json]                     List all entries
  hort describe <name> [--json]          Show one entry
  hort search <terms>... [--json]        Search names, descriptions, fields and scopes
  hort status [--json]                   Show local vault status: locked or unlocked, account,
                                         server, registration, device and entry count

MANAGE:
  hort history <name> [--json]           Show revision history, including values
  hort delete <name> [<field>] [--env <env>] [--context <ctx>]
                                         Without field, env and context: delete the whole entry.
                                         Otherwise delete that one value.
  hort init [--server <url>] [--name <n>]
                                         Create a new vault: account, Secret Key and passphrase.
                                         Prints the Emergency Kit and, on a terminal, waits until
                                         you type the last group of the Secret Key back.
  hort unlock                            Unlock the vault with your passphrase; the Secret Key
                                         comes from ~/.hort/secret-key
  hort lock                              Lock the vault (clears the session key)
  hort kit                               Print the Emergency Kit again (needs an unlocked vault)
  hort passphrase                        Set a new passphrase, keeping the Secret Key
  hort migrate                           Convert a v3 vault (Hort 0.4.x) into a v4 vault once;
                                         read 'hort migrate --help' first

TOPICS:
  hort help recovery                     What can and cannot be recovered

FLAGS:
  --env <name>          Environment (default: * baseline)
  --context <name>      Context, e.g. tenant or customer (default: * baseline)
  --value <value>       Value to store
  --value-stdin         Read the value to store from stdin (keeps secrets out of argv)
  --description <text>  Description of the whole entry, for discovery
  --json                Machine-readable JSON output
  --help                Show this help text

  HORT_PASSPHRASE and HORT_SECRET_KEY replace the passphrase prompt and the
  Secret Key file for automation. Without a terminal, init prints the
  Emergency Kit and skips the typed-back confirmation.

KEYS:
  Your vault opens only with your passphrase plus your Secret Key. The Secret
  Key is stored in ~/.hort/secret-key and printed in the Emergency Kit; Hort
  cannot recover either for you (hort help recovery).

  Unlock errors: "Secret Key mistyped" means the Secret Key fails its check
  symbol; "wrong passphrase" means the slot did not open.

NAMES, FIELDS, ENVIRONMENTS AND CONTEXTS:
  An entry (name) holds values. A value belongs to a field, an environment and
  a context. Without <field> a command uses the default field.

  Rules for new writes:
    name     1-128 bytes, no whitespace or control characters, not starting with -
    field    lowercase letters, digits, '.', '_' and '-', up to 64 characters,
             starting with a letter or digit
    env, context
             no ':', no whitespace or control characters; '*' only as the whole part
    value    at most 48 KiB of UTF-8
  Older entries that break these rules stay readable and can be deleted, but a
  write to them fails: delete the secret and create it again under a valid name.

  Each value is keyed by field and env:context. The baseline is *:*. Within the
  field you ask for, reads fall back:
    env+context → env+* → *+*
  A missing field never falls back to the default field.

  Example:
    hort set tenant-id --value "default-123"
    hort set tenant-id --value "heine-prod" --env prod --context heine
    hort get tenant-id --env prod --context heine   → heine-prod
    hort get tenant-id --env staging                → default-123 (fallback)

    hort set db-login username --value "app"
    hort set db-login password --value-stdin
    hort get db-login password

AGENT INSTRUCTIONS:
  Hort is designed to be used by AI agents (Claude, Codex, Gemini) as a local
  secret store.

  1. Discovery: Run 'hort list --json' to see all entries with their fields,
     environments and contexts. Use 'hort describe <name> --json' for one entry
     and 'hort search <terms>...' to narrow down.

  2. Reading: 'hort get <name> [<field>]' returns just the value on stdout —
     safe for piping and $(...) subshells.

  3. Writing: Pipe sensitive values to '--value-stdin' so they never appear in
     process arguments.

  4. Error handling:
     - Exit code 0: success, value on stdout
     - Exit code 1: general error, one line on stderr
     - Exit code 2: vault is locked — ask user to run 'hort unlock'

  5. History: 'hort history <name> [--json]' includes values. Use it only
     when the user requests past values or changes.
     Imported legacy revisions have an unknown recorded time.

  6. Do NOT parse vault files directly. Always use the CLI.
  7. Do NOT store hort output in files or logs.

EXAMPLES:
  # Read a value via the fallback chain
  TOKEN=$(hort get grafana-token --env prod)

  # Store a value without putting it into process arguments
  printf '%s' "$TOKEN" | hort set grafana-token --value-stdin --env prod
`

// RecoveryText answers "what if I lose something" and is shown by
// 'hort help recovery'. Rows for server and browser recovery come with those features.
const RecoveryText = `What can and cannot be recovered.

  Lost or compromised     Still available         Outcome
  ----------------------  ----------------------  ------------------------------------------
  Passphrase              an unlocked device      'hort passphrase' sets a new one
  Secret Key              an unlocked device      'hort kit' prints it again
  Passphrase or           nothing unlocked        The data cannot be recovered. Hort cannot
  Secret Key                                      help, by design.
  The vault key is        anything                Nothing helps except a new account: run
  compromised (a stolen                           'hort init' on a clean device, set the
  unlocked device, a                              values again and rotate the exposed secrets
  leaked session file)                            at their source.

Keep the Emergency Kit (Secret Key and account) somewhere safe and separate from
the passphrase. Whoever holds both can read everything.
`

// ConvergeFirst is the rollout order of contract §9.2, shown before migrating.
const ConvergeFirst = "Before migrating, run `hort sync` with Hort 0.4.x on every device. Then migrate on one device and enroll the others."

// MigrateText is the help of 'hort migrate' (contract §9.1, §9.2).
const MigrateText = `Convert the v3 vault of Hort 0.4.x into a v4 vault, once and locally.

` + ConvergeFirst + `

migrate asks for your passphrase, creates a new account with a new Secret Key
and keeps every revision unchanged. The v3 file stays as
~/.hort/vault.enc.pre-v4.bak. Nothing is written when an entry holds a revision
too large for one sync envelope. Afterwards migrate prints the Emergency Kit;
run 'hort sync' to register the vault on the server. A v2 vault must first be
migrated with Hort 0.4.1.
`
