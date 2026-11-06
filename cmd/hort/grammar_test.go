package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/vault"
)

// hortStdin runs the CLI with stdin, for --value-stdin.
func hortStdin(t *testing.T, home, stdin string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = []string{"HOME=" + home, "USERPROFILE=" + home, "HORT_TEST_RUN_CLI=1", passphrase}
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("hort %v: %v, stderr %q", args, err, stderr.String())
	}
	return cliResult{stdout.String(), stderr.String(), 0}
}

func newVault(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	hortOK(t, home, "init", "--server", offlineServer)
	return home
}

func TestCLIGetSetDeleteWithFields(t *testing.T) {
	home := newVault(t)
	set := hortOK(t, home, "set", "db", "--value", "default", "--description", "database")
	if set.stdout != "" || !strings.Contains(set.stderr, "Abruf: `hort get db`") {
		t.Fatalf("set: %+v", set)
	}
	set = hortOK(t, home, "set", "db", "password", "--value", "pw-prod", "--env", "prod", "--context", "heine")
	if set.stdout != "" || !strings.Contains(set.stderr, "Abruf: `hort get db password --env prod --context heine`") {
		t.Fatalf("set with field: %+v", set)
	}
	if got := hortStdin(t, home, "from-stdin", "set", "db", "token", "--value-stdin"); got.stdout != "" {
		t.Fatalf("set --value-stdin: %+v", got)
	}
	wantStdout(t, hort(t, home, "get", "db"), "default")
	wantStdout(t, hort(t, home, "get", "db", "password", "--env", "prod", "--context", "heine"), "pw-prod")
	wantStdout(t, hort(t, home, "get", "db", "password", "-e", "prod", "-c", "heine"), "pw-prod")
	wantStdout(t, hort(t, home, "get", "db", "token"), "from-stdin")
	// No fallback from a missing field to the default field.
	wantError(t, hort(t, home, "get", "db", "missing"), 1, "not found")
	wantError(t, hort(t, home, "get", "db", "password"), 1, "not found")

	// delete NAME FIELD removes only that value; without all three the entry goes.
	got := hortOK(t, home, "delete", "db", "token")
	if got.stdout != "" || !strings.Contains(got.stderr, "Deleted.") {
		t.Fatalf("delete: %+v", got)
	}
	wantError(t, hort(t, home, "get", "db", "token"), 1, "not found")
	wantStdout(t, hort(t, home, "get", "db"), "default")
	wantError(t, hort(t, home, "delete", "db", "token"), 1, "no value")
	hortOK(t, home, "delete", "db", "password", "--env", "prod", "--context", "heine")
	wantError(t, hort(t, home, "get", "db", "password", "--env", "prod", "--context", "heine"), 1, "not found")
	hortOK(t, home, "delete", "db")
	wantError(t, hort(t, home, "get", "db"), 1, "not found")
	wantError(t, hort(t, home, "delete", "db"), 1, "not found")
}

func TestCLIListDescribeSearchHistory(t *testing.T) {
	home := newVault(t)
	hortOK(t, home, "set", "db", "--value", "v-default", "--description", "main database")
	hortOK(t, home, "set", "db", "password", "--value", "v-pw", "--env", "prod")
	hortOK(t, home, "set", "api-key", "--value", "v-key")

	var list []map[string]any
	out := hortOK(t, home, "list", "--json")
	if err := json.Unmarshal([]byte(out.stdout), &list); err != nil || len(list) != 2 || out.stderr != "" {
		t.Fatalf("list --json: %v, %+v", err, out)
	}
	db := list[1]
	if db["name"] != "db" || db["description"] != "main database" || len(db["fields"].([]any)) != 1 || len(db["variants"].([]any)) != 2 {
		t.Fatalf("db entry: %v", db)
	}
	if text := hortOK(t, home, "list"); !strings.Contains(text.stdout, "db") || !strings.Contains(text.stdout, "[fields: password]") || strings.Contains(text.stdout+text.stderr, "v-pw") {
		t.Fatalf("list: %+v", text)
	}

	var one map[string]any
	if err := json.Unmarshal([]byte(hortOK(t, home, "describe", "db", "--json").stdout), &one); err != nil || one["name"] != "db" {
		t.Fatalf("describe --json: %v %v", err, one)
	}
	if text := hortOK(t, home, "describe", "db"); !strings.Contains(text.stdout, "Fields:       password") {
		t.Fatalf("describe: %+v", text)
	}
	wantError(t, hort(t, home, "describe", "nope"), 1, "not found")

	var found []map[string]any
	if err := json.Unmarshal([]byte(hortOK(t, home, "search", "main", "database", "--json").stdout), &found); err != nil || len(found) != 1 || found[0]["name"] != "db" {
		t.Fatalf("search: %v %v", err, found)
	}
	if text := hortOK(t, home, "search", "password"); !strings.Contains(text.stdout, "db") || strings.Contains(text.stdout, "api-key") {
		t.Fatalf("search by field: %+v", text)
	}
	wantStdout(t, hort(t, home, "search", "zzz"), "No entries found.\n")

	var history struct {
		Name      string
		Revisions []map[string]any
	}
	if err := json.Unmarshal([]byte(hortOK(t, home, "history", "db", "--json").stdout), &history); err != nil || history.Name != "db" || len(history.Revisions) != 3 {
		t.Fatalf("history --json: %v %+v", err, history)
	}
	rev := history.Revisions[2]
	if rev["op"] != "set" || rev["field"] != "password" || rev["env"] != "prod" || rev["context"] != "*" || rev["value"] != "v-pw" || rev["recorded_at"] == nil || rev["id"] == "" {
		t.Fatalf("history revision: %v", rev)
	}
	if text := hortOK(t, home, "history", "db"); !strings.Contains(text.stdout, `field="password"`) || !strings.Contains(text.stdout, `value="v-pw"`) {
		t.Fatalf("history: %+v", text)
	}
}

func TestCLIValidatesNewWrites(t *testing.T) {
	home := newVault(t)
	for _, args := range [][]string{
		{"set", "my name", "--value", "v"},
		{"set", "ok", "Bad_Field", "--value", "v"},
		{"set", "ok", "--value", "v", "--env", "a:b"},
		{"set", "ok", "--value", "v", "--context", "a b"},
		{"set", "ok", "--value", "v", "--env", "pr*"},
		{"set", "ok", "--value", strings.Repeat("x", 48<<10+1)},
	} {
		got := hort(t, home, args...)
		if got.code != 1 || got.stdout != "" || got.stderr == "" || len(got.stderr) > 200 {
			t.Errorf("%.40v: %+v", args, got)
		}
	}
	// A name starting with - needs the -- separator, and is still refused as a name.
	wantError(t, hort(t, home, "set", "--value", "v", "--", "-lead"), 1, "must not start with -")
	hortOK(t, home, "set", "ok", "--value", strings.Repeat("x", 48<<10))
	if got := hortOK(t, home, "get", "ok"); len(got.stdout) != 48<<10 {
		t.Fatalf("value at the limit: %d bytes", len(got.stdout))
	}
	wantError(t, hort(t, home, "set", "ok"), 1, "--value or --value-stdin")
}

func TestCLIRemovedRootGrammar(t *testing.T) {
	home := newVault(t)
	for _, args := range [][]string{
		{"--secret", "x"}, {"--set-secret", "x", "--value", "v"}, {"--list"}, {"--describe", "x"}, {"--delete", "x"}, {"token"}, {"source", "list"},
	} {
		got := hort(t, home, args...)
		if got.code != 1 || got.stdout != "" || got.stderr == "" {
			t.Errorf("%v: %+v", args, got)
		}
	}
}

func TestCLIHelpAndRecoveryTopic(t *testing.T) {
	home := t.TempDir()
	help := hort(t, home, "--help")
	for _, want := range []string{"hort get <name> [<field>]", "hort set <name> [<field>]", "hort delete <name>", "hort list", "hort describe", "hort search", "hort history", "hort migrate", "hort help recovery", "hort sync", "hort enroll <account-id>", "hort devices revoke <device-id>", "hort mcp"} {
		if help.code != 0 || !strings.Contains(help.stdout, want) {
			t.Fatalf("help lacks %q: %+v", want, help)
		}
	}
	for _, removed := range []string{"--secret", "--set-secret", "--list", "--describe", "--delete"} {
		if strings.Contains(help.stdout, removed) {
			t.Errorf("help names %q", removed)
		}
	}
	mcp := hort(t, home, "mcp", "--help")
	if mcp.code != 0 || !strings.Contains(mcp.stdout, "claude mcp add hort -- hort mcp") || !strings.Contains(mcp.stdout, "request_secret") {
		t.Fatalf("mcp help: %+v", mcp)
	}
	recovery := hort(t, home, "help", "recovery")
	if recovery.code != 0 || !strings.Contains(recovery.stdout, "hort passphrase") || !strings.Contains(recovery.stdout, "hort kit") || !strings.Contains(recovery.stdout, "compromised") || !strings.Contains(recovery.stdout, "hort devices revoke") {
		t.Fatalf("recovery: %+v", recovery)
	}
}

func TestCLILockedExitCodeForNewCommands(t *testing.T) {
	home := newVault(t)
	hortOK(t, home, "set", "t", "--value", "v")
	hortOK(t, home, "lock")
	for _, args := range [][]string{{"get", "t"}, {"set", "t", "--value", "v"}, {"delete", "t"}, {"list"}, {"describe", "t"}, {"search", "t"}, {"history", "t"}} {
		wantError(t, hort(t, home, args...), 2, "")
	}
}

func TestCLILegacyEntryReadableAndDeletable(t *testing.T) {
	home := newVault(t)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ref, err := vault.PrimaryRef()
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.LoadSessionFor(ref)
	if err != nil {
		t.Fatal(err)
	}
	err = vault.UpdateVault(ref, key, func(data *vault.VaultData) error {
		rev, err := vault.NewRevision("set", "prod:ctx:with:colons", "legacy-value")
		data.Append("my legacy name", rev)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	wantStdout(t, hort(t, home, "get", "my legacy name", "--env", "prod", "--context", "ctx:with:colons"), "legacy-value")
	if list := hortOK(t, home, "list", "--json"); !strings.Contains(list.stdout, `"my legacy name"`) || !strings.Contains(list.stdout, `"ctx:with:colons"`) {
		t.Fatalf("list: %+v", list)
	}
	if h := hortOK(t, home, "history", "my legacy name"); !strings.Contains(h.stdout, "legacy-value") {
		t.Fatalf("history: %+v", h)
	}
	wantError(t, hort(t, home, "set", "my legacy name", "--value", "new"), 1, "delete it and create it again under a valid name")
	hortOK(t, home, "delete", "my legacy name")
	wantError(t, hort(t, home, "get", "my legacy name", "--env", "prod", "--context", "ctx:with:colons"), 1, "not found")
}
