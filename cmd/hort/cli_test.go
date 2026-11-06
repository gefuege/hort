package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The test binary doubles as the hort CLI, so exit codes and the split between
// stdout and stderr are checked on the real command path.
func TestMain(m *testing.M) {
	if os.Getenv("HORT_TEST_RUN_CLI") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type cliResult struct {
	stdout, stderr string
	code           int
}

// hortEnv runs the CLI in home; env entries are added to the minimal environment.
func hortEnv(t *testing.T, home string, env []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append([]string{"HOME=" + home, "HORT_TEST_RUN_CLI=1"}, env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return cliResult{stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()}
}

const passphrase = "HORT_PASSPHRASE=synthetic-passphrase"

func hort(t *testing.T, home string, args ...string) cliResult {
	t.Helper()
	return hortEnv(t, home, []string{passphrase}, args...)
}

func hortOK(t *testing.T, home string, args ...string) cliResult {
	t.Helper()
	got := hort(t, home, args...)
	if got.code != 0 {
		t.Fatalf("hort %v: exit %d, stderr %q", args, got.code, got.stderr)
	}
	return got
}

func wantStdout(t *testing.T, got cliResult, want string) {
	t.Helper()
	if got.code != 0 || got.stdout != want {
		t.Fatalf("exit %d, stdout %q, want %q; stderr %q", got.code, got.stdout, want, got.stderr)
	}
}

func wantError(t *testing.T, got cliResult, code int, text string) {
	t.Helper()
	if got.code != code || !strings.Contains(got.stderr, text) || got.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit %d with %q", got.code, got.stdout, got.stderr, code, text)
	}
}

func TestCLIRoundTripInitSetLockUnlockGet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	initRun := hortOK(t, home, "init", "--name", "laptop")
	if initRun.stdout != "" || !strings.Contains(initRun.stderr, "HORT EMERGENCY KIT") || !strings.Contains(initRun.stderr, "Secret Key:  H4-") || strings.Contains(initRun.stderr, "synthetic-passphrase") {
		t.Fatalf("init output: stdout %q, stderr %q", initRun.stdout, initRun.stderr)
	}
	if info, err := os.Stat(filepath.Join(home, ".hort", "secret-key")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("secret-key: %v", err)
	}
	wantError(t, hort(t, home, "init"), 1, "already exists")

	hortOK(t, home, "--set-secret", "token", "--value", "value", "--env", "prod")
	wantStdout(t, hort(t, home, "--secret", "token", "--env", "prod"), "value")

	hortOK(t, home, "lock")
	wantError(t, hort(t, home, "--secret", "token", "--env", "prod"), 2, "locked")
	hortOK(t, home, "unlock")
	wantStdout(t, hort(t, home, "--secret", "token", "--env", "prod"), "value")

	var status map[string]any
	if err := json.Unmarshal([]byte(hortOK(t, home, "status", "--json").stdout), &status); err != nil {
		t.Fatal(err)
	}
	if status["ready"] != true || status["registered"] != false || status["secret_count"] != float64(1) || status["server"] != "https://hort.pm" || len(status["account_id"].(string)) != 26 || status["device_id"] == "" {
		t.Fatalf("status: %v", status)
	}

	kit := hortOK(t, home, "kit")
	if kit.stdout != "" || !strings.Contains(kit.stderr, status["account_id"].(string)) {
		t.Fatalf("kit: %+v", kit)
	}
}

func TestCLIPassphraseChange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	hortOK(t, home, "init")
	hortOK(t, home, "--set-secret", "token", "--value", "value")
	if got := hortEnv(t, home, []string{"HORT_PASSPHRASE=new-passphrase"}, "passphrase"); got.code != 0 {
		t.Fatalf("passphrase: %+v", got)
	}
	hortOK(t, home, "lock")
	wantError(t, hort(t, home, "unlock"), 1, "wrong passphrase")
	if got := hortEnv(t, home, []string{"HORT_PASSPHRASE=new-passphrase"}, "unlock"); got.code != 0 {
		t.Fatalf("unlock with new passphrase: %+v", got)
	}
	wantStdout(t, hort(t, home, "--secret", "token"), "value")
}

func TestCLISeparatesMistypedSecretKeyFromWrongPassphrase(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	hortOK(t, home, "init")
	hortOK(t, home, "lock")
	raw, err := os.ReadFile(filepath.Join(home, ".hort", "secret-key"))
	if err != nil {
		t.Fatal(err)
	}
	sk := strings.TrimSpace(string(raw))
	check := sk[len(sk)-1]
	mistyped := sk[:len(sk)-1] + map[bool]string{true: "0", false: "1"}[check != '0']
	wantError(t, hortEnv(t, home, []string{passphrase, "HORT_SECRET_KEY=" + mistyped}, "unlock"), 1, "Secret Key mistyped")
	wantError(t, hortEnv(t, home, []string{"HORT_PASSPHRASE=wrong"}, "unlock"), 1, "wrong passphrase")
	if got := hortEnv(t, home, []string{passphrase, "HORT_SECRET_KEY=" + strings.ToLower(sk)}, "unlock"); got.code != 0 {
		t.Fatalf("HORT_SECRET_KEY override: %+v", got)
	}
}

func TestCLIRejectsV3Vault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	dir := filepath.Join(home, ".hort")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	v3 := append([]byte("HRT\x03\x03"), make([]byte, 100)...)
	if err := os.WriteFile(filepath.Join(dir, "vault.enc"), v3, 0600); err != nil {
		t.Fatal(err)
	}
	wantError(t, hort(t, home, "unlock"), 1, "hort migrate")
	// A session left over from Hort 0.4 holds a v3 key of the same shape as VK.
	if err := os.WriteFile(filepath.Join(dir, ".session"), []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	wantError(t, hort(t, home, "--secret", "token"), 1, "hort migrate")
	wantError(t, hort(t, home, "status"), 1, "hort migrate")
	if got, _ := os.ReadFile(filepath.Join(dir, "vault.enc")); !bytes.Equal(got, v3) {
		t.Fatal("v3 vault changed")
	}
}
