package main

import (
	"bytes"
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

func hort(t *testing.T, home string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = []string{"HOME=" + home, "HORT_TEST_RUN_CLI=1", "HORT_PASSPHRASE=synthetic-passphrase"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return cliResult{stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()}
}

func hortOK(t *testing.T, home string, args ...string) cliResult {
	t.Helper()
	got := hort(t, home, args...)
	if got.code != 0 {
		t.Fatalf("hort %v: exit %d, stderr %q", args, got.code, got.stderr)
	}
	return got
}

// isolate keeps the test process itself away from any real home directory.
func isolate(t *testing.T) (a, b, folder string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return t.TempDir(), t.TempDir(), t.TempDir()
}

func syncFiles(t *testing.T, folder string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(folder, "hort-*"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// joinDevices sets up A and joins B the documented way: copy, restore, setup.
func joinDevices(t *testing.T, a, b, folder string) {
	t.Helper()
	hortOK(t, a, "init")
	hortOK(t, a, "sync", "setup", "--path", folder)
	files := syncFiles(t, folder)
	if len(files) != 1 {
		t.Fatalf("folder holds %d files", len(files))
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(b, ".hort"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, ".hort", "vault.enc"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	hortOK(t, b, "init", "--restore")
	hortOK(t, b, "sync", "setup", "--path", folder)
}

func wantStdout(t *testing.T, got cliResult, want string) {
	t.Helper()
	if got.code != 0 || got.stdout != want {
		t.Fatalf("exit %d, stdout %q, want %q; stderr %q", got.code, got.stdout, want, got.stderr)
	}
}

func TestCLIWithoutSetupBehavesAsBefore(t *testing.T) {
	a, _, folder := isolate(t)
	hortOK(t, a, "init")
	set := hortOK(t, a, "--set-secret", "token", "--value", "value")
	if strings.Contains(set.stderr, "sync") {
		t.Fatalf("stderr mentions sync: %q", set.stderr)
	}
	got := hort(t, a, "--secret", "token")
	wantStdout(t, got, "value")
	if got.stderr != "" {
		t.Fatalf("stderr: %q", got.stderr)
	}
	if files := syncFiles(t, folder); len(files) != 0 {
		t.Fatalf("folder touched: %v", files)
	}
	if got := hort(t, a, "sync"); got.code != 1 || !strings.Contains(got.stderr, "sync setup") {
		t.Fatalf("sync without setup: %+v", got)
	}
}

func TestCLITwoOfflineDevicesConvergeInBothOrders(t *testing.T) {
	for _, test := range []struct {
		name  string
		first func(a, b string) string
	}{
		{"older device first", func(a, b string) string { return a }},
		{"newer device first", func(a, b string) string { return b }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b, folder := isolate(t)
			joinDevices(t, a, b, folder)
			hortOK(t, a, "--set-secret", "shared", "--value", "joined")
			wantStdout(t, hort(t, b, "--secret", "shared"), "joined")

			offline := folder + ".offline"
			if err := os.Rename(folder, offline); err != nil {
				t.Fatal(err)
			}
			hortOK(t, a, "--set-secret", "token", "--value", "older")
			hortOK(t, b, "--set-secret", "token", "--value", "newer")
			if err := os.Rename(offline, folder); err != nil {
				t.Fatal(err)
			}

			first := test.first(a, b)
			second := a
			if first == a {
				second = b
			}
			hortOK(t, first, "sync")
			hortOK(t, second, "sync")
			hortOK(t, first, "sync")
			for _, home := range []string{a, b} {
				wantStdout(t, hort(t, home, "--secret", "token"), "newer")
				history := hortOK(t, home, "history", "token")
				if !strings.Contains(history.stdout, `"older"`) || !strings.Contains(history.stdout, `"newer"`) {
					t.Fatalf("history: %q", history.stdout)
				}
			}
		})
	}
}

func TestCLIMissingFolderOnlyWarnsOnStderr(t *testing.T) {
	a, b, folder := isolate(t)
	joinDevices(t, a, b, folder)
	hortOK(t, a, "--set-secret", "token", "--value", "before")
	offline := folder + ".offline"
	if err := os.Rename(folder, offline); err != nil {
		t.Fatal(err)
	}

	got := hort(t, a, "--secret", "token")
	wantStdout(t, got, "before")
	if strings.Count(got.stderr, "warning:") != 1 {
		t.Fatalf("stderr: %q", got.stderr)
	}
	set := hortOK(t, a, "--set-secret", "token", "--value", "offline")
	if strings.Count(set.stderr, "warning:") != 1 {
		t.Fatalf("write warned more than once: %q", set.stderr)
	}
	if status := hortOK(t, a, "status"); strings.Contains(status.stderr, "warning:") {
		t.Fatalf("status touched the folder: %q", status.stderr)
	}
	if got := hort(t, a, "sync"); got.code != 1 {
		t.Fatalf("explicit sync must fail: %+v", got)
	}
	if _, err := os.Stat(folder); !os.IsNotExist(err) {
		t.Fatal("folder was created")
	}

	if err := os.Rename(offline, folder); err != nil {
		t.Fatal(err)
	}
	wantStdout(t, hort(t, a, "--secret", "token"), "offline")
	wantStdout(t, hort(t, b, "--secret", "token"), "offline")
}

func TestCLITruncatedFileOnlyWarns(t *testing.T) {
	a, b, folder := isolate(t)
	joinDevices(t, a, b, folder)
	hortOK(t, a, "--set-secret", "token", "--value", "value")
	if err := os.WriteFile(filepath.Join(folder, "hort-partial.enc"), []byte("HORT"), 0600); err != nil {
		t.Fatal(err)
	}
	got := hort(t, a, "--secret", "token")
	wantStdout(t, got, "value")
	if !strings.Contains(got.stderr, "hort-partial.enc") {
		t.Fatalf("stderr: %q", got.stderr)
	}
}

func TestCLILockedVaultLeavesFolderAlone(t *testing.T) {
	a, b, folder := isolate(t)
	joinDevices(t, a, b, folder)
	hortOK(t, b, "--set-secret", "token", "--value", "value")
	hortOK(t, a, "lock")
	vaultPath := filepath.Join(a, ".hort", "vault.enc")
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	files := syncFiles(t, folder)
	for _, args := range [][]string{{"--secret", "token"}, {"sync"}, {"sync", "setup", "--path", folder}} {
		if got := hort(t, a, args...); got.code != 2 || got.stdout != "" {
			t.Fatalf("hort %v: %+v", args, got)
		}
	}
	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || len(syncFiles(t, folder)) != len(files) {
		t.Fatal("locked vault took part in sync")
	}
}

func TestCLISetupRefusesForeignKey(t *testing.T) {
	a, b, folder := isolate(t)
	hortOK(t, a, "init")
	hortOK(t, a, "sync", "setup", "--path", folder)
	hortOK(t, b, "init")
	got := hort(t, b, "sync", "setup", "--path", folder)
	if got.code != 1 || !strings.Contains(got.stderr, "nothing changed") {
		t.Fatalf("%+v", got)
	}
	if files := syncFiles(t, folder); len(files) != 1 {
		t.Fatalf("folder holds %d files", len(files))
	}
}

func TestCLIFailedMergeStillReadsLocally(t *testing.T) {
	a, b, folder := isolate(t)
	joinDevices(t, a, b, folder)
	hortOK(t, a, "--set-secret", "token", "--value", "local")
	hortOK(t, b, "--set-secret", "other", "--value", "pending")
	dir := filepath.Join(a, ".hort")
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	got := hort(t, a, "--secret", "token")
	wantStdout(t, got, "local")
	if !strings.Contains(got.stderr, "warning:") {
		t.Fatalf("stderr: %q", got.stderr)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	wantStdout(t, hort(t, a, "--secret", "other"), "pending")
}
