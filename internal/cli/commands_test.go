package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitRestoreMissingVaultPreservesBackup(t *testing.T) {
	for _, test := range []struct {
		name, passphrase string
	}{
		{name: "without passphrase"},
		{name: "with passphrase", passphrase: "synthetic-test-passphrase"},
	} {
		t.Run(test.name, func(t *testing.T) {
			testInitRestoreMissingVaultPreservesBackup(t, test.passphrase)
		})
	}
}

func testInitRestoreMissingVaultPreservesBackup(t *testing.T, passphrase string) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("HORT_PASSPHRASE", passphrase)
	dir := filepath.Join(home, ".hort")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "vault.enc.bak")
	want := []byte("synthetic-existing-backup")
	if err := os.WriteFile(backup, want, 0600); err != nil {
		t.Fatal(err)
	}
	err := CmdInit(true)
	if err == nil || !strings.Contains(err.Error(), "no vault found") {
		t.Errorf("restore without input: got %v, want no vault found", err)
	}
	got, readErr := os.ReadFile(backup)
	if readErr != nil || !bytes.Equal(got, want) {
		t.Errorf("backup changed: read error %v", readErr)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "vault.enc.bak" {
		t.Errorf("restore created files: %v", files)
	}
}
