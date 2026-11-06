package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/vault"
)

func TestInitRefusesExistingVaultWithoutChanges(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("HORT_PASSPHRASE", "synthetic-test-passphrase")
	dir := filepath.Join(home, ".hort")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.enc")
	want := []byte("synthetic-existing-vault")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CmdInit("", ""); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("init over an existing vault: got %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, want) {
		t.Errorf("vault changed: read error %v", readErr)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Errorf("refused init created files: %v", files)
	}
}

func TestKitShowsEverythingButThePassphrase(t *testing.T) {
	account := bytes.Repeat([]byte{0x01}, vault.AccountIDSize)
	sk := bytes.Repeat([]byte{0x02}, vault.SecretKeySize)
	kit := FormatKit("https://self.example", account, sk)
	for _, want := range []string{"https://self.example", vault.FormatAccountID(account), vault.FormatSecretKey(sk), "Passphrase:  ____"} {
		if !strings.Contains(kit, want) {
			t.Fatalf("kit lacks %q:\n%s", want, kit)
		}
	}
}

func TestConfirmLastGroup(t *testing.T) {
	sk := bytes.Repeat([]byte{0x02}, vault.SecretKeySize)
	group := lastGroup(sk)
	if len(group) != 5 || !strings.Contains(vault.FormatSecretKey(sk), "-"+group+"-") {
		t.Fatalf("last group %q", group)
	}
	if err := confirmLastGroup(strings.NewReader("WRONG\n"+strings.ToLower(group)+"\n"), sk); err != nil {
		t.Fatalf("retyped group refused: %v", err)
	}
	if err := confirmLastGroup(strings.NewReader("WRONG\n"), sk); err == nil {
		t.Fatal("end of input confirmed the kit")
	}
}
