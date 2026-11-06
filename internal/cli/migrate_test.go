package cli

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/vault"
)

// writeV3Vault seals body the way Hort 0.4 wrote a v3 vault (280e403,
// internal/vault/crypto.go and format.go): magic, version 3, KDF byte 0, salt,
// Argon2id parameters, nonce; the header without its nonce is the AAD.
func writeV3Vault(t *testing.T, path, passphrase, body string) {
	t.Helper()
	salt := bytes.Repeat([]byte{0x22}, vault.SaltSize)
	params := vault.ArgonParams{Time: 1, Memory: 8, Threads: 1}
	header := append([]byte(vault.V3Magic), 3, 0)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, params.Time)
	header = binary.BigEndian.AppendUint32(header, params.Memory)
	header = append(header, params.Threads)
	nonce := bytes.Repeat([]byte{0x33}, vault.NonceSize)
	block, err := aes.NewCipher(vault.DeriveKey([]byte(passphrase), salt, params))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(append(append([]byte(nil), header...), nonce...), gcm.Seal(nil, nonce, []byte(body), header)...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// capture returns what run writes to the given stream.
func capture(t *testing.T, stream **os.File, run func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := *stream
	*stream = w
	runErr := run()
	*stream = saved
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out), runErr
}

func TestMigrateThenEverydayCommands(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("HORT_PASSPHRASE", "synthetic-v3-passphrase")
	dir := filepath.Join(home, ".hort")
	if err := os.MkdirAll(filepath.Join(dir, "sources"), 0700); err != nil {
		t.Fatal(err)
	}
	writeV3Vault(t, filepath.Join(dir, "vault.enc"), "synthetic-v3-passphrase", `{"version":3,"source_id":"000000000000000000000000000000ff","secrets":{`+
		`"legacy token":{"revisions":[{"id":"00000000000000000000000000000001","recorded_at":null,"op":"set","key":"*:*","value":"from-v1"},`+
		`{"id":"00000000000000000000000000000002","recorded_at":"2024-03-01T10:00:00.5Z","op":"set","key":"prod:tenant:a","value":"colon"}]},`+
		`"api":{"revisions":[{"id":"00000000000000000000000000000003","recorded_at":"2024-03-02T10:00:00Z","op":"set","key":"*:*","value":"secret-api"},`+
		`{"id":"00000000000000000000000000000004","recorded_at":"2024-03-02T10:00:01Z","op":"describe","key":"","value":"API token"}]}}}`)

	stderr, err := capture(t, &os.Stderr, CmdMigrate)
	if err != nil {
		t.Fatalf("migrate: %v\n%s", err, stderr)
	}
	for _, want := range []string{"Before migrating, run `hort sync`", "pre-v4.bak", "sources is left untouched", "HORT EMERGENCY KIT", "Run `hort sync` to register this vault on https://hort.pm."} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("migrate output lacks %q:\n%s", want, stderr)
		}
	}

	for _, c := range []struct {
		run  func() error
		want string
	}{
		{func() error { return CmdGet("api", "", "", "") }, "secret-api"},
		{func() error { return CmdGet("legacy token", "", "prod", "tenant:a") }, "colon"},
		{func() error { return CmdGet("legacy token", "", "staging", "") }, "from-v1"},
		{func() error { return CmdList(true) }, `"description": "API token"`},
		{func() error { return CmdHistory("legacy token", false) }, "unknown 00000000000000000000000000000001 set"},
	} {
		out, err := capture(t, &os.Stdout, c.run)
		if err != nil || !strings.Contains(out, c.want) {
			t.Fatalf("got %q, %v; want %q", out, err, c.want)
		}
	}
	kit, err := capture(t, &os.Stderr, CmdKit)
	if err != nil || !strings.Contains(kit, "HORT EMERGENCY KIT") || !strings.Contains(kit, "Secret Key:  H4-") {
		t.Fatalf("kit: %v\n%s", err, kit)
	}

	if _, err := capture(t, &os.Stderr, CmdMigrate); !errors.Is(err, vault.ErrAlreadyMigrated) {
		t.Fatalf("rerun: %v", err)
	}
}
