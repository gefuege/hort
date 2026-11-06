package vault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// aliasRef names the vault at path the way PrimaryRef does, under its own name.
func aliasRef(t *testing.T, name, path string) VaultRef {
	t.Helper()
	lockPath, err := vaultLockPath(path)
	if err != nil {
		t.Fatal(err)
	}
	return VaultRef{Name: name, Path: path, LockPath: lockPath}
}

func TestVaultAliasesSerializeUpdates(t *testing.T) {
	for _, alias := range []string{"same-path", "symlink", "symlink-directory", "primary", "case-file", "case-parent"} {
		t.Run(alias, func(t *testing.T) {
			setHomeDir(t, t.TempDir())
			first := primaryRefOrFatal(t)
			key := testVault(t, first, "passphrase")
			path := first.Path
			if alias == "case-file" || alias == "case-parent" {
				if alias == "case-file" {
					path = filepath.Join(filepath.Dir(path), strings.ToUpper(filepath.Base(path)))
				} else {
					dir := filepath.Dir(path)
					path = filepath.Join(filepath.Dir(dir), strings.ToUpper(filepath.Base(dir)), filepath.Base(path))
				}
				aliasInfo, err := os.Stat(path)
				if os.IsNotExist(err) {
					t.Skip("filesystem distinguishes case; no case alias")
				}
				if err != nil {
					t.Fatal(err)
				}
				originalInfo, err := os.Stat(first.Path)
				if err != nil || !os.SameFile(originalInfo, aliasInfo) {
					t.Fatalf("fixture does not reference the same file: %v", err)
				}
			}
			if alias == "symlink" {
				path = filepath.Join(t.TempDir(), "alias.enc")
				if err := os.Symlink(first.Path, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			if alias == "symlink-directory" {
				dir := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(filepath.Dir(first.Path), dir); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				path = filepath.Join(dir, filepath.Base(first.Path))
			}
			second := aliasRef(t, "second", path)
			if alias != "primary" {
				first = aliasRef(t, "first", first.Path)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			firstDone, secondDone := make(chan error, 1), make(chan error, 1)
			go func() {
				firstDone <- UpdateVault(first, key, func(data *VaultData) error {
					close(entered)
					<-release
					data.Secrets["first"] = Entry{Revisions: []Revision{testRevision(t, "describe", "", "first")}}
					return nil
				})
			}()
			select {
			case <-entered:
			case err := <-firstDone:
				t.Fatalf("first update failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("first update stalled")
			}
			go func() {
				secondDone <- UpdateVault(second, key, func(data *VaultData) error {
					data.Secrets["second"] = Entry{Revisions: []Revision{testRevision(t, "describe", "", "second")}}
					return nil
				})
			}()
			select {
			case err := <-secondDone:
				close(release)
				<-firstDone
				t.Fatalf("alias bypassed held write lock: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
			for _, done := range []chan error{firstDone, secondDone} {
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("update did not complete after release")
				}
			}
			for _, ref := range []VaultRef{first, second} {
				data, _, err := LoadVault(ref, key)
				if err != nil {
					t.Fatal(err)
				}
				_, firstDesc, _ := data.Secrets["first"].Current()
				_, secondDesc, _ := data.Secrets["second"].Current()
				if len(data.Secrets) != 2 || firstDesc != "first" || secondDesc != "second" {
					t.Fatalf("lost alias write via %s: %+v", ref.Name, data.Secrets)
				}
			}
			if alias == "symlink" {
				info, err := os.Lstat(path)
				if err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("update replaced symlink: %v", err)
				}
			}
			if first.LockPath != second.LockPath {
				t.Fatalf("aliases use different locks: %s, %s", first.LockPath, second.LockPath)
			}
			lockBytes, err := os.ReadFile(first.LockPath)
			if err != nil || len(lockBytes) != 0 {
				t.Fatalf("lock contains bytes or cannot be read: %v", err)
			}
			if strings.Contains(first.LockPath, "vault.enc") || bytes.Contains(lockBytes, key) {
				t.Fatal("lock exposes vault path or key")
			}
		})
	}
}

func TestParseFormatRejectsUnsafeArgonParameters(t *testing.T) {
	cases := []ArgonParams{
		{0, 65536, 4}, {3, 0, 4}, {3, 65536, 0},
		{4, 65536, 4}, {3, 65537, 4}, {3, 65536, 5},
		{^uint32(0), ^uint32(0), 255}, {1, 31, 4},
	}
	for _, params := range cases {
		t.Run(fmt.Sprint(params), func(t *testing.T) {
			header := buildV3Header(KDFArgon2id, make([]byte, SaltSize), params, make([]byte, NonceSize))
			if _, err := ParseFormat(header); err == nil {
				t.Fatal("unsafe Argon parameters accepted")
			}
		})
	}
}

func TestCanonicalVaultPathKeepsDistinctCaseSensitiveFiles(t *testing.T) {
	setHomeDir(t, t.TempDir())
	dir := t.TempDir()
	upper := filepath.Join(dir, "Vault.enc")
	lower := filepath.Join(dir, "vault.enc")
	if err := os.WriteFile(upper, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lower); err == nil {
		t.Skip("filesystem ignores case; distinct case-sensitive files unavailable")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(lower, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := vaultLockPath(upper)
	if err != nil {
		t.Fatal(err)
	}
	second, err := vaultLockPath(lower)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("distinct case-sensitive files share a lock identity")
	}
}

func TestUnlockRejectsUnsafeArgonBeforeDerivation(t *testing.T) {
	for _, params := range []ArgonParams{{0, 65536, 4}, {3, 0, 4}, {3, 65536, 0}, {^uint32(0), ^uint32(0), 255}} {
		header := buildV3Header(KDFArgon2id, make([]byte, SaltSize), params, make([]byte, NonceSize))
		if _, err := UnlockWithMaterial(header, []byte("test")); err == nil || !strings.Contains(err.Error(), "Argon2id parameters") {
			t.Fatalf("unlock must reject before derivation: %v", err)
		}
	}
}

func TestParseFormatSupportedArgonBounds(t *testing.T) {
	for _, params := range []ArgonParams{{1, 8, 1}, {1, 32, 4}, DefaultArgonParams()} {
		if _, err := ParseFormat(buildV3Header(KDFArgon2id, make([]byte, SaltSize), params, make([]byte, NonceSize))); err != nil {
			t.Fatal(err)
		}
	}
}
