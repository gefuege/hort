package store

import (
	"fmt"
	"sync"
	"testing"

	"github.com/s16e/hort/internal/vault"
)

// setHomeDir points os.UserHomeDir() at dir on every platform. On Windows it
// reads USERPROFILE first; on Unix it reads HOME.
func setHomeDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func primarySetup(t *testing.T) {
	t.Helper()
	setHomeDir(t, t.TempDir())
	ref, err := vault.PrimaryRef()
	if err != nil {
		t.Fatalf("PrimaryRef(): %v", err)
	}
	key, err := vault.CreatePrimaryVault([]byte("passphrase"))
	if err != nil {
		t.Fatalf("CreatePrimaryVault(): %v", err)
	}
	if err := vault.SaveSessionFor(ref, key); err != nil {
		t.Fatalf("SaveSessionFor(): %v", err)
	}
}

func TestConcurrentMutationsKeepAllEntries(t *testing.T) {
	primarySetup(t)

	const writers = 32

	var wg sync.WaitGroup
	errCh := make(chan error, writers)

	for i := 0; i < writers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := NewFromSession()
			if err != nil {
				errCh <- err
				return
			}

			name := fmt.Sprintf("entry-%02d", i)
			value := fmt.Sprintf("value-%02d", i)
			if i%2 == 0 {
				err = s.SetSecret("", name, value, "dev", "spuerhund", "test entry")
			} else {
				err = s.SetSecret("", name, value, "dev", "spuerhund", "test entry")
			}
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent mutation failed: %v", err)
		}
	}

	s, err := NewFromSession()
	if err != nil {
		t.Fatalf("NewFromSession(): %v", err)
	}

	for i := 0; i < writers; i++ {
		name := fmt.Sprintf("entry-%02d", i)
		expected := fmt.Sprintf("value-%02d", i)
		if i%2 == 0 {
			value, src, err := s.GetSecret(name, "dev", "spuerhund")
			if err != nil {
				t.Fatalf("GetSecret(%s): %v", name, err)
			}
			if value != expected {
				t.Fatalf("GetSecret(%s) = %q, want %q", name, value, expected)
			}
			if src != vault.PrimarySourceName {
				t.Fatalf("GetSecret(%s) source = %q, want primary", name, src)
			}
		} else {
			value, _, err := s.GetSecret(name, "dev", "spuerhund")
			if err != nil {
				t.Fatalf("GetSecret(%s): %v", name, err)
			}
			if value != expected {
				t.Fatalf("GetSecret(%s) = %q, want %q", name, value, expected)
			}
		}
	}
}

func TestMergedReadsAcrossMounts(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatalf("NewFromSession(): %v", err)
	}

	// Write one value in primary
	if err := s.SetSecret("", "primary-only", "pval", "*", "*", "only in primary"); err != nil {
		t.Fatalf("primary set: %v", err)
	}

	// Mount a second source
	rawKey := make([]byte, vault.KeySize)
	for i := range rawKey {
		rawKey[i] = 0x42
	}
	mountPath := t.TempDir() + "/mnt.enc"
	ref, err := vault.MountedRefAt("mnt-a", mountPath)
	if err != nil {
		t.Fatalf("MountedRefAt(): %v", err)
	}
	mntKey, err := vault.CreateVault(ref, rawKey, vault.KDFRawKey)
	if err != nil {
		t.Fatalf("CreateVault(mount): %v", err)
	}
	if err := vault.SaveSessionFor(ref, mntKey); err != nil {
		t.Fatalf("SaveSessionFor(mount): %v", err)
	}
	if err := vault.AddSource(vault.SourceRecord{Name: "mnt-a", Path: mountPath, KDF: vault.KDFRawKey}); err != nil {
		t.Fatalf("AddSource(): %v", err)
	}

	// Reload store with the mount visible
	s2, err := NewFromSession()
	if err != nil {
		t.Fatalf("NewFromSession() after mount: %v", err)
	}

	if err := s2.SetSecret("mnt-a", "mount-only", "mval", "*", "*", "only in mount"); err != nil {
		t.Fatalf("set in mount: %v", err)
	}

	// Merged read finds each
	if v, src, err := s2.GetSecret("primary-only", "*", "*"); err != nil || v != "pval" || src != "primary" {
		t.Fatalf("primary-only: got (%q, %q, %v)", v, src, err)
	}
	if v, src, err := s2.GetSecret("mount-only", "*", "*"); err != nil || v != "mval" || src != "mnt-a" {
		t.Fatalf("mount-only: got (%q, %q, %v)", v, src, err)
	}

	// Ambiguity: same key in both
	if err := s2.SetSecret("", "dup", "from-primary", "*", "*", ""); err != nil {
		t.Fatalf("dup primary: %v", err)
	}
	if err := s2.SetSecret("mnt-a", "dup", "from-mount", "*", "*", ""); err != nil {
		t.Fatalf("dup mount: %v", err)
	}
	s3, _ := NewFromSession()
	if _, _, err := s3.GetSecret("dup", "*", "*"); err == nil {
		t.Fatal("expected ambiguity error, got nil")
	}

	// Targeted read resolves the conflict
	v, err := s3.GetFrom("mnt-a", "dup", "*", "*")
	if err != nil || v != "from-mount" {
		t.Fatalf("GetFrom(mnt-a, dup): got (%q, %v)", v, err)
	}
}

func TestListIncludesSourceField(t *testing.T) {
	primarySetup(t)
	s, _ := NewFromSession()
	if err := s.SetSecret("", "alpha", "1", "*", "*", ""); err != nil {
		t.Fatalf("set alpha: %v", err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Source != vault.PrimarySourceName {
		t.Fatalf("source = %q, want primary", entries[0].Source)
	}
}
