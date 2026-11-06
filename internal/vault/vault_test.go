package vault

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func testRevision(t *testing.T, op, key, value string) Revision {
	t.Helper()
	r, err := NewRevision(op, key, value)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func primaryRefOrFatal(t *testing.T) VaultRef {
	t.Helper()
	ref, err := PrimaryRef()
	if err != nil {
		t.Fatalf("PrimaryRef(): %v", err)
	}
	return ref
}

// setHomeDir points os.UserHomeDir() at dir on every platform. On Windows it
// reads USERPROFILE first; on Unix it reads HOME. We set both so the same
// test helper works in CI across OSes.
func setHomeDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func TestWriteLockBlocksConcurrentWriter(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)

	unlock, err := lockVault(ref)
	if err != nil {
		t.Fatalf("lockVault(): %v", err)
	}
	defer func() {
		_ = unlock()
	}()

	acquired := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		nextUnlock, err := lockVault(ref)
		if err != nil {
			errCh <- err
			return
		}
		defer func() {
			_ = nextUnlock()
		}()
		close(acquired)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("concurrent lock failed: %v", err)
	case <-acquired:
		t.Fatal("concurrent writer acquired lock before release")
	case <-time.After(150 * time.Millisecond):
	}

	if err := unlock(); err != nil {
		t.Fatalf("unlock(): %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("concurrent lock failed after release: %v", err)
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent writer did not acquire lock after release")
	}
}

func TestSaveVaultCreatesBackup(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	vk := testVault(t, ref, "passphrase")

	data, raw, err := LoadVault(ref, vk)
	if err != nil {
		t.Fatalf("LoadVault(): %v", err)
	}

	data.Secrets["demo"] = Entry{Revisions: []Revision{testRevision(t, "set", MakeLookupKey("dev", "spuerhund"), "value"), testRevision(t, "describe", "", "demo")}}

	if err := SaveVault(ref, data, vk, raw); err != nil {
		t.Fatalf("SaveVault(): %v", err)
	}

	backup, err := os.ReadFile(BackupPathFor(ref))
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(backup, raw) {
		t.Fatal("backup does not hold the previous file")
	}
}
