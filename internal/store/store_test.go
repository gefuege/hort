package store

import (
	"fmt"
	"sync"
	"testing"

	"github.com/gefuege/hort/internal/vault"
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
	created, err := vault.CreateVault(ref, vault.DefaultServer, "test-device", []byte("passphrase"))
	if err != nil {
		t.Fatalf("CreateVault(): %v", err)
	}
	if err := vault.SaveSessionFor(ref, created.VK); err != nil {
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
			if err := s.SetSecret(name, "", value, "dev", "spuerhund", "test entry"); err != nil {
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
		value, err := s.GetSecret(name, "", "dev", "spuerhund")
		if err != nil {
			t.Fatalf("GetSecret(%s): %v", name, err)
		}
		if value != expected {
			t.Fatalf("GetSecret(%s) = %q, want %q", name, value, expected)
		}
	}
}

func NewFromSession() (*Store, error) {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return nil, err
	}
	key, err := vault.LoadSessionFor(ref)
	if err != nil {
		return nil, err
	}
	return New(ref, key), nil
}
