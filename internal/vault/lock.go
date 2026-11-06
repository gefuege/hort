package vault

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// canonicalVaultPath resolves aliases, including an existing parent when the
// vault has not been created yet. Atomic writes must target this same path.
func canonicalVaultPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := canonicalExistingPath(abs)
	if os.IsNotExist(err) {
		parent, parentErr := canonicalVaultPath(filepath.Dir(abs))
		if parentErr != nil {
			return "", parentErr
		}
		return filepath.Join(parent, filepath.Base(abs)), nil
	}
	return resolved, err
}

// vaultLockPath uses only the canonical file identity, never mount names or
// secret material. The digest also avoids exposing the external file path.
func vaultLockPath(path string) (string, error) {
	canonical, err := canonicalVaultPath(path)
	if err != nil {
		return "", fmt.Errorf("resolving vault path: %w", err)
	}
	dir, err := HortDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "locks", fmt.Sprintf("%x.lock", sha256.Sum256([]byte(canonical)))), nil
}

// lockVault acquires an exclusive file lock on the given vault ref.
func lockVault(ref VaultRef) (func() error, error) {
	lockPath, err := vaultLockPath(ref.Path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return nil, fmt.Errorf("creating lock directory: %w", err)
	}

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening vault lock: %w", err)
	}

	if err := lockFile(file); err != nil {
		_ = file.Close()
		return nil, err
	}

	return func() error {
		return unlockFile(file)
	}, nil
}
