package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// BackupPathFor returns the backup path for the given vault ref.
func BackupPathFor(ref VaultRef) string {
	return ref.Path + ".bak"
}

func backupFile(path string, perm os.FileMode) error {
	current, err := readFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading current file for backup: %w", err)
	}

	backupPath := path + ".bak"
	if err := writeFileAtomic(backupPath, current, perm); err != nil {
		return fmt.Errorf("writing backup: %w", err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	tmpPath := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpPath)
	}

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("setting temp file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := replaceFile(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}
