package vault

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// SaveSessionFor stores VK as hex in the session file for the given ref (§2.4).
func SaveSessionFor(ref VaultRef, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(ref.SessionPath), 0700); err != nil {
		return fmt.Errorf("creating session directory: %w", err)
	}
	encoded := hex.EncodeToString(key)
	return os.WriteFile(ref.SessionPath, []byte(encoded), 0600)
}

// LoadSessionFor reads the session key for the given ref. Returns an error if
// the vault is locked (session file absent).
func LoadSessionFor(ref VaultRef) ([]byte, error) {
	data, err := os.ReadFile(ref.SessionPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("vault is locked — run `hort unlock` first")
	}
	if err != nil {
		return nil, fmt.Errorf("reading session: %w", err)
	}
	key, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("invalid session file: %w", err)
	}
	return key, nil
}

// ClearSessionFor removes the session key file for the given ref.
func ClearSessionFor(ref VaultRef) error {
	err := os.Remove(ref.SessionPath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// IsUnlockedFor reports whether a session file exists for the given ref.
func IsUnlockedFor(ref VaultRef) bool {
	_, err := os.Stat(ref.SessionPath)
	return err == nil
}
