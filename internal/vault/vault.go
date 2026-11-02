package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// LookupKey combines environment and context as "env:context".
// Baseline is "*:*". Environment-only is "prod:*". Full is "prod:heine".
type LookupKey = string

// MakeLookupKey builds a lookup key from env and context.
func MakeLookupKey(env, context string) LookupKey {
	if env == "" {
		env = "*"
	}
	if context == "" {
		context = "*"
	}
	return env + ":" + context
}

// ParseLookupKey splits a lookup key into env and context.
func ParseLookupKey(key LookupKey) (env, context string) {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return key[:i], key[i+1:]
		}
	}
	return key, "*"
}

// VaultData is the decrypted vault content.
type VaultData struct {
	Version  int              `json:"version"`
	SourceID string           `json:"source_id"`
	Secrets  map[string]Entry `json:"secrets"`
}

// NewVaultData creates an empty vault.
func NewVaultData() (*VaultData, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return &VaultData{
		Version:  3,
		SourceID: id,
		Secrets:  make(map[string]Entry),
	}, nil
}

// PrimarySourceName is the reserved name for the primary vault.
const PrimarySourceName = "primary"

// VaultRef identifies a vault file and its local lock/session artifacts.
type VaultRef struct {
	Name        string
	Path        string
	LockPath    string
	SessionPath string
}

// HortDir returns the hort config directory path.
func HortDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, ".hort"), nil
}

// SourcesDir returns the directory that holds mounted source vaults.
func SourcesDir() (string, error) {
	dir, err := HortDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sources"), nil
}

// PrimaryRef returns the VaultRef for the primary vault (~/.hort/vault.enc).
func PrimaryRef() (VaultRef, error) {
	dir, err := HortDir()
	if err != nil {
		return VaultRef{}, err
	}
	path := filepath.Join(dir, "vault.enc")
	lockPath, err := vaultLockPath(path)
	if err != nil {
		return VaultRef{}, err
	}
	return VaultRef{
		Name:        PrimarySourceName,
		Path:        path,
		LockPath:    lockPath,
		SessionPath: filepath.Join(dir, ".session"),
	}, nil
}

// MountedRefAt returns the VaultRef for a mount with the given name, using the
// supplied vault file path. Sessions use a per-name slot; locks identify the
// canonical vault file so aliases serialize the same writes.
func MountedRefAt(name, vaultPath string) (VaultRef, error) {
	if err := validateSourceName(name); err != nil {
		return VaultRef{}, err
	}
	sourcesDir, err := SourcesDir()
	if err != nil {
		return VaultRef{}, err
	}
	lockPath, err := vaultLockPath(vaultPath)
	if err != nil {
		return VaultRef{}, err
	}
	return VaultRef{
		Name:        name,
		Path:        vaultPath,
		LockPath:    lockPath,
		SessionPath: filepath.Join(sourcesDir, name+".session"),
	}, nil
}

// VaultPath returns the path to the primary vault file. Kept as a package-level
// convenience for CLI/status code that only cares about the primary vault.
func VaultPath() (string, error) {
	ref, err := PrimaryRef()
	if err != nil {
		return "", err
	}
	return ref.Path, nil
}

// VaultExists reports whether the primary vault file exists.
func VaultExists() (bool, error) {
	ref, err := PrimaryRef()
	if err != nil {
		return false, err
	}
	return RefExists(ref)
}

// RefExists reports whether the vault file for the given ref exists.
func RefExists(ref VaultRef) (bool, error) {
	_, err := os.Stat(ref.Path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// CreateVault creates a new v3 vault file at ref using the given KDF mode and
// material. Returns the derived session key for immediate caching.
func CreateVault(ref VaultRef, material []byte, kdf KDFMode) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(ref.Path), 0700); err != nil {
		return nil, fmt.Errorf("creating vault directory: %w", err)
	}

	data, err := NewVaultData()
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling vault: %w", err)
	}

	fileBytes, sessionKey, err := CreateEncrypted(plaintext, material, kdf)
	if err != nil {
		return nil, err
	}

	if err := writeFileAtomic(ref.Path, fileBytes, 0600); err != nil {
		return nil, fmt.Errorf("writing vault: %w", err)
	}
	return sessionKey, nil
}

// CreatePrimaryVault creates the primary vault with a passphrase (Argon2id
// KDF, v3 format).
func CreatePrimaryVault(passphrase []byte) ([]byte, error) {
	ref, err := PrimaryRef()
	if err != nil {
		return nil, err
	}
	return CreateVault(ref, passphrase, KDFArgon2id)
}

// LoadVault reads and decrypts the given vault using a session key.
// Returns the vault data and the raw encrypted bytes (needed for re-encryption).
func LoadVault(ref VaultRef, sessionKey []byte) (*VaultData, []byte, error) {
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading vault %s: %w", ref.Name, err)
	}
	plaintext, err := DecryptWithKey(raw, sessionKey)
	if err != nil {
		return nil, nil, err
	}
	data, err := decodeVault(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing vault %s: %w", ref.Name, err)
	}
	return data, raw, nil
}

// SaveVault encrypts and writes the vault data back, preserving the file format.
func SaveVault(ref VaultRef, data *VaultData, sessionKey []byte, existingRaw []byte) error {
	if err := validateVault(data); err != nil {
		return err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling vault: %w", err)
	}
	encrypted, err := EncryptPreservingFormat(plaintext, sessionKey, existingRaw)
	if err != nil {
		return err
	}
	if err := backupFile(ref.Path, 0600); err != nil {
		return err
	}
	return writeFileAtomic(ref.Path, encrypted, 0600)
}

// UpdateVault serializes the full read-modify-write cycle for vault mutations.
func UpdateVault(ref VaultRef, sessionKey []byte, mutate func(data *VaultData) error) error {
	path, err := canonicalVaultPath(ref.Path)
	if err != nil {
		return fmt.Errorf("resolving vault path: %w", err)
	}
	ref.Path = path
	unlock, err := lockVault(ref)
	if err != nil {
		return err
	}
	defer func() {
		_ = unlock()
	}()

	data, raw, err := LoadVault(ref, sessionKey)
	if err != nil {
		return err
	}
	if err := mutate(data); err != nil {
		return err
	}
	return SaveVault(ref, data, sessionKey, raw)
}

// UnlockVault decrypts the vault at ref with the given material (passphrase or
// raw 32-byte key depending on its KDF mode) and returns the derived session key.
func UnlockVault(ref VaultRef, material []byte) ([]byte, error) {
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, fmt.Errorf("reading vault %s: %w", ref.Name, err)
	}
	return UnlockWithMaterial(raw, material)
}
