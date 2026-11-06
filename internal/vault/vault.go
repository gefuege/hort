package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
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

// VaultData is body_json of a v4 vault (contract §2.3), decoded strictly.
type VaultData struct {
	Version int              `json:"version"`
	Device  Device           `json:"device"`
	Sync    SyncState        `json:"sync"`
	Secrets map[string]Entry `json:"secrets"`
}

// Device is this device's identity. The Ed25519 seed is sealed in the body
// (§5.2); the name waits here until the account is registered.
type Device struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
}

// SyncState is the local server sync state (§6.6). Pending holds every local
// revision not yet pushed.
type SyncState struct {
	Registered     bool     `json:"registered"`
	Cursor         uint64   `json:"cursor"`
	Pending        []string `json:"pending"`
	DevicesVersion uint64   `json:"devices_version"`
	KnownDevices   []string `json:"known_devices"`
}

func newBody(deviceName string) (*VaultData, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	seed, err := randomBytes(ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return &VaultData{
		Version: 4,
		Device:  Device{ID: id, Name: deviceName, PrivateKey: hex.EncodeToString(seed)},
		Sync:    SyncState{Pending: []string{}, KnownDevices: []string{}},
		Secrets: make(map[string]Entry),
	}, nil
}

// Append stamps r by the Append rule into entry name and queues it for push.
func (d *VaultData) Append(name string, r Revision) {
	entry := d.Secrets[name]
	entry.Append(r)
	d.Secrets[name] = entry
	d.Sync.Pending = append(d.Sync.Pending, r.ID)
}

func decodeBody(raw []byte) (*VaultData, error) {
	var d VaultData
	if err := strictJSON(raw, &d); err != nil {
		return nil, err
	}
	if err := validateBody(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// validateBody also guards writes: strictJSON rejects the null a nil slice encodes to.
func validateBody(d *VaultData) error {
	if d == nil || d.Version != 4 {
		return errors.New("invalid v4 vault content")
	}
	seed, err := hex.DecodeString(d.Device.PrivateKey)
	if !validID(d.Device.ID) || err != nil || len(seed) != ed25519.SeedSize || d.Device.PrivateKey != hex.EncodeToString(seed) {
		return errors.New("invalid device in vault")
	}
	if d.Sync.Pending == nil || d.Sync.KnownDevices == nil {
		return errors.New("invalid sync state in vault")
	}
	for _, ids := range [][]string{d.Sync.Pending, d.Sync.KnownDevices} {
		for _, id := range ids {
			if !validID(id) {
				return errors.New("invalid identity in vault sync state")
			}
		}
	}
	return validateSecrets(d.Secrets, true)
}

// VaultRef identifies a vault file and its local lock, session and Secret Key files.
type VaultRef struct {
	Path          string
	LockPath      string
	SessionPath   string
	SecretKeyPath string
}

// HortDir returns the hort config directory path.
func HortDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	return filepath.Join(home, ".hort"), nil
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
		Path:          path,
		LockPath:      lockPath,
		SessionPath:   filepath.Join(dir, ".session"),
		SecretKeyPath: filepath.Join(dir, "secret-key"),
	}, nil
}

// RefExists reports whether the vault file for the given ref exists.
func RefExists(ref VaultRef) (bool, error) {
	_, err := os.Stat(ref.Path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}
	return b, nil
}

// NewVault is what `hort init` created and the Emergency Kit shows.
type NewVault struct {
	AccountID []byte
	Server    string
	SecretKey []byte
	VK        []byte
}

// CreateVault creates a v4 vault with a new account, VK, Secret Key, passphrase
// slot and device key. It writes the Secret Key file before vault.enc (§9.1);
// the caller saves the session.
func CreateVault(ref VaultRef, server, deviceName string, passphrase []byte) (NewVault, error) {
	return createVault(ref, server, deviceName, passphrase, DefaultArgonParams())
}

func createVault(ref VaultRef, server, deviceName string, passphrase []byte, params ArgonParams) (NewVault, error) {
	if err := checkServerURL(server); err != nil {
		return NewVault{}, err
	}
	if err := os.MkdirAll(filepath.Dir(ref.Path), 0700); err != nil {
		return NewVault{}, fmt.Errorf("creating vault directory: %w", err)
	}
	unlock, err := lockVault(ref)
	if err != nil {
		return NewVault{}, err
	}
	defer func() { _ = unlock() }()
	if exists, err := RefExists(ref); err != nil {
		return NewVault{}, err
	} else if exists {
		return NewVault{}, fmt.Errorf("a vault already exists at %s", ref.Path)
	}
	// A vault moved away still needs its Secret Key, and its backup would be
	// replaced by the first save of the new vault.
	for _, path := range []string{ref.SecretKeyPath, BackupPathFor(ref)} {
		if _, err := os.Lstat(path); err == nil {
			return NewVault{}, fmt.Errorf("%s exists and may belong to a vault moved away; remove it only if no vault uses it, then run init again", path)
		} else if !os.IsNotExist(err) {
			return NewVault{}, err
		}
	}

	nv := NewVault{Server: server}
	if nv.AccountID, err = randomBytes(AccountIDSize); err != nil {
		return NewVault{}, err
	}
	if nv.VK, err = randomBytes(KeySize); err != nil {
		return NewVault{}, err
	}
	if nv.SecretKey, err = randomBytes(SecretKeySize); err != nil {
		return NewVault{}, err
	}
	body, err := newBody(deviceName)
	if err != nil {
		return NewVault{}, err
	}
	keys, err := DeriveAccountKeys(nv.VK, nv.AccountID)
	if err != nil {
		return NewVault{}, err
	}
	h := fileHeader{AccountID: nv.AccountID, Server: server}
	if err := h.sealPassphraseSlot(nv.VK, keys.AK, string(passphrase), nv.SecretKey, 1, params); err != nil {
		return NewVault{}, err
	}
	file, err := sealV4(keys.FK, h, body)
	if err != nil {
		return NewVault{}, err
	}
	if err := writeFileAtomic(ref.SecretKeyPath, []byte(FormatSecretKey(nv.SecretKey)+"\n"), 0600); err != nil {
		return NewVault{}, fmt.Errorf("writing Secret Key: %w", err)
	}
	if err := writeFileAtomic(ref.Path, file, 0600); err != nil {
		return NewVault{}, fmt.Errorf("writing vault: %w", err)
	}
	return nv, nil
}

// ReadSecretKeyFile returns the text of the Secret Key file, unparsed.
func ReadSecretKeyFile(ref VaultRef) (string, error) {
	raw, err := os.ReadFile(ref.SecretKeyPath)
	if os.IsNotExist(err) {
		return "", fmt.Errorf("no Secret Key at %s — restore it from your Emergency Kit or set HORT_SECRET_KEY", ref.SecretKeyPath)
	}
	if err != nil {
		return "", fmt.Errorf("reading Secret Key: %w", err)
	}
	return string(raw), nil
}

// VaultInfo is the plaintext header information of a vault.
type VaultInfo struct {
	AccountID []byte
	Server    string
}

// ReadInfo parses the header without any key.
func ReadInfo(ref VaultRef) (VaultInfo, error) {
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return VaultInfo{}, fmt.Errorf("reading vault: %w", err)
	}
	f, err := parseV4(raw)
	if err != nil {
		return VaultInfo{}, err
	}
	return VaultInfo{AccountID: f.AccountID, Server: f.Server}, nil
}

func loadV4(ref VaultRef, vk []byte) (*VaultData, v4File, AccountKeys, error) {
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, v4File{}, AccountKeys{}, fmt.Errorf("reading vault: %w", err)
	}
	return openRaw(ref, raw, vk)
}

func openRaw(ref VaultRef, raw, vk []byte) (*VaultData, v4File, AccountKeys, error) {
	f, err := parseV4(raw)
	if err != nil {
		return nil, v4File{}, AccountKeys{}, err
	}
	keys, err := DeriveAccountKeys(vk, f.AccountID)
	if err != nil {
		return nil, v4File{}, AccountKeys{}, err
	}
	data, err := openV4(keys.FK, f)
	if err != nil {
		return nil, v4File{}, AccountKeys{}, fmt.Errorf("opening vault: %w", err)
	}
	return data, f, keys, nil
}

// LoadVault reads and decrypts the vault with VK from the session. It returns
// the raw file bytes, which SaveVault needs to keep the header.
func LoadVault(ref VaultRef, vk []byte) (*VaultData, []byte, error) {
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading vault: %w", err)
	}
	data, _, _, err := openRaw(ref, raw, vk)
	if err != nil {
		return nil, nil, err
	}
	return data, raw, nil
}

// SaveVault seals data under the header of existingRaw with a fresh body nonce.
func SaveVault(ref VaultRef, data *VaultData, vk []byte, existingRaw []byte) error {
	f, err := parseV4(existingRaw)
	if err != nil {
		return err
	}
	keys, err := DeriveAccountKeys(vk, f.AccountID)
	if err != nil {
		return err
	}
	file, err := sealV4(keys.FK, f.fileHeader, data)
	if err != nil {
		return err
	}
	if err := backupFile(ref.Path, 0600); err != nil {
		return err
	}
	return writeFileAtomic(ref.Path, file, 0600)
}

// UpdateVault serializes the full read-modify-write cycle for vault mutations.
func UpdateVault(ref VaultRef, vk []byte, mutate func(data *VaultData) error) error {
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

	data, raw, err := LoadVault(ref, vk)
	if err != nil {
		return err
	}
	if err := mutate(data); err != nil {
		return err
	}
	return SaveVault(ref, data, vk, raw)
}

// UnlockVault unwraps VK from the passphrase slot and checks that it opens the
// body. The caller parses the Secret Key first, so a mistyped one never
// reaches Argon2id.
func UnlockVault(ref VaultRef, passphrase, secretKey []byte) ([]byte, error) {
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}
	f, err := parseV4(raw)
	if err != nil {
		return nil, err
	}
	vk, err := f.openPassphraseSlot(string(passphrase), secretKey)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveAccountKeys(vk, f.AccountID)
	if err != nil {
		return nil, err
	}
	if _, err := openV4(keys.FK, f); err != nil {
		return nil, fmt.Errorf("opening vault: %w", err)
	}
	return vk, nil
}

// ChangePassphrase rewraps VK under a new passphrase and the same Secret Key
// with slot_version+1. The backup is replaced too, so no local copy of the
// old slot remains.
func ChangePassphrase(ref VaultRef, vk, passphrase, secretKey []byte) error {
	return changePassphrase(ref, vk, passphrase, secretKey, DefaultArgonParams())
}

func changePassphrase(ref VaultRef, vk, passphrase, secretKey []byte, params ArgonParams) error {
	path, err := canonicalVaultPath(ref.Path)
	if err != nil {
		return fmt.Errorf("resolving vault path: %w", err)
	}
	ref.Path = path
	unlock, err := lockVault(ref)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()

	data, f, keys, err := loadV4(ref, vk)
	if err != nil {
		return err
	}
	if f.SlotVersion == math.MaxUint64 {
		return errors.New("slot version exhausted")
	}
	h := f.fileHeader
	if err := h.sealPassphraseSlot(vk, keys.AK, string(passphrase), secretKey, f.SlotVersion+1, params); err != nil {
		return err
	}
	file, err := sealV4(keys.FK, h, data)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(ref.Path, file, 0600); err != nil {
		return err
	}
	if err := writeFileAtomic(BackupPathFor(ref), file, 0600); err != nil {
		return fmt.Errorf("writing backup: %w", err)
	}
	return nil
}
