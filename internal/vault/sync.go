package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// A sync folder holds one byte-exact copy of vault.enc per device. Every other
// file with this prefix, such as a sync service's conflict copy, is read too.
const syncFilePrefix = "hort-"

// ErrSyncNotSetUp reports that this device has no sync folder.
var ErrSyncNotSetUp = errors.New("sync is not set up — run `hort sync setup --path <dir>`")

var errNoNewRevisions = errors.New("no new revisions")

// SyncResult reports one exchange with the sync folder.
type SyncResult struct {
	Read          int
	Unreadable    []string
	OwnUnreadable bool
	NewRevisions  int
	Pushed        bool
}

type syncFolder struct {
	vaults        []*VaultData
	ownRaw        []byte
	unreadable    []string
	ownUnreadable bool
}

// readSyncFolder never fails on a single file: a partial delivery or a foreign
// key is reported and the next run reads whatever has arrived by then.
func readSyncFolder(dir, ownName string, key []byte) (syncFolder, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return syncFolder{}, fmt.Errorf("reading sync folder: %w", err)
	}
	var folder syncFolder
	for _, file := range files {
		name := file.Name()
		if !file.Type().IsRegular() || !strings.HasPrefix(name, syncFilePrefix) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		var data *VaultData
		if err == nil {
			data, err = decodeSyncFile(raw, key)
		}
		if err != nil {
			folder.unreadable = append(folder.unreadable, name)
			folder.ownUnreadable = folder.ownUnreadable || name == ownName
			continue
		}
		folder.vaults = append(folder.vaults, data)
		if name == ownName {
			folder.ownRaw = raw
		}
	}
	return folder, nil
}

func decodeSyncFile(raw, key []byte) (*VaultData, error) {
	plaintext, err := DecryptWithKey(raw, key)
	if err != nil {
		return nil, err
	}
	return decodeVault(plaintext)
}

// mergeRevisions forms the union by revision identity. Identities are checked
// vault-wide because validateVault rejects duplicates across entries.
func mergeRevisions(dst *VaultData, sources []*VaultData) int {
	known := make(map[string]bool)
	for _, entry := range dst.Secrets {
		for _, r := range entry.Revisions {
			known[r.ID] = true
		}
	}
	added := 0
	for _, source := range sources {
		for name, incoming := range source.Secrets {
			for _, r := range incoming.Revisions {
				if known[r.ID] {
					continue
				}
				known[r.ID] = true
				entry := dst.Secrets[name]
				entry.Revisions = append(entry.Revisions, r)
				dst.Secrets[name] = entry
				added++
			}
		}
	}
	return added
}

func syncFile() (string, error) {
	reg, err := LoadSourceRegistry()
	if err != nil {
		return "", err
	}
	return reg.SyncFile, nil
}

// Sync exchanges the vault with the sync folder. Folder I/O stays outside the
// vault lock so a hanging folder cannot block local writers; a run that loses a
// race leaves the device's file briefly stale and the next run heals it.
func Sync(ref VaultRef, key []byte) (SyncResult, error) {
	own, err := syncFile()
	if err != nil {
		return SyncResult{}, err
	}
	if own == "" {
		return SyncResult{}, ErrSyncNotSetUp
	}
	folder, err := readSyncFolder(filepath.Dir(own), filepath.Base(own), key)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{Read: len(folder.vaults), Unreadable: folder.unreadable, OwnUnreadable: folder.ownUnreadable}

	err = UpdateVault(ref, key, func(data *VaultData) error {
		result.NewRevisions = mergeRevisions(data, folder.vaults)
		if result.NewRevisions == 0 {
			return errNoNewRevisions
		}
		return nil
	})
	if err != nil && !errors.Is(err, errNoNewRevisions) {
		return SyncResult{}, fmt.Errorf("merging sync folder: %w", err)
	}

	// An undecryptable own file may be all that is left of an earlier key.
	if folder.ownUnreadable {
		return result, nil
	}
	_, raw, err := LoadVault(ref, key)
	if err != nil {
		return result, err
	}
	if bytes.Equal(raw, folder.ownRaw) {
		return result, nil
	}
	if err := writeFileAtomic(own, raw, 0600); err != nil {
		return result, fmt.Errorf("writing sync file: %w", err)
	}
	result.Pushed = true
	return result, nil
}

// SetupSync connects this device to path and runs the first exchange. It changes
// nothing while the folder holds a file this vault cannot decrypt.
func SetupSync(ref VaultRef, key []byte, path string) (SyncResult, error) {
	dir, err := checkSyncDir(path)
	if err != nil {
		return SyncResult{}, err
	}
	if _, _, err := LoadVault(ref, key); err != nil {
		return SyncResult{}, err
	}
	previous, err := syncFile()
	if err != nil {
		return SyncResult{}, err
	}
	name := filepath.Base(previous)
	if previous == "" {
		id, err := newID()
		if err != nil {
			return SyncResult{}, err
		}
		name = syncFilePrefix + id + ".enc"
	}
	folder, err := readSyncFolder(dir, name, key)
	if err != nil {
		return SyncResult{}, err
	}
	if len(folder.unreadable) > 0 {
		return SyncResult{}, fmt.Errorf("sync folder holds files this vault cannot decrypt (%s) — all devices need the same vault key; nothing changed", strings.Join(folder.unreadable, ", "))
	}
	err = UpdateSourceRegistry(func(reg *SourceRegistry) error {
		reg.SyncFile = filepath.Join(dir, name)
		return nil
	})
	if err != nil {
		return SyncResult{}, err
	}
	return Sync(ref, key)
}

// checkSyncDir keeps the session file out of anything a service replicates, and
// never creates the folder: an unmounted path must not turn into a local one.
func checkSyncDir(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("sync folder: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("sync folder %s is not a directory", path)
	}
	dir, err := canonicalVaultPath(path)
	if err != nil {
		return "", fmt.Errorf("resolving sync folder: %w", err)
	}
	hortDir, err := HortDir()
	if err != nil {
		return "", err
	}
	hortDir, err = canonicalVaultPath(hortDir)
	if err != nil {
		return "", fmt.Errorf("resolving hort directory: %w", err)
	}
	if pathContains(dir, hortDir) || pathContains(hortDir, dir) {
		return "", fmt.Errorf("sync folder must neither contain nor lie inside %s", hortDir)
	}
	return dir, nil
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
