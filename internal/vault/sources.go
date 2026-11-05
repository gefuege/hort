package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SourceRecord is the persistent registry entry describing a mounted source.
type SourceRecord struct {
	Name string  `json:"name"`
	Path string  `json:"path"`
	KDF  KDFMode `json:"kdf"`
}

// SourceRegistry is the on-disk list of mounted sources.
type SourceRegistry struct {
	Version  int            `json:"version"`
	Sources  []SourceRecord `json:"sources"`
	SyncFile string         `json:"sync_file,omitempty"` // this device's file in the sync folder
}

// SourceRegistryPath returns the path to sources/index.json.
func SourceRegistryPath() (string, error) {
	dir, err := SourcesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "index.json"), nil
}

// sourceRegistryLockPath returns the path to the registry's lock file.
func sourceRegistryLockPath() (string, error) {
	dir, err := SourcesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "index.lock"), nil
}

// LoadSourceRegistry returns the current registry, creating an empty one if
// the file does not yet exist.
func LoadSourceRegistry() (*SourceRegistry, error) {
	path, err := SourceRegistryPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &SourceRegistry{Version: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading source registry: %w", err)
	}
	var reg SourceRegistry
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, fmt.Errorf("parsing source registry: %w", err)
	}
	if reg.Version == 0 {
		reg.Version = 1
	}
	return &reg, nil
}

// SaveSourceRegistry persists the registry atomically.
func SaveSourceRegistry(reg *SourceRegistry) error {
	dir, err := SourcesDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating sources directory: %w", err)
	}
	path, err := SourceRegistryPath()
	if err != nil {
		return err
	}
	sort.Slice(reg.Sources, func(i, j int) bool {
		return reg.Sources[i].Name < reg.Sources[j].Name
	})
	raw, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling source registry: %w", err)
	}
	return writeFileAtomic(path, append(raw, '\n'), 0600)
}

// UpdateSourceRegistry serializes a registry mutation under an exclusive lock.
func UpdateSourceRegistry(mutate func(*SourceRegistry) error) error {
	lockPath, err := sourceRegistryLockPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return fmt.Errorf("creating sources directory: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("opening source registry lock: %w", err)
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		return err
	}
	defer func() {
		_ = unlockFile(file)
	}()

	reg, err := LoadSourceRegistry()
	if err != nil {
		return err
	}
	if err := mutate(reg); err != nil {
		return err
	}
	return SaveSourceRegistry(reg)
}

// FindSource returns the named record from a registry, if present.
func (r *SourceRegistry) FindSource(name string) *SourceRecord {
	for i := range r.Sources {
		if r.Sources[i].Name == name {
			return &r.Sources[i]
		}
	}
	return nil
}

// AddSource inserts or replaces a record and saves the registry.
func AddSource(record SourceRecord) error {
	if err := validateSourceName(record.Name); err != nil {
		return err
	}
	return UpdateSourceRegistry(func(reg *SourceRegistry) error {
		for i := range reg.Sources {
			if reg.Sources[i].Name == record.Name {
				reg.Sources[i] = record
				return nil
			}
		}
		reg.Sources = append(reg.Sources, record)
		return nil
	})
}

// RemoveSource removes a named record. Returns an error if it does not exist.
func RemoveSource(name string) error {
	return UpdateSourceRegistry(func(reg *SourceRegistry) error {
		for i := range reg.Sources {
			if reg.Sources[i].Name == name {
				reg.Sources = append(reg.Sources[:i], reg.Sources[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("source %q not found", name)
	})
}

// ListSources returns all registered source records.
func ListSources() ([]SourceRecord, error) {
	reg, err := LoadSourceRegistry()
	if err != nil {
		return nil, err
	}
	out := make([]SourceRecord, len(reg.Sources))
	copy(out, reg.Sources)
	return out, nil
}

// RefFromRecord builds a VaultRef from a registry record.
func RefFromRecord(rec SourceRecord) (VaultRef, error) {
	return MountedRefAt(rec.Name, rec.Path)
}

var errInvalidSourceName = errors.New("source name must be lowercase letters, digits, '-' or '_'")

func validateSourceName(name string) error {
	if name == "" {
		return fmt.Errorf("source name must not be empty")
	}
	if name == PrimarySourceName {
		return fmt.Errorf("source name %q is reserved", PrimarySourceName)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return errInvalidSourceName
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasPrefix(name, ".") {
		return errInvalidSourceName
	}
	return nil
}
