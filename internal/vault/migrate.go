package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// strictJSON rejects duplicate object keys as well as unknown fields and trailing
// data: none can be silently discarded during a destructive format conversion.
func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func(reflect.Type) error
	walk = func(typ reflect.Type) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if tok == nil && typ.Kind() != reflect.Pointer {
			return fmt.Errorf("unexpected null in vault payload")
		}
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				fields := map[string]reflect.Type{}
				if typ.Kind() == reflect.Struct {
					for i := 0; i < typ.NumField(); i++ {
						f := typ.Field(i)
						fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
					}
				}
				for dec.More() {
					k, err := dec.Token()
					if err != nil {
						return err
					}
					key := k.(string)
					if seen[key] {
						return fmt.Errorf("duplicate JSON field %q", key)
					}
					seen[key] = true
					var child reflect.Type
					if typ.Kind() == reflect.Map {
						child = typ.Elem()
					} else if typ.Kind() == reflect.Struct {
						child = fields[key]
					}
					if child == nil {
						return fmt.Errorf("unexpected JSON field %q", key)
					}
					if err := walk(child); err != nil {
						return err
					}
				}
				for field := range fields {
					if !seen[field] {
						return fmt.Errorf("missing JSON field %q", field)
					}
				}
			case '[':
				if typ.Kind() != reflect.Slice {
					return fmt.Errorf("unexpected JSON array")
				}
				for dec.More() {
					if err := walk(typ.Elem()); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unexpected JSON delimiter")
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(reflect.TypeOf(dst).Elem()); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func decodeVault(raw []byte) (*VaultData, error) {
	var d VaultData
	if err := strictJSON(raw, &d); err != nil {
		return nil, err
	}
	if err := validateVault(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

type legacyEntry struct {
	Description *string           `json:"description"`
	Values      map[string]string `json:"values"`
}
type legacyVault struct {
	Version int                    `json:"version"`
	Secrets map[string]legacyEntry `json:"secrets"`
	Configs map[string]legacyEntry `json:"configs"`
}

func convertLegacy(raw []byte) (*VaultData, error) {
	var old legacyVault
	if err := strictJSON(raw, &old); err != nil {
		return nil, err
	}
	if old.Version != 1 || old.Secrets == nil || old.Configs == nil {
		return nil, fmt.Errorf("expected complete legacy inner version 1 payload")
	}
	collisions := []string{}
	for name := range old.Secrets {
		if _, ok := old.Configs[name]; ok {
			collisions = append(collisions, name)
		}
	}
	if len(collisions) > 0 {
		sort.Strings(collisions)
		return nil, fmt.Errorf("secret/config name collisions: %s", strings.Join(collisions, ", "))
	}
	data, err := NewVaultData()
	if err != nil {
		return nil, err
	}
	for _, entries := range []map[string]legacyEntry{old.Secrets, old.Configs} {
		for name, e := range entries {
			if e.Description == nil || e.Values == nil {
				return nil, fmt.Errorf("incomplete legacy entry %q", name)
			}
			// Keys are deliberately preserved byte for byte, including unusual keys.
			id, err := newID()
			if err != nil {
				return nil, err
			}
			entry := Entry{Revisions: []Revision{{ID: id, Op: "describe", Value: *e.Description}}}
			for key, val := range e.Values {
				id, err := newID()
				if err != nil {
					return nil, err
				}
				entry.Revisions = append(entry.Revisions, Revision{ID: id, Op: "set", Key: key, Value: val})
			}
			data.Secrets[name] = entry
		}
	}
	return data, nil
}

// MigrateVault converts exactly one unlocked source under the canonical write
// lock. The encrypted pre-v3 backup is permanent and is never rotated by saves.
func MigrateVault(ref VaultRef, key []byte) error {
	path, err := canonicalVaultPath(ref.Path)
	if err != nil {
		return err
	}
	ref.Path = path
	unlock, err := lockVault(ref)
	if err != nil {
		return err
	}
	defer unlock()
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	info, err := parseFormat(raw, true)
	if err != nil {
		return err
	}
	if info.Version != 2 {
		return fmt.Errorf("migration requires a v2 vault")
	}
	plaintext, err := openGCM(raw[info.CipherAt:], info.Nonce, key, nil)
	if err != nil {
		return err
	}
	data, err := convertLegacy(plaintext)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	cipher, nonce, err := sealGCM(encoded, key, buildV3Header(info.KDF, info.Salt, info.Argon, nil)[:HeaderSize-NonceSize])
	if err != nil {
		return err
	}
	converted := append(buildV3Header(info.KDF, info.Salt, info.Argon, nonce), cipher...)
	check, err := DecryptWithKey(converted, key)
	if err != nil {
		return err
	}
	roundtrip, err := decodeVault(check)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(data, roundtrip) {
		return fmt.Errorf("migration roundtrip mismatch")
	}
	// Compare the complete legacy logical content, not only successfully read
	// fallback values; empty entries and exact keys must also survive.
	var old legacyVault
	if err := strictJSON(plaintext, &old); err != nil {
		return err
	}
	for _, entries := range []map[string]legacyEntry{old.Secrets, old.Configs} {
		for name, e := range entries {
			values, desc, visible := roundtrip.Secrets[name].Current()
			if !visible || desc != *e.Description || !reflect.DeepEqual(values, e.Values) {
				return fmt.Errorf("migration content mismatch for %q", name)
			}
		}
	}
	backup := path + ".pre-v3.bak"
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		stat, statErr := os.Lstat(backup)
		if statErr != nil {
			return statErr
		}
		if !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 {
			return fmt.Errorf("existing migration backup must be a regular 0600 file")
		}
		prior, readErr := os.ReadFile(backup)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(prior, raw) {
			return fmt.Errorf("existing migration backup differs from current v2 vault")
		}
	} else if err != nil {
		return err
	} else {
		if _, err = f.Write(raw); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := syncMigrationDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := writeFileAtomic(path, converted, 0600); err != nil {
		return err
	}
	return syncMigrationDir(filepath.Dir(path))
}
