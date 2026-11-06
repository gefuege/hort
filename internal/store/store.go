package store

import (
	"fmt"
	"sort"
	"time"

	"github.com/gefuege/hort/internal/vault"
)

// EntryInfo is the metadata of an entry (contract §4). Fields lists the named
// fields; the default field appears in Variants with Field "".
type EntryInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Fields      []string      `json:"fields"`
	Variants    []VariantInfo `json:"variants"`
}
type VariantInfo struct {
	Field   string `json:"field"`
	Env     string `json:"env"`
	Context string `json:"context"`
}

// Store reads and writes the one local vault with VK from the session.
type Store struct {
	ref vault.VaultRef
	key []byte
}

func New(ref vault.VaultRef, key []byte) *Store { return &Store{ref: ref, key: key} }

func (s *Store) load() (*vault.VaultData, error) {
	data, _, err := vault.LoadVault(s.ref, s.key)
	return data, err
}

func (s *Store) GetSecret(name, field, env, context string) (string, error) {
	data, err := s.load()
	if err != nil {
		return "", err
	}
	if v, ok := data.Secrets[name].Resolve(field, env, context); ok {
		return v, nil
	}
	return "", fmt.Errorf("%q not found (field=%q, env=%q, context=%q)", name, field, env, context)
}

// validated checks the new revisions of one write. A failure points at
// deleting and re-creating the entry only when the entry already holds what
// breaks the rules: its name, or the key being written.
func validated(name string, entry vault.Entry, exists bool, revisions ...vault.Revision) error {
	for _, r := range revisions {
		err := vault.ValidateWrite(name, r)
		if err == nil {
			continue
		}
		if exists && (vault.ValidateName(name) != nil || (vault.ValidateKey(r.Key) != nil && holdsKey(entry, r.Key))) {
			err = vault.WithLegacyHint(err)
		}
		return err
	}
	return nil
}

func holdsKey(entry vault.Entry, key vault.LookupKey) bool {
	values, _, _ := entry.Current()
	for k := range values {
		if k.Key == key {
			return true
		}
	}
	return false
}

func (s *Store) SetSecret(name, field, value, env, context, description string) error {
	data, err := s.load()
	if err != nil {
		return err
	}
	entry, exists := data.Secrets[name]
	revision, err := vault.NewRevision("set", vault.MakeLookupKey(env, context), value)
	if err != nil {
		return err
	}
	revision.Field = field
	revisions := []vault.Revision{revision}
	if _, current, _ := entry.Current(); description != "" && description != current {
		desc, err := vault.NewRevision("describe", "", description)
		if err != nil {
			return err
		}
		revisions = append(revisions, desc)
	}
	if err := validated(name, entry, exists, revisions...); err != nil {
		return err
	}
	return vault.UpdateVault(s.ref, s.key, func(data *vault.VaultData) error {
		for _, r := range revisions {
			data.Append(name, r)
		}
		return nil
	})
}
func (s *Store) List() ([]EntryInfo, error) {
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	entries := []EntryInfo{}
	for name, entry := range data.Secrets {
		if _, _, visible := entry.Current(); visible {
			entries = append(entries, entryToInfo(name, entry))
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}
func (s *Store) Describe(name string) (EntryInfo, error) {
	data, err := s.load()
	if err != nil {
		return EntryInfo{}, err
	}
	entry := data.Secrets[name]
	if _, _, visible := entry.Current(); !visible {
		return EntryInfo{}, fmt.Errorf("entry %q not found", name)
	}
	return entryToInfo(name, entry), nil
}

// Delete removes one value (field, env, context), or the whole entry when
// none of the three is given. Legacy names and keys can always be deleted.
func (s *Store) Delete(name, field, env, context string) error {
	op, key := "delete", vault.MakeLookupKey(env, context)
	if field == "" && env == "" && context == "" {
		op, key = "delete-entry", ""
	}
	revision, err := vault.NewRevision(op, key, "")
	if err != nil {
		return err
	}
	revision.Field = field
	if err := vault.ValidateWrite(name, revision); err != nil {
		return err
	}
	return vault.UpdateVault(s.ref, s.key, func(data *vault.VaultData) error {
		entry, ok := data.Secrets[name]
		values, _, visible := entry.Current()
		if !ok || !visible {
			return fmt.Errorf("entry %q not found", name)
		}
		if op == "delete" {
			if _, ok := values[vault.ValueKey{Field: field, Key: key}]; !ok {
				return fmt.Errorf("entry %q has no value for field=%q, env=%q, context=%q", name, field, env, context)
			}
		}
		data.Append(name, revision)
		return nil
	})
}

// HistoryRevision is a revision with its lookup key split into env and context.
type HistoryRevision struct {
	ID         string     `json:"id"`
	RecordedAt *time.Time `json:"recorded_at"`
	Op         string     `json:"op"`
	Field      string     `json:"field"`
	Env        string     `json:"env"`
	Context    string     `json:"context"`
	Value      string     `json:"value"`
}
type HistoryInfo struct {
	Name      string            `json:"name"`
	Revisions []HistoryRevision `json:"revisions"`
}

// History includes deleted entries; it is the explicit value read.
func (s *Store) History(name string) (HistoryInfo, error) {
	data, err := s.load()
	if err != nil {
		return HistoryInfo{}, err
	}
	entry, ok := data.Secrets[name]
	if !ok {
		return HistoryInfo{}, fmt.Errorf("entry %q not found", name)
	}
	revisions := []HistoryRevision{}
	for _, r := range entry.History() {
		h := HistoryRevision{ID: r.ID, RecordedAt: r.RecordedAt, Op: r.Op, Field: r.Field, Value: r.Value}
		if r.Key != "" {
			h.Env, h.Context = vault.ParseLookupKey(r.Key)
		}
		revisions = append(revisions, h)
	}
	return HistoryInfo{Name: name, Revisions: revisions}, nil
}

func entryToInfo(name string, entry vault.Entry) EntryInfo {
	values, description, _ := entry.Current()
	fields := map[string]bool{}
	variants := make([]VariantInfo, 0, len(values))
	for vk := range values {
		env, ctx := vault.ParseLookupKey(vk.Key)
		if vk.Field != "" {
			fields[vk.Field] = true
		}
		variants = append(variants, VariantInfo{Field: vk.Field, Env: env, Context: ctx})
	}
	sort.Slice(variants, func(i, j int) bool {
		a, b := variants[i], variants[j]
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		if a.Env != b.Env {
			return a.Env < b.Env
		}
		return a.Context < b.Context
	})
	return EntryInfo{Name: name, Description: description, Fields: sortedSetKeys(fields), Variants: variants}
}
func sortedSetKeys(m map[string]bool) []string {
	keys := []string{}
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
