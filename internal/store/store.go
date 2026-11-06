package store

import (
	"fmt"
	"sort"

	"github.com/s16e/hort/internal/vault"
)

type EntryInfo struct {
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	Environments []string      `json:"environments"`
	Contexts     []string      `json:"contexts"`
	Variants     []VariantInfo `json:"variants,omitempty"`
}
type VariantInfo struct {
	Env     string `json:"env"`
	Context string `json:"context"`
}

// Store reads and writes the one local vault with VK from the session.
type Store struct {
	ref vault.VaultRef
	key []byte
}

func New(ref vault.VaultRef, key []byte) *Store { return &Store{ref: ref, key: key} }

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

func (s *Store) load() (*vault.VaultData, error) {
	data, _, err := vault.LoadVault(s.ref, s.key)
	return data, err
}

func (s *Store) GetSecret(name, env, context string) (string, error) {
	data, err := s.load()
	if err != nil {
		return "", err
	}
	if v, ok := data.Secrets[name].Resolve("", env, context); ok {
		return v, nil
	}
	return "", fmt.Errorf("%q not found (env=%q, context=%q)", name, env, context)
}

func (s *Store) SetSecret(name, value, env, context, description string) error {
	revision, err := vault.NewRevision("set", vault.MakeLookupKey(env, context), value)
	if err != nil {
		return err
	}
	var desc *vault.Revision
	if description != "" {
		r, err := vault.NewRevision("describe", "", description)
		if err != nil {
			return err
		}
		desc = &r
	}
	return vault.UpdateVault(s.ref, s.key, func(data *vault.VaultData) error {
		data.Append(name, revision)
		if desc != nil {
			data.Append(name, *desc)
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
func (s *Store) Delete(name, env, context string) error {
	op, key := "delete", vault.MakeLookupKey(env, context)
	if env == "" && context == "" {
		op = "delete-entry"
		key = ""
	}
	revision, err := vault.NewRevision(op, key, "")
	if err != nil {
		return err
	}
	return vault.UpdateVault(s.ref, s.key, func(data *vault.VaultData) error {
		entry, ok := data.Secrets[name]
		values, _, visible := entry.Current()
		if !ok || !visible {
			return fmt.Errorf("entry %q not found", name)
		}
		if op == "delete" {
			if _, ok := values[vault.ValueKey{Key: key}]; !ok {
				return fmt.Errorf("entry %q has no variant %q", name, key)
			}
		}
		data.Append(name, revision)
		return nil
	})
}

type HistoryInfo struct {
	Revisions []vault.Revision `json:"revisions"`
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
	return HistoryInfo{Revisions: entry.History()}, nil
}

func entryToInfo(name string, entry vault.Entry) EntryInfo {
	values, description, _ := entry.Current()
	envs, contexts := map[string]bool{}, map[string]bool{}
	variants := make([]VariantInfo, 0, len(values))
	for vk := range values {
		env, ctx := vault.ParseLookupKey(vk.Key)
		envs[env] = true
		if ctx != "*" {
			contexts[ctx] = true
		}
		variants = append(variants, VariantInfo{Env: env, Context: ctx})
	}
	sort.Slice(variants, func(i, j int) bool {
		if variants[i].Env != variants[j].Env {
			return variants[i].Env < variants[j].Env
		}
		return variants[i].Context < variants[j].Context
	})
	return EntryInfo{Name: name, Description: description, Environments: sortedSetKeys(envs), Contexts: sortedSetKeys(contexts), Variants: variants}
}
func sortedSetKeys(m map[string]bool) []string {
	keys := []string{}
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
