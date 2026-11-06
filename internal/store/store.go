package store

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/s16e/hort/internal/vault"
)

type EntryInfo struct {
	Name         string        `json:"name"`
	Source       string        `json:"source"`
	Description  string        `json:"description"`
	Environments []string      `json:"environments"`
	Contexts     []string      `json:"contexts"`
	Variants     []VariantInfo `json:"variants,omitempty"`
}
type VariantInfo struct {
	Env     string `json:"env"`
	Context string `json:"context"`
}
type Source struct {
	Name       string
	Ref        vault.VaultRef
	SessionKey []byte
	Primary    bool
}
type Store struct {
	primary *Source
	mounts  []*Source
}

func New(primary *Source, mounts []*Source) *Store { return &Store{primary: primary, mounts: mounts} }

func NewFromSession() (*Store, error) {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return nil, err
	}
	key, err := vault.LoadSessionFor(ref)
	if err != nil {
		return nil, err
	}
	s := New(&Source{Name: ref.Name, Ref: ref, SessionKey: key, Primary: true}, nil)
	records, err := vault.ListSources()
	if err != nil {
		return nil, err
	}
	for _, rec := range records {
		ref, err := vault.RefFromRecord(rec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: mount %s has invalid registry entry: %v\n", rec.Name, err)
			continue
		}
		key, err := vault.LoadSessionFor(ref)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: mount %s is locked, skipping merged reads\n", rec.Name)
			continue
		}
		s.mounts = append(s.mounts, &Source{Name: rec.Name, Ref: ref, SessionKey: key})
	}
	return s, nil
}
func (s *Store) Sources() []*Source {
	out := make([]*Source, 0, 1+len(s.mounts))
	if s.primary != nil {
		out = append(out, s.primary)
	}
	return append(out, s.mounts...)
}
func (s *Store) sourceByName(name string) (*Source, error) {
	if name == "" || name == vault.PrimarySourceName {
		if s.primary == nil {
			return nil, fmt.Errorf("primary vault is not available")
		}
		return s.primary, nil
	}
	for _, src := range s.mounts {
		if src.Name == name {
			return src, nil
		}
	}
	return nil, fmt.Errorf("source %q is not mounted or not unlocked", name)
}

func (s *Store) GetSecret(name, env, context string) (string, string, error) {
	var value, source string
	var names []string
	for _, src := range s.Sources() {
		data, _, err := vault.LoadVault(src.Ref, src.SessionKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: source %s unreadable: %v\n", src.Name, err)
			continue
		}
		if v, ok := data.Secrets[name].Resolve("", env, context); ok {
			value = v
			source = src.Name
			names = append(names, src.Name)
		}
	}
	if len(names) == 0 {
		return "", "", fmt.Errorf("%q not found (env=%q, context=%q)", name, env, context)
	}
	if len(names) > 1 {
		sort.Strings(names)
		return "", "", fmt.Errorf("%q is ambiguous across sources [%s] — rerun with --source <name>", name, strings.Join(names, ", "))
	}
	return value, source, nil
}
func (s *Store) GetFrom(source, name, env, context string) (string, error) {
	src, err := s.sourceByName(source)
	if err != nil {
		return "", err
	}
	data, _, err := vault.LoadVault(src.Ref, src.SessionKey)
	if err != nil {
		return "", err
	}
	if v, ok := data.Secrets[name].Resolve("", env, context); ok {
		return v, nil
	}
	return "", fmt.Errorf("secret %q not found in source %q (env=%q, context=%q)", name, src.Name, env, context)
}

func (s *Store) SetSecret(source, name, value, env, context, description string) error {
	src, err := s.sourceByName(source)
	if err != nil {
		return err
	}
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
	return vault.UpdateVault(src.Ref, src.SessionKey, func(data *vault.VaultData) error {
		entry := data.Secrets[name]
		entry.Append(revision)
		if desc != nil {
			entry.Append(*desc)
		}
		data.Secrets[name] = entry
		return nil
	})
}
func (s *Store) List() ([]EntryInfo, error) {
	entries := []EntryInfo{}
	for _, src := range s.Sources() {
		data, _, err := vault.LoadVault(src.Ref, src.SessionKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: source %s unreadable: %v\n", src.Name, err)
			continue
		}
		for name, entry := range data.Secrets {
			if _, _, visible := entry.Current(); visible {
				entries = append(entries, entryToInfo(name, src.Name, entry))
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Source != entries[j].Source {
			return sourceSortKey(entries[i].Source) < sourceSortKey(entries[j].Source)
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}
func (s *Store) Describe(name string) ([]EntryInfo, error) {
	entries, err := s.List()
	if err != nil {
		return nil, err
	}
	matches := []EntryInfo{}
	for _, entry := range entries {
		if entry.Name == name {
			matches = append(matches, entry)
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("entry %q not found", name)
	}
	return matches, nil
}
func (s *Store) Delete(source, name, env, context string) error {
	src, err := s.sourceByName(source)
	if err != nil {
		return err
	}
	op, key := "delete", vault.MakeLookupKey(env, context)
	if env == "" && context == "" {
		op = "delete-entry"
		key = ""
	}
	revision, err := vault.NewRevision(op, key, "")
	if err != nil {
		return err
	}
	return vault.UpdateVault(src.Ref, src.SessionKey, func(data *vault.VaultData) error {
		entry, ok := data.Secrets[name]
		values, _, visible := entry.Current()
		if !ok || !visible {
			return fmt.Errorf("entry %q not found in source %q", name, src.Name)
		}
		if op == "delete" {
			if _, ok := values[vault.ValueKey{Key: key}]; !ok {
				return fmt.Errorf("entry %q has no variant %q", name, key)
			}
		}
		entry.Append(revision)
		data.Secrets[name] = entry
		return nil
	})
}
func (s *Store) ContextValues(source, name, env string) (map[string]string, error) {
	src, err := s.sourceByName(source)
	if err != nil {
		return nil, err
	}
	data, _, err := vault.LoadVault(src.Ref, src.SessionKey)
	if err != nil {
		return nil, err
	}
	if env == "" {
		env = "*"
	}
	result := map[string]string{}
	values, _, _ := data.Secrets[name].Current()
	for vk, value := range values {
		if vk.Field == "" && strings.HasPrefix(vk.Key, env+":") {
			_, ctx := vault.ParseLookupKey(vk.Key)
			result[ctx] = value
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no values for %q in env %q", name, env)
	}
	return result, nil
}

type HistoryInfo struct {
	Source    string           `json:"source"`
	Revisions []vault.Revision `json:"revisions"`
}

// History disambiguates on the entry's existence, including deleted entries.
func (s *Store) History(source, name string) (HistoryInfo, error) {
	sources := s.Sources()
	if source != "" {
		src, err := s.sourceByName(source)
		if err != nil {
			return HistoryInfo{}, err
		}
		sources = []*Source{src}
	}
	var hits []HistoryInfo
	for _, src := range sources {
		data, _, err := vault.LoadVault(src.Ref, src.SessionKey)
		if err != nil {
			return HistoryInfo{}, err
		}
		if entry, ok := data.Secrets[name]; ok {
			hits = append(hits, HistoryInfo{Source: src.Name, Revisions: entry.History()})
		}
	}
	if len(hits) == 0 {
		return HistoryInfo{}, fmt.Errorf("entry %q not found", name)
	}
	if len(hits) > 1 {
		names := []string{}
		for _, hit := range hits {
			names = append(names, hit.Source)
		}
		sort.Strings(names)
		return HistoryInfo{}, fmt.Errorf("%q is ambiguous across sources [%s] — rerun with --source <name>", name, strings.Join(names, ", "))
	}
	return hits[0], nil
}

func entryToInfo(name, source string, entry vault.Entry) EntryInfo {
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
	return EntryInfo{Name: name, Source: source, Description: description, Environments: sortedSetKeys(envs), Contexts: sortedSetKeys(contexts), Variants: variants}
}
func sortedSetKeys(m map[string]bool) []string {
	keys := []string{}
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func sourceSortKey(name string) string {
	if name == vault.PrimarySourceName {
		return "\x00" + name
	}
	return "\x01" + name
}
