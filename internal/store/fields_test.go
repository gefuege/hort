package store

import (
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/vault"
)

func TestFieldsResolveWithoutFallbackToDefaultField(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct{ field, value, env string }{
		{"", "default-value", ""}, {"password", "pw-base", ""}, {"password", "pw-prod", "prod"}, {"username", "user", "prod"},
	} {
		if err := s.SetSecret("db", w.field, w.value, w.env, "", "database"); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []struct{ field, env, want string }{
		{"", "", "default-value"}, {"", "prod", "default-value"},
		{"password", "", "pw-base"}, {"password", "prod", "pw-prod"}, {"password", "staging", "pw-base"},
		{"username", "prod", "user"},
	} {
		if v, err := s.GetSecret("db", r.field, r.env, ""); err != nil || v != r.want {
			t.Errorf("field=%q env=%q: %q, %v; want %q", r.field, r.env, v, err, r.want)
		}
	}
	// username has only a prod value: no fallback to its absent baseline, no
	// fallback to the default field, no value for a field that does not exist.
	for _, r := range []struct{ field, env string }{{"username", ""}, {"username", "staging"}, {"token", "prod"}} {
		if v, err := s.GetSecret("db", r.field, r.env, ""); err == nil {
			t.Errorf("field=%q env=%q resolved to %q", r.field, r.env, v)
		}
	}

	entries, err := s.List()
	if err != nil || len(entries) != 1 {
		t.Fatalf("list: %v %v", entries, err)
	}
	e := entries[0]
	if strings.Join(e.Fields, ",") != "password,username" || len(e.Variants) != 4 {
		t.Fatalf("entry info: %+v", e)
	}
	want := []VariantInfo{{"", "*", "*"}, {"password", "*", "*"}, {"password", "prod", "*"}, {"username", "prod", "*"}}
	for i, v := range e.Variants {
		if v != want[i] {
			t.Errorf("variant %d: %+v, want %+v", i, v, want[i])
		}
	}
}

func TestDeleteFieldAndEntry(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"", "a", "b"} {
		if err := s.SetSecret("e", field, "v-"+field, "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete("e", "a", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecret("e", "a", "", ""); err == nil {
		t.Fatal("deleted field still resolves")
	}
	if v, err := s.GetSecret("e", "b", "", ""); err != nil || v != "v-b" {
		t.Fatalf("other field affected: %q %v", v, err)
	}
	if err := s.Delete("e", "a", "", ""); err == nil {
		t.Fatal("deleting a missing value succeeded")
	}
	if err := s.Delete("e", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Describe("e"); err == nil {
		t.Fatal("entry survived delete-entry")
	}
}

func TestHistoryJSONShape(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret("e", "pw", "v", "prod", "heine", "d"); err != nil {
		t.Fatal(err)
	}
	h, err := s.History("e")
	if err != nil || h.Name != "e" || len(h.Revisions) != 2 {
		t.Fatalf("history: %+v %v", h, err)
	}
	set, describe := h.Revisions[0], h.Revisions[1]
	if set.Op != "set" || set.Field != "pw" || set.Env != "prod" || set.Context != "heine" || set.Value != "v" {
		t.Errorf("set revision: %+v", set)
	}
	if describe.Op != "describe" || describe.Env != "" || describe.Context != "" || describe.Value != "d" {
		t.Errorf("describe revision: %+v", describe)
	}
}

// legacyVault holds what a v3 vault may hold and the new write rules refuse.
func legacyVault(t *testing.T) *Store {
	t.Helper()
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	err = vault.UpdateVault(s.ref, s.key, func(data *vault.VaultData) error {
		for _, r := range []vault.Revision{
			{Op: "set", Key: "prod:ctx:with:colons", Value: "legacy-value"},
			{Op: "describe", Value: "old entry"},
		} {
			rev, err := vault.NewRevision(r.Op, r.Key, r.Value)
			if err != nil {
				return err
			}
			data.Append("my legacy name", rev)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLegacyEntryStaysReadableAndDeletable(t *testing.T) {
	s := legacyVault(t)
	// The key splits at the first colon: env "prod", context "ctx:with:colons".
	if v, err := s.GetSecret("my legacy name", "", "prod", "ctx:with:colons"); err != nil || v != "legacy-value" {
		t.Fatalf("get: %q %v", v, err)
	}
	entries, err := s.List()
	if err != nil || len(entries) != 1 || entries[0].Name != "my legacy name" || entries[0].Variants[0].Context != "ctx:with:colons" {
		t.Fatalf("list: %+v %v", entries, err)
	}
	if h, err := s.History("my legacy name"); err != nil || len(h.Revisions) != 2 || h.Revisions[0].Context != "ctx:with:colons" {
		t.Fatalf("history: %+v %v", h, err)
	}
	if err := s.Delete("my legacy name", "", "prod", "ctx:with:colons"); err != nil {
		t.Fatalf("delete of the legacy value: %v", err)
	}
	if err := s.Delete("my legacy name", "", "", ""); err != nil {
		t.Fatalf("delete-entry of the legacy name: %v", err)
	}
}

func TestSetOnLegacyEntryPointsAtRecreating(t *testing.T) {
	s := legacyVault(t)
	for _, env := range []string{"", "prod"} {
		err := s.SetSecret("my legacy name", "", "new", env, "", "")
		if err == nil || !strings.Contains(err.Error(), "delete it and create it again under a valid name") {
			t.Fatalf("env=%q: %v", env, err)
		}
	}
	// A new name that breaks the rules gets the plain error without the hint.
	err := s.SetSecret("bad name", "", "v", "", "", "")
	if err == nil || strings.Contains(err.Error(), "predates") {
		t.Fatalf("new invalid name: %v", err)
	}
	if v, err := s.GetSecret("my legacy name", "", "prod", "ctx:with:colons"); err != nil || v != "legacy-value" {
		t.Fatalf("refused write changed the entry: %q %v", v, err)
	}
}

func TestSetRefusesInvalidWritesWithoutChanges(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct{ name, field, env, ctx string }{
		{"-lead", "", "", ""}, {"a b", "", "", ""}, {"ok", "Bad", "", ""}, {"ok", "", "a:b", ""}, {"ok", "", "", "x y"}, {"ok", "", "pr*", ""},
	} {
		if err := s.SetSecret(w.name, w.field, "v", w.env, w.ctx, "d"); err == nil {
			t.Errorf("accepted %+v", w)
		}
	}
	if entries, _ := s.List(); len(entries) != 0 {
		t.Fatalf("refused writes left entries: %+v", entries)
	}
}
