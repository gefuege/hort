package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/vault"
)

func TestLegacyHintOnlyWhenEntryHoldsTheViolation(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret("db-login", "", "v", "", "", ""); err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct{ field, env string }{{"", "a b"}, {"Bad", ""}} {
		err := s.SetSecret("db-login", w.field, "x", w.env, "", "")
		if err == nil || strings.Contains(err.Error(), "predates") {
			t.Errorf("valid entry, bad new write %+v: %v", w, err)
		}
	}
	err = s.SetSecret("db-login", "", strings.Repeat("a", vault.MaxValueBytes+1), "", "", "")
	if err == nil || strings.Contains(err.Error(), "predates") {
		t.Errorf("oversize on valid entry: %v", err)
	}
}

func TestLegacyHintWhenEntryHoldsTheViolatingKey(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	err = vault.UpdateVault(s.ref, s.key, func(data *vault.VaultData) error {
		rev, err := vault.NewRevision("set", "a b:*", "old")
		if err != nil {
			return err
		}
		data.Append("valid-name", rev)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.SetSecret("valid-name", "", "new", "a b", "", "")
	if err == nil || !strings.Contains(err.Error(), "predates") {
		t.Fatalf("existing violating key: %v", err)
	}
	err = s.SetSecret("valid-name", "", "new", "c d", "", "")
	if err == nil || strings.Contains(err.Error(), "predates") {
		t.Fatalf("new violating key: %v", err)
	}
}

func TestSetAppendsDescribeOnlyWhenItChanges(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1", "2"} {
		if err := s.SetSecret("tok", "", v, "", "", "same"); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetSecret("tok", "", "3", "", "", "changed"); err != nil {
		t.Fatal(err)
	}
	h, err := s.History("tok")
	if err != nil {
		t.Fatal(err)
	}
	var describes []string
	for _, r := range h.Revisions {
		if r.Op == "describe" {
			describes = append(describes, r.Value)
		}
	}
	if len(describes) != 2 || describes[0] != "same" || describes[1] != "changed" {
		t.Fatalf("describe revisions: %v", describes)
	}
}

func TestSetRefusesInvalidUTF8Scope(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []struct{ env, ctx string }{{"\xff", ""}, {"", "a\xffb"}} {
		if err := s.SetSecret("ok", "", "v", w.env, w.ctx, ""); err == nil {
			t.Errorf("accepted %q/%q", w.env, w.ctx)
		}
	}
}

func TestSaveSharedWritesAllOrNothing(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret("taken", "", "old", "", "", ""); err != nil {
		t.Fatal(err)
	}
	revisions := func() int {
		data, err := s.load()
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range data.Secrets {
			n += len(e.Revisions)
		}
		return n
	}
	before := revisions()
	ok := vault.SharedField{Field: "", Value: "v"}
	for name, fields := range map[string][]vault.SharedField{
		"taken": {ok},
		"fresh": {ok, {Field: "Bad_Field", Value: "v"}},
	} {
		if err := s.SaveShared(name, "desc", fields); err == nil {
			t.Fatalf("%s: refused write accepted", name)
		}
		if got := revisions(); got != before {
			t.Fatalf("%s: %d revisions, want %d", name, got, before)
		}
	}
	if err := s.SaveShared("taken", "", []vault.SharedField{ok}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("existing name: %v", err)
	}
	if err := s.SaveShared("fresh", "desc", []vault.SharedField{ok, {Field: "user", Value: "u"}}); err != nil {
		t.Fatal(err)
	}
	if got := revisions(); got != before+3 {
		t.Fatalf("%d revisions after saving, want %d", got, before+3)
	}
}
