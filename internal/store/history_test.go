package store

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/s16e/hort/internal/vault"
)

func TestHistoryFallbacksEmptyValuesAndMetadata(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ env, ctx, value, desc string }{
		{"", "", "baseline", "Überblick"}, {"prod", "", "production", ""}, {"prod", "kunde", "", ""},
	} {
		if err := s.SetSecret("", "ä", test.value, test.env, test.ctx, test.desc); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct{ env, ctx, value string }{
		{"staging", "kunde", "baseline"}, {"prod", "other", "production"}, {"prod", "kunde", ""},
	} {
		v, src, err := s.GetSecret("ä", test.env, test.ctx)
		if err != nil || src != "primary" || v != test.value {
			t.Fatalf("fallback env=%q ctx=%q: %q %s %v", test.env, test.ctx, v, src, err)
		}
	}
	if err := s.Delete("", "ä", "prod", "kunde"); err != nil {
		t.Fatal(err)
	}
	if v, _, err := s.GetSecret("ä", "prod", "kunde"); err != nil || v != "production" {
		t.Fatal("scope delete did not restore fallback")
	}
	entries, err := s.List()
	if err != nil || len(entries) != 1 || entries[0].Description != "Überblick" {
		t.Fatal("metadata lost")
	}
	metadata, _ := json.Marshal(entries)
	for _, value := range []string{"baseline", "production", "\"type\""} {
		if strings.Contains(string(metadata), value) {
			t.Fatal("list leaked value or removed type")
		}
	}
	history, err := s.History("", "ä")
	if err != nil || len(history.Revisions) != 5 {
		t.Fatalf("history: %v, %d", err, len(history.Revisions))
	}
	for _, r := range history.Revisions {
		if r.RecordedAt == nil {
			t.Fatal("new revision has unknown time")
		}
	}
	if err := s.Delete("", "ä", "", ""); err != nil {
		t.Fatal(err)
	}
	entries, err = s.Describe("ä")
	if err == nil || len(entries) != 0 {
		t.Fatal("describe exposed deleted entry")
	}
	history, err = s.History("", "ä")
	if err != nil || len(history.Revisions) != 6 {
		t.Fatal("whole delete discarded history")
	}
	if err := s.SetSecret("", "ä", "revived", "dev", "only", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GetSecret("ä", "prod", "kunde"); err == nil {
		t.Fatal("revival restored unrelated old scope")
	}
	if v, _, err := s.GetSecret("ä", "dev", "only"); err != nil || v != "revived" {
		t.Fatal("revival failed")
	}
}

func TestConcurrentChangesKeepOneEntriesHistory(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	const writers = 24
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.SetSecret("", "same", "value", "", "", "") }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	history, err := s.History("", "same")
	if err != nil || len(history.Revisions) != writers {
		t.Fatal("lost concurrent revision")
	}
	seen := map[string]bool{}
	for _, r := range history.Revisions {
		if seen[r.ID] {
			t.Fatal("duplicate revision ID")
		}
		seen[r.ID] = true
	}
}

func TestHistoryDisambiguatesDeletedEntriesAcrossSources(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := vault.MountedRefAt("other", t.TempDir()+"/other.enc")
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.CreateVault(ref, make([]byte, vault.KeySize), vault.KDFRawKey)
	if err != nil {
		t.Fatal(err)
	}
	s.mounts = []*Source{{Name: "other", Ref: ref, SessionKey: key}}
	if err := s.SetSecret("", "same", "primary", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret("other", "same", "mounted", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("", "same", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.History("", "same"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatal("history chose source silently")
	}
	if h, err := s.History("primary", "same"); err != nil || len(h.Revisions) != 2 {
		t.Fatal("explicit deleted history unavailable")
	}
}
