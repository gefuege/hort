package store

import (
	"errors"
	"testing"
	"time"

	"github.com/gefuege/hort/internal/vault"
)

// foldVault stores what an older Hort could write: one secret under two
// spellings, and env TEST next to env test for the same field and context.
func foldVault(t *testing.T) *Store {
	t.Helper()
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	err = vault.UpdateVault(s.ref, s.key, func(data *vault.VaultData) error {
		for i, w := range []struct{ name, field, key, value string }{
			{"DHL-Developer-Portal", "api-secret", "TEST:Heine", "older"},
			{"dhl-developer-portal", "api-secret", "test:heine", "newest"},
		} {
			r, err := vault.NewRevision("set", w.key, w.value)
			if err != nil {
				return err
			}
			r.Field = w.field
			stamp := at.Add(time.Duration(i) * time.Second)
			r.RecordedAt = &stamp
			e := data.Secrets[w.name]
			e.Revisions = append(e.Revisions, r)
			data.Secrets[w.name] = e
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLegacyDuplicateReducesToNewestAndKeepsHistory(t *testing.T) {
	s := foldVault(t)
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "DHL-Developer-Portal" || len(list[0].Variants) != 1 {
		t.Fatalf("list: %+v", list)
	}
	if v := list[0].Variants[0]; v.Field != "api-secret" || v.Env != "TEST" || v.Context != "Heine" {
		t.Fatalf("display spelling: %+v", v)
	}
	if v, err := s.GetSecret("dhl-developer-portal", "api-secret", "test", "heine"); err != nil || v != "newest" {
		t.Fatalf("get: %q, %v", v, err)
	}
	h, err := s.History("DHL-DEVELOPER-PORTAL")
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "DHL-Developer-Portal" || len(h.Revisions) != 2 || h.Revisions[0].Value != "older" || h.Revisions[1].Value != "newest" {
		t.Fatalf("history: %+v", h)
	}
}

func TestLookupIgnoresCaseInNameFieldEnvAndContext(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecret("Github-Token", "api", "v", "Prod", "Heine", ""); err != nil {
		t.Fatal(err)
	}
	for _, q := range [][4]string{
		{"github-token", "API", "prod", "heine"},
		{"GITHUB-TOKEN", "Api", "PROD", "HEINE"},
	} {
		if v, err := s.GetSecret(q[0], q[1], q[2], q[3]); err != nil || v != "v" {
			t.Errorf("get %v: %q, %v", q, v, err)
		}
	}
	if _, err := s.Describe("GITHUB-token"); err != nil {
		t.Errorf("describe: %v", err)
	}
}

func TestWriteWithOtherSpellingLandsOnExistingKey(t *testing.T) {
	s := foldVault(t)
	if err := s.SetSecret("dhl-DEVELOPER-portal", "API-SECRET", "third", "test", "HEINE", ""); err != nil {
		t.Fatal(err)
	}
	data, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	last := data.Secrets["DHL-Developer-Portal"].Revisions
	if len(data.Secrets) != 2 || len(last) != 2 {
		t.Fatalf("stored names: %d, revisions under the first spelling: %d", len(data.Secrets), len(last))
	}
	if r := last[1]; r.Field != "api-secret" || r.Key != "TEST:Heine" || r.Value != "third" {
		t.Fatalf("write spelling: %+v", r)
	}
	if v, _ := s.GetSecret("dhl-developer-portal", "api-secret", "test", "heine"); v != "third" {
		t.Fatalf("newest write did not win: %q", v)
	}
	if err := s.Delete("DHL-developer-PORTAL", "api-secret", "Test", "heine"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSecret("dhl-developer-portal", "api-secret", "test", "heine"); err == nil {
		t.Fatal("value survived its delete")
	}
}

func TestSaveSharedRefusesNameThatDiffersOnlyInCase(t *testing.T) {
	s := foldVault(t)
	err := s.SaveShared("DHL-DEVELOPER-PORTAL", "", []vault.SharedField{{Field: "", Value: "x"}})
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("SaveShared: %v", err)
	}
}

func TestEnvAndContextKeepTheirSpellingAcrossFieldsAndPartners(t *testing.T) {
	primarySetup(t)
	s, err := NewFromSession()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range [][4]string{
		{"X", "password", "PROD", "Heine"},
		{"x", "password", "prod", "x"},
		{"x", "user", "dev", "heine"},
	} {
		if err := s.SetSecret(w[0], w[1], "v", w[2], w[3], ""); err != nil {
			t.Fatal(err)
		}
	}
	info, err := s.Describe("x")
	if err != nil {
		t.Fatal(err)
	}
	envs, contexts := map[string]bool{}, map[string]bool{}
	for _, v := range info.Variants {
		envs[v.Env], contexts[v.Context] = true, true
	}
	if info.Name != "X" || envs["prod"] || contexts["heine"] || !envs["PROD"] || !contexts["Heine"] {
		t.Fatalf("spelling: %+v", info)
	}
}
