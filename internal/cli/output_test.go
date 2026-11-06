package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/store"
)

func TestUnifiedOutputHasNoTypeOrConfigCount(t *testing.T) {
	entries := []store.EntryInfo{{Name: "endpoint", Description: "URL", Fields: []string{}, Variants: []store.VariantInfo{{Env: "*", Context: "*"}}}}
	count := 1
	for _, jsonOutput := range []bool{false, true} {
		for _, output := range []string{FormatList(entries, jsonOutput), FormatDescribe(entries[0], jsonOutput), FormatStatus(Status{Ready: true, Unlocked: true, SecretCount: &count}, jsonOutput)} {
			for _, removed := range []string{"\"type\"", "Type:", "config_count", "Configs:"} {
				if strings.Contains(output, removed) {
					t.Fatal("removed contract present:", removed)
				}
			}
		}
	}
}

func TestListJSONShapeHasFieldsAndVariants(t *testing.T) {
	entries := []store.EntryInfo{{
		Name: "db", Description: "database", Fields: []string{"password"},
		Variants: []store.VariantInfo{{Field: "", Env: "*", Context: "*"}, {Field: "password", Env: "prod", Context: "heine"}},
	}}
	var got []map[string]any
	if err := json.Unmarshal([]byte(FormatList(entries, true)), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0]) != 4 || got[0]["name"] != "db" || got[0]["description"] != "database" {
		t.Fatalf("shape: %v", got)
	}
	variants := got[0]["variants"].([]any)
	if v := variants[1].(map[string]any); v["field"] != "password" || v["env"] != "prod" || v["context"] != "heine" {
		t.Fatalf("variant: %v", v)
	}
	if empty := FormatList(nil, true); strings.TrimSpace(empty) != "[]" {
		t.Fatalf("empty list: %q", empty)
	}
}

func TestFilterEntriesMatchesNameDescriptionFieldAndScope(t *testing.T) {
	entries := []store.EntryInfo{
		{Name: "endpoint", Description: "URL", Fields: []string{}, Variants: []store.VariantInfo{{Env: "*", Context: "*"}}},
		{Name: "db", Description: "database", Fields: []string{"password"}, Variants: []store.VariantInfo{{Field: "password", Env: "prod", Context: "heine"}}},
	}
	for query, want := range map[string]int{"url endpoint": 1, "PASSWORD": 1, "heine prod": 1, "db url": 0, "": 2} {
		if got := FilterEntries(entries, query); len(got) != want {
			t.Errorf("%q: %d entries, want %d", query, len(got), want)
		}
	}
}

func TestAgentLine(t *testing.T) {
	for _, test := range []struct{ name, field, env, ctx, want string }{
		{"token", "", "", "", "Ich habe das Secret `token` im Hort gespeichert. Abruf: `hort get token`"},
		{"db", "password", "prod", "heine", "Ich habe das Secret `db` (Field: password, Env: prod, Context: heine) im Hort gespeichert. Abruf: `hort get db password --env prod --context heine`"},
		{"a;b", "", "it's", "", "Ich habe das Secret `a;b` (Env: it's) im Hort gespeichert. Abruf: `hort get 'a;b' --env 'it'\\''s'`"},
	} {
		if got := AgentLine(test.name, test.field, test.env, test.ctx); got != test.want {
			t.Errorf("got  %s\nwant %s", got, test.want)
		}
	}
}
