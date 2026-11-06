package cli

import (
	"strings"
	"testing"

	"github.com/s16e/hort/internal/store"
)

func TestUnifiedOutputHasNoTypeOrConfigCount(t *testing.T) {
	entries := []store.EntryInfo{{Name: "endpoint", Description: "URL", Environments: []string{"*"}}}
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
	filtered := FilterEntries(entries, "url endpoint")
	if len(filtered) != 1 {
		t.Fatal("bareword search changed")
	}
}
