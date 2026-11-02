package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/s16e/hort/internal/store"
	"github.com/s16e/hort/internal/vault"
)

// FormatList formats entry list for human or JSON output.
func FormatList(entries []store.EntryInfo, jsonOutput bool) string {
	if jsonOutput {
		data, _ := json.MarshalIndent(entries, "", "  ")
		return string(data)
	}

	if len(entries) == 0 {
		return "No entries found.\n"
	}

	var b strings.Builder
	for _, e := range entries {
		envs := strings.Join(e.Environments, ", ")
		desc := e.Description
		if desc == "" {
			desc = "(no description)"
		}

		prefix := ""
		if e.Source != "" && e.Source != vault.PrimarySourceName {
			prefix = fmt.Sprintf("[%s] ", e.Source)
		}

		line := fmt.Sprintf("%s%-8s %-30s %s  [env: %s]", prefix, e.Type, e.Name, desc, envs)
		if len(e.Contexts) > 0 {
			line += fmt.Sprintf("  [ctx: %s]", strings.Join(e.Contexts, ", "))
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// FormatDescribe formats entry details for human or JSON output.
// Accepts multiple matches (one per source) so ambiguity is explicit.
func FormatDescribe(entries []store.EntryInfo, jsonOutput bool) string {
	if jsonOutput {
		data, _ := json.MarshalIndent(entries, "", "  ")
		return string(data)
	}

	var b strings.Builder
	for i, entry := range entries {
		if i > 0 {
			b.WriteString("---\n")
		}
		fmt.Fprintf(&b, "Name:         %s\n", entry.Name)
		fmt.Fprintf(&b, "Source:       %s\n", entry.Source)
		fmt.Fprintf(&b, "Type:         %s\n", entry.Type)
		fmt.Fprintf(&b, "Description:  %s\n", entry.Description)
		fmt.Fprintf(&b, "Environments: %s\n", strings.Join(entry.Environments, ", "))
		if len(entry.Contexts) > 0 {
			fmt.Fprintf(&b, "Contexts:     %s\n", strings.Join(entry.Contexts, ", "))
		}
	}
	return b.String()
}

// SourceStatus captures one line in `hort source list` output.
type SourceStatus struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	KDF      string `json:"kdf"`
	Unlocked bool   `json:"unlocked"`
	Primary  bool   `json:"primary"`
}

// FormatSourceList renders the source list.
func FormatSourceList(items []SourceStatus, jsonOutput bool) string {
	if jsonOutput {
		data, _ := json.MarshalIndent(items, "", "  ")
		return string(data)
	}
	var b strings.Builder
	for _, s := range items {
		state := "locked"
		if s.Unlocked {
			state = "unlocked"
		}
		primaryMark := ""
		if s.Primary {
			primaryMark = " (primary)"
		}
		fmt.Fprintf(&b, "%-24s %-8s %-8s %s%s\n", s.Name, state, s.KDF, s.Path, primaryMark)
	}
	return b.String()
}

// FormatStatus formats primary vault status. Apps integrating Hort
// can parse the JSON form as a single readiness check.
func FormatStatus(unlocked bool, vaultPath string, secretCount, configCount int, jsonOutput bool) string {
	if jsonOutput {
		status := map[string]any{
			"primary": map[string]any{
				"unlocked":     unlocked,
				"vault_path":   vaultPath,
				"secret_count": secretCount,
				"config_count": configCount,
			},
			"ready": unlocked,
		}
		data, _ := json.MarshalIndent(status, "", "  ")
		return string(data)
	}

	var b strings.Builder
	if unlocked {
		fmt.Fprintln(&b, "Status:   unlocked")
	} else {
		fmt.Fprintln(&b, "Status:   locked")
	}
	fmt.Fprintf(&b, "Vault:    %s\n", vaultPath)
	fmt.Fprintf(&b, "Secrets:  %d\n", secretCount)
	fmt.Fprintf(&b, "Configs:  %d\n", configCount)
	if !unlocked {
		fmt.Fprintln(&b, "Next:     run `hort unlock` to use secrets")
	}
	return b.String()
}

// FormatContextValues formats context→value map for human or JSON output.
func FormatContextValues(values map[string]string, jsonOutput bool) string {
	if jsonOutput {
		data, _ := json.MarshalIndent(values, "", "  ")
		return string(data)
	}

	var b strings.Builder
	for ctx, val := range values {
		fmt.Fprintf(&b, "%-20s %s\n", ctx, val)
	}
	return b.String()
}
