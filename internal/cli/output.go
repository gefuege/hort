package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/s16e/hort/internal/store"
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

		line := fmt.Sprintf("%-30s %s  [env: %s]", e.Name, desc, envs)
		if len(e.Contexts) > 0 {
			line += fmt.Sprintf("  [ctx: %s]", strings.Join(e.Contexts, ", "))
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// FormatDescribe formats entry details for human or JSON output.
func FormatDescribe(entry store.EntryInfo, jsonOutput bool) string {
	if jsonOutput {
		data, _ := json.MarshalIndent(entry, "", "  ")
		return string(data)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Name:         %s\n", entry.Name)
	fmt.Fprintf(&b, "Description:  %s\n", entry.Description)
	fmt.Fprintf(&b, "Environments: %s\n", strings.Join(entry.Environments, ", "))
	if len(entry.Contexts) > 0 {
		fmt.Fprintf(&b, "Contexts:     %s\n", strings.Join(entry.Contexts, ", "))
	}
	return b.String()
}

// Status is the local status of §4. Fields that need the unlocked body are
// omitted while the vault is locked: unknown is not zero.
type Status struct {
	Ready       bool   `json:"ready"`
	Unlocked    bool   `json:"unlocked"`
	AccountID   string `json:"account_id,omitempty"`
	Server      string `json:"server,omitempty"`
	Registered  *bool  `json:"registered,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	SecretCount *int   `json:"secret_count,omitempty"`
}

// FormatStatus formats the vault status. Apps integrating Hort can parse the
// JSON form as a single readiness check.
func FormatStatus(st Status, jsonOutput bool) string {
	if jsonOutput {
		data, _ := json.MarshalIndent(st, "", "  ")
		return string(data)
	}

	var b strings.Builder
	switch {
	case st.AccountID == "":
		fmt.Fprintln(&b, "Status:     no vault")
		fmt.Fprintln(&b, "Next:       run `hort init` to create one")
		return b.String()
	case st.Unlocked:
		fmt.Fprintln(&b, "Status:     unlocked")
	default:
		fmt.Fprintln(&b, "Status:     locked")
	}
	fmt.Fprintf(&b, "Account:    %s\n", st.AccountID)
	fmt.Fprintf(&b, "Server:     %s\n", st.Server)
	if st.Registered != nil {
		fmt.Fprintf(&b, "Registered: %t\n", *st.Registered)
		fmt.Fprintf(&b, "Device:     %s\n", st.DeviceID)
		fmt.Fprintf(&b, "Secrets:    %d\n", *st.SecretCount)
	}
	if !st.Unlocked {
		fmt.Fprintln(&b, "Next:       run `hort unlock` to use secrets")
	}
	return b.String()
}
