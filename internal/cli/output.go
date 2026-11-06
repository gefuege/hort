package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gefuege/hort/internal/store"
)

// scopes returns the sorted distinct environments and contexts of the variants.
func scopes(e store.EntryInfo) (envs, contexts []string) {
	seenEnv, seenCtx := map[string]bool{}, map[string]bool{}
	for _, v := range e.Variants {
		if !seenEnv[v.Env] {
			seenEnv[v.Env] = true
			envs = append(envs, v.Env)
		}
		if v.Context != "*" && !seenCtx[v.Context] {
			seenCtx[v.Context] = true
			contexts = append(contexts, v.Context)
		}
	}
	sort.Strings(envs)
	sort.Strings(contexts)
	return envs, contexts
}

// FormatList formats entry list for human or JSON output.
func FormatList(entries []store.EntryInfo, jsonOutput bool) string {
	if jsonOutput {
		if entries == nil {
			entries = []store.EntryInfo{}
		}
		data, _ := json.MarshalIndent(entries, "", "  ")
		return string(data) + "\n"
	}

	if len(entries) == 0 {
		return "No entries found.\n"
	}

	var b strings.Builder
	for _, e := range entries {
		envs, contexts := scopes(e)
		desc := e.Description
		if desc == "" {
			desc = "(no description)"
		}

		line := fmt.Sprintf("%-30s %s  [env: %s]", e.Name, desc, strings.Join(envs, ", "))
		if len(contexts) > 0 {
			line += fmt.Sprintf("  [ctx: %s]", strings.Join(contexts, ", "))
		}
		if len(e.Fields) > 0 {
			line += fmt.Sprintf("  [fields: %s]", strings.Join(e.Fields, ", "))
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// FormatDescribe formats entry details for human or JSON output.
func FormatDescribe(entry store.EntryInfo, jsonOutput bool) string {
	if jsonOutput {
		data, _ := json.MarshalIndent(entry, "", "  ")
		return string(data) + "\n"
	}

	envs, contexts := scopes(entry)
	var b strings.Builder
	fmt.Fprintf(&b, "Name:         %s\n", entry.Name)
	fmt.Fprintf(&b, "Description:  %s\n", entry.Description)
	if len(entry.Fields) > 0 {
		fmt.Fprintf(&b, "Fields:       %s\n", strings.Join(entry.Fields, ", "))
	}
	fmt.Fprintf(&b, "Environments: %s\n", strings.Join(envs, ", "))
	if len(contexts) > 0 {
		fmt.Fprintf(&b, "Contexts:     %s\n", strings.Join(contexts, ", "))
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
