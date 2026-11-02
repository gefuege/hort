package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/s16e/hort/internal/store"
	"golang.org/x/term"
)

// AgentLine builds the sentence a user can paste to an agent after storing an
// entry. It never contains the value — the agent retrieves it via hort.
func AgentLine(kind, name, env, context, source string) string {
	scope := []string{}
	retrieve := fmt.Sprintf("hort --%s %s", kind, name)
	if context != "" {
		scope = append(scope, "Context: "+context)
		retrieve += " --context " + context
	}
	if env != "" {
		scope = append(scope, "Env: "+env)
		retrieve += " --env " + env
	}
	if source != "" {
		scope = append(scope, "Source: "+source)
		retrieve += " --source " + source
	}
	where := ""
	if len(scope) > 0 {
		where = " (" + strings.Join(scope, ", ") + ")"
	}
	return fmt.Sprintf("Ich habe das %s `%s`%s im Hort gespeichert. Abruf: `%s`", strings.ToUpper(kind[:1])+kind[1:], name, where, retrieve)
}

// announceStored prints the paste-ready agent line and, on an interactive
// terminal, offers Enter to finish or c to copy the line to the clipboard.
func announceStored(kind, name, env, context, source string) {
	line := AgentLine(kind, name, env, context, source)
	fmt.Fprintln(os.Stderr, line)

	in := int(os.Stdin.Fd())
	if !term.IsTerminal(in) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return
	}
	fmt.Fprint(os.Stderr, "[Enter] fertig · [c] kopieren ")
	state, err := term.MakeRaw(in)
	if err != nil {
		fmt.Fprintln(os.Stderr)
		return
	}
	buf := make([]byte, 1)
	_, _ = os.Stdin.Read(buf)
	_ = term.Restore(in, state)
	fmt.Fprint(os.Stderr, "\r\n")
	if buf[0] != 'c' && buf[0] != 'C' {
		return
	}
	if err := copyToClipboard(line); err != nil {
		fmt.Fprintln(os.Stderr, "Kopieren fehlgeschlagen:", err)
		return
	}
	fmt.Fprintln(os.Stderr, "In die Zwischenablage kopiert.")
}

func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "windows":
		cmd = exec.Command("clip")
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd = exec.Command("wl-copy")
		} else {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		}
	}
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// FilterEntries keeps entries whose name, description, type, environments,
// contexts or source contain every whitespace-separated term (case-insensitive).
func FilterEntries(entries []store.EntryInfo, query string) []store.EntryInfo {
	terms := strings.Fields(strings.ToLower(query))
	var out []store.EntryInfo
	for _, e := range entries {
		hay := strings.ToLower(strings.Join([]string{
			e.Name, e.Description, e.Type, e.Source,
			strings.Join(e.Environments, " "), strings.Join(e.Contexts, " "),
		}, " "))
		match := true
		for _, t := range terms {
			if !strings.Contains(hay, t) {
				match = false
				break
			}
		}
		if match {
			out = append(out, e)
		}
	}
	return out
}

// CmdSearch lists entries matching the query.
func CmdSearch(query string, jsonOutput bool) error {
	entries, err := requireStore().List("")
	if err != nil {
		return err
	}
	fmt.Print(FormatList(FilterEntries(entries, query), jsonOutput))
	return nil
}
