package cli

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/gefuege/hort/internal/store"
	"golang.org/x/term"
)

// AgentLine builds the sentence a user can paste to an agent after storing a
// secret. It never contains the value — the agent retrieves it via hort.
func AgentLine(name, field, env, context string) string {
	scope := []string{}
	retrieve := "hort get " + shellWord(name)
	if field != "" {
		scope = append(scope, "Field: "+field)
		retrieve += " " + shellWord(field)
	}
	if env != "" {
		scope = append(scope, "Env: "+env)
		retrieve += " --env " + shellWord(env)
	}
	if context != "" {
		scope = append(scope, "Context: "+context)
		retrieve += " --context " + shellWord(context)
	}
	where := ""
	if len(scope) > 0 {
		where = " (" + strings.Join(scope, ", ") + ")"
	}
	return fmt.Sprintf("Ich habe das Secret `%s`%s im Hort gespeichert. Abruf: `%s`", name, where, retrieve)
}

// shellWord quotes s for a POSIX shell unless it is plainly safe. A leading =
// is quoted too, since zsh expands it as a command path.
func shellWord(s string) string {
	if strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/@%+=,") == "" && s != "" && s[0] != '=' {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// announceStored prints the paste-ready agent line and, on an interactive
// terminal, offers Enter to finish or c to copy the line to the clipboard.
func announceStored(name, field, env, context string) {
	line := AgentLine(name, field, env, context)
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

// FilterEntries keeps entries whose name, description, fields, environments
// or contexts contain every whitespace-separated term (case-insensitive).
func FilterEntries(entries []store.EntryInfo, query string) []store.EntryInfo {
	terms := strings.Fields(strings.ToLower(query))
	var out []store.EntryInfo
	for _, e := range entries {
		words := append([]string{e.Name, e.Description}, e.Fields...)
		for _, v := range e.Variants {
			words = append(words, v.Env, v.Context)
		}
		hay := strings.ToLower(strings.Join(words, " "))
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

// CmdSearch lists entries matching the terms.
func CmdSearch(terms []string, jsonOutput bool) error {
	entries, err := readStore().List()
	if err != nil {
		return err
	}
	fmt.Print(FormatList(FilterEntries(entries, strings.Join(terms, " ")), jsonOutput))
	return nil
}
