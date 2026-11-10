package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/gefuege/hort/internal/api"
	"golang.org/x/term"
)

const releasesURL = "https://github.com/gefuege/hort/releases/latest"

// parseVersion reads "1.2.3" or "v1.2.3"; anything else is not a release.
func parseVersion(s string) ([3]int, bool) {
	var v [3]int
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p != strconv.Itoa(n) {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

// newerThan reports whether latest is a release after own; false if either
// is not a plain release version (a `dev` build never gets the hint).
func newerThan(latest, own string) bool {
	l, ok := parseVersion(latest)
	if !ok {
		return false
	}
	o, ok := parseVersion(own)
	if !ok {
		return false
	}
	for i := range l {
		if l[i] != o[i] {
			return l[i] > o[i]
		}
	}
	return false
}

// writeUpdateHint prints the one-line hint when stderr is a terminal and the
// server's release is newer than the binary's own.
func writeUpdateHint(w io.Writer, isTerminal bool, own, latest string) {
	if isTerminal && newerThan(latest, own) {
		fmt.Fprintf(w, "Hort %s is available. Run: hort update\n", latest)
	}
}

// PrintUpdateHint prints the update hint on stderr for the release a server
// answer of this command stated; it prints nothing if none did.
func PrintUpdateHint(own string) {
	writeUpdateHint(os.Stderr, term.IsTerminal(int(os.Stderr.Fd())), own, api.Latest())
}

const (
	brewCommand  = "brew upgrade --formula sebastian-breitzke/tap/hort"
	npmCommand   = "npm install -g @s16e/hort@latest"
	scoopCommand = "scoop update hort"
)

// updatePlan says what `hort update` does for a binary at exe on goos: argv
// is the command to run (nil to only print), say what is printed, and
// unknown that the install was not recognized.
type updatePlan struct {
	argv    []string
	say     string
	unknown bool
}

func planUpdate(exe, goos string) updatePlan {
	path := strings.ToLower(strings.ReplaceAll(exe, `\`, "/"))
	windows := goos == "windows"
	switch {
	case strings.Contains(path, "node_modules/@s16e/hort/"):
		if windows {
			return updatePlan{say: npmCommand}
		}
		return updatePlan{argv: strings.Fields(npmCommand), say: npmCommand}
	case windows && strings.Contains(path, "/scoop/apps/hort/"):
		return updatePlan{say: scoopCommand}
	case !windows && strings.Contains(path, "/cellar/hort/"):
		return updatePlan{argv: strings.Fields(brewCommand), say: brewCommand}
	}
	return updatePlan{say: releasesURL, unknown: true}
}

// runInTerminal runs argv attached to the terminal and returns its exit code.
func runInTerminal(argv []string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 0, err
}

// runUpdate prints the plan and runs it; it returns the exit code to end with.
func runUpdate(w io.Writer, exe, goos string, run func([]string) (int, error)) int {
	plan := planUpdate(exe, goos)
	if plan.unknown {
		fmt.Fprintln(w, "Could not tell which package manager installed this Hort. Download the latest release:")
		fmt.Fprintln(w, plan.say)
		return 0
	}
	if plan.argv == nil {
		fmt.Fprintf(w, "A running Hort cannot be replaced on Windows. Run: %s\n", plan.say)
		return 0
	}
	fmt.Fprintf(w, "Running: %s\n", plan.say)
	code, err := run(plan.argv)
	if err != nil {
		fmt.Fprintf(w, "update: %v\n", err)
		return 1
	}
	return code
}

// CmdUpdate updates Hort through the package manager that installed it and
// returns the command's exit code. It needs no vault and no server.
func CmdUpdate() int {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: finding this binary: %v\n", err)
		return 1
	}
	return runUpdate(os.Stderr, exe, runtime.GOOS, runInTerminal)
}
