package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewerThan(t *testing.T) {
	for _, c := range []struct {
		latest, own string
		want        bool
	}{
		{"1.3.0", "1.2.0", true},
		{"1.2.0", "1.2.0", false},
		{"1.1.0", "1.2.0", false},
		{"1.10.0", "1.9.0", true},
		{"1.9.0", "1.10.0", false},
		{"1.3.0", "dev", false},
		{"1.3.0", "", false},
		{"garbage", "1.2.0", false},
		{"1.3.0", "1.2", false},
		{"v1.3.0", "1.2.0", true},
	} {
		if got := newerThan(c.latest, c.own); got != c.want {
			t.Errorf("newerThan(%q, %q) = %v, want %v", c.latest, c.own, got, c.want)
		}
	}
}

func TestWriteUpdateHint(t *testing.T) {
	var out bytes.Buffer
	writeUpdateHint(&out, true, "1.2.0", "1.3.0")
	if out.String() != "Hort 1.3.0 is available. Run: hort update\n" {
		t.Errorf("hint = %q", out.String())
	}
	for name, c := range map[string]struct {
		term        bool
		own, latest string
	}{
		"not a terminal": {false, "1.2.0", "1.3.0"},
		"not newer":      {true, "1.3.0", "1.3.0"},
		"dev build":      {true, "dev", "1.3.0"},
		"no header":      {true, "1.2.0", ""},
	} {
		out.Reset()
		writeUpdateHint(&out, c.term, c.own, c.latest)
		if out.Len() != 0 {
			t.Errorf("%s: printed %q", name, out.String())
		}
	}
}

func TestPlanUpdate(t *testing.T) {
	for _, c := range []struct {
		name, exe, goos string
		argv            string
		say             string
		unknown         bool
	}{
		{"homebrew", "/opt/homebrew/Cellar/hort/1.2.0/bin/hort", "darwin", brewCommand, brewCommand, false},
		{"npm", "/usr/lib/node_modules/@s16e/hort/bin/hort", "linux", npmCommand, npmCommand, false},
		{"scoop on windows", `C:\Users\a\scoop\apps\hort\1.2.0\hort.exe`, "windows", "", scoopCommand, false},
		{"npm on windows", `C:\Users\a\AppData\Roaming\npm\node_modules\@s16e\hort\bin\hort.exe`, "windows", "", npmCommand, false},
		{"unknown", "/usr/local/bin/hort", "linux", "", releasesURL, true},
		{"unknown on windows", `C:\tools\hort.exe`, "windows", "", releasesURL, true},
	} {
		p := planUpdate(c.exe, c.goos)
		if strings.Join(p.argv, " ") != c.argv || p.say != c.say || p.unknown != c.unknown {
			t.Errorf("%s: plan = %+v", c.name, p)
		}
	}
}

func TestRunUpdate(t *testing.T) {
	var ran [][]string
	run := func(code int) func([]string) (int, error) {
		return func(argv []string) (int, error) { ran = append(ran, argv); return code, nil }
	}
	var out bytes.Buffer

	if code := runUpdate(&out, "/opt/homebrew/Cellar/hort/1.2.0/bin/hort", "darwin", run(7)); code != 7 {
		t.Errorf("exit code = %d, want the command's 7", code)
	}
	if len(ran) != 1 || strings.Join(ran[0], " ") != brewCommand || !strings.Contains(out.String(), "Running: "+brewCommand) {
		t.Errorf("ran %v, output %q", ran, out.String())
	}

	ran = nil
	for _, exe := range []string{`C:\Users\a\scoop\apps\hort\1.2.0\hort.exe`, `C:\x\node_modules\@s16e\hort\bin\hort.exe`, `C:\tools\hort.exe`} {
		runUpdate(&out, exe, "windows", run(0))
	}
	runUpdate(&out, "/usr/local/bin/hort", "linux", run(0))
	if len(ran) != 0 {
		t.Errorf("ran %v where nothing should run", ran)
	}
}
