package vault

import (
	"strings"
	"testing"
)

func setRev(field, key, value string) Revision {
	return Revision{Op: "set", Field: field, Key: key, Value: value}
}

func TestValidateWriteRules(t *testing.T) {
	long := strings.Repeat("a", MaxNameBytes)
	for _, test := range []struct {
		label string
		name  string
		rev   Revision
		ok    bool
	}{
		{"plain", "token", setRev("", "*:*", "v"), true},
		{"name at limit", long, setRev("", "*:*", "v"), true},
		{"name too long", long + "a", setRev("", "*:*", "v"), false},
		{"empty name", "", setRev("", "*:*", "v"), false},
		{"name with space", "my token", setRev("", "*:*", "v"), false},
		{"name with tab", "my\ttoken", setRev("", "*:*", "v"), false},
		{"name with newline", "my\ntoken", setRev("", "*:*", "v"), false},
		{"name with NUL", "my\x00token", setRev("", "*:*", "v"), false},
		{"name with unicode space", "my token", setRev("", "*:*", "v"), false},
		{"leading dash", "-token", setRev("", "*:*", "v"), false},
		{"inner dash", "my-token", setRev("", "*:*", "v"), true},
		{"unicode name", "ä", setRev("", "*:*", "v"), true},
		{"invalid UTF-8 name", "a\xffb", setRev("", "*:*", "v"), false},
		{"field", "t", setRev("password", "*:*", "v"), true},
		{"field with dots", "t", setRev("a.b_c-d", "*:*", "v"), true},
		{"field uppercase", "t", setRev("Password", "*:*", "v"), false},
		{"field leading dot", "t", setRev(".x", "*:*", "v"), false},
		{"field leading dash", "t", setRev("-x", "*:*", "v"), false},
		{"field 64", "t", setRev(strings.Repeat("a", 64), "*:*", "v"), true},
		{"field 65", "t", setRev(strings.Repeat("a", 65), "*:*", "v"), false},
		{"env and context", "t", setRev("", "prod:heine", "v"), true},
		{"env with colon", "t", setRev("", "a:b:c", "v"), false},
		{"context with colon", "t", setRev("", "prod:he:ine", "v"), false},
		{"env with space", "t", setRev("", "pr od:*", "v"), false},
		{"context with space", "t", setRev("", "prod:he ine", "v"), false},
		{"context with control", "t", setRev("", "prod:he\x01ine", "v"), false},
		{"star inside env", "t", setRev("", "pr*:*", "v"), false},
		{"star inside context", "t", setRev("", "prod:he*", "v"), false},
		{"star as whole parts", "t", setRev("", "*:heine", "v"), true},
		{"key without colon", "t", setRev("", "prod", "v"), false},
		{"value at limit", "t", setRev("", "*:*", strings.Repeat("a", MaxValueBytes)), true},
		{"value over limit", "t", setRev("", "*:*", strings.Repeat("a", MaxValueBytes+1)), false},
		{"value invalid UTF-8", "t", setRev("", "*:*", "a\xffb"), false},
		{"describe", "t", Revision{Op: "describe", Value: "d"}, true},
		{"describe with field", "t", Revision{Op: "describe", Field: "x", Value: "d"}, false},
		{"describe bad name", "t t", Revision{Op: "describe", Value: "d"}, false},
		{"delete-entry", "t t", Revision{Op: "delete-entry"}, true},
		{"delete-entry with field", "t", Revision{Op: "delete-entry", Field: "x"}, false},
		{"delete legacy name and key", "t t", Revision{Op: "delete", Key: "a:b:c"}, true},
		{"delete field", "t", Revision{Op: "delete", Field: "pass", Key: "*:*"}, true},
		{"delete bad field", "t", Revision{Op: "delete", Field: "Pass", Key: "*:*"}, false},
		{"unknown op", "t", Revision{Op: "x"}, false},
	} {
		if err := ValidateWrite(test.name, test.rev); (err == nil) != test.ok {
			t.Errorf("%s: err = %v, want ok = %t", test.label, err, test.ok)
		}
	}
}

func TestEnvelopePlaintextLimit(t *testing.T) {
	name := strings.Repeat("n", MaxNameBytes)
	rev := setRev("", "*:*", "")
	base, err := EnvelopePlaintext(name, rev)
	if err != nil {
		t.Fatal(err)
	}
	// A newline encodes as two bytes, so escaping alone can break the 64 KiB
	// envelope although the value is far below 48 KiB.
	fit := (MaxEnvelopeBytes - envelopeOverhead - len(base)) / 2
	if fit >= MaxValueBytes {
		t.Fatalf("test needs escaping to dominate: %d", fit)
	}
	rev.Value = strings.Repeat("\n", fit)
	if err := ValidateWrite(name, rev); err != nil {
		t.Fatalf("value at the envelope limit refused: %v", err)
	}
	if plain, _ := EnvelopePlaintext(name, rev); len(plain)+envelopeOverhead > MaxEnvelopeBytes {
		t.Fatalf("envelope %d over limit", len(plain)+envelopeOverhead)
	}
	rev.Value += "\n"
	if err := ValidateWrite(name, rev); err == nil || !strings.Contains(err.Error(), "encoded revision") {
		t.Fatalf("value over the envelope limit accepted: %v", err)
	}
}
