package vault

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Write limits of contract §3.4 and §6.6.
const (
	MaxNameBytes     = 128
	MaxValueBytes    = 48 << 10
	MaxEnvelopeBytes = 64 << 10
	// envelopeOverhead is the AES-GCM nonce (12) plus tag (16) around the plaintext (§6.4).
	envelopeOverhead = 12 + 16
)

// legacyHint is appended to a write error when the entry already exists: old
// data stays readable and deletable, but is never written under old rules.
const legacyHint = "this secret predates the current rules; delete it and create it again under a valid name"

func checkText(label, s string) error {
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain whitespace or control characters", label)
		}
	}
	return nil
}

// ValidateName applies the name rule for new writes.
func ValidateName(name string) error {
	switch {
	case name == "" || len(name) > MaxNameBytes:
		return fmt.Errorf("name must be 1-%d bytes", MaxNameBytes)
	case !utf8.ValidString(name):
		return fmt.Errorf("name must be valid UTF-8")
	case strings.HasPrefix(name, "-"):
		return fmt.Errorf("name must not start with -")
	}
	return checkText("name", name)
}

// ValidateField applies the field rule; "" is the default field.
func ValidateField(field string) error {
	if field != "" && !fieldPattern.MatchString(field) {
		return fmt.Errorf("field %q must match %s", field, fieldPattern)
	}
	return nil
}

// validateScopePart checks one env or context part; "*" is valid only as the whole part.
func validateScopePart(label, part string) error {
	if part == "*" {
		return nil
	}
	if !utf8.ValidString(part) {
		return fmt.Errorf("%s must be valid UTF-8", label)
	}
	if strings.ContainsAny(part, ":*") {
		return fmt.Errorf("%s must not contain : or *", label)
	}
	return checkText(label, part)
}

// ValidateKey applies the env and context rules to one lookup key.
func ValidateKey(key LookupKey) error {
	if strings.Count(key, ":") != 1 {
		return fmt.Errorf("env and context must not contain :")
	}
	env, context := ParseLookupKey(key)
	if err := validateScopePart("env", env); err != nil {
		return err
	}
	return validateScopePart("context", context)
}

// EnvelopePlaintext is the plaintext {"name","revision"} of a revision
// envelope (§6.4) and the size basis of the write limit. recorded_at is
// encoded in its longest form, so the size does not depend on the stamp.
func EnvelopePlaintext(name string, r Revision) ([]byte, error) {
	longest := time.Date(2000, 1, 1, 0, 0, 0, 123456789, time.UTC)
	r.RecordedAt = &longest
	return marshalEnvelope(name, r)
}

func validateSize(name string, r Revision) error {
	if len(r.Value) > MaxValueBytes {
		return fmt.Errorf("value is %d bytes; the limit is %d", len(r.Value), MaxValueBytes)
	}
	if !utf8.ValidString(r.Value) {
		return fmt.Errorf("value must be valid UTF-8")
	}
	plain, err := EnvelopePlaintext(name, r)
	if err != nil {
		return err
	}
	if limit := MaxEnvelopeBytes - envelopeOverhead; len(plain) > limit {
		return fmt.Errorf("encoded revision is %d bytes; the limit is %d", len(plain), limit)
	}
	return nil
}

// ValidateWrite applies the stricter rules of §3.4 to a new revision. Names
// and keys of delete and delete-entry are not checked, so legacy data can
// always be removed.
func ValidateWrite(name string, r Revision) error {
	switch r.Op {
	case "set":
		for _, err := range []error{ValidateName(name), ValidateField(r.Field), ValidateKey(r.Key)} {
			if err != nil {
				return err
			}
		}
		return validateSize(name, r)
	case "describe":
		if r.Field != "" {
			return fmt.Errorf("a description applies to the whole entry, not to a field")
		}
		if err := ValidateName(name); err != nil {
			return err
		}
		return validateSize(name, r)
	case "delete":
		return ValidateField(r.Field)
	case "delete-entry":
		if r.Field != "" {
			return fmt.Errorf("deleting an entry takes no field")
		}
		return nil
	}
	return fmt.Errorf("unknown revision operation %q", r.Op)
}

// WithLegacyHint explains a failed write to an entry that already exists.
func WithLegacyHint(err error) error { return fmt.Errorf("%w; %s", err, legacyHint) }
