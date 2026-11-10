package vault

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Entry persists only revisions. Current values are reduced on demand.
type Entry struct {
	Revisions []Revision `json:"revisions"`
}
type Revision struct {
	ID         string     `json:"id"`
	RecordedAt *time.Time `json:"recorded_at"`
	Op         string     `json:"op"`
	Field      string     `json:"field,omitempty"` // "" is the default field; omitted so v3 files stay byte-compatible
	Key        LookupKey  `json:"key"`
	Value      string     `json:"value"`
}

func newID() (string, error) {
	var id [16]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return "", fmt.Errorf("generating revision identity: %w", err)
	}
	return hex.EncodeToString(id[:]), nil
}

func NewRevision(op, key, value string) (Revision, error) {
	id, err := newID()
	if err != nil {
		return Revision{}, err
	}
	now := time.Now().UTC()
	return Revision{ID: id, RecordedAt: &now, Op: op, Key: key, Value: value}, nil
}

// Append stamps r behind every revision the entry already knows, so a local
// change is never outranked by a pulled revision from a clock running ahead.
func (e *Entry) Append(r Revision) {
	e.appendAt(r, time.Now().UTC())
}

func (e *Entry) appendAt(r Revision, at time.Time) {
	for _, known := range e.Revisions {
		if known.RecordedAt != nil && !known.RecordedAt.Before(at) {
			at = known.RecordedAt.UTC().Add(time.Nanosecond)
		}
	}
	r.RecordedAt = &at
	e.Revisions = append(e.Revisions, r)
}

// History orders unknown import times first, then UTC time and identity.
func (e Entry) History() []Revision {
	out := append([]Revision(nil), e.Revisions...)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RecordedAt == nil && b.RecordedAt != nil {
			return true
		}
		if a.RecordedAt != nil && b.RecordedAt == nil {
			return false
		}
		if a.RecordedAt != nil && !a.RecordedAt.Equal(*b.RecordedAt) {
			return a.RecordedAt.Before(*b.RecordedAt)
		}
		return a.ID < b.ID
	})
	return out
}

// FoldKey is the identity of a secret name, field, env or context: names
// that differ only in letter case are the same key. It lowercases per code
// point, with U+0130 becoming "i" followed by U+0307 (spec/vectors/fold.json).
func FoldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == 'İ' {
			b.WriteString("i\u0307")
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// ValueKey addresses one value of an entry: a field and its lookup key.
type ValueKey struct {
	Field string
	Key   LookupKey
}

// spellings returns how the entry spells a value key: field, env and context
// each take the spelling of the earliest set or delete in history order whose
// part folds alike; a part the entry does not hold keeps its own spelling.
// Spelling never changes identity, since a spelled part folds like the original.
func spellings(history []Revision) func(ValueKey) ValueKey {
	parts := [3]map[string]string{{}, {}, {}}
	spell := func(k ValueKey, learn bool) ValueKey {
		env, context, colon := strings.Cut(k.Key, ":")
		p := [3]string{k.Field, env, context}
		for i := range p {
			if s, ok := parts[i][FoldKey(p[i])]; ok {
				p[i] = s
			} else if learn {
				parts[i][FoldKey(p[i])] = p[i]
			}
		}
		if !colon {
			return ValueKey{p[0], p[1]}
		}
		return ValueKey{p[0], p[1] + ":" + p[2]}
	}
	for _, r := range history {
		if r.Op == "set" || r.Op == "delete" {
			spell(ValueKey{r.Field, r.Key}, true)
		}
	}
	return func(k ValueKey) ValueKey { return spell(k, false) }
}

// Spelling returns k as the entry spells it (see spellings). Writes carry
// this spelling, and Current keys its values by it.
func (e Entry) Spelling(k ValueKey) ValueKey { return spellings(e.History())(k) }

// Current is an ephemeral projection, never a second persisted state. Values
// whose field and lookup key differ only in case are one value, keyed by
// their spelling (see spellings).
func (e Entry) Current() (values map[ValueKey]string, description string, visible bool) {
	values = make(map[ValueKey]string)
	deleted := false
	history := e.History()
	spell := spellings(history)
	for _, r := range history {
		k := spell(ValueKey{r.Field, r.Key})
		switch r.Op {
		case "set":
			values[k] = r.Value
			visible = true
			deleted = false
		case "delete":
			delete(values, k)
		case "delete-entry":
			clear(values)
			description = ""
			visible = false
			deleted = true
		case "describe":
			description = r.Value
			if !deleted {
				visible = true
			}
		}
	}
	return
}

// Resolve reads one field for env and context, falling back to env:* and *:*
// within that field only (§3.3). Field, env and context compare by FoldKey.
func (e Entry) Resolve(field, env, context string) (string, bool) {
	values, _, _ := e.Current()
	for _, key := range []LookupKey{MakeLookupKey(env, context), MakeLookupKey(env, "*"), MakeLookupKey("*", "*")} {
		if value, ok := values[e.Spelling(ValueKey{field, key})]; ok {
			return value, true
		}
	}
	return "", false
}

func validID(id string) bool { return lowerHex(id, 16) }

// ValidKnownID accepts an ID of GET /devices as known_devices and
// known_revoked store it: a device (16 bytes) or a passkey (32 bytes), in
// lowercase hex.
func ValidKnownID(id string) bool { return lowerHex(id, 16) || lowerHex(id, 32) }

func lowerHex(id string, size int) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == size && id == hex.EncodeToString(b)
}

// fieldPattern is the field rule of §3.4; "" is the default field.
var fieldPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// validateSecrets applies the decoding rules of §3.4 to every entry. v3
// revisions carry no field.
func validateSecrets(secrets map[string]Entry, fields bool) error {
	if secrets == nil {
		return fmt.Errorf("missing secrets")
	}
	ids := make(map[string]bool)
	for name, e := range secrets {
		if name == "" {
			return fmt.Errorf("empty entry name")
		}
		if e.Revisions == nil {
			return fmt.Errorf("missing revisions for %q", name)
		}
		for _, r := range e.Revisions {
			if !validID(r.ID) || ids[r.ID] {
				return fmt.Errorf("invalid or duplicate revision identity for %q", name)
			}
			ids[r.ID] = true
			if r.Field != "" && (!fields || !fieldPattern.MatchString(r.Field)) {
				return fmt.Errorf("invalid field for %q", name)
			}
			if r.RecordedAt != nil {
				_, offset := r.RecordedAt.Zone()
				if offset != 0 {
					return fmt.Errorf("revision time must be UTC for %q", name)
				}
			}
			switch r.Op {
			case "set":
			case "delete":
				if r.Value != "" {
					return fmt.Errorf("invalid delete for %q", name)
				}
			case "delete-entry":
				if r.Key != "" || r.Value != "" {
					return fmt.Errorf("invalid entry deletion for %q", name)
				}
			case "describe":
				if r.Key != "" {
					return fmt.Errorf("invalid description for %q", name)
				}
			default:
				return fmt.Errorf("unknown revision operation for %q", name)
			}
		}
	}
	return nil
}
