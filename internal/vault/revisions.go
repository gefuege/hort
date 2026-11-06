package vault

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
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

// ValueKey addresses one value of an entry: a field and its lookup key.
type ValueKey struct {
	Field string
	Key   LookupKey
}

// Current is an ephemeral projection, never a second persisted state.
func (e Entry) Current() (values map[ValueKey]string, description string, visible bool) {
	values = make(map[ValueKey]string)
	deleted := false
	for _, r := range e.History() {
		switch r.Op {
		case "set":
			values[ValueKey{r.Field, r.Key}] = r.Value
			visible = true
			deleted = false
		case "delete":
			delete(values, ValueKey{r.Field, r.Key})
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
// within that field only (§3.3).
func (e Entry) Resolve(field, env, context string) (string, bool) {
	values, _, _ := e.Current()
	for _, key := range []LookupKey{MakeLookupKey(env, context), MakeLookupKey(env, "*"), MakeLookupKey("*", "*")} {
		if value, ok := values[ValueKey{field, key}]; ok {
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
