package vault

import (
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func revisionAt(n int, at *time.Time, op, key, value string) Revision {
	return Revision{ID: fmt.Sprintf("%032x", n), RecordedAt: at, Op: op, Key: key, Value: value}
}
func TestRevisionReductionIsArrivalIndependent(t *testing.T) {
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	later := first.Add(time.Hour)
	revisions := []Revision{
		revisionAt(1, nil, "set", "*:*", "imported"),
		revisionAt(2, &first, "set", "*:*", "first"),
		revisionAt(3, &first, "set", "*:*", "tie-winner"),
		revisionAt(4, &later, "delete", "*:*", ""),
	}
	for _, order := range [][]int{{0, 1, 2, 3}, {3, 2, 0, 1}, {2, 1, 3, 0}} {
		e := Entry{}
		for _, i := range order {
			e.Revisions = append(e.Revisions, revisions[i])
		}
		values, _, visible := e.Current()
		if len(values) != 0 || !visible {
			t.Fatalf("delete reduction: %v %v", values, visible)
		}
		history := e.History()
		if !reflect.DeepEqual(history, revisions) {
			t.Fatal("history depends on arrival order")
		}
	}
	e := Entry{Revisions: revisions[:3]}
	values, _, _ := e.Current()
	if values[ValueKey{Key: "*:*"}] != "tie-winner" {
		t.Fatal("ID tie order failed")
	}
}
func TestWholeEntryDeleteAndRevival(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	before := start.Add(-time.Hour)
	after := start.Add(time.Hour)
	e := Entry{Revisions: []Revision{
		revisionAt(3, &start, "delete-entry", "", ""),
		revisionAt(2, &before, "set", "prod:offline", "late-arrival"),
		revisionAt(1, nil, "describe", "", "baseline"),
		revisionAt(4, &after, "describe", "", "description cannot revive"),
	}}
	values, _, visible := e.Current()
	if visible || len(values) != 0 {
		t.Fatal("deleted entry resurrected")
	}
	e.Revisions = append(e.Revisions, revisionAt(5, &after, "set", "dev:*", "revived"))
	values, desc, visible := e.Current()
	if !visible || len(values) != 1 || values[ValueKey{Key: "dev:*"}] != "revived" || desc != "description cannot revive" {
		t.Fatal("set did not revive only its scope")
	}
}

type brokenRandom struct{}

func (brokenRandom) Read([]byte) (int, error) { return 0, errors.New("synthetic RNG failure") }
func TestIdentityGenerationErrorsAreReturned(t *testing.T) {
	original := rand.Reader
	rand.Reader = brokenRandom{}
	defer func() { rand.Reader = original }()
	if _, err := NewRevision("set", "*:*", "value"); err == nil {
		t.Fatal("revision ignored RNG failure")
	}
	if _, err := NewBody("device"); err == nil {
		t.Fatal("device identity ignored RNG failure")
	}
}
