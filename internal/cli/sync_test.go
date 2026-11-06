package cli

import (
	"errors"
	"testing"
	"time"
)

func TestLimitSyncStopsWaitingForHangingRun(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	started := time.Now()
	_, err := limitSync(10*time.Millisecond, func() (int, error) {
		<-release
		return 0, nil
	})
	if err == nil {
		t.Fatal("expected a limit error")
	}
	if time.Since(started) > time.Second {
		t.Fatal("waited for the hanging run")
	}
}

func TestLimitSyncPassesResultThrough(t *testing.T) {
	want := errors.New("synthetic")
	got, err := limitSync(time.Minute, func() (int, error) {
		return 3, want
	})
	if got != 3 || !errors.Is(err, want) {
		t.Fatalf("got %+v, %v", got, err)
	}
}
