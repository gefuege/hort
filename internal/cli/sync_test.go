package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/s16e/hort/internal/vault"
)

func TestLimitSyncStopsWaitingForHangingFolder(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	started := time.Now()
	_, err := limitSync(10*time.Millisecond, func() (vault.SyncResult, error) {
		<-release
		return vault.SyncResult{}, nil
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
	got, err := limitSync(time.Minute, func() (vault.SyncResult, error) {
		return vault.SyncResult{NewRevisions: 3}, want
	})
	if got.NewRevisions != 3 || !errors.Is(err, want) {
		t.Fatalf("got %+v, %v", got, err)
	}
}
