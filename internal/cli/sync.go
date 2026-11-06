package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/s16e/hort/internal/vault"
)

// syncLimit bounds the automatic run: a placeholder file or dead mount must not
// hold up a local read. Stopping is safe, all writes are atomic.
const syncLimit = 2 * time.Second

// syncIdle spares the post-write run when the run before the command already
// found no sync folder to work with, so one command warns and waits only once.
var syncIdle bool

func limitSync(limit time.Duration, run func() (vault.SyncResult, error)) (vault.SyncResult, error) {
	type outcome struct {
		result vault.SyncResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := run()
		done <- outcome{result, err}
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case o := <-done:
		return o.result, o.err
	case <-timer.C:
		return vault.SyncResult{}, fmt.Errorf("no answer within %s", limit)
	}
}

func autoSync() (vault.SyncResult, error) {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return vault.SyncResult{}, err
	}
	key, err := vault.LoadSessionFor(ref)
	if err != nil {
		return vault.SyncResult{}, err
	}
	return limitSync(syncLimit, func() (vault.SyncResult, error) {
		return vault.Sync(ref, key)
	})
}

func warnSyncFailed(err error) {
	fmt.Fprintf(os.Stderr, "warning: sync skipped, continuing locally: %v\n", err)
}

func warnSyncFiles(result vault.SyncResult) {
	for _, name := range result.Unreadable {
		fmt.Fprintf(os.Stderr, "warning: skipped sync file %s: cannot read or decrypt it\n", name)
	}
	for _, name := range result.Pending {
		fmt.Fprintf(os.Stderr, "warning: could not read sync file %s, it is probably not downloaded yet; the next run tries again\n", name)
	}
	if result.OwnPending {
		fmt.Fprintln(os.Stderr, "warning: could not read this device's sync file, it is probably not downloaded yet, so nothing was pushed; if this persists, remove it from the folder by hand")
	}
	if result.OwnUnreadable {
		fmt.Fprintln(os.Stderr, "warning: this device's sync file cannot be read or decrypted, so nothing was pushed; remove it from the sync folder by hand and the next run writes it anew")
	}
}

func syncBeforeUse() {
	result, err := autoSync()
	if err != nil {
		syncIdle = true
		if !errors.Is(err, vault.ErrSyncNotSetUp) {
			warnSyncFailed(err)
		}
		return
	}
	warnSyncFiles(result)
}

func syncAfterWrite() {
	if syncIdle {
		return
	}
	if _, err := autoSync(); err != nil {
		warnSyncFailed(err)
	}
}

func requirePrimaryKey() (vault.VaultRef, []byte) {
	ref, err := vault.PrimaryRef()
	if err == nil {
		var key []byte
		if key, err = vault.LoadSessionFor(ref); err == nil {
			return ref, key
		}
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(ExitLocked)
	return vault.VaultRef{}, nil
}

func reportSync(result vault.SyncResult) {
	warnSyncFiles(result)
	pushed := "nothing to push"
	if result.Pushed {
		pushed = "pushed"
	}
	fmt.Fprintf(os.Stderr, "Sync: %d files read, %d unreadable, %d not downloaded yet, %d new revisions, %s.\n",
		result.Read, len(result.Unreadable), len(result.Pending), result.NewRevisions, pushed)
}

// CmdSync runs one exchange without a time limit and reports it.
func CmdSync() error {
	ref, key := requirePrimaryKey()
	result, err := vault.Sync(ref, key)
	if err != nil {
		return err
	}
	reportSync(result)
	return nil
}

// CmdSyncSetup connects the primary vault to a sync folder.
func CmdSyncSetup(path string) error {
	if path == "" {
		return fmt.Errorf("--path is required")
	}
	ref, key := requirePrimaryKey()
	result, err := vault.SetupSync(ref, key, path)
	if err != nil {
		return err
	}
	reportSync(result)
	return nil
}
