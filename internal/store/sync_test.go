package store

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s16e/hort/internal/vault"
)

var (
	at15 = time.Date(2026, 11, 5, 15, 0, 0, 0, time.UTC)
	at16 = time.Date(2026, 11, 5, 16, 0, 0, 0, time.UTC)
)

// device is one isolated HOME with its own view of the sync folder. Delivery
// between devices happens only through deliver, so tests control arrival order.
type device struct {
	t            *testing.T
	home, folder string
	key          []byte
}

func (d *device) ref() vault.VaultRef {
	d.t.Helper()
	setHomeDir(d.t, d.home)
	ref, err := vault.PrimaryRef()
	if err != nil {
		d.t.Fatal(err)
	}
	return ref
}

func (d *device) store() *Store {
	d.t.Helper()
	d.ref()
	s, err := NewFromSession()
	if err != nil {
		d.t.Fatal(err)
	}
	return s
}

func (d *device) sync() vault.SyncResult {
	d.t.Helper()
	result, err := vault.Sync(d.ref(), d.key)
	if err != nil {
		d.t.Fatalf("sync: %v", err)
	}
	return result
}

// record appends a revision with a chosen time, as an offline device would have.
func (d *device) record(name, op, key, value string, at time.Time) vault.Revision {
	d.t.Helper()
	r, err := vault.NewRevision(op, key, value)
	if err != nil {
		d.t.Fatal(err)
	}
	r.RecordedAt = &at
	err = vault.UpdateVault(d.ref(), d.key, func(data *vault.VaultData) error {
		entry := data.Secrets[name]
		entry.Revisions = append(entry.Revisions, r)
		data.Secrets[name] = entry
		return nil
	})
	if err != nil {
		d.t.Fatal(err)
	}
	return r
}

func (d *device) get(name, env, context string) (string, bool) {
	d.t.Helper()
	value, err := d.store().GetFrom("", name, env, context)
	return value, err == nil
}

func (d *device) wantValue(name, want string) {
	d.t.Helper()
	if got, ok := d.get(name, "", ""); !ok || got != want {
		d.t.Fatalf("%s: got %q (found %v), want %q", name, got, ok, want)
	}
}

func (d *device) wantGone(name string) {
	d.t.Helper()
	if got, ok := d.get(name, "", ""); ok {
		d.t.Fatalf("%s: still visible as %q", name, got)
	}
}

func (d *device) wantHistory(name string, values ...string) {
	d.t.Helper()
	history, err := d.store().History("", name)
	if err != nil {
		d.t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range history.Revisions {
		seen[r.Value] = true
	}
	for _, value := range values {
		if !seen[value] {
			d.t.Fatalf("%s: history lacks %q", name, value)
		}
	}
}

func folderFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		files[filepath.Base(path)] = raw
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func deliver(t *testing.T, from, to *device) {
	t.Helper()
	for name, raw := range folderFiles(t, from.folder) {
		if err := os.WriteFile(filepath.Join(to.folder, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// exchange lets first deliver before second, then closes the loop.
func exchange(t *testing.T, first, second *device) {
	t.Helper()
	first.sync()
	deliver(t, first, second)
	second.sync()
	deliver(t, second, first)
	first.sync()
}

func ownFile(t *testing.T, d *device) string {
	t.Helper()
	d.ref()
	reg, err := vault.LoadSourceRegistry()
	if err != nil {
		t.Fatal(err)
	}
	return reg.SyncFile
}

// twoDevices joins B by copying A's vault file, the documented way in.
func twoDevices(t *testing.T) (*device, *device) {
	t.Helper()
	a := &device{t: t, home: t.TempDir(), folder: t.TempDir()}
	b := &device{t: t, home: t.TempDir(), folder: t.TempDir()}
	ref := a.ref()
	key, err := vault.CreatePrimaryVault([]byte("synthetic-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveSessionFor(ref, key); err != nil {
		t.Fatal(err)
	}
	a.key, b.key = key, key
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		t.Fatal(err)
	}
	refB := b.ref()
	if err := os.MkdirAll(filepath.Dir(refB.Path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refB.Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveSessionFor(refB, key); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*device{a, b} {
		if _, err := vault.SetupSync(d.ref(), key, d.folder); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

// bothOrders runs a scenario with each device delivering first.
func bothOrders(t *testing.T, scenario func(t *testing.T, a, b *device, first, second func() *device)) {
	for _, aFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("a first %v", aFirst), func(t *testing.T) {
			a, b := twoDevices(t)
			first, second := func() *device { return a }, func() *device { return b }
			if !aFirst {
				first, second = second, first
			}
			scenario(t, a, b, first, second)
		})
	}
}

func TestSyncLaterTimeWinsInBothArrivalOrders(t *testing.T) {
	bothOrders(t, func(t *testing.T, a, b *device, first, second func() *device) {
		a.record("token", "set", "*:*", "value-15h", at15)
		b.record("token", "set", "*:*", "value-16h", at16)
		exchange(t, first(), second())
		for _, d := range []*device{a, b} {
			d.wantValue("token", "value-16h")
			d.wantHistory("token", "value-15h", "value-16h")
		}
	})
}

func TestSyncEntryDeleteAgainstSet(t *testing.T) {
	t.Run("later delete wins", func(t *testing.T) {
		bothOrders(t, func(t *testing.T, a, b *device, first, second func() *device) {
			a.record("token", "set", "*:*", "value-15h", at15)
			b.record("token", "delete-entry", "", "", at16)
			exchange(t, first(), second())
			for _, d := range []*device{a, b} {
				d.wantGone("token")
				d.wantHistory("token", "value-15h")
			}
		})
	})
	t.Run("later set wins", func(t *testing.T) {
		bothOrders(t, func(t *testing.T, a, b *device, first, second func() *device) {
			a.record("token", "delete-entry", "", "", at15)
			b.record("token", "set", "*:*", "value-16h", at16)
			exchange(t, first(), second())
			for _, d := range []*device{a, b} {
				d.wantValue("token", "value-16h")
			}
		})
	})
}

func TestSyncKeepsChangesToDifferentVariants(t *testing.T) {
	a, b := twoDevices(t)
	a.record("token", "set", "prod:*", "prod-value", at16)
	b.record("token", "set", "*:*", "baseline-value", at15)
	exchange(t, a, b)
	for _, d := range []*device{a, b} {
		d.wantValue("token", "baseline-value")
		if got, ok := d.get("token", "prod", ""); !ok || got != "prod-value" {
			t.Fatalf("prod variant: %q %v", got, ok)
		}
	}
}

func TestSyncEqualTimesPickTheSameWinnerEverywhere(t *testing.T) {
	a, b := twoDevices(t)
	first := a.record("token", "set", "*:*", "value-a", at16)
	second := b.record("token", "set", "*:*", "value-b", at16)
	exchange(t, a, b)
	want := "value-a"
	if second.ID > first.ID {
		want = "value-b"
	}
	a.wantValue("token", want)
	b.wantValue("token", want)
}

func TestLocalChangeOutranksPulledRevisionFromFastClock(t *testing.T) {
	a, b := twoDevices(t)
	ahead := time.Now().UTC().Add(5 * time.Second)
	a.record("token", "set", "*:*", "from-fast-clock", ahead)
	exchange(t, a, b)
	if err := b.store().Delete("", "token", "", ""); err != nil {
		t.Fatal(err)
	}
	b.wantGone("token")
	exchange(t, b, a)
	a.wantGone("token")
	b.wantGone("token")

	a.record("other", "set", "*:*", "from-fast-clock", ahead)
	exchange(t, a, b)
	if err := b.store().SetSecret("", "other", "newer-here", "", "", "described"); err != nil {
		t.Fatal(err)
	}
	exchange(t, b, a)
	a.wantValue("other", "newer-here")
	history, err := a.store().History("", "other")
	if err != nil {
		t.Fatal(err)
	}
	last := history.Revisions[len(history.Revisions)-1]
	if last.Op != "describe" || !last.RecordedAt.After(ahead) {
		t.Fatalf("revisions not stamped behind the pulled time: %+v", last)
	}
}

func TestSyncSurvivesDeliveryProblems(t *testing.T) {
	a, b := twoDevices(t)
	a.record("token", "set", "*:*", "value-1", at15)
	a.sync()
	stale := folderFiles(t, a.folder)
	a.record("token", "set", "*:*", "value-2", at16)
	exchange(t, a, b)
	b.wantValue("token", "value-2")

	// A late delivery of the older snapshot adds nothing.
	for name, raw := range stale {
		if err := os.WriteFile(filepath.Join(b.folder, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := b.sync(); got.NewRevisions != 0 {
		t.Fatalf("stale file added %d revisions", got.NewRevisions)
	}
	b.wantValue("token", "value-2")

	// A conflict copy is ordinary input, and only it holds this revision.
	c := b.record("only-in-copy", "set", "*:*", "copy-value", at16)
	b.sync()
	raw, err := os.ReadFile(ownFile(t, b))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hort-ab12 2.enc", "hort-ab12.sync-conflict-20261105.enc"} {
		if err := os.WriteFile(filepath.Join(a.folder, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.sync(); got.NewRevisions != 1 {
		t.Fatalf("conflict copies added %d revisions, want %s once", got.NewRevisions, c.ID)
	}
	a.wantValue("only-in-copy", "copy-value")

	// A truncated file is skipped now and read once it is complete.
	truncated := filepath.Join(a.folder, "hort-partial.enc")
	if err := os.WriteFile(truncated, raw[:len(raw)/2], 0600); err != nil {
		t.Fatal(err)
	}
	got := a.sync()
	if len(got.Unreadable) != 1 || got.Unreadable[0] != "hort-partial.enc" || got.OwnUnreadable {
		t.Fatalf("truncated file: %+v", got)
	}
	a.wantValue("token", "value-2")
	if err := os.WriteFile(truncated, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got := a.sync(); len(got.Unreadable) != 0 {
		t.Fatalf("complete file still unreadable: %+v", got)
	}
}

func TestSyncReadsOnlyRegularHortFiles(t *testing.T) {
	a, _ := twoDevices(t)
	for _, name := range []string{".hort-x.enc.icloud", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(a.folder, name), []byte("not a vault"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(a.folder, "hort-dir"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := a.sync(); len(got.Unreadable) != 0 {
		t.Fatalf("foreign names were read: %+v", got)
	}
}

func TestSyncRestoresOwnFile(t *testing.T) {
	a, _ := twoDevices(t)
	own := ownFile(t, a)
	old, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}
	a.record("token", "set", "*:*", "value", at16)
	a.sync()
	current, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(own); err != nil {
		t.Fatal(err)
	}
	if got := a.sync(); !got.Pushed {
		t.Fatal("deleted own file was not restored")
	}
	if raw, _ := os.ReadFile(own); !bytes.Equal(raw, current) {
		t.Fatal("restored file differs from local vault")
	}

	if err := os.WriteFile(own, old, 0600); err != nil {
		t.Fatal(err)
	}
	if got := a.sync(); !got.Pushed {
		t.Fatal("outdated own file was not replaced")
	}
	if raw, _ := os.ReadFile(own); !bytes.Equal(raw, current) {
		t.Fatal("replaced file differs from local vault")
	}

	if _, err := vault.SetupSync(a.ref(), a.key, a.folder); err != nil {
		t.Fatal(err)
	}
	if again := ownFile(t, a); again != own {
		t.Fatalf("repeated setup moved the device file to %s", again)
	}
}

func TestSetupRefusesForeignKeyWithoutChanges(t *testing.T) {
	a, _ := twoDevices(t)
	foreign := &device{t: t, home: t.TempDir(), folder: a.folder}
	ref := foreign.ref()
	key, err := vault.CreatePrimaryVault([]byte("synthetic-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveSessionFor(ref, key); err != nil {
		t.Fatal(err)
	}
	foreign.key = key
	before, err := os.ReadFile(ref.Path)
	if err != nil {
		t.Fatal(err)
	}
	folderBefore := folderFiles(t, a.folder)

	_, err = vault.SetupSync(ref, key, a.folder)
	if err == nil || !strings.Contains(err.Error(), "cannot decrypt") {
		t.Fatalf("setup: %v", err)
	}
	after, err := os.ReadFile(ref.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("local vault changed")
	}
	folderAfter := folderFiles(t, a.folder)
	if len(folderAfter) != len(folderBefore) {
		t.Fatal("folder gained files")
	}
	for name, raw := range folderBefore {
		if !bytes.Equal(raw, folderAfter[name]) {
			t.Fatalf("%s changed", name)
		}
	}
	if own := ownFile(t, foreign); own != "" {
		t.Fatalf("setup was stored: %s", own)
	}
}

func TestNewVaultDoesNotOverwriteOwnOldFile(t *testing.T) {
	a, _ := twoDevices(t)
	a.record("token", "set", "*:*", "value", at16)
	a.sync()
	own := ownFile(t, a)
	before, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}
	ref := a.ref()
	key, err := vault.CreatePrimaryVault([]byte("another-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.SaveSessionFor(ref, key); err != nil {
		t.Fatal(err)
	}
	a.key = key
	got := a.sync()
	if !got.OwnUnreadable || got.Pushed {
		t.Fatalf("result: %+v", got)
	}
	after, err := os.ReadFile(own)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("own old file was overwritten")
	}
}

func TestSetupRejectsUnfitFolders(t *testing.T) {
	a := &device{t: t, home: t.TempDir()}
	ref := a.ref()
	key, err := vault.CreatePrimaryVault([]byte("synthetic-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(a.home, ".hort", "sync")
	if err := os.Mkdir(inside, 0700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "not-mounted")
	plainFile := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(plainFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(a.home, ".hort"), inside, a.home, missing, plainFile} {
		if _, err := vault.SetupSync(ref, key, path); err == nil {
			t.Fatalf("%s was accepted", path)
		}
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("missing folder was created")
	}
	if own := ownFile(t, a); own != "" {
		t.Fatalf("setup was stored: %s", own)
	}
}

func TestMissingFolderKeepsLocalWorkAndCatchesUpLater(t *testing.T) {
	a, b := twoDevices(t)
	offline := a.folder + ".offline"
	if err := os.Rename(a.folder, offline); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.Sync(a.ref(), a.key); err == nil {
		t.Fatal("missing folder went unnoticed")
	}
	if err := a.store().SetSecret("", "token", "written-offline", "", "", ""); err != nil {
		t.Fatal(err)
	}
	a.wantValue("token", "written-offline")
	if _, err := vault.Sync(a.ref(), a.key); err == nil {
		t.Fatal("missing folder went unnoticed")
	}
	if _, err := os.Stat(a.folder); !os.IsNotExist(err) {
		t.Fatal("folder was created")
	}
	if err := os.Rename(offline, a.folder); err != nil {
		t.Fatal(err)
	}
	exchange(t, a, b)
	b.wantValue("token", "written-offline")
}

func TestConvergedSyncWritesNothing(t *testing.T) {
	a, b := twoDevices(t)
	a.record("token", "set", "*:*", "value", at16)
	exchange(t, a, b)
	deliver(t, b, a)
	a.sync()
	deliver(t, a, b)
	b.sync()

	for _, d := range []*device{a, b} {
		ref := d.ref()
		before, err := os.ReadFile(ref.Path)
		if err != nil {
			t.Fatal(err)
		}
		stat, err := os.Stat(ref.Path)
		if err != nil {
			t.Fatal(err)
		}
		folder := folderFiles(t, d.folder)
		got := d.sync()
		if got.NewRevisions != 0 || got.Pushed {
			t.Fatalf("idle run: %+v", got)
		}
		after, err := os.ReadFile(ref.Path)
		if err != nil {
			t.Fatal(err)
		}
		statAfter, err := os.Stat(ref.Path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) || !stat.ModTime().Equal(statAfter.ModTime()) {
			t.Fatal("vault was rewritten")
		}
		for name, raw := range folderFiles(t, d.folder) {
			if !bytes.Equal(raw, folder[name]) {
				t.Fatalf("%s was rewritten", name)
			}
		}
	}
}

func TestSyncFolderHoldsNoPlaintextOrKeys(t *testing.T) {
	a, b := twoDevices(t)
	const name, value, description = "synthetic-entry-name", "synthetic-plain-value", "synthetic-description"
	if err := a.store().SetSecret("", name, value, "synthetic-env", "", description); err != nil {
		t.Fatal(err)
	}
	exchange(t, a, b)
	b.wantHistory(name, value)

	needles := [][]byte{
		[]byte(name), []byte(value), []byte(description), []byte("synthetic-env"),
		[]byte("synthetic-passphrase"), []byte(`"revisions"`),
		a.key, []byte(hex.EncodeToString(a.key)),
	}
	for _, d := range []*device{a, b} {
		files := folderFiles(t, d.folder)
		if len(files) < 2 {
			t.Fatalf("expected a file per device, got %d", len(files))
		}
		for file, raw := range files {
			for _, needle := range needles {
				if bytes.Contains(raw, needle) {
					t.Fatalf("%s contains secret material", file)
				}
			}
			info, err := os.Stat(filepath.Join(d.folder, file))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("%s has mode %o", file, info.Mode().Perm())
			}
		}
	}
}

func TestParallelWritersLoseNoRevisionDuringSync(t *testing.T) {
	a, b := twoDevices(t)
	b.record("token", "set", "*:*", "pulled-during-writes", at15)
	b.sync()
	deliver(t, b, a)
	s := a.store()
	ref := a.ref()
	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers+4)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.SetSecret("", "token", fmt.Sprintf("value-%d", i), "", "", "")
		}()
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := vault.Sync(ref, a.key)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	exchange(t, a, b)
	for _, d := range []*device{a, b} {
		history, err := d.store().History("", "token")
		if err != nil {
			t.Fatal(err)
		}
		if len(history.Revisions) != writers+1 {
			t.Fatalf("got %d revisions, want %d", len(history.Revisions), writers+1)
		}
	}
}
