package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// v3Revision, v3Entry and v3Doc are the v3 body exactly as Hort 0.4 wrote it
// with json.Marshal (280e403, internal/vault/vault.go and revisions.go):
// revisions carry no field.
type v3Revision struct {
	ID         string     `json:"id"`
	RecordedAt *time.Time `json:"recorded_at"`
	Op         string     `json:"op"`
	Key        string     `json:"key"`
	Value      string     `json:"value"`
}
type v3Entry struct {
	Revisions []v3Revision `json:"revisions"`
}
type v3Doc struct {
	Version  int                `json:"version"`
	SourceID string             `json:"source_id"`
	Secrets  map[string]v3Entry `json:"secrets"`
}

const migratePassphrase = "v3 passphrase"

func at(s string) *time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	t = t.UTC()
	return &t
}

func rid(n int) string {
	return strings.Repeat("0", 30) + string("0123456789abcdef"[n/16]) + string("0123456789abcdef"[n%16])
}

// envelopeFit is the longest ASCII value of a set revision under name that
// still fits one envelope.
func envelopeFit(t *testing.T, name string) int {
	t.Helper()
	plain, err := EnvelopePlaintext(name, Revision{ID: rid(0), Op: "set", Key: "*:*"})
	if err != nil {
		t.Fatal(err)
	}
	return MaxEnvelopeBytes - envelopeOverhead - len(plain)
}

// richV3 covers what v3 can hold: imported v1 history without a time, names
// with whitespace, contexts with ':', delete, delete-entry, descriptions and a
// value exactly at the envelope limit.
func richV3(t *testing.T) v3Doc {
	return v3Doc{Version: 3, SourceID: rid(255), Secrets: map[string]v3Entry{
		"legacy token": {Revisions: []v3Revision{
			{ID: rid(1), RecordedAt: nil, Op: "set", Key: "*:*", Value: "imported from v1"},
			{ID: rid(2), RecordedAt: nil, Op: "describe", Key: "", Value: "imported description"},
			{ID: rid(3), RecordedAt: at("2024-03-01T10:00:00.123456789Z"), Op: "set", Key: "prod:*", Value: "newer"},
		}},
		"db": {Revisions: []v3Revision{
			{ID: rid(4), RecordedAt: at("2024-03-02T10:00:00Z"), Op: "set", Key: "prod:tenant:a", Value: "colon context"},
			{ID: rid(5), RecordedAt: at("2024-03-02T10:00:01Z"), Op: "describe", Key: "", Value: "Database"},
			{ID: rid(6), RecordedAt: at("2024-03-02T10:00:02Z"), Op: "delete", Key: "prod:tenant:a", Value: ""},
			{ID: rid(7), RecordedAt: at("2024-03-02T10:00:03Z"), Op: "set", Key: "*:*", Value: "line1\nline2 \"quoted\" ü"},
		}},
		"gone": {Revisions: []v3Revision{
			{ID: rid(8), RecordedAt: at("2024-03-03T10:00:00Z"), Op: "set", Key: "*:*", Value: "old"},
			{ID: rid(9), RecordedAt: at("2024-03-03T10:00:01Z"), Op: "delete-entry", Key: "", Value: ""},
		}},
		"near-limit": {Revisions: []v3Revision{
			{ID: rid(10), RecordedAt: at("2024-03-04T10:00:00Z"), Op: "set", Key: "*:*", Value: strings.Repeat("x", envelopeFit(t, "near-limit"))},
		}},
		"-dash name": {Revisions: []v3Revision{
			{ID: rid(11), RecordedAt: at("2024-03-05T10:00:00Z"), Op: "set", Key: "a b:c\td", Value: "legacy scope"},
		}},
	}}
}

// migrateSetup writes doc as a v3 primary vault into a fresh HOME.
func migrateSetup(t *testing.T, doc v3Doc) (VaultRef, []byte) {
	t.Helper()
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	if err := os.MkdirAll(filepath.Dir(ref.Path), 0700); err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return ref, writeV3(t, ref.Path, migratePassphrase, plaintext)
}

func migrateRun(t *testing.T, ref VaultRef, passphrase string) (NewVault, error) {
	t.Helper()
	raw, err := ReadV3(ref)
	if err != nil {
		return NewVault{}, err
	}
	return migrateV3(ref, raw, []byte(passphrase), "migrated-device", fastArgon)
}

// snapshot hashes every file below HOME except the lock directory, which the
// lock itself creates.
func snapshot(t *testing.T) map[string][32]byte {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][32]byte{}
	err = filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "locks" {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = sha256.Sum256(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameSnapshot(t *testing.T, before, after map[string][32]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("files changed: before %d, after %d", len(before), len(after))
	}
	for path, sum := range before {
		if after[path] != sum {
			t.Fatalf("%s changed", path)
		}
	}
}

func TestMigrateKeepsEveryRevision(t *testing.T) {
	doc := richV3(t)
	ref, original := migrateSetup(t, doc)
	nv, err := migrateRun(t, ref, migratePassphrase)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	data, raw, err := LoadVault(ref, nv.VK)
	if err != nil {
		t.Fatalf("migrated vault does not open: %v", err)
	}
	if len(data.Secrets) != len(doc.Secrets) {
		t.Fatalf("entries: got %d, want %d", len(data.Secrets), len(doc.Secrets))
	}
	var ids []string
	for name, entry := range doc.Secrets {
		got := data.Secrets[name].Revisions
		if len(got) != len(entry.Revisions) {
			t.Fatalf("%q: got %d revisions, want %d", name, len(got), len(entry.Revisions))
		}
		for i, want := range entry.Revisions {
			r := got[i]
			sameTime := (r.RecordedAt == nil && want.RecordedAt == nil) ||
				(r.RecordedAt != nil && want.RecordedAt != nil && r.RecordedAt.Equal(*want.RecordedAt))
			if r.ID != want.ID || !sameTime || r.Op != want.Op || r.Key != want.Key || r.Value != want.Value || r.Field != "" {
				t.Fatalf("%q revision %d: got %+v, want %+v", name, i, r, want)
			}
			ids = append(ids, want.ID)
		}
	}

	pending := map[string]bool{}
	for _, id := range data.Sync.Pending {
		pending[id] = true
	}
	if len(pending) != len(ids) || len(data.Sync.Pending) != len(ids) {
		t.Fatalf("pending: got %v, want every revision once", data.Sync.Pending)
	}
	for _, id := range ids {
		if !pending[id] {
			t.Fatalf("pending lacks %s", id)
		}
	}
	if data.Sync.Registered || data.Sync.Cursor != 0 || data.Device.Name != "migrated-device" {
		t.Fatalf("sync or device state: %+v %+v", data.Sync, data.Device)
	}

	f, err := parseV4(raw)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveAccountKeys(nv.VK, nv.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	msg := SlotSigMessage(f.AccountID, PassphraseSlotID, f.SlotVersion, SlotBytes(ArgonSlotParams(f.SlotSalt, f.Argon), f.WrapNonce, f.WrappedVK))
	if f.SlotVersion != 1 || f.Server != DefaultServer || !ed25519.Verify(keys.AK.Public().(ed25519.PublicKey), msg, f.SlotSig) {
		t.Fatalf("slot: version %d, server %q, signature valid %t", f.SlotVersion, f.Server, ed25519.Verify(keys.AK.Public().(ed25519.PublicKey), msg, f.SlotSig))
	}

	backup, err := os.ReadFile(PreV4BackupPath(ref))
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("backup is not a byte copy of the v3 file: %v", err)
	}
	if info, err := os.Stat(PreV4BackupPath(ref)); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("backup mode: %v %v", info.Mode(), err)
	}
	skText, err := ReadSecretKeyFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ParseSecretKey(strings.TrimSpace(skText))
	if err != nil || !bytes.Equal(sk, nv.SecretKey) {
		t.Fatalf("Secret Key file: %v", err)
	}
	if vk, err := UnlockVault(ref, []byte(migratePassphrase), sk); err != nil || !bytes.Equal(vk, nv.VK) {
		t.Fatalf("unlock with the same passphrase and the new Secret Key: %v", err)
	}
	if IsUnlockedFor(ref) {
		t.Fatal("the vault package must leave the session to the caller")
	}
	if value, ok := data.Secrets["db"].Resolve("", "prod", "tenant:a"); !ok || value != "line1\nline2 \"quoted\" ü" {
		t.Fatalf("db resolves to %q, %t", value, ok)
	}
}

func TestMigrateStopsOnOversizedValueBeforeAnyWrite(t *testing.T) {
	doc := richV3(t)
	over := strings.Repeat("y", envelopeFit(t, "too big")+1)
	doc.Secrets["too big"] = v3Entry{Revisions: []v3Revision{
		{ID: rid(20), RecordedAt: at("2024-03-06T10:00:00Z"), Op: "set", Key: "*:*", Value: over},
		{ID: rid(21), RecordedAt: at("2024-03-06T10:00:01Z"), Op: "set", Key: "*:*", Value: "short again"},
	}}
	doc.Secrets["huge description"] = v3Entry{Revisions: []v3Revision{
		{ID: rid(22), RecordedAt: at("2024-03-06T10:00:00Z"), Op: "describe", Key: "", Value: strings.Repeat("d", MaxEnvelopeBytes)},
	}}
	ref, _ := migrateSetup(t, doc)
	before := snapshot(t)
	_, err := migrateRun(t, ref, migratePassphrase)
	if err == nil || !strings.Contains(err.Error(), `"huge description", "too big"`) || strings.Contains(err.Error(), "near-limit") {
		t.Fatalf("oversized revisions: got %v", err)
	}
	sameSnapshot(t, before, snapshot(t))
}

func TestMigrateCrashPoints(t *testing.T) {
	crashAt := func(t *testing.T, step string) {
		migrateCrash = func(s string) error {
			if s == step {
				return errors.New("synthetic crash after " + s)
			}
			return nil
		}
		t.Cleanup(func() { migrateCrash = nil })
	}
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }

	t.Run("after 6.1", func(t *testing.T) {
		ref, original := migrateSetup(t, richV3(t))
		crashAt(t, "6.1")
		if _, err := migrateRun(t, ref, migratePassphrase); err == nil {
			t.Fatal("no crash")
		}
		if cur, _ := os.ReadFile(ref.Path); !bytes.Equal(cur, original) || exists(ref.SecretKeyPath) {
			t.Fatal("state after 6.1 must be the v3 file plus its backup only")
		}
		migrateCrash = nil
		nv, err := migrateRun(t, ref, migratePassphrase)
		if err != nil {
			t.Fatalf("rerun with an equal backup: %v", err)
		}
		if _, _, err := LoadVault(ref, nv.VK); err != nil {
			t.Fatal(err)
		}
		if backup, _ := os.ReadFile(PreV4BackupPath(ref)); !bytes.Equal(backup, original) {
			t.Fatal("rerun changed the backup")
		}
	})

	t.Run("after 6.2", func(t *testing.T) {
		ref, original := migrateSetup(t, richV3(t))
		crashAt(t, "6.2")
		if _, err := migrateRun(t, ref, migratePassphrase); err == nil {
			t.Fatal("no crash")
		}
		stale, err := os.ReadFile(ref.SecretKeyPath)
		if cur, _ := os.ReadFile(ref.Path); err != nil || !bytes.Equal(cur, original) {
			t.Fatalf("state after 6.2 must be the v3 file plus a Secret Key: %v", err)
		}
		migrateCrash = nil
		nv, err := migrateRun(t, ref, migratePassphrase)
		if err != nil {
			t.Fatalf("rerun over a stale Secret Key: %v", err)
		}
		fresh, _ := os.ReadFile(ref.SecretKeyPath)
		if bytes.Equal(fresh, stale) || strings.TrimSpace(string(fresh)) != FormatSecretKey(nv.SecretKey) {
			t.Fatal("rerun must replace the Secret Key with the new account's")
		}
		if _, err := UnlockVault(ref, []byte(migratePassphrase), nv.SecretKey); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("after 6.3 and 6.4", func(t *testing.T) {
		ref, _ := migrateSetup(t, richV3(t))
		nv, err := migrateRun(t, ref, migratePassphrase)
		if err != nil {
			t.Fatal(err)
		}
		// After 6.3: complete v4 vault, no session yet. Rerun refuses; unlock recovers.
		if _, err := migrateRun(t, ref, migratePassphrase); !errors.Is(err, ErrAlreadyMigrated) {
			t.Fatalf("rerun after 6.3: %v", err)
		}
		sk, err := ParseSecretKey(strings.TrimSpace(string(must(os.ReadFile(ref.SecretKeyPath)))))
		if err != nil {
			t.Fatal(err)
		}
		vk, err := UnlockVault(ref, []byte(migratePassphrase), sk)
		if err != nil || !bytes.Equal(vk, nv.VK) {
			t.Fatalf("unlock after 6.3: %v", err)
		}
		// After 6.4: the session holds VK and opens the vault; rerun still refuses.
		if err := SaveSessionFor(ref, nv.VK); err != nil {
			t.Fatal(err)
		}
		key, err := LoadSessionFor(ref)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadVault(ref, key); err != nil {
			t.Fatalf("session after 6.4: %v", err)
		}
		if _, err := migrateRun(t, ref, migratePassphrase); err == nil || err.Error() != "already migrated; run `hort kit` to see your Emergency Kit" {
			t.Fatalf("rerun after 6.4: %v", err)
		}
	})
}

func TestMigrateStopsOnDifferentBackup(t *testing.T) {
	ref, _ := migrateSetup(t, richV3(t))
	if err := os.WriteFile(PreV4BackupPath(ref), []byte("some other file"), 0600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t)
	if _, err := migrateRun(t, ref, migratePassphrase); err == nil || !strings.Contains(err.Error(), "differs from the v3 vault") {
		t.Fatalf("different backup: %v", err)
	}
	sameSnapshot(t, before, snapshot(t))
}

func TestMigrateRefusesOtherFormats(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	if _, err := ReadV3(ref); err == nil || !strings.Contains(err.Error(), "no vault found") {
		t.Fatalf("missing vault: %v", err)
	}
	testCreate(t, ref, "pass")
	if _, err := ReadV3(ref); !errors.Is(err, ErrAlreadyMigrated) {
		t.Fatalf("v4: %v", err)
	}
	v2 := append([]byte(v2Magic), make([]byte, HeaderSize)...)
	if err := os.WriteFile(ref.Path, v2, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadV3(ref); !errors.Is(err, errV2Vault) || !strings.Contains(err.Error(), "0.4.1") {
		t.Fatalf("v2: %v", err)
	}
	if err := os.WriteFile(ref.Path, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadV3(ref); err == nil || !strings.Contains(err.Error(), "not a hort vault") {
		t.Fatalf("garbage: %v", err)
	}
}

func TestMigrateWrongPassphraseStopsBeforeLock(t *testing.T) {
	ref, _ := migrateSetup(t, richV3(t))
	unlock, err := lockVault(ref)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	before := snapshot(t)
	done := make(chan error, 1)
	go func() {
		_, err := migrateRun(t, ref, "wrong passphrase")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
			t.Fatalf("wrong passphrase: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a wrong passphrase waited for the vault lock")
	}
	sameSnapshot(t, before, snapshot(t))
}
