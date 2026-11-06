package vault

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// legacyFixture creates the exact nil-AAD outer v2 / inner v1 format, without
// using a production v2 writer or any real vault material.
func legacyFixture(t *testing.T, ref VaultRef, plain string, kdf KDFMode) ([]byte, []byte) {
	t.Helper()
	material := bytes.Repeat([]byte{0x41}, KeySize)
	params := ArgonParams{}
	salt := make([]byte, SaltSize)
	if kdf == KDFArgon2id {
		params = ArgonParams{Time: 1, Memory: 8, Threads: 1}
	}
	key, err := deriveSessionKey(FormatInfo{KDF: kdf, Salt: salt, Argon: params}, material)
	if err != nil {
		t.Fatal(err)
	}
	cipher, nonce, err := sealGCM([]byte(plain), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	header := buildV3Header(kdf, salt, params, nonce)
	copy(header, V2Magic)
	header[4] = 2
	raw := append(header, cipher...)
	if err := os.MkdirAll(filepath.Dir(ref.Path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ref.Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	unlocked, err := UnlockVault(ref, material)
	if err != nil || !bytes.Equal(unlocked, key) {
		t.Fatalf("legacy unlock: %v", err)
	}
	return key, raw
}

func TestExplicitMigrationPreservesCompleteContentAndBackup(t *testing.T) {
	for _, kdf := range []KDFMode{KDFArgon2id, KDFRawKey} {
		t.Run(fmt.Sprint(kdf), func(t *testing.T) {
			setHomeDir(t, t.TempDir())
			ref := primaryRefOrFatal(t)
			if kdf == KDFRawKey {
				var err error
				ref, err = MountedRefAt("raw", filepath.Join(t.TempDir(), "raw.enc"))
				if err != nil {
					t.Fatal(err)
				}
			}
			key, raw := legacyFixture(t, ref, `{"version":1,"secrets":{"ä":{"description":"Größe","values":{"*:*":"","prod:*":"prod","odd":"kept","prod:ctx:tail":"exact","":"empty key"}},"empty":{"description":"","values":{}}},"configs":{"url":{"description":"URL","values":{"*:*":"https://invalid.test"}}}}`, kdf)
			if _, _, err := LoadVault(ref, key); err == nil {
				t.Fatal("ordinary load accepted v2")
			}
			if err := UpdateVault(ref, key, func(*VaultData) error { t.Fatal("ordinary update touched v2"); return nil }); err == nil {
				t.Fatal("ordinary update accepted v2")
			}
			if err := MigrateVault(ref, key); err != nil {
				t.Fatal(err)
			}
			data, current, err := LoadVault(ref, key)
			if err != nil {
				t.Fatal(err)
			}
			if data.Version != 3 || !validID(data.SourceID) || len(data.Secrets) != 3 {
				t.Fatal("wrong migrated contract")
			}
			values, desc, visible := data.Secrets["ä"].Current()
			want := map[ValueKey]string{{Key: "*:*"}: "", {Key: "prod:*"}: "prod", {Key: "odd"}: "kept", {Key: "prod:ctx:tail"}: "exact", {Key: ""}: "empty key"}
			if !visible || desc != "Größe" || !reflect.DeepEqual(values, want) {
				t.Fatal("legacy keys/values/description changed")
			}
			if _, _, visible := data.Secrets["empty"].Current(); !visible {
				t.Fatal("empty entry lost")
			}
			for _, e := range data.Secrets {
				for _, r := range e.Revisions {
					if r.RecordedAt != nil {
						t.Fatal("invented legacy timestamp")
					}
				}
			}
			info, err := ParseFormat(current)
			if err != nil || info.KDF != kdf {
				t.Fatal("header parameters changed")
			}
			legacyInfo, _ := parseFormat(raw, true)
			if !bytes.Equal(info.Salt, legacyInfo.Salt) || info.Argon != legacyInfo.Argon || bytes.Equal(info.Nonce, legacyInfo.Nonce) {
				t.Fatal("KDF/salt/nonce preservation failed")
			}
			sourceID := data.SourceID
			for i := 0; i < 3; i++ {
				if err := UpdateVault(ref, key, func(d *VaultData) error {
					e := d.Secrets["url"]
					e.Revisions = append(e.Revisions, testRevision(t, "set", "*:*", fmt.Sprint(i)))
					d.Secrets["url"] = e
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			data, _, err = LoadVault(ref, key)
			if err != nil || data.SourceID != sourceID {
				t.Fatal("source identity changed")
			}
			backup, err := os.ReadFile(ref.Path + ".pre-v3.bak")
			if err != nil || !bytes.Equal(backup, raw) {
				t.Fatal("permanent backup changed")
			}
			stat, err := os.Stat(ref.Path + ".pre-v3.bak")
			if err != nil || stat.Mode().Perm() != 0600 {
				t.Fatal("backup permissions")
			}
		})
	}
}

func TestMigrationRejectsMalformedWithoutSideEffects(t *testing.T) {
	cases := map[string]string{
		"future":         `{"version":2,"secrets":{},"configs":{}}`,
		"unknown":        `{"version":1,"secrets":{},"configs":{},"extra":1}`,
		"case ambiguity": `{"Version":1,"secrets":{},"configs":{}}`,
		"duplicate":      `{"version":1,"secrets":{},"secrets":{},"configs":{}}`,
		"missing":        `{"version":1,"secrets":{}}`,
		"null entry":     `{"version":1,"secrets":{"x":null},"configs":{}}`,
		"null value":     `{"version":1,"secrets":{"x":{"description":"","values":{"*:*":null}}},"configs":{}}`,
		"missing values": `{"version":1,"secrets":{"x":{"description":""}},"configs":{}}`,
		"unknown entry":  `{"version":1,"secrets":{"x":{"description":"","values":{},"extra":1}},"configs":{}}`,
		"collision":      `{"version":1,"secrets":{"same":{"description":"","values":{"*:*":"hidden-secret"}}},"configs":{"same":{"description":"","values":{"*:*":"hidden-config"}}}}`,
	}
	for name, plain := range cases {
		t.Run(name, func(t *testing.T) {
			setHomeDir(t, t.TempDir())
			ref := primaryRefOrFatal(t)
			key, raw := legacyFixture(t, ref, plain, KDFRawKey)
			err := MigrateVault(ref, key)
			if err == nil {
				t.Fatal("malformed migration accepted")
			}
			if strings.Contains(err.Error(), "hidden-") {
				t.Fatal("error exposes values")
			}
			after, _ := os.ReadFile(ref.Path)
			if !bytes.Equal(raw, after) {
				t.Fatal("failed migration changed vault")
			}
			if _, err := os.Stat(ref.Path + ".pre-v3.bak"); !os.IsNotExist(err) {
				t.Fatal("failed validation created backup")
			}
		})
	}
}
func TestMigrationWrongKeyAndBackupRetry(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	key, raw := legacyFixture(t, ref, `{"version":1,"secrets":{},"configs":{}}`, KDFRawKey)
	if err := MigrateVault(ref, bytes.Repeat([]byte{0x42}, KeySize)); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := os.Stat(ref.Path + ".pre-v3.bak"); !os.IsNotExist(err) {
		t.Fatal("wrong key created backup")
	}
	backup := ref.Path + ".pre-v3.bak"
	if err := os.WriteFile(backup, []byte("different"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateVault(ref, key); err == nil {
		t.Fatal("different prior backup accepted")
	}
	after, _ := os.ReadFile(ref.Path)
	if !bytes.Equal(after, raw) {
		t.Fatal("mismatched backup changed original")
	}
	if err := os.WriteFile(backup, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateVault(ref, key); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(backup)
	if !bytes.Equal(got, raw) {
		t.Fatal("retry changed backup")
	}
}

func TestV3HeaderIsAuthenticatedAndCannotDowngrade(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, KeySize)
	raw, _, err := CreateEncrypted([]byte(`{"synthetic":true}`), key, KDFRawKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{5, 6, 38, 42, 46} {
		altered := append([]byte(nil), raw...)
		altered[offset] ^= 1
		if _, err := DecryptWithKey(altered, key); err == nil {
			t.Fatalf("header byte %d unauthenticated", offset)
		}
	}
	altered := append([]byte(nil), raw...)
	copy(altered, V2Magic)
	altered[4] = 2
	if _, err := UnlockWithMaterial(altered, key); err == nil {
		t.Fatal("v3 accepted as v2")
	}
	info, err := parseFormat(altered, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openGCM(altered[info.CipherAt:], info.Nonce, key, nil); err == nil {
		t.Fatal("legacy nil-AAD decrypt accepted downgraded v3")
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
	if _, err := NewVaultData(); err == nil {
		t.Fatal("source ignored RNG failure")
	}
}
