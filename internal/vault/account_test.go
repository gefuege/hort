package vault

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestMergePulledUnionAndConflict(t *testing.T) {
	data, err := NewBody("device")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	local := Revision{ID: "000000000000000000000000000000aa", RecordedAt: &at, Op: "set", Key: "*:*", Value: "local"}
	data.Secrets["token"] = Entry{Revisions: []Revision{local}}

	same := local
	other := local
	other.Value = "other"
	fresh := Revision{ID: "000000000000000000000000000000bb", Op: "set", Key: "*:*", Value: "new"}
	added, conflicts := data.MergePulled([]Pulled{{"token", same}, {"token", other}, {"renamed", local}, {"api", fresh}, {"api", fresh}})
	if added != 1 || !reflect.DeepEqual(conflicts, []string{local.ID, local.ID}) {
		t.Fatalf("added %d, conflicts %v", added, conflicts)
	}
	if got := data.Secrets["token"].Revisions; len(got) != 1 || got[0].Value != "local" {
		t.Fatalf("local revision changed: %+v", got)
	}
	if got := data.Secrets["api"].Revisions; len(got) != 1 || got[0].Value != "new" {
		t.Fatalf("new revision: %+v", got)
	}
	if err := validateBody(data); err != nil {
		t.Fatal(err)
	}
}

func TestOpenServerSlotChecksAccountKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ref, err := PrimaryRef()
	if err != nil {
		t.Fatal(err)
	}
	nv := testCreate(t, ref, "pass")
	_, acct, err := OpenAccount(ref, nv.VK)
	if err != nil {
		t.Fatal(err)
	}
	akPub := acct.Keys.AK.Public().(ed25519.PublicKey)
	vk, err := OpenServerSlot(nv.AccountID, acct.Slot, akPub, "pass", nv.SecretKey)
	if err != nil || !bytes.Equal(vk, nv.VK) {
		t.Fatalf("open: %v", err)
	}
	if _, err := OpenServerSlot(nv.AccountID, acct.Slot, akPub, "wrong", nv.SecretKey); err != ErrWrongPassphrase {
		t.Fatalf("wrong passphrase: %v", err)
	}
	stranger, _, _ := ed25519.GenerateKey(nil)
	if _, err := OpenServerSlot(nv.AccountID, acct.Slot, stranger, "pass", nv.SecretKey); err == nil {
		t.Fatal("accepted a foreign ak_pub")
	}
	forged := acct.Slot
	forged.AKSig = make([]byte, ed25519.SignatureSize)
	if _, err := OpenServerSlot(nv.AccountID, forged, akPub, "pass", nv.SecretKey); err == nil {
		t.Fatal("accepted a slot without a valid ak_sig")
	}
	if _, err := OpenServerSlot(nv.AccountID, Slot{Version: 1, Bytes: []byte("x"), AKSig: forged.AKSig}, akPub, "pass", nv.SecretKey); err == nil {
		t.Fatal("accepted malformed slot bytes")
	}
}

func TestReplaceSlotTakesOnlyANewerSignedSlot(t *testing.T) {
	setHomeDir(t, t.TempDir())
	a := primaryRefOrFatal(t)
	nv := testCreate(t, a, "old")
	raw, err := os.ReadFile(a.Path)
	if err != nil {
		t.Fatal(err)
	}
	setHomeDir(t, t.TempDir())
	b := primaryRefOrFatal(t)
	if err := os.MkdirAll(filepath.Dir(b.Path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, old, err := OpenAccount(b, nv.VK)
	if err != nil {
		t.Fatal(err)
	}
	if err := changePassphrase(a, nv.VK, []byte("new"), nv.SecretKey, fastArgon); err != nil {
		t.Fatal(err)
	}
	_, acct, err := OpenAccount(a, nv.VK)
	if err != nil {
		t.Fatal(err)
	}
	akPub := acct.Keys.AK.Public().(ed25519.PublicKey)
	stranger, strangerKey, _ := ed25519.GenerateKey(nil)
	forged := acct.Slot
	forged.AKSig = ed25519.Sign(strangerKey, SlotSigMessage(nv.AccountID, PassphraseSlotID, forged.Version, forged.Bytes))
	for name, c := range map[string]struct {
		slot  Slot
		akPub []byte
	}{
		"foreign ak_pub": {acct.Slot, stranger},
		"foreign ak_sig": {forged, akPub},
		"equal version":  {old.Slot, akPub},
		"older version":  {Slot{Version: 0, Bytes: old.Slot.Bytes, AKSig: old.Slot.AKSig}, akPub},
	} {
		if err := ReplaceSlot(b, nv.VK, c.slot, c.akPub); err == nil {
			t.Fatalf("%s: replaced the slot", name)
		}
	}
	if _, err := UnlockVault(b, []byte("old"), nv.SecretKey); err != nil {
		t.Fatalf("a refused slot changed the vault: %v", err)
	}

	if err := ReplaceSlot(b, nv.VK, acct.Slot, akPub); err != nil {
		t.Fatal(err)
	}
	backup := b
	backup.Path = BackupPathFor(b)
	for _, ref := range []VaultRef{b, backup} {
		if _, err := UnlockVault(ref, []byte("old"), nv.SecretKey); !errors.Is(err, ErrWrongPassphrase) {
			t.Fatalf("old passphrase still opens %s: %v", ref.Path, err)
		}
		if vk, err := UnlockVault(ref, []byte("new"), nv.SecretKey); err != nil || !bytes.Equal(vk, nv.VK) {
			t.Fatalf("new passphrase on %s: %v", ref.Path, err)
		}
	}
}
