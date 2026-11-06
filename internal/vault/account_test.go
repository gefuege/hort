package vault

import (
	"bytes"
	"crypto/ed25519"
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
