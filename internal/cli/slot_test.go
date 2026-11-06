package cli

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/vault"
)

// slotServer answers PUT /slots/passphrase with putStatus, GET
// /accounts/{id}/slot with akPub and slot, and GET /revisions with an empty
// page that reports slotVersion.
type slotServer struct {
	mu          sync.Mutex
	putStatus   int
	puts        []uint64
	akPub       []byte
	slot        api.Slot
	slotVersion uint64
}

func (s *slotServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == "PUT" && r.URL.Path == "/api/v1/slots/passphrase":
		var slot api.Slot
		if err := json.NewDecoder(r.Body).Decode(&slot); err != nil || slot.ID != "" {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		s.puts = append(s.puts, slot.Version)
		w.WriteHeader(s.putStatus)
		_, _ = w.Write([]byte("{}"))
	case r.Method == "GET" && r.URL.Path == "/api/v1/revisions":
		_ = json.NewEncoder(w).Encode(map[string]any{"revisions": []any{}, "cursor": 0, "more": false, "devices_version": 0, "slot_version": s.slotVersion})
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/slot"):
		slot := s.slot
		slot.ID = vault.PassphraseSlotID
		_ = json.NewEncoder(w).Encode(map[string]any{"ak_pub": s.akPub, "slot": slot})
	default:
		http.NotFound(w, r)
	}
}

func (s *slotServer) pushed() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint64(nil), s.puts...)
}

// registeredVault creates an unlocked, registered vault on srv in a fresh home.
func registeredVault(t *testing.T, srv *httptest.Server, passphrase string) (vault.VaultRef, []byte) {
	t.Helper()
	use(t, t.TempDir())
	ref := primary(t)
	nv, err := vault.CreateVault(ref, srv.URL, "dev", []byte(passphrase))
	must(t, err)
	must(t, vault.SaveSessionFor(ref, nv.VK))
	must(t, vault.UpdateVault(ref, nv.VK, func(d *vault.VaultData) error { d.Sync.Registered = true; return nil }))
	return ref, nv.VK
}

func slotServerFor(t *testing.T) (*slotServer, *httptest.Server) {
	fake := &slotServer{putStatus: http.StatusOK}
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	orig := api.HTTPClient
	api.HTTPClient = srv.Client()
	t.Cleanup(func() { api.HTTPClient = orig })
	return fake, srv
}

func slotVersion(t *testing.T, ref vault.VaultRef, vk []byte) uint64 {
	t.Helper()
	_, acct, err := vault.OpenAccount(ref, vk)
	must(t, err)
	return acct.Slot.Version
}

func TestPassphrasePushIsResentBySync(t *testing.T) {
	fake, srv := slotServerFor(t)
	ref, vk := registeredVault(t, srv, "old")
	t.Setenv("HORT_PASSPHRASE", "new")

	fake.putStatus = http.StatusServiceUnavailable
	must(t, CmdPassphrase())
	if got := fake.pushed(); len(got) != 1 || got[0] != 2 || slotVersion(t, ref, vk) != 2 {
		t.Fatalf("pushes %v, local version %d", got, slotVersion(t, ref, vk))
	}
	if _, err := vault.UnlockVault(ref, []byte("new"), mustSecretKey(t, ref)); err != nil {
		t.Fatalf("the new passphrase does not apply locally: %v", err)
	}

	fake.putStatus = http.StatusOK
	_, acct, err := vault.OpenAccount(ref, vk)
	must(t, err)
	must(t, syncSlot(ref, vk, acct, 1))
	must(t, syncSlot(ref, vk, acct, 2))
	if got := fake.pushed(); len(got) != 2 || got[1] != 2 {
		t.Fatalf("pushes after sync: %v", got)
	}
}

func TestPassphraseConflictKeepsTheServerSlot(t *testing.T) {
	fake, srv := slotServerFor(t)
	ref, vk := registeredVault(t, srv, "old")
	t.Setenv("HORT_PASSPHRASE", "new")
	fake.putStatus = http.StatusConflict
	if err := CmdPassphrase(); err == nil || err.Error() != slotConflict {
		t.Fatalf("conflict: %v", err)
	}
	_, acct, err := vault.OpenAccount(ref, vk)
	must(t, err)
	if err := syncSlot(ref, vk, acct, 1); err != nil {
		t.Fatalf("a conflict in sync is a warning: %v", err)
	}
	if got := fake.pushed(); len(got) != 2 {
		t.Fatalf("pushes %v", got)
	}
}

func TestSyncTakesOnlyANewerSignedServerSlot(t *testing.T) {
	fake, srv := slotServerFor(t)
	ref, vk := registeredVault(t, srv, "old")
	sk := mustSecretKey(t, ref)
	_, old, err := vault.OpenAccount(ref, vk)
	must(t, err)
	// Another device's change: version 2 under "new", while this vault stays at 1.
	raw, err := os.ReadFile(ref.Path)
	must(t, err)
	must(t, vault.ChangePassphrase(ref, vk, []byte("new"), sk))
	_, changed, err := vault.OpenAccount(ref, vk)
	must(t, err)
	must(t, os.WriteFile(ref.Path, raw, 0600))
	akPub := changed.Keys.AK.Public().(ed25519.PublicKey)
	wire := func(s vault.Slot) api.Slot { return api.Slot{Version: s.Version, Bytes: s.Bytes, AKSig: s.AKSig} }

	forged := wire(changed.Slot)
	forged.AKSig = make([]byte, ed25519.SignatureSize)
	stranger, _, _ := ed25519.GenerateKey(nil)
	for name, c := range map[string]struct {
		akPub []byte
		slot  api.Slot
	}{
		"foreign ak_sig":    {akPub, forged},
		"foreign ak_pub":    {stranger, wire(changed.Slot)},
		"not a higher slot": {akPub, wire(old.Slot)},
	} {
		fake.akPub, fake.slot = c.akPub, c.slot
		if err := syncSlot(ref, vk, old, 2); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if slotVersion(t, ref, vk) != 1 {
			t.Fatalf("%s: replaced the local slot", name)
		}
	}

	fake.akPub, fake.slot = akPub, wire(changed.Slot)
	must(t, syncSlot(ref, vk, old, 2))
	if _, err := vault.UnlockVault(ref, []byte("old"), sk); err == nil {
		t.Fatal("the old passphrase still unlocks")
	}
	if got, err := vault.UnlockVault(ref, []byte("new"), sk); err != nil || string(got) != string(vk) {
		t.Fatalf("the new passphrase: %v", err)
	}
	if len(fake.pushed()) != 0 {
		t.Fatal("pushed while taking the server slot")
	}
}

// Another device set version 2 while this one, still at 1, sets a passphrase:
// the sync before the change takes version 2, so the new one is 3 and wins.
func TestPassphraseAfterAnotherDeviceSetTheSameVersion(t *testing.T) {
	fake, srv := slotServerFor(t)
	ref, vk := registeredVault(t, srv, "old")
	sk := mustSecretKey(t, ref)
	raw, err := os.ReadFile(ref.Path)
	must(t, err)
	must(t, vault.ChangePassphrase(ref, vk, []byte("other"), sk))
	_, other, err := vault.OpenAccount(ref, vk)
	must(t, err)
	must(t, os.WriteFile(ref.Path, raw, 0600))
	fake.akPub = other.Keys.AK.Public().(ed25519.PublicKey)
	fake.slot = api.Slot{Version: other.Slot.Version, Bytes: other.Slot.Bytes, AKSig: other.Slot.AKSig}
	fake.slotVersion = 2

	t.Setenv("HORT_PASSPHRASE", "mine")
	must(t, CmdPassphrase())
	if got := fake.pushed(); len(got) != 1 || got[0] != 3 || slotVersion(t, ref, vk) != 3 {
		t.Fatalf("pushes %v, local version %d", got, slotVersion(t, ref, vk))
	}
}

func TestEnrollChecksTheServerURLFirst(t *testing.T) {
	use(t, t.TempDir())
	t.Setenv("HORT_SECRET_KEY", "x")
	err := CmdEnroll(strings.Repeat("0", 26), "http://hort.example", "dev")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("enroll over http: %v", err)
	}
}

func mustSecretKey(t *testing.T, ref vault.VaultRef) []byte {
	t.Helper()
	sk, err := readSecretKey(ref)
	must(t, err)
	return sk
}
