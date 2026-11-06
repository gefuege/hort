package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fastArgon keeps unit tests quick; production slots use DefaultArgonParams.
var fastArgon = ArgonParams{Time: 1, Memory: 8, Threads: 1}

// testVault creates a v4 vault at ref and returns VK.
func testVault(t *testing.T, ref VaultRef, passphrase string) []byte {
	t.Helper()
	nv := testCreate(t, ref, passphrase)
	return nv.VK
}

func testCreate(t *testing.T, ref VaultRef, passphrase string) NewVault {
	t.Helper()
	if ref.SecretKeyPath == "" {
		ref.SecretKeyPath = ref.Path + ".secret-key"
	}
	nv, err := createVault(ref, DefaultServer, "test-device", []byte(passphrase), fastArgon)
	if err != nil {
		t.Fatalf("createVault: %v", err)
	}
	return nv
}

// writeV3Fixture writes a synthetic v3 vault the way Hort 0.4 did.
func writeV3Fixture(t *testing.T, path string) []byte {
	t.Helper()
	params := fastArgon
	salt := bytes.Repeat([]byte{0x11}, SaltSize)
	key := DeriveKey([]byte("v3-passphrase"), salt, params)
	nonce, err := randomNonce()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealGCMWithNonce([]byte(`{"version":3,"source_id":"00000000000000000000000000000001","secrets":{}}`), key, nonce, buildV3Header(KDFArgon2id, salt, params, nil)[:HeaderSize-NonceSize])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(buildV3Header(KDFArgon2id, salt, params, nonce), ct...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestV4RoundTrip(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	nv := testCreate(t, ref, "correct horse")

	skText, err := ReadSecretKeyFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	if sk, err := ParseSecretKey(strings.TrimSpace(skText)); err != nil || !bytes.Equal(sk, nv.SecretKey) {
		t.Fatalf("Secret Key file: %v", err)
	}
	if info, err := os.Stat(ref.SecretKeyPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("Secret Key file mode: %v", err)
	}

	r := testRevision(t, "set", MakeLookupKey("prod", "*"), "value")
	if err := UpdateVault(ref, nv.VK, func(d *VaultData) error { d.Append("token", r); return nil }); err != nil {
		t.Fatal(err)
	}

	vk, err := UnlockVault(ref, []byte("correct horse"), nv.SecretKey)
	if err != nil || !bytes.Equal(vk, nv.VK) {
		t.Fatalf("unlock: %v", err)
	}
	data, raw, err := LoadVault(ref, vk)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := data.Secrets["token"].Resolve("", "prod", "x"); !ok || v != "value" {
		t.Fatal("value did not round-trip")
	}
	if data.Version != 4 || data.Sync.Registered || len(data.Sync.Pending) != 1 || data.Sync.Pending[0] != r.ID || data.Device.Name != "test-device" {
		t.Fatalf("body: %+v", data)
	}

	f, err := parseV4(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.AccountID, nv.AccountID) || f.Server != DefaultServer || f.SlotVersion != 1 || f.Argon != fastArgon {
		t.Fatalf("header: %+v", f.fileHeader)
	}
	keys, err := DeriveAccountKeys(vk, f.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	msg := SlotSigMessage(f.AccountID, PassphraseSlotID, f.SlotVersion, SlotBytes(ArgonSlotParams(f.SlotSalt, f.Argon), f.WrapNonce, f.WrappedVK))
	if !ed25519.Verify(keys.AK.Public().(ed25519.PublicKey), msg, f.SlotSig) {
		t.Fatal("slot_ak_sig does not verify against AK")
	}
}

func TestUnlockReportsWrongPassphrase(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	nv := testCreate(t, ref, "right")
	if _, err := UnlockVault(ref, []byte("wrong"), nv.SecretKey); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v", err)
	}
}

func TestChangePassphraseRetiresOldSlot(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	nv := testCreate(t, ref, "old")
	r := testRevision(t, "set", "*:*", "kept")
	if err := UpdateVault(ref, nv.VK, func(d *VaultData) error { d.Append("x", r); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := changePassphrase(ref, nv.VK, []byte("new"), nv.SecretKey, fastArgon); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseV4(raw)
	if err != nil || f.SlotVersion != 2 {
		t.Fatalf("slot_version: %v %d", err, f.SlotVersion)
	}
	if _, err := UnlockVault(ref, []byte("old"), nv.SecretKey); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase still opens the vault: %v", err)
	}
	backup := ref
	backup.Path = BackupPathFor(ref)
	if _, err := UnlockVault(backup, []byte("old"), nv.SecretKey); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase still opens the backup: %v", err)
	}
	vk, err := UnlockVault(ref, []byte("new"), nv.SecretKey)
	if err != nil || !bytes.Equal(vk, nv.VK) {
		t.Fatalf("new passphrase: %v", err)
	}
	data, _, err := LoadVault(ref, vk)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := data.Secrets["x"].Resolve("", "", ""); !ok || v != "kept" || len(data.Sync.Pending) != 1 {
		t.Fatal("rewrap changed the body")
	}
}

func TestCreateRefusesExistingVault(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	if err := os.MkdirAll(hortDirOrFatal(t), 0700); err != nil {
		t.Fatal(err)
	}
	want := writeV3Fixture(t, ref.Path)
	if _, err := createVault(ref, DefaultServer, "d", []byte("p"), fastArgon); err == nil {
		t.Fatal("init overwrote an existing vault")
	}
	if got, _ := os.ReadFile(ref.Path); !bytes.Equal(got, want) {
		t.Fatal("existing vault changed")
	}
	if _, err := os.Stat(ref.SecretKeyPath); !os.IsNotExist(err) {
		t.Fatal("refused init wrote a Secret Key")
	}
}

func hortDirOrFatal(t *testing.T) string {
	t.Helper()
	dir, err := HortDir()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestV3AndV2RejectedOutsideMigrate(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	if err := os.MkdirAll(hortDirOrFatal(t), 0700); err != nil {
		t.Fatal(err)
	}
	raw := writeV3Fixture(t, ref.Path)
	v3Key, err := UnlockWithMaterial(raw, []byte("v3-passphrase"))
	if err != nil {
		t.Fatalf("the migrate reader must still open v3: %v", err)
	}
	if _, _, err := LoadVault(ref, v3Key); !errors.Is(err, ErrV3Vault) {
		t.Fatalf("LoadVault: %v", err)
	}
	if err := UpdateVault(ref, v3Key, func(*VaultData) error { t.Fatal("update touched v3"); return nil }); !errors.Is(err, ErrV3Vault) {
		t.Fatalf("UpdateVault: %v", err)
	}
	if _, err := UnlockVault(ref, []byte("v3-passphrase"), make([]byte, SecretKeySize)); !errors.Is(err, ErrV3Vault) {
		t.Fatalf("UnlockVault: %v", err)
	}
	if _, err := ReadInfo(ref); !errors.Is(err, ErrV3Vault) || !strings.Contains(err.Error(), "hort migrate") {
		t.Fatalf("ReadInfo: %v", err)
	}
	if after, _ := os.ReadFile(ref.Path); !bytes.Equal(after, raw) {
		t.Fatal("rejection changed the v3 file")
	}

	v2 := append([]byte(nil), raw...)
	copy(v2, v2Magic)
	if _, err := parseV4(v2); !errors.Is(err, errV2Vault) {
		t.Fatalf("v2: %v", err)
	}
}

func TestV3HeaderIsAuthenticated(t *testing.T) {
	raw := writeV3Fixture(t, t.TempDir()+"/v3.enc")
	key, err := UnlockWithMaterial(raw, []byte("v3-passphrase"))
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
}

// headerWith encodes h followed by a body nonce and an empty GCM tag.
func headerWith(h fileHeader) []byte {
	return append(h.encode(), make([]byte, NonceSize+16)...)
}

func validHeader() fileHeader {
	return fileHeader{
		AccountID: make([]byte, AccountIDSize), Server: DefaultServer, SlotVersion: 1,
		SlotSalt: make([]byte, SaltSize), Argon: DefaultArgonParams(),
		SlotSig: make([]byte, ed25519.SignatureSize), WrapNonce: make([]byte, NonceSize), WrappedVK: make([]byte, wrappedVKSize),
	}
}

func TestParseV4RejectsTruncationAndBadLengths(t *testing.T) {
	full := headerWith(validHeader())
	if _, err := parseV4(full); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}
	for n := 0; n < len(full); n++ {
		if _, err := parseV4(full[:n]); err == nil {
			t.Fatalf("truncated header of %d bytes accepted", n)
		}
	}
	// server_len claims more bytes than the file holds.
	long := append([]byte(nil), full...)
	binary.BigEndian.PutUint16(long[5+AccountIDSize:], 0xffff)
	if _, err := parseV4(long); err == nil {
		t.Fatal("oversized server_len accepted")
	}
	badVersion := append([]byte(nil), full...)
	badVersion[4] = 5
	if _, err := parseV4(badVersion); err == nil {
		t.Fatal("wrong version byte accepted")
	}
	for _, server := range []string{"", "http://hort.pm", "hort.pm", "https://", "https://h\xffrt.pm", "ftp://hort.pm"} {
		h := validHeader()
		h.Server = server
		if _, err := parseV4(headerWith(h)); err == nil {
			t.Fatalf("server %q accepted", server)
		}
	}
}

func TestParseV4RejectsUnsafeArgonParameters(t *testing.T) {
	cases := []ArgonParams{
		{0, 65536, 4}, {3, 0, 4}, {3, 65536, 0},
		{4, 65536, 4}, {3, 65537, 4}, {3, 65536, 5},
		{^uint32(0), ^uint32(0), 255}, {1, 31, 4},
	}
	for _, params := range cases {
		t.Run(fmt.Sprint(params), func(t *testing.T) {
			h := validHeader()
			h.Argon = params
			if _, err := parseV4(headerWith(h)); err == nil || !strings.Contains(err.Error(), "Argon2id parameters") {
				t.Fatalf("unsafe Argon parameters accepted: %v", err)
			}
		})
	}
	for _, params := range []ArgonParams{{1, 8, 1}, {1, 32, 4}, DefaultArgonParams()} {
		h := validHeader()
		h.Argon = params
		if _, err := parseV4(headerWith(h)); err != nil {
			t.Fatalf("supported parameters %v rejected: %v", params, err)
		}
	}
}

func TestUnlockV4RejectsUnsafeArgonBeforeDerivation(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	if err := os.MkdirAll(hortDirOrFatal(t), 0700); err != nil {
		t.Fatal(err)
	}
	for _, params := range []ArgonParams{{0, 65536, 4}, {3, 0, 4}, {3, 65536, 0}, {^uint32(0), ^uint32(0), 255}} {
		h := validHeader()
		h.Argon = params
		if err := os.WriteFile(ref.Path, headerWith(h), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := UnlockVault(ref, []byte("p"), make([]byte, SecretKeySize)); err == nil || !strings.Contains(err.Error(), "Argon2id parameters") {
			t.Fatalf("unlock must reject %v before derivation: %v", params, err)
		}
	}
}

func TestV4HeaderIsAuthenticated(t *testing.T) {
	setHomeDir(t, t.TempDir())
	ref := primaryRefOrFatal(t)
	vk := testVault(t, ref, "p")
	raw, err := os.ReadFile(ref.Path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseV4(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Every byte before body_nonce; a flipped account ID also changes FK.
	for off := 0; off < len(f.prefix); off++ {
		altered := append([]byte(nil), raw...)
		altered[off] ^= 0x01
		af, err := parseV4(altered)
		if err != nil {
			continue
		}
		keys, err := DeriveAccountKeys(vk, af.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openV4(keys.FK, af); err == nil {
			t.Fatalf("header byte %d is not authenticated", off)
		}
	}
}

func TestBodyIsDecodedStrictly(t *testing.T) {
	valid := `{"version":4,"device":{"id":"00000000000000000000000000000001","name":"d","private_key":"` + strings.Repeat("00", 32) + `"},"sync":{"registered":false,"cursor":0,"pending":[],"devices_version":0,"known_devices":[]},"secrets":{}}`
	if _, err := decodeBody([]byte(valid)); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	for name, body := range map[string]string{
		"unknown field": strings.Replace(valid, `"secrets":{}`, `"secrets":{},"source_id":"x"`, 1),
		"null pending":  strings.Replace(valid, `"pending":[]`, `"pending":null`, 1),
		"missing sync":  strings.Replace(valid, `"sync":{"registered":false,"cursor":0,"pending":[],"devices_version":0,"known_devices":[]},`, ``, 1),
		"version 3":     strings.Replace(valid, `"version":4`, `"version":3`, 1),
		"short seed":    strings.Replace(valid, strings.Repeat("00", 32), "00", 1),
		"bad pending":   strings.Replace(valid, `"pending":[]`, `"pending":["x"]`, 1),
		"empty name":    strings.Replace(valid, `"secrets":{}`, `"secrets":{"":{"revisions":[]}}`, 1),
	} {
		if _, err := decodeBody([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
