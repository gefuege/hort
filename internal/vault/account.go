package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Server-side view of a vault: the passphrase slot, the account and device
// keys the sync client signs with, enrollment and merging pulled revisions
// (contract §2.2, §5, §6).

// Slot is the passphrase slot as the server stores it: slot_bytes and ak_sig.
type Slot struct {
	Version uint64
	Bytes   []byte
	AKSig   []byte
}

// Account is what the sync client needs from an unlocked vault.
type Account struct {
	ID     []byte
	Server string
	Keys   AccountKeys
	Slot   Slot
}

// OpenAccount reads the vault with VK. It takes no lock; a caller changes the
// vault only through UpdateVault.
func OpenAccount(ref VaultRef, vk []byte) (*VaultData, Account, error) {
	data, f, keys, err := loadV4(ref, vk)
	if err != nil {
		return nil, Account{}, err
	}
	slot := Slot{
		Version: f.SlotVersion,
		Bytes:   SlotBytes(ArgonSlotParams(f.SlotSalt, f.Argon), f.WrapNonce, f.WrappedVK),
		AKSig:   f.SlotSig,
	}
	return data, Account{ID: f.AccountID, Server: f.Server, Keys: keys, Slot: slot}, nil
}

// Key returns the device's Ed25519 key; validateBody guarantees a valid seed.
func (d Device) Key() ed25519.PrivateKey {
	seed, _ := hex.DecodeString(d.PrivateKey)
	return ed25519.NewKeyFromSeed(seed)
}

// uncanon splits a canon() encoding with the given tag into exactly n fields.
func uncanon(tag string, b []byte, n int) ([][]byte, bool) {
	if !bytes.HasPrefix(b, []byte(tag)) {
		return nil, false
	}
	b = b[len(tag):]
	var fields [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, false
		}
		size := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint64(size) > uint64(len(b)) {
			return nil, false
		}
		fields = append(fields, b[:size])
		b = b[size:]
	}
	return fields, len(fields) == n
}

// slotHeader parses slot_bytes from the untrusted server into header fields,
// with the same bounds parseV4 applies to a local header.
func slotHeader(accountID []byte, s Slot) (fileHeader, error) {
	bad := errors.New("the server sent a malformed passphrase slot")
	outer, ok := uncanon("hort/v4/slot-bytes\n", s.Bytes, 3)
	if !ok || len(outer[1]) != NonceSize || len(outer[2]) != wrappedVKSize || len(s.AKSig) != ed25519.SignatureSize {
		return fileHeader{}, bad
	}
	argon, ok := uncanon("hort/v4/argon\n", outer[0], 4)
	if !ok || len(argon[0]) != SaltSize || len(argon[1]) != 4 || len(argon[2]) != 4 || len(argon[3]) != 1 {
		return fileHeader{}, bad
	}
	p := ArgonParams{Time: binary.BigEndian.Uint32(argon[1]), Memory: binary.BigEndian.Uint32(argon[2]), Threads: argon[3][0]}
	if err := checkArgon(p); err != nil {
		return fileHeader{}, err
	}
	return fileHeader{
		AccountID:   accountID,
		SlotVersion: s.Version,
		SlotSalt:    argon[0],
		Argon:       p,
		SlotSig:     s.AKSig,
		WrapNonce:   outer[1],
		WrappedVK:   outer[2],
	}, nil
}

// OpenServerSlot unwraps VK from the passphrase slot the server returned for
// enrollment (§5.3 step 4). VK counts only if its AK is the account's ak_pub
// and signs the slot, so a server cannot hand out a slot of its own.
func OpenServerSlot(accountID []byte, s Slot, akPub []byte, passphrase string, secretKey []byte) ([]byte, error) {
	h, err := slotHeader(accountID, s)
	if err != nil {
		return nil, err
	}
	vk, err := h.openPassphraseSlot(passphrase, secretKey)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveAccountKeys(vk, accountID)
	if err != nil {
		return nil, err
	}
	pub := keys.AK.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, akPub) {
		return nil, errors.New("the server's account key does not belong to this vault key")
	}
	if !ed25519.Verify(pub, SlotSigMessage(accountID, PassphraseSlotID, s.Version, s.Bytes), s.AKSig) {
		return nil, errors.New("the server's passphrase slot is not signed by the account key")
	}
	return vk, nil
}

// CheckNewVault refuses to create a vault where one exists or where files of
// a vault moved away remain. The caller holds the vault lock.
func CheckNewVault(ref VaultRef) error {
	if exists, err := RefExists(ref); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("a vault already exists at %s", ref.Path)
	}
	// A vault moved away still needs its Secret Key, and its backup would be
	// replaced by the first save of the new vault.
	for _, path := range []string{ref.SecretKeyPath, BackupPathFor(ref)} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s exists and may belong to a vault moved away; remove it only if no vault uses it, then try again", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// WriteEnrolledVault writes an enrolled device's vault with the server slot
// and the pulled body: the Secret Key file first, then vault.enc (§5.3 step 6,
// §9.1). The caller saves the session.
func WriteEnrolledVault(ref VaultRef, server string, accountID []byte, s Slot, vk, secretKey []byte, data *VaultData) error {
	if err := checkServerURL(server); err != nil {
		return err
	}
	h, err := slotHeader(accountID, s)
	if err != nil {
		return err
	}
	h.Server = server
	keys, err := DeriveAccountKeys(vk, accountID)
	if err != nil {
		return err
	}
	file, err := sealV4(keys.FK, h, data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ref.Path), 0700); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}
	unlock, err := lockVault(ref)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	if err := CheckNewVault(ref); err != nil {
		return err
	}
	if err := writeSecretKeyFile(ref, secretKey); err != nil {
		return err
	}
	if err := writeFileAtomic(ref.Path, file, 0600); err != nil {
		return fmt.Errorf("writing vault: %w", err)
	}
	return nil
}

// Pulled is one revision decrypted from the server.
type Pulled struct {
	Name     string
	Revision Revision
}

// ValidatePulled applies the decoding rules of §3.4 to one pulled revision.
func ValidatePulled(p Pulled) error {
	return validateSecrets(map[string]Entry{p.Name: {Revisions: []Revision{p.Revision}}}, true)
}

// MergePulled forms the union by revision identity (§6.6, §6.7). A pulled
// revision whose ID the vault holds with other content can only come from a
// bug: the local revision stays and the ID is returned as a conflict.
func (d *VaultData) MergePulled(pulled []Pulled) (added int, conflicts []string) {
	known := make(map[string]Pulled)
	for name, entry := range d.Secrets {
		for _, r := range entry.Revisions {
			known[r.ID] = Pulled{name, r}
		}
	}
	for _, p := range pulled {
		if local, ok := known[p.Revision.ID]; ok {
			if !samePulled(local, p) {
				conflicts = append(conflicts, p.Revision.ID)
			}
			continue
		}
		known[p.Revision.ID] = p
		entry := d.Secrets[p.Name]
		entry.Revisions = append(entry.Revisions, p.Revision)
		d.Secrets[p.Name] = entry
		added++
	}
	return added, conflicts
}

func samePulled(a, b Pulled) bool {
	x, y := a.Revision, b.Revision
	sameTime := (x.RecordedAt == nil && y.RecordedAt == nil) ||
		(x.RecordedAt != nil && y.RecordedAt != nil && x.RecordedAt.Equal(*y.RecordedAt))
	return a.Name == b.Name && sameTime && x.Op == y.Op && x.Field == y.Field && x.Key == y.Key && x.Value == y.Value
}
