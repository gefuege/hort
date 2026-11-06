package vault

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"unicode/utf8"
)

// v4 file layout (contract §2.3). The header is plaintext and untrusted until
// the body opens; the body AEAD under FK authenticates every header byte.

const (
	// V4Magic marks the current vault format.
	V4Magic = "HRT\x04"
	// DefaultServer is the server URL of a vault created without --server.
	DefaultServer = "https://hort.pm"

	wrappedVKSize = KeySize + 16
	// v4FixedSize is every header byte except server_url, up to body_nonce.
	v4FixedSize = len(V4Magic) + 1 + AccountIDSize + 2 + 8 + SaltSize + 4 + 4 + 1 + ed25519.SignatureSize + NonceSize + wrappedVKSize
	// v4MinSize adds body_nonce and the GCM tag of an empty body.
	v4MinSize = v4FixedSize + NonceSize + 16
)

var (
	// ErrV3Vault rejects a v3 vault outside `hort migrate` (contract §1, §9.2).
	ErrV3Vault = errors.New("this vault is in the old v3 format; run `hort migrate` to convert it. Before migrating, run `hort sync` with Hort 0.4.x on every device. Then migrate on one device and enroll the others")
	errV2Vault = errors.New("this vault is in the old v2 format; migrate it with Hort 0.4.1 first, then run `hort migrate`")
	// ErrWrongPassphrase is an AEAD failure while unwrapping the passphrase slot.
	ErrWrongPassphrase = errors.New("wrong passphrase")
)

// fileHeader holds the header fields of §2.3; the slot is the one passphrase slot.
type fileHeader struct {
	AccountID   []byte
	Server      string
	SlotVersion uint64
	SlotSalt    []byte
	Argon       ArgonParams
	SlotSig     []byte
	WrapNonce   []byte
	WrappedVK   []byte
}

// v4File is a parsed vault file: header, the header bytes before body_nonce
// (AAD input) and the sealed body.
type v4File struct {
	fileHeader
	prefix    []byte
	bodyNonce []byte
	body      []byte
}

// encode serializes the header up to, not including, body_nonce.
func (h fileHeader) encode() []byte {
	out := make([]byte, 0, v4FixedSize+len(h.Server))
	out = append(out, V4Magic...)
	out = append(out, 4)
	out = append(out, h.AccountID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(h.Server)))
	out = append(out, h.Server...)
	out = binary.BigEndian.AppendUint64(out, h.SlotVersion)
	out = append(out, h.SlotSalt...)
	out = binary.BigEndian.AppendUint32(out, h.Argon.Time)
	out = binary.BigEndian.AppendUint32(out, h.Argon.Memory)
	out = append(out, h.Argon.Threads)
	out = append(out, h.SlotSig...)
	out = append(out, h.WrapNonce...)
	return append(out, h.WrappedVK...)
}

// parseV4 checks every untrusted length and the Argon2id bounds, so a caller
// can derive the slot KEK from the result without further checks.
func parseV4(data []byte) (v4File, error) {
	if len(data) >= len(V4Magic) {
		switch string(data[:len(V4Magic)]) {
		case V3Magic:
			return v4File{}, ErrV3Vault
		case v2Magic:
			return v4File{}, errV2Vault
		}
	}
	if len(data) < len(V4Magic) || string(data[:len(V4Magic)]) != V4Magic {
		return v4File{}, errors.New("not a hort vault")
	}
	if len(data) < v4MinSize {
		return v4File{}, errors.New("vault file too short for header")
	}
	if data[4] != 4 {
		return v4File{}, errors.New("unsupported vault format version")
	}
	var f v4File
	off := 5
	take := func(n int) []byte {
		b := data[off : off+n]
		off += n
		return b
	}
	f.AccountID = take(AccountIDSize)
	serverLen := int(binary.BigEndian.Uint16(take(2)))
	if len(data) < v4MinSize+serverLen {
		return v4File{}, errors.New("vault file too short for its server URL")
	}
	f.Server = string(take(serverLen))
	if err := checkServerURL(f.Server); err != nil {
		return v4File{}, err
	}
	f.SlotVersion = binary.BigEndian.Uint64(take(8))
	f.SlotSalt = take(SaltSize)
	f.Argon.Time = binary.BigEndian.Uint32(take(4))
	f.Argon.Memory = binary.BigEndian.Uint32(take(4))
	f.Argon.Threads = take(1)[0]
	if err := checkArgon(f.Argon); err != nil {
		return v4File{}, err
	}
	f.SlotSig = take(ed25519.SignatureSize)
	f.WrapNonce = take(NonceSize)
	f.WrappedVK = take(wrappedVKSize)
	f.prefix = data[:off]
	f.bodyNonce = take(NonceSize)
	f.body = data[off:]
	return f, nil
}

// checkServerURL enforces "UTF-8 (https only)" of §2.3 and the u16 length.
func checkServerURL(s string) error {
	if len(s) > math.MaxUint16 || !utf8.ValidString(s) {
		return errors.New("invalid server URL")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("server URL must be an https URL: %q", s)
	}
	return nil
}

func fileAAD(prefix []byte) []byte { return canon("hort/v4/file\n", prefix) }

// sealV4 builds the complete file: header, fresh body_nonce, sealed body.
func sealV4(fk []byte, h fileHeader, data *VaultData) ([]byte, error) {
	if err := validateBody(data); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling vault: %w", err)
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	prefix := h.encode()
	ct, err := sealGCMWithNonce(plaintext, fk, nonce, fileAAD(prefix))
	if err != nil {
		return nil, err
	}
	return append(append(prefix, nonce...), ct...), nil
}

// openV4 opens the body with FK; a wrong key and any changed header byte fail alike.
func openV4(fk []byte, f v4File) (*VaultData, error) {
	plaintext, err := openGCM(f.body, f.bodyNonce, fk, fileAAD(f.prefix))
	if err != nil {
		return nil, err
	}
	return decodeBody(plaintext)
}

// sealPassphraseSlot wraps vk in a new passphrase slot with a fresh salt and
// signs it with AK (§2.2, §2.3).
func (h *fileHeader) sealPassphraseSlot(vk []byte, ak ed25519.PrivateKey, passphrase string, secretKey []byte, version uint64, params ArgonParams) error {
	salt, err := GenerateSalt()
	if err != nil {
		return err
	}
	kek, err := PassphraseKEK(passphrase, secretKey, h.AccountID, salt, params)
	if err != nil {
		return err
	}
	slotParams := ArgonSlotParams(salt, params)
	nonce, wrapped, err := WrapVK(kek, vk, h.AccountID, PassphraseSlotID, version, slotParams)
	if err != nil {
		return err
	}
	h.SlotVersion, h.SlotSalt, h.Argon, h.WrapNonce, h.WrappedVK = version, salt, params, nonce, wrapped
	h.SlotSig = ed25519.Sign(ak, SlotSigMessage(h.AccountID, PassphraseSlotID, version, SlotBytes(slotParams, nonce, wrapped)))
	return nil
}

// openPassphraseSlot unwraps VK. The header must come from parseV4, which
// bounds the Argon2id parameters.
func (h fileHeader) openPassphraseSlot(passphrase string, secretKey []byte) ([]byte, error) {
	kek, err := PassphraseKEK(passphrase, secretKey, h.AccountID, h.SlotSalt, h.Argon)
	if err != nil {
		return nil, err
	}
	vk, err := UnwrapVK(kek, h.WrapNonce, h.WrappedVK, h.AccountID, PassphraseSlotID, h.SlotVersion, ArgonSlotParams(h.SlotSalt, h.Argon))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return vk, nil
}
