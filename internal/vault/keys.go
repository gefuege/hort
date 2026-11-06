package vault

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// v4 key hierarchy, slots, envelopes and request signing (contract §2, §6, §7).
// spec/vectors pins every output of this file.

const (
	AccountIDSize = 16
	SecretKeySize = 16
	PRFSize       = 32

	// PassphraseSlotID is the slot_id of the one passphrase slot, locally and on the server.
	PassphraseSlotID = "passphrase"
	// AKDeviceID is the device field of requests signed with AK instead of a device key.
	AKDeviceID = "ak"
)

// canon is the length-prefixed encoding of every v4 signature and AAD (§2.1):
// tag || u32be(len f1) || f1 || ... || u32be(len fn) || fn.
func canon(tag string, fields ...[]byte) []byte {
	n := len(tag)
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := make([]byte, 0, n)
	out = append(out, tag...)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func be64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func hkdf32(ikm, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, salt, info, KeySize)
}

// AccountKeys are the subkeys derived from the vault key VK.
type AccountKeys struct {
	FK []byte             // local file AEAD
	RK []byte             // revision and request envelopes
	AK ed25519.PrivateKey // account auth key, seeded by AKs
}

// DeriveAccountKeys derives FK, RK and AK from VK, salted with the account ID.
func DeriveAccountKeys(vk, accountID []byte) (AccountKeys, error) {
	if len(vk) != KeySize || len(accountID) != AccountIDSize {
		return AccountKeys{}, errors.New("vault key must be 32 bytes and account id 16 bytes")
	}
	fk, err := hkdf32(vk, accountID, "hort/v4/file")
	if err != nil {
		return AccountKeys{}, err
	}
	rk, err := hkdf32(vk, accountID, "hort/v4/revision")
	if err != nil {
		return AccountKeys{}, err
	}
	seed, err := hkdf32(vk, accountID, "hort/v4/account-auth")
	if err != nil {
		return AccountKeys{}, err
	}
	return AccountKeys{FK: fk, RK: rk, AK: ed25519.NewKeyFromSeed(seed)}, nil
}

// PassphraseKEK derives the passphrase slot KEK by 2SKD (§2.2). Callers bound
// untrusted Argon2id parameters before calling it.
func PassphraseKEK(passphrase string, secretKey, accountID, salt []byte, p ArgonParams) ([]byte, error) {
	if len(secretKey) != SecretKeySize || len(accountID) != AccountIDSize || len(salt) != SaltSize {
		return nil, errors.New("secret key and account id must be 16 bytes and slot salt 32 bytes")
	}
	a := passphraseArgon(passphrase, salt, p)
	s, err := secretKeyHalf(secretKey, accountID)
	if err != nil {
		return nil, err
	}
	for i := range a {
		a[i] ^= s[i]
	}
	return hkdf32(a, salt, "hort/v4/kek")
}

// passphraseArgon is A of §2.2: Argon2id over the NFC form of the passphrase.
func passphraseArgon(passphrase string, salt []byte, p ArgonParams) []byte {
	return argon2.IDKey([]byte(norm.NFC.String(passphrase)), salt, p.Time, p.Memory, p.Threads, KeySize)
}

// secretKeyHalf is S of §2.2.
func secretKeyHalf(secretKey, accountID []byte) ([]byte, error) {
	return hkdf32(secretKey, accountID, "hort/v4/secret-key")
}

// PRFEvalSalt is the WebAuthn PRF eval input for an account (§2.2).
func PRFEvalSalt(accountID []byte) []byte {
	sum := sha256.Sum256(append([]byte("hort/v4/prf\n"), accountID...))
	return sum[:]
}

// PasskeyKEK derives a passkey slot KEK from the 32-byte PRF output (§2.2).
func PasskeyKEK(prf, accountID []byte) ([]byte, error) {
	if len(prf) != PRFSize || len(accountID) != AccountIDSize {
		return nil, errors.New("PRF output must be 32 bytes and account id 16 bytes")
	}
	return hkdf32(prf, accountID, "hort/v4/kek-passkey")
}

// ArgonSlotParams is slot_params of the passphrase slot (§2.3).
func ArgonSlotParams(salt []byte, p ArgonParams) []byte {
	return canon("hort/v4/argon\n", salt, be32(p.Time), be32(p.Memory), []byte{p.Threads})
}

// PasskeySlot returns slot_id and slot_params of the passkey slot of a WebAuthn
// credential (§2.2, spec/vectors/passkey-slot.json): cred_hash =
// SHA-256(credential ID), slot_id = "passkey:" + hex(cred_hash) and
// slot_params = canon("hort/v4/passkey\n", cred_hash).
func PasskeySlot(credentialID []byte) (slotID string, params []byte) {
	sum := sha256.Sum256(credentialID)
	return "passkey:" + hex.EncodeToString(sum[:]), canon("hort/v4/passkey\n", sum[:])
}

func slotAAD(accountID []byte, slotID string, version uint64, params []byte) []byte {
	return canon("hort/v4/slot\n", accountID, []byte(slotID), be64(version), params)
}

// WrapVK seals VK under a slot KEK with a fresh nonce (§2.2).
func WrapVK(kek, vk, accountID []byte, slotID string, version uint64, params []byte) (nonce, wrapped []byte, err error) {
	if nonce, err = randomNonce(); err != nil {
		return nil, nil, err
	}
	wrapped, err = wrapVK(kek, vk, accountID, slotID, version, params, nonce)
	return nonce, wrapped, err
}

func wrapVK(kek, vk, accountID []byte, slotID string, version uint64, params, nonce []byte) ([]byte, error) {
	if len(vk) != KeySize {
		return nil, errors.New("vault key must be 32 bytes")
	}
	return sealGCMWithNonce(vk, kek, nonce, slotAAD(accountID, slotID, version, params))
}

// UnwrapVK opens a slot; a wrong KEK and a tampered slot fail alike.
func UnwrapVK(kek, nonce, wrapped, accountID []byte, slotID string, version uint64, params []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("invalid slot nonce")
	}
	vk, err := openGCM(wrapped, nonce, kek, slotAAD(accountID, slotID, version, params))
	if err != nil {
		return nil, errors.New("slot does not open — wrong key or corrupted slot")
	}
	if len(vk) != KeySize {
		return nil, errors.New("slot holds no 32-byte vault key")
	}
	return vk, nil
}

// SlotBytes is the one encoding of a slot's content that local file and
// server share inside ak_sig (Revision 2.1, point 2).
func SlotBytes(params, nonce, wrapped []byte) []byte {
	return canon("hort/v4/slot-bytes\n", params, nonce, wrapped)
}

// SlotSigMessage is what AK signs as a slot's ak_sig (§2.2).
func SlotSigMessage(accountID []byte, slotID string, version uint64, slotBytes []byte) []byte {
	return canon("hort/v4/slot-sig\n", accountID, []byte(slotID), be64(version), slotBytes)
}

// sealEnvelope returns nonce || AES-256-GCM(key, plaintext, aad).
func sealEnvelope(key, nonce, plaintext, aad []byte) ([]byte, error) {
	ct, err := sealGCMWithNonce(plaintext, key, nonce, aad)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), nonce...), ct...), nil
}

func openEnvelope(key, envelope, aad []byte) ([]byte, error) {
	if len(envelope) < NonceSize+16 {
		return nil, errors.New("envelope too short")
	}
	return openGCM(envelope[NonceSize:], envelope[:NonceSize], key, aad)
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return nonce, nil
}

func decodeID(id string) ([]byte, error) {
	if !validID(id) {
		return nil, fmt.Errorf("invalid identity %q", id)
	}
	return hex.DecodeString(id)
}

type revisionEnvelope struct {
	Name     string   `json:"name"`
	Revision Revision `json:"revision"`
}

// marshalEnvelope is the one encoding of the revision envelope plaintext,
// shared by sealing and the write size check.
func marshalEnvelope(name string, r Revision) ([]byte, error) {
	return json.Marshal(revisionEnvelope{Name: name, Revision: r})
}

// SealRevision encrypts one revision for the wire (§6.4).
func SealRevision(rk, accountID []byte, name string, r Revision) ([]byte, error) {
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	return sealRevision(rk, accountID, name, r, nonce)
}

func sealRevision(rk, accountID []byte, name string, r Revision, nonce []byte) ([]byte, error) {
	id, err := decodeID(r.ID)
	if err != nil {
		return nil, err
	}
	plaintext, err := marshalEnvelope(name, r)
	if err != nil {
		return nil, err
	}
	return sealEnvelope(rk, nonce, plaintext, canon("hort/v4/rev\n", accountID, id))
}

// OpenRevision decrypts an envelope received under revision ID id and checks
// that the sealed revision carries that same ID.
func OpenRevision(rk, accountID []byte, id string, envelope []byte) (string, Revision, error) {
	idBytes, err := decodeID(id)
	if err != nil {
		return "", Revision{}, err
	}
	plaintext, err := openEnvelope(rk, envelope, canon("hort/v4/rev\n", accountID, idBytes))
	if err != nil {
		return "", Revision{}, err
	}
	var env revisionEnvelope
	if err := strictJSON(plaintext, &env); err != nil {
		return "", Revision{}, fmt.Errorf("revision %s: %w", id, err)
	}
	if env.Revision.ID != id {
		return "", Revision{}, fmt.Errorf("revision %s: envelope holds revision %s", id, env.Revision.ID)
	}
	return env.Name, env.Revision, nil
}

// RequestMeta is the encrypted metadata of an agent request (§7.2 step 3).
type RequestMeta struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Field       string `json:"field"`
	Env         string `json:"env"`
	Context     string `json:"context"`
}

// requestMetaAAD uses its own tag, apart from the request signature's
// "hort/v4/req\n" (Kopf decision, spec/vectors/README.md).
func requestMetaAAD(accountID, requestID []byte) []byte {
	return canon("hort/v4/req-meta\n", accountID, requestID)
}

// SealRequestMeta produces meta_ct = nonce || AES-256-GCM(RK, meta JSON).
func SealRequestMeta(rk, accountID []byte, requestID string, m RequestMeta) ([]byte, error) {
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	return sealRequestMeta(rk, accountID, requestID, m, nonce)
}

func sealRequestMeta(rk, accountID []byte, requestID string, m RequestMeta, nonce []byte) ([]byte, error) {
	id, err := decodeID(requestID)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return sealEnvelope(rk, nonce, plaintext, requestMetaAAD(accountID, id))
}

// OpenRequestMeta decrypts meta_ct of request requestID.
func OpenRequestMeta(rk, accountID []byte, requestID string, metaCT []byte) (RequestMeta, error) {
	id, err := decodeID(requestID)
	if err != nil {
		return RequestMeta{}, err
	}
	plaintext, err := openEnvelope(rk, metaCT, requestMetaAAD(accountID, id))
	if err != nil {
		return RequestMeta{}, err
	}
	var m RequestMeta
	if err := strictJSON(plaintext, &m); err != nil {
		return RequestMeta{}, fmt.Errorf("request %s: %w", requestID, err)
	}
	return m, nil
}

// RequestMessage is the byte string a device key or AK signs for Hort-Signature
// (§6.2). deviceID is the decoded device ID, or []byte(AKDeviceID).
func RequestMessage(accountID, deviceID []byte, method, pathWithQuery string, timestamp uint64, body []byte) []byte {
	sum := sha256.Sum256(body)
	return canon("hort/v4/req\n", accountID, deviceID, []byte(method), []byte(pathWithQuery), be64(timestamp), sum[:])
}
