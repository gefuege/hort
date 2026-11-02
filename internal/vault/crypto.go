package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize  = 32
	NonceSize = 12 // AES-256-GCM standard nonce
	KeySize   = 32 // AES-256

	DefaultArgonTime    = 3
	DefaultArgonMemory  = 64 * 1024 // 64 MB
	DefaultArgonThreads = 4
)

// ArgonParams holds the Argon2id parameters stored in the vault header.
type ArgonParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DefaultArgonParams returns the default Argon2id parameters.
func DefaultArgonParams() ArgonParams {
	return ArgonParams{
		Time:    DefaultArgonTime,
		Memory:  DefaultArgonMemory,
		Threads: DefaultArgonThreads,
	}
}

// DeriveKey derives an AES-256 key from a passphrase and salt using Argon2id.
func DeriveKey(passphrase []byte, salt []byte, params ArgonParams) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, KeySize)
}

// GenerateSalt creates a cryptographically random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	return salt, nil
}

// sealGCM encrypts plaintext under key with a fresh nonce and returns both.
// v3 binds the header prefix as AAD; GCM authenticates the nonce itself.
func sealGCM(plaintext, key, aad []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// openGCM decrypts ciphertext using key and nonce.
func openGCM(ciphertext, nonce, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("decryption failed — wrong key or corrupted vault")
	}
	return plaintext, nil
}

// deriveSessionKey computes the 32-byte session key for the given format.
// For Argon2id formats it derives from passphrase material using the stored
// salt and params. For raw-key formats it validates that material is already
// 32 bytes and returns it directly.
func deriveSessionKey(fmtInfo FormatInfo, material []byte) ([]byte, error) {
	switch fmtInfo.KDF {
	case KDFArgon2id:
		return DeriveKey(material, fmtInfo.Salt, fmtInfo.Argon), nil
	case KDFRawKey:
		if len(material) != KeySize {
			return nil, fmt.Errorf("raw-key vault requires %d-byte key, got %d", KeySize, len(material))
		}
		buf := make([]byte, KeySize)
		copy(buf, material)
		return buf, nil
	default:
		return nil, fmt.Errorf("unknown KDF mode %d", fmtInfo.KDF)
	}
}

// CreateEncrypted encodes plaintext as a v3 vault file using the given KDF mode
// and key material. Returns the full file bytes plus the derived session key.
func CreateEncrypted(plaintext, material []byte, kdf KDFMode) ([]byte, []byte, error) {
	var salt []byte
	params := DefaultArgonParams()

	switch kdf {
	case KDFArgon2id:
		var err error
		salt, err = GenerateSalt()
		if err != nil {
			return nil, nil, err
		}
	case KDFRawKey:
		salt = make([]byte, SaltSize)
		params = ArgonParams{}
	default:
		return nil, nil, fmt.Errorf("unknown KDF mode %d", kdf)
	}

	sessionKey, err := deriveSessionKey(FormatInfo{KDF: kdf, Salt: salt, Argon: params}, material)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, nonce, err := sealGCM(plaintext, sessionKey, buildV3Header(kdf, salt, params, nil)[:HeaderSize-NonceSize])
	if err != nil {
		return nil, nil, err
	}

	header := buildV3Header(kdf, salt, params, nonce)
	return append(header, ciphertext...), sessionKey, nil
}

// DecryptWithKey decrypts any supported vault format using a pre-derived session key.
func DecryptWithKey(data, sessionKey []byte) ([]byte, error) {
	info, err := ParseFormat(data)
	if err != nil {
		return nil, err
	}
	return openGCM(data[info.CipherAt:], info.Nonce, sessionKey, data[:HeaderSize-NonceSize])
}

// UnlockWithMaterial parses the vault header, derives a session key from the
// provided material per the stored KDF mode, verifies decryption succeeds, and
// returns the session key.
func UnlockWithMaterial(data, material []byte) ([]byte, error) {
	info, err := parseFormat(data, true)
	if err != nil {
		return nil, err
	}
	key, err := deriveSessionKey(info, material)
	if err != nil {
		return nil, err
	}
	var aad []byte
	if info.Version == 3 {
		aad = data[:HeaderSize-NonceSize]
	}
	if _, err := openGCM(data[info.CipherAt:], info.Nonce, key, aad); err != nil {
		return nil, errors.New("decryption failed — wrong passphrase/key or corrupted vault")
	}
	return key, nil
}

// EncryptPreservingFormat re-encrypts plaintext using the existing file's
// format (version, KDF, salt, argon params). A fresh nonce is generated for
// each write. The session key must match the existing vault's key.
func EncryptPreservingFormat(plaintext, sessionKey, existingRaw []byte) ([]byte, error) {
	info, err := ParseFormat(existingRaw)
	if err != nil {
		return nil, err
	}
	ciphertext, nonce, err := sealGCM(plaintext, sessionKey, existingRaw[:HeaderSize-NonceSize])
	if err != nil {
		return nil, err
	}
	header := buildV3Header(info.KDF, info.Salt, info.Argon, nonce)
	return append(header, ciphertext...), nil
}

// ProbeKey verifies that the given session key can decrypt the file.
func ProbeKey(data, sessionKey []byte) error {
	_, err := DecryptWithKey(data, sessionKey)
	return err
}
