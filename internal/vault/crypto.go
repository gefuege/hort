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

// sealGCMWithNonce encrypts under key with the given nonce; callers draw it
// from randomNonce, only test vectors pin it.
func sealGCMWithNonce(plaintext, key, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
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

// DecryptWithKey decrypts a v3 vault with its file key.
func DecryptWithKey(data, sessionKey []byte) ([]byte, error) {
	info, err := ParseFormat(data)
	if err != nil {
		return nil, err
	}
	return openGCM(data[info.CipherAt:], info.Nonce, sessionKey, data[:HeaderSize-NonceSize])
}

// UnlockWithMaterial derives the v3 file key from the passphrase with the
// header's salt and parameters and verifies that it decrypts the vault.
func UnlockWithMaterial(data, passphrase []byte) ([]byte, error) {
	info, err := ParseFormat(data)
	if err != nil {
		return nil, err
	}
	key := DeriveKey(passphrase, info.Salt, info.Argon)
	if _, err := openGCM(data[info.CipherAt:], info.Nonce, key, data[:HeaderSize-NonceSize]); err != nil {
		return nil, errors.New("decryption failed — wrong passphrase or corrupted vault")
	}
	return key, nil
}
