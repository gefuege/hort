package vault

import (
	"encoding/binary"
	"errors"
)

// KDFMode selects how a vault's file-level key is derived from mount material.
type KDFMode uint8

const (
	// KDFArgon2id derives the AES key from a passphrase via Argon2id using the
	// salt and parameters stored in the vault header. This is the original Hort
	// format and the default for the primary vault.
	KDFArgon2id KDFMode = 0

	// KDFRawKey uses the supplied 32-byte material directly as the AES key,
	// skipping any KDF. Used for machine-mounted sources that carry their own
	// key (e.g. a Fachwerk instance's FACHWERK_SECRETS_MASTER_KEY).
	KDFRawKey KDFMode = 1
)

const (
	// Layout: [magic:4][version:1][kdf:1][salt:32][time:4][memory:4][threads:1][nonce:12][ciphertext+tag:...]
	V2HeaderSize = len(V2Magic) + 1 + 1 + SaltSize + 4 + 4 + 1 + NonceSize
)

// V2Magic is the 4-byte prefix that marks a vault file.
const V2Magic = "HRT\x02"

// FormatInfo describes the header of a vault file after parsing.
type FormatInfo struct {
	Version  int
	KDF      KDFMode
	Salt     []byte
	Argon    ArgonParams
	Nonce    []byte
	CipherAt int
}

// ParseFormat inspects the vault file header and returns layout information.
func ParseFormat(data []byte) (FormatInfo, error) {
	if len(data) >= len(V2Magic) && string(data[0:len(V2Magic)]) == V2Magic {
		if len(data) < V2HeaderSize {
			return FormatInfo{}, errors.New("vault file too short for v2 header")
		}
		off := len(V2Magic)
		version := data[off]
		off++
		kdf := KDFMode(data[off])
		off++
		salt := data[off : off+SaltSize]
		off += SaltSize
		params := ArgonParams{
			Time:    binary.BigEndian.Uint32(data[off : off+4]),
			Memory:  binary.BigEndian.Uint32(data[off+4 : off+8]),
			Threads: data[off+8],
		}
		off += 9
		nonce := data[off : off+NonceSize]
		off += NonceSize

		if version != 2 {
			return FormatInfo{}, errors.New("unsupported vault format version")
		}
		// Headers are untrusted until decryption succeeds. Support positive
		// Argon costs up to Hort's defaults, with no silent Argon memory clamp.
		if kdf == KDFArgon2id && (params.Time < 1 || params.Time > DefaultArgonTime ||
			params.Threads < 1 || params.Threads > DefaultArgonThreads ||
			params.Memory < 8*uint32(params.Threads) || params.Memory > DefaultArgonMemory) {
			return FormatInfo{}, errors.New("unsupported Argon2id parameters")
		}
		return FormatInfo{
			Version:  2,
			KDF:      kdf,
			Salt:     salt,
			Argon:    params,
			Nonce:    nonce,
			CipherAt: V2HeaderSize,
		}, nil
	}

	return FormatInfo{}, errors.New("not a hort vault file (unsupported or legacy format)")
}

// buildV2Header serializes a v2 header.
func buildV2Header(kdf KDFMode, salt []byte, params ArgonParams, nonce []byte) []byte {
	h := make([]byte, V2HeaderSize)
	off := copy(h, V2Magic)
	h[off] = 2
	off++
	h[off] = byte(kdf)
	off++
	copy(h[off:off+SaltSize], salt)
	off += SaltSize
	binary.BigEndian.PutUint32(h[off:off+4], params.Time)
	binary.BigEndian.PutUint32(h[off+4:off+8], params.Memory)
	h[off+8] = params.Threads
	off += 9
	copy(h[off:off+NonceSize], nonce)
	return h
}
