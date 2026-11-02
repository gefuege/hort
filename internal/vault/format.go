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
	HeaderSize = len(V3Magic) + 1 + 1 + SaltSize + 4 + 4 + 1 + NonceSize
)

// V2Magic is accepted only for unlocking and explicit migration.
const V2Magic = "HRT\x02"

// V3Magic marks the current vault format.
const V3Magic = "HRT\x03"

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
	return parseFormat(data, false)
}

func parseFormat(data []byte, allowLegacy bool) (FormatInfo, error) {
	if len(data) >= len(V3Magic) && (string(data[:4]) == V3Magic || (allowLegacy && string(data[:4]) == V2Magic)) {
		if len(data) < HeaderSize {
			return FormatInfo{}, errors.New("vault file too short for header")
		}
		off := len(V3Magic)
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

		if (version != 3 || string(data[:4]) != V3Magic) && !(allowLegacy && version == 2 && string(data[:4]) == V2Magic) {
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
			Version:  int(version),
			KDF:      kdf,
			Salt:     salt,
			Argon:    params,
			Nonce:    nonce,
			CipherAt: HeaderSize,
		}, nil
	}

	return FormatInfo{}, errors.New("not a v3 hort vault — legacy v2 requires explicit `hort migrate`")
}

// buildV3Header serializes a v3 header.
func buildV3Header(kdf KDFMode, salt []byte, params ArgonParams, nonce []byte) []byte {
	h := make([]byte, HeaderSize)
	off := copy(h, V3Magic)
	h[off] = 3
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
