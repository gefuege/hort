package vault

import (
	"encoding/binary"
	"errors"
)

// v3 is no runtime format any more (contract §1). This file, the v3 helpers
// in crypto.go and v3.go stay only so that `hort migrate` can read a v3 vault.

// KDFMode is the KDF byte of a v3 header.
type KDFMode uint8

// KDFArgon2id derives the v3 file key from the passphrase via Argon2id using
// the salt and parameters stored in the header.
const KDFArgon2id KDFMode = 0

const (
	// Layout: [magic:4][version:1][kdf:1][salt:32][time:4][memory:4][threads:1][nonce:12][ciphertext+tag:...]
	HeaderSize = len(V3Magic) + 1 + 1 + SaltSize + 4 + 4 + 1 + NonceSize
)

// v2Magic is only recognized to point a v2 vault at Hort 0.4.1.
const v2Magic = "HRT\x02"

// V3Magic marks the previous vault format.
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

// ParseFormat inspects a v3 vault file header and returns layout information.
func ParseFormat(data []byte) (FormatInfo, error) {
	if len(data) >= len(V3Magic) && string(data[:4]) == V3Magic {
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

		if version != 3 {
			return FormatInfo{}, errors.New("unsupported vault format version")
		}
		if kdf != KDFArgon2id {
			return FormatInfo{}, errors.New("unsupported vault KDF")
		}
		if err := checkArgon(params); err != nil {
			return FormatInfo{}, err
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

	return FormatInfo{}, errors.New("not a v3 hort vault")
}

// checkArgon bounds untrusted header parameters before any derivation runs:
// positive costs up to Hort's defaults, with no silent Argon memory clamp.
// Threads == 0 would make argon2.IDKey panic.
func checkArgon(p ArgonParams) error {
	if p.Time < 1 || p.Time > DefaultArgonTime ||
		p.Threads < 1 || p.Threads > DefaultArgonThreads ||
		p.Memory < 8*uint32(p.Threads) || p.Memory > DefaultArgonMemory {
		return errors.New("unsupported Argon2id parameters")
	}
	return nil
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
