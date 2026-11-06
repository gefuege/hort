package vault

import (
	"crypto/sha256"
	"errors"
	"strings"
)

// Secret Key (§2.5) and account ID (§2.6) text forms. Both put 16 bytes into
// 26 Crockford base32 symbols, most significant bit first; the last symbol
// carries the final 3 bits followed by 2 zero bits.

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// secretKeyPrefix opens the displayed Secret Key and names format v4.
const secretKeyPrefix = "H4"

var (
	ErrSecretKeyMistyped = errors.New("Secret Key mistyped")
	errAccountID         = errors.New("invalid account id")
)

func encode128(b []byte) string {
	if len(b) != 16 {
		panic("vault: 16-byte value required")
	}
	out := make([]byte, 0, 26)
	var acc uint32
	bits := 0
	for _, x := range b {
		acc = acc<<8 | uint32(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, crockford[(acc>>bits)&31])
		}
	}
	return string(append(out, crockford[(acc<<(5-bits))&31]))
}

// decode128 reverses encode128 on normalized input and rejects set padding bits.
func decode128(s string) ([]byte, bool) {
	if len(s) != 26 {
		return nil, false
	}
	out := make([]byte, 0, 16)
	var acc uint32
	bits := 0
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(crockford, s[i])
		if v < 0 {
			return nil, false
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out, acc&3 == 0
}

// NormalizeCrockford upper-cases ASCII, drops dashes and spaces and reads
// I and L as 1 and O as 0. Every other byte passes through and fails decoding.
func NormalizeCrockford(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case '-', ' ':
			continue
		case 'I', 'L':
			c = '1'
		case 'O':
			c = '0'
		}
		out = append(out, c)
	}
	return string(out)
}

func secretKeyCheck(key []byte) byte {
	sum := sha256.Sum256(append([]byte("hort/v4/sk-check\n"), key...))
	return crockford[sum[0]>>3]
}

// FormatSecretKey renders a 16-byte Secret Key as H4-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-C.
func FormatSecretKey(key []byte) string {
	d := encode128(key)
	return strings.Join([]string{secretKeyPrefix, d[0:6], d[6:11], d[11:16], d[16:21], d[21:26], string(secretKeyCheck(key))}, "-")
}

// ParseSecretKey reads a typed Secret Key, with or without the H4 prefix.
// Any malformed input, including a wrong check symbol, is ErrSecretKeyMistyped.
func ParseSecretKey(s string) ([]byte, error) {
	n := NormalizeCrockford(s)
	if len(n) == 29 && strings.HasPrefix(n, secretKeyPrefix) {
		n = n[2:]
	}
	if len(n) != 27 {
		return nil, ErrSecretKeyMistyped
	}
	key, ok := decode128(n[:26])
	if !ok || n[26] != secretKeyCheck(key) {
		return nil, ErrSecretKeyMistyped
	}
	return key, nil
}

// FormatAccountID renders 16 account ID bytes as 26 lowercase symbols.
func FormatAccountID(id []byte) string {
	return strings.ToLower(encode128(id))
}

// ParseAccountID reads an account ID with the same tolerance as a Secret Key.
func ParseAccountID(s string) ([]byte, error) {
	id, ok := decode128(NormalizeCrockford(s))
	if !ok {
		return nil, errAccountID
	}
	return id, nil
}
