package vault

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Sharing a secret by link (spec/vectors/share.json pins every output).
// The link https://<origin>/s/<share ID>#<link key> carries the link key only
// in its fragment. The recipient's normalized name goes through Argon2id and
// is combined with the link key into the share key, from which come the
// encryption key of the share ciphertext and the access token whose SHA-256
// the server stores.

// ShareLinkKeySize is the size of the random link key in the URL fragment.
const ShareLinkKeySize = 32

// NormalizeShareName is the one form of a recipient's name that Go and the
// browser derive keys from: NFKC, FoldKey (lowercase per code point, U+0130
// becoming "i" followed by U+0307, as in Unicode's full lowercase mapping),
// final sigma ς and σ alike, ß as "ss", NFKC again, then whitespace runs
// collapsed to one space and trimmed. Whitespace is Unicode White_Space.
func NormalizeShareName(name string) string {
	lower := strings.NewReplacer("ς", "σ", "ß", "ss").Replace(FoldKey(norm.NFKC.String(name)))
	return strings.Join(strings.FieldsFunc(norm.NFKC.String(lower), unicode.IsSpace), " ")
}

// ShareKeys are what a share key yields: the AES-256-GCM key of the share
// ciphertext and the access token the recipient presents to the server.
type ShareKeys struct {
	Enc   []byte
	Token []byte
}

// DeriveShareKeys derives the keys of share shareID for the name the
// recipient typed, always at production Argon2id parameters.
func DeriveShareKeys(name string, linkKey []byte, shareID string) (ShareKeys, error) {
	return deriveShareKeys(name, linkKey, shareID, DefaultArgonParams())
}

func deriveShareKeys(name string, linkKey []byte, shareID string, p ArgonParams) (ShareKeys, error) {
	_, k, err := shareKey(name, linkKey, shareID, p)
	if err != nil {
		return ShareKeys{}, err
	}
	id, _ := decodeID(shareID)
	enc, err := hkdf32(k, id, "hort/v4/share-enc")
	if err != nil {
		return ShareKeys{}, err
	}
	token, err := hkdf32(k, id, "hort/v4/share-token")
	if err != nil {
		return ShareKeys{}, err
	}
	return ShareKeys{Enc: enc, Token: token}, nil
}

// shareKey returns A = Argon2id(normalized name, salt = share ID bytes) and
// the share key K = HKDF(A XOR link key, share ID bytes, "hort/v4/share").
func shareKey(name string, linkKey []byte, shareID string, p ArgonParams) (a, k []byte, err error) {
	id, err := decodeID(shareID)
	if err != nil {
		return nil, nil, err
	}
	if len(linkKey) != ShareLinkKeySize {
		return nil, nil, errors.New("link key must be 32 bytes")
	}
	n := NormalizeShareName(name)
	if n == "" {
		return nil, nil, errors.New("name is empty")
	}
	a = argon2.IDKey([]byte(n), id, p.Time, p.Memory, p.Threads, KeySize)
	ikm := make([]byte, KeySize)
	for i := range ikm {
		ikm[i] = a[i] ^ linkKey[i]
	}
	k, err = hkdf32(ikm, id, "hort/v4/share")
	return a, k, err
}

// SharedSecret is the plaintext of a share: one snapshot of a secret's
// description and the chosen fields; field "" is the default field.
type SharedSecret struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Fields      []SharedField `json:"fields"`
}

type SharedField struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

func (s SharedSecret) validate() error {
	if s.Name == "" {
		return errors.New("shared secret has no name")
	}
	if len(s.Fields) == 0 {
		return errors.New("shared secret has no fields")
	}
	seen := map[string]bool{}
	for _, f := range s.Fields {
		if f.Field != "" && !fieldPattern.MatchString(f.Field) {
			return fmt.Errorf("shared field %q is invalid", f.Field)
		}
		if seen[f.Field] {
			return fmt.Errorf("shared field %q appears twice", f.Field)
		}
		seen[f.Field] = true
	}
	return nil
}

func shareAAD(id []byte) []byte { return canon("hort/v4/share-ct\n", id) }

// sealShare returns ct = nonce || AES-256-GCM(enc, JSON secret, aad).
func sealShare(enc []byte, shareID string, s SharedSecret, nonce []byte) ([]byte, error) {
	id, err := decodeID(shareID)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return sealEnvelope(enc, nonce, plaintext, shareAAD(id))
}

// OpenShare decrypts the ciphertext of share shareID.
func OpenShare(enc []byte, shareID string, ct []byte) (SharedSecret, error) {
	id, err := decodeID(shareID)
	if err != nil {
		return SharedSecret{}, err
	}
	plaintext, err := openEnvelope(enc, ct, shareAAD(id))
	if err != nil {
		return SharedSecret{}, errors.New("share does not open")
	}
	var s SharedSecret
	if err := strictJSON(plaintext, &s); err != nil {
		return SharedSecret{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	if err := s.validate(); err != nil {
		return SharedSecret{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	return s, nil
}

// shareMeta is the owner's encrypted view of a share, sealed under RK like
// request meta: the secret's name, the recipient's name as the owner typed
// it, and the shared field names.
type shareMeta struct {
	Name      string   `json:"name"`
	Recipient string   `json:"recipient"`
	Fields    []string `json:"fields"`
}

func shareMetaAAD(accountID, shareID []byte) []byte {
	return canon("hort/v4/share-meta\n", accountID, shareID)
}

func sealShareMeta(rk, accountID []byte, shareID string, m shareMeta, nonce []byte) ([]byte, error) {
	id, err := decodeID(shareID)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return sealEnvelope(rk, nonce, plaintext, shareMetaAAD(accountID, id))
}

func openShareMeta(rk, accountID []byte, shareID string, metaCT []byte) (shareMeta, error) {
	id, err := decodeID(shareID)
	if err != nil {
		return shareMeta{}, err
	}
	plaintext, err := openEnvelope(rk, metaCT, shareMetaAAD(accountID, id))
	if err != nil {
		return shareMeta{}, err
	}
	var m shareMeta
	if err := strictJSON(plaintext, &m); err != nil {
		return shareMeta{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	return m, nil
}

var errShareLink = errors.New("not a Hort share link (https://<host>/s/<id>#<key>)")

// ParseShareLink splits a share link into the origin that serves its API,
// the share ID and the link key. The key is unpadded base64url of 32 bytes.
func ParseShareLink(link string) (origin, shareID string, linkKey []byte, err error) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery {
		return "", "", nil, errShareLink
	}
	id, ok := strings.CutPrefix(u.EscapedPath(), "/s/")
	if !ok || !validID(id) {
		return "", "", nil, errShareLink
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(u.EscapedFragment())
	if err != nil || len(key) != ShareLinkKeySize {
		return "", "", nil, errShareLink
	}
	return "https://" + u.Host, id, key, nil
}
