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

// Share kinds: a share hands values over; a request also asks the recipient
// to send values back once (the answer, sealed under the same enc key).
const (
	ShareKindShare   = "share"
	ShareKindRequest = "request"
)

// SharedSecret is the plaintext of a share: one snapshot of a secret's
// description and the chosen fields; field "" is the default field. A
// request may carry empty values.
type SharedSecret struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Fields      []SharedField `json:"fields"`
	Kind        string        `json:"kind"`
}

type SharedField struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

func (s SharedSecret) validate() error {
	if s.Kind != ShareKindShare && s.Kind != ShareKindRequest {
		return fmt.Errorf("share kind %q is invalid", s.Kind)
	}
	return validateShared(s.Name, s.Fields)
}

func validateShared(name string, fields []SharedField) error {
	if name == "" {
		return errors.New("shared secret has no name")
	}
	if len(fields) == 0 {
		return errors.New("shared secret has no fields")
	}
	seen := map[string]bool{}
	for _, f := range fields {
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

func shareAnswerAAD(id []byte) []byte { return canon("hort/v4/share-answer\n", id) }

// shareKind reads the kind member of a share plaintext or meta: absent in
// the form of an older Hort, which reads as "share". The one place Go maps
// that form.
func shareKind(plaintext []byte) (string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &members); err != nil {
		return "", err
	}
	raw, ok := members["kind"]
	if !ok {
		return ShareKindShare, nil
	}
	var kind string
	if err := json.Unmarshal(raw, &kind); err != nil || (kind != ShareKindShare && kind != ShareKindRequest) {
		return "", fmt.Errorf("share kind %s is invalid", raw)
	}
	return kind, nil
}

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
	var w struct {
		Name        string        `json:"name"`
		Description string        `json:"description"`
		Fields      []SharedField `json:"fields"`
		Kind        string        `json:"kind,omitempty"`
	}
	if err := strictJSON(plaintext, &w); err != nil {
		return SharedSecret{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	kind, err := shareKind(plaintext)
	if err != nil {
		return SharedSecret{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	s := SharedSecret{Name: w.Name, Description: w.Description, Fields: w.Fields, Kind: kind}
	if err := s.validate(); err != nil {
		return SharedSecret{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	return s, nil
}

// shareAnswer is what the recipient of a request sends back: the secret's
// name, description and fields with the values as the recipient left them.
// It is sealed under the share's enc key with its own AAD tag.
type shareAnswer struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Fields      []SharedField `json:"fields"`
}

func sealShareAnswer(enc []byte, shareID string, a shareAnswer, nonce []byte) ([]byte, error) {
	id, err := decodeID(shareID)
	if err != nil {
		return nil, err
	}
	if err := validateShared(a.Name, a.Fields); err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	return sealEnvelope(enc, nonce, plaintext, shareAnswerAAD(id))
}

func openShareAnswer(enc []byte, shareID string, ct []byte) (shareAnswer, error) {
	id, err := decodeID(shareID)
	if err != nil {
		return shareAnswer{}, err
	}
	plaintext, err := openEnvelope(enc, ct, shareAnswerAAD(id))
	if err != nil {
		return shareAnswer{}, errors.New("answer does not open")
	}
	var a shareAnswer
	if err := strictJSON(plaintext, &a); err != nil {
		return shareAnswer{}, fmt.Errorf("answer %s: %w", shareID, err)
	}
	if err := validateShared(a.Name, a.Fields); err != nil {
		return shareAnswer{}, fmt.Errorf("answer %s: %w", shareID, err)
	}
	return a, nil
}

// shareMeta is the owner's encrypted view of a share, sealed under RK like
// request meta: the secret's name, the recipient's name as the owner typed
// it, the shared field names, the kind, the env and context of the row, and
// for a request the link key (unpadded base64url, "" for a share), so the
// owner can derive the share keys again to open the answer.
type shareMeta struct {
	Name      string   `json:"name"`
	Recipient string   `json:"recipient"`
	Fields    []string `json:"fields"`
	Kind      string   `json:"kind"`
	Env       string   `json:"env"`
	Context   string   `json:"context"`
	LinkKey   string   `json:"link_key"`
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
	// The form of an older Hort has only name, recipient and fields.
	var w struct {
		Name      string   `json:"name"`
		Recipient string   `json:"recipient"`
		Fields    []string `json:"fields"`
		Kind      string   `json:"kind,omitempty"`
		Env       *string  `json:"env,omitempty"`
		Context   *string  `json:"context,omitempty"`
		LinkKey   *string  `json:"link_key,omitempty"`
	}
	if err := strictJSON(plaintext, &w); err != nil {
		return shareMeta{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	kind, err := shareKind(plaintext)
	if err != nil {
		return shareMeta{}, fmt.Errorf("share %s: %w", shareID, err)
	}
	m := shareMeta{Name: w.Name, Recipient: w.Recipient, Fields: w.Fields, Kind: kind}
	if w.Kind != "" {
		if w.Env == nil || w.Context == nil || w.LinkKey == nil {
			return shareMeta{}, fmt.Errorf("share %s: metadata misses env, context or link_key", shareID)
		}
		m.Env, m.Context, m.LinkKey = *w.Env, *w.Context, *w.LinkKey
	} else if w.Env != nil || w.Context != nil || w.LinkKey != nil {
		return shareMeta{}, fmt.Errorf("share %s: metadata without kind carries env, context or link_key", shareID)
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(m.LinkKey)
	if m.Kind == ShareKindShare && m.LinkKey != "" || m.Kind == ShareKindRequest && (err != nil || len(key) != ShareLinkKeySize) {
		return shareMeta{}, fmt.Errorf("share %s: link_key does not fit kind %s", shareID, m.Kind)
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
