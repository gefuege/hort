package mcp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/vault"
)

// This file stands in for the browser page /r/<id> on the MCP path only: a
// software passkey (ES256, attestation "none") signs in, then fulfill is
// built the way contract §7.3 describes. It does not test /r.

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func cborHead(major, n int) []byte {
	switch {
	case n < 24:
		return []byte{byte(major<<5 | n)}
	case n < 256:
		return []byte{byte(major<<5 | 24), byte(n)}
	}
	return []byte{byte(major<<5 | 25), byte(n >> 8), byte(n)}
}

func cborInt(n int) []byte {
	if n >= 0 {
		return cborHead(0, n)
	}
	return cborHead(1, -1-n)
}
func cborBytes(b []byte) []byte { return append(cborHead(2, len(b)), b...) }
func cborText(s string) []byte  { return append(cborHead(3, len(s)), s...) }

type passkey struct {
	key    *ecdsa.PrivateKey
	credID []byte
	origin string
	rpID   string
}

func (p passkey) authData(flags byte, attested bool, cose []byte) []byte {
	rp := sha256.Sum256([]byte(p.rpID))
	out := append(rp[:], flags, 0, 0, 0, 0)
	if attested {
		out = append(out, make([]byte, 16)...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(p.credID)))
		out = append(append(out, p.credID...), cose...)
	}
	return out
}

func (p passkey) clientData(typ, challenge string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": p.origin, "crossOrigin": false})
	return raw
}

// browserSession registers a passkey for the account through the AK-signed
// calls and signs in with it; it returns the session cookie.
func browserSession(t *testing.T, target string, ak api.Client) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	p := passkey{key: must1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)), credID: make([]byte, 20), origin: u.Scheme + "://" + u.Host, rpID: u.Hostname()}
	_, _ = rand.Read(p.credID)

	var opts struct {
		Challenge string `json:"challenge"`
	}
	if err := ak.Do("POST", "/webauthn/register/options", nil, &opts); err != nil {
		t.Fatal(err)
	}
	pub := p.key.PublicKey
	cose := bytes.Join([][]byte{{0xa5}, cborInt(1), cborInt(2), cborInt(3), cborInt(-7), cborInt(-1), cborInt(1),
		cborInt(-2), cborBytes(pub.X.FillBytes(make([]byte, 32))), cborInt(-3), cborBytes(pub.Y.FillBytes(make([]byte, 32)))}, nil)
	attestation := bytes.Join([][]byte{{0xa3}, cborText("fmt"), cborText("none"), cborText("attStmt"), {0xa0},
		cborText("authData"), cborBytes(p.authData(0x01|0x04|0x40, true, cose))}, nil)
	register := map[string]any{"response": map[string]any{
		"id": b64u(p.credID), "rawId": b64u(p.credID), "type": "public-key",
		"response":               map[string]any{"clientDataJSON": b64u(p.clientData("webauthn.create", opts.Challenge)), "attestationObject": b64u(attestation), "transports": []string{"internal"}},
		"clientExtensionResults": map[string]any{},
	}, "slot": nil}
	if err := ak.Do("POST", "/webauthn/register/verify", register, nil); err != nil {
		t.Fatal(err)
	}

	res, err := http.Post(target+"/api/v1/webauthn/login/options", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(res.Body).Decode(&opts); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	auth := p.authData(0x01|0x04, false, nil)
	hash := sha256.Sum256(append(auth, sha256Sum(p.clientData("webauthn.get", opts.Challenge))...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.key, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	login, _ := json.Marshal(map[string]any{
		"id": b64u(p.credID), "rawId": b64u(p.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u(p.clientData("webauthn.get", opts.Challenge)), "authenticatorData": b64u(auth),
			"signature": b64u(sig), "userHandle": b64u(ak.AccountID)},
		"clientExtensionResults": map[string]any{},
	})
	res, err = http.Post(target+"/api/v1/webauthn/login/verify", "application/json", bytes.NewReader(login))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("passkey login: %s %s", res.Status, body)
	}
	return strings.SplitN(res.Header.Get("Set-Cookie"), ";", 2)[0]
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func must1[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// browserFulfill answers request id like the page: a set revision stamped
// with the Append rule against what the vault knows, a describe revision when
// the description differs, sealed with RK, sent with the session cookie.
func browserFulfill(t *testing.T, target, cookie string, data *vault.VaultData, acct vault.Account, dev api.Client, id, value string) {
	t.Helper()
	st, err := dev.GetRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := vault.OpenRequestMeta(acct.Keys.RK, acct.ID, id, st.MetaCT)
	if err != nil {
		t.Fatal(err)
	}
	entry := data.Secrets[meta.Name]
	set := vault.Revision{ID: randomHex(), Op: "set", Field: meta.Field, Key: vault.MakeLookupKey(meta.Env, meta.Context), Value: value}
	entry.Append(set)
	revs := []vault.Revision{entry.Revisions[len(entry.Revisions)-1]}
	if _, current, _ := entry.Current(); current != meta.Description {
		describe := vault.Revision{ID: randomHex(), Op: "describe", Value: meta.Description}
		entry.Append(describe)
		revs = append(revs, entry.Revisions[len(entry.Revisions)-1])
	}
	var envelopes []api.Envelope
	for _, r := range revs {
		ct, err := vault.SealRevision(acct.Keys.RK, acct.ID, meta.Name, r)
		if err != nil {
			t.Fatal(err)
		}
		envelopes = append(envelopes, api.Envelope{ID: r.ID, CT: ct})
	}
	body, _ := json.Marshal(map[string]any{"revisions": envelopes})
	req, _ := http.NewRequest("POST", target+"/api/v1/requests/"+id+"/fulfill", bytes.NewReader(body))
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Hort-CSRF", "1")
	req.Header.Set("Origin", target)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		out, _ := io.ReadAll(res.Body)
		t.Fatalf("fulfill: %s %s", res.Status, out)
	}
}

func randomHex() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
