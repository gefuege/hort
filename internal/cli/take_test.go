package cli

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/store"
	"github.com/gefuege/hort/internal/vault"
)

// shareVector is the production-parameter key case of spec/vectors/share.json.
type shareVector struct {
	Name     string `json:"input"`
	ShareID  string `json:"share_id"`
	LinkKey  string `json:"link_key_hex"`
	EncKey   string `json:"enc_key_hex"`
	Token    string `json:"token_base64"`
	TestOnly bool   `json:"test_params_only"`
}

func productionShareVector(t *testing.T) shareVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "share.json"))
	must(t, err)
	var file struct {
		Vectors struct {
			Keys []shareVector `json:"keys"`
		} `json:"vectors"`
	}
	must(t, json.Unmarshal(raw, &file))
	for _, v := range file.Vectors.Keys {
		if !v.TestOnly {
			return v
		}
	}
	t.Fatal("no production-parameter key vector")
	return shareVector{}
}

// shareServer answers the two recipient endpoints for one share.
type shareServer struct {
	id, token    string
	ct           []byte
	deleteStatus int

	pull []api.Envelope // revisions GET /api/v1/revisions serves, as the sync server

	mu       sync.Mutex
	requests []string // "METHOD path"
	leaked   bool     // a request carried a query, body or the link key
}

func (s *shareServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/api/v1/revisions" {
		page := []map[string]any{}
		for i, e := range s.pull {
			page = append(page, map[string]any{"seq": i + 1, "id": e.ID, "ct": e.CT})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"revisions": page, "cursor": len(s.pull), "more": false, "devices_version": 0, "slot_version": 0})
		return
	}
	b, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	if r.URL.RawQuery != "" || len(b) > 0 {
		s.leaked = true
	}
	s.mu.Unlock()
	if r.Header.Get("Hort-Share-Token") != s.token {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"tries_left":3}`))
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "POST /api/v1/shares/" + s.id + "/open":
		_ = json.NewEncoder(w).Encode(map[string][]byte{"ct": s.ct})
	case "DELETE /api/v1/shares/" + s.id:
		w.WriteHeader(s.deleteStatus)
	default:
		http.Error(w, "this link no longer opens", http.StatusNotFound)
	}
}

func (s *shareServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

type takeCase struct {
	srv    *shareServer
	link   string
	values []string
}

// newTake serves secret as the vector's share from a TLS server whose origin
// differs from the vault's sync server, in a fresh home with an unlocked,
// unregistered vault (so the automatic sync stays local).
func newTake(t *testing.T, secret vault.SharedSecret) takeCase {
	t.Helper()
	v := productionShareVector(t)
	enc, _ := hex.DecodeString(v.EncKey)
	id, _ := hex.DecodeString(v.ShareID)
	linkKey, _ := hex.DecodeString(v.LinkKey)
	plaintext, err := json.Marshal(secret)
	must(t, err)
	block, err := aes.NewCipher(enc)
	must(t, err)
	gcm, err := cipher.NewGCM(block)
	must(t, err)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	aad := append([]byte("hort/v4/share-ct\n\x00\x00\x00\x10"), id...)
	fake := &shareServer{id: v.ShareID, token: v.Token, ct: gcm.Seal(nonce, nonce, plaintext, aad), deleteStatus: http.StatusNoContent}
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	orig := api.HTTPClient
	api.HTTPClient = srv.Client()
	t.Cleanup(func() { api.HTTPClient = orig })

	use(t, t.TempDir())
	ref := primary(t)
	nv, err := vault.CreateVault(ref, "https://127.0.0.1:9", "dev", []byte("synthetic-passphrase"))
	must(t, err)
	must(t, vault.SaveSessionFor(ref, nv.VK))
	values := []string{}
	for _, f := range secret.Fields {
		values = append(values, f.Value)
	}
	return takeCase{fake, srv.URL + "/s/" + v.ShareID + "#" + base64.RawURLEncoding.EncodeToString(linkKey), values}
}

// take runs CmdTake with name on stdin and returns stdout, stderr and the error.
func (c takeCase) take(t *testing.T, name, as string) (string, string, error) {
	t.Helper()
	in := filepath.Join(t.TempDir(), "stdin")
	must(t, os.WriteFile(in, []byte(name+"\n"), 0600))
	f, err := os.Open(in)
	must(t, err)
	defer f.Close()
	origIn, origOut := os.Stdin, os.Stdout
	os.Stdin = f
	r, w, err := os.Pipe()
	must(t, err)
	os.Stdout = w
	errs := captureStderr(t)
	m := errs.mark()
	runErr := CmdTake(c.link, as)
	os.Stdin, os.Stdout = origIn, origOut
	_ = w.Close()
	out, _ := io.ReadAll(r)
	stderr := errs.since(m)
	text := string(out) + stderr
	if runErr != nil {
		text += runErr.Error()
	}
	for _, v := range c.values {
		if strings.Contains(text, v) {
			t.Fatalf("output shows a value: %q", text)
		}
	}
	if c.srv.leaked {
		t.Fatal("a request carried a query or body")
	}
	return string(out), stderr, runErr
}

var dbShare = vault.SharedSecret{Name: "db", Description: "Postgres of tenant heine", Fields: []vault.SharedField{
	{Field: "", Value: "synthetic-url-7f3a"},
	{Field: "user", Value: "synthetic-user-9c2e"},
	{Field: "password", Value: "synthetic-pw-ä41d"},
}}

func entryOf(t *testing.T, name string) (vault.Entry, bool) {
	t.Helper()
	data, _, err := vault.LoadVault(primary(t), session(t))
	must(t, err)
	e, ok := data.Secrets[name]
	return e, ok
}

func wantSaved(t *testing.T, name string, secret vault.SharedSecret) {
	t.Helper()
	s := store.New(primary(t), session(t))
	for _, f := range secret.Fields {
		got, err := s.GetSecret(name, f.Field, "", "")
		if err != nil || got != f.Value {
			t.Fatalf("field %q of %s: not the shared value (%v)", f.Field, name, err)
		}
	}
	info, err := s.Describe(name)
	must(t, err)
	if info.Description != secret.Description || len(info.Variants) != len(secret.Fields) {
		t.Fatalf("entry %s: %+v", name, info)
	}
	for _, v := range info.Variants {
		if v.Env != "*" || v.Context != "*" {
			t.Fatalf("variant %+v is not the default", v)
		}
	}
}

func TestTakeSavesEveryFieldThenDeletesTheShare(t *testing.T) {
	c := newTake(t, dbShare)
	v := productionShareVector(t)
	out, errs, err := c.take(t, "  jörg MÜLLER ", "")
	if err != nil {
		t.Fatal(err)
	}
	if out != "" || !strings.Contains(errs, "Saved db (3 fields). The shared link is deleted.\n") {
		t.Fatalf("stdout %q, stderr %q", out, errs)
	}
	wantSaved(t, "db", dbShare)
	// The link's origin served both calls, not the vault's sync server.
	want := []string{"POST /api/v1/shares/" + v.ShareID + "/open", "DELETE /api/v1/shares/" + v.ShareID}
	if got := c.srv.seen(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests %v, want %v", got, want)
	}
}

func TestTakeOneFieldAsAnotherName(t *testing.T) {
	one := vault.SharedSecret{Name: "github-token", Fields: []vault.SharedField{{Field: "", Value: "synthetic-token-b81c"}}}
	c := newTake(t, one)
	_, errs, err := c.take(t, "Jörg Müller", "gh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errs, "Saved gh (1 field). The shared link is deleted.\n") {
		t.Fatalf("stderr %q", errs)
	}
	wantSaved(t, "gh", one)
	if _, ok := entryOf(t, "github-token"); ok {
		t.Fatal("saved under the shared name despite --as")
	}
}

func TestTakeWrongNameWritesNothing(t *testing.T) {
	c := newTake(t, dbShare)
	_, _, err := c.take(t, "Someone Else", "")
	if err == nil || !strings.Contains(err.Error(), "3 tries left") {
		t.Fatalf("wrong name: %v", err)
	}
	if _, ok := entryOf(t, "db"); ok {
		t.Fatal("wrong name wrote an entry")
	}
	if got := c.srv.seen(); len(got) != 1 {
		t.Fatalf("requests after a wrong name: %v", got)
	}
}

func TestTakeEndedLinkAsksForANewOne(t *testing.T) {
	c := newTake(t, dbShare)
	c.srv.id = "00000000000000000000000000000000"
	_, _, err := c.take(t, "Jörg Müller", "")
	if err == nil || !strings.Contains(err.Error(), "no longer opens") || !strings.Contains(err.Error(), "new one") {
		t.Fatalf("ended link: %v", err)
	}
}

func TestTakeExistingNameWritesNothingAndKeepsTheShare(t *testing.T) {
	c := newTake(t, dbShare)
	must(t, store.New(primary(t), session(t)).SetSecret("db", "", "synthetic-old-5e0b", "", "", ""))
	before, _ := entryOf(t, "db")
	_, _, err := c.take(t, "Jörg Müller", "")
	if err == nil || !strings.Contains(err.Error(), "--as") {
		t.Fatalf("existing name: %v", err)
	}
	if after, _ := entryOf(t, "db"); len(after.Revisions) != len(before.Revisions) {
		t.Fatal("existing entry changed")
	}
	if got := c.srv.seen(); len(got) != 1 || strings.HasPrefix(got[0], "DELETE") {
		t.Fatalf("requests: %v", got)
	}
	if _, _, err := c.take(t, "Jörg Müller", "db2"); err != nil {
		t.Fatal(err)
	}
	wantSaved(t, "db2", dbShare)
}

func TestTakeInvalidWriteWritesNothing(t *testing.T) {
	for name, secret := range map[string]vault.SharedSecret{
		"invalid name":       {Name: "my db", Fields: []vault.SharedField{{Field: "", Value: "synthetic-a"}}},
		"second too large":   {Name: "big", Fields: []vault.SharedField{{Field: "", Value: "synthetic-b"}, {Field: "x", Value: strings.Repeat("y", 48<<10+1)}}},
		"description breaks": {Name: "desc", Description: strings.Repeat("d", 48<<10+1), Fields: []vault.SharedField{{Field: "", Value: "synthetic-c"}}},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTake(t, secret)
			if _, _, err := c.take(t, "Jörg Müller", ""); err == nil {
				t.Fatal("invalid write accepted")
			}
			if _, ok := entryOf(t, secret.Name); ok {
				t.Fatal("refused take wrote an entry")
			}
			if got := c.srv.seen(); len(got) != 1 {
				t.Fatalf("requests: %v", got)
			}
		})
	}
}

func TestTakeFailedDeleteKeepsTheSavedSecret(t *testing.T) {
	c := newTake(t, dbShare)
	c.srv.deleteStatus = http.StatusInternalServerError
	_, errs, err := c.take(t, "Jörg Müller", "")
	if err != nil {
		t.Fatalf("a saved secret is success: %v", err)
	}
	if !strings.Contains(errs, "Saved db (3 fields).\n") || strings.Contains(errs, "The shared link is deleted.") || !strings.Contains(errs, "stays open until it expires") {
		t.Fatalf("stderr %q", errs)
	}
	wantSaved(t, "db", dbShare)
}

// The name exists only on the sync server, from another device: take syncs
// before the check, refuses with --as and writes nothing.
func TestTakeRefusesANameThatExistsOnlyOnTheServer(t *testing.T) {
	c := newTake(t, dbShare)
	origin, _, _, err := vault.ParseShareLink(c.link)
	must(t, err)
	use(t, t.TempDir())
	ref := primary(t)
	nv, err := vault.CreateVault(ref, origin, "dev", []byte("synthetic-passphrase"))
	must(t, err)
	must(t, vault.SaveSessionFor(ref, nv.VK))
	must(t, vault.UpdateVault(ref, nv.VK, func(d *vault.VaultData) error { d.Sync.Registered = true; return nil }))
	_, acct, err := vault.OpenAccount(ref, nv.VK)
	must(t, err)
	remote, err := vault.NewRevision("set", vault.MakeLookupKey("", ""), "synthetic-remote-3d9f")
	must(t, err)
	ct, err := vault.SealRevision(acct.Keys.RK, acct.ID, "db", remote)
	must(t, err)
	c.srv.pull = []api.Envelope{{ID: remote.ID, CT: ct}}

	_, _, err = c.take(t, "Jörg Müller", "")
	if err == nil || !strings.Contains(err.Error(), "--as") {
		t.Fatalf("name on the server: %v", err)
	}
	if e, _ := entryOf(t, "db"); len(e.Revisions) != 1 || e.Revisions[0].ID != remote.ID {
		t.Fatalf("db holds %d revisions, want only the pulled one", len(e.Revisions))
	}
	for _, req := range c.srv.seen() {
		if strings.HasPrefix(req, "DELETE") {
			t.Fatal("the share was deleted")
		}
	}
}
