package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/store"
	"github.com/gefuege/hort/internal/vault"
)

// TestServerSync runs devices in temporary homes against the Hort Worker:
//
//	cd server && npx wrangler dev -c wrangler.dev.jsonc --persist-to "$(mktemp -d)"
//	HORT_TEST_SERVER=http://localhost:8787 go test ./internal/cli -run TestServerSync -count=1 -v
//
// The CLI speaks https only, so a local TLS proxy forwards to the Worker and
// injects the interruptions. Each run creates one account on the dev Worker
// (5 account creations per hour and IP).
func TestServerSync(t *testing.T) {
	target := os.Getenv("HORT_TEST_SERVER")
	if target == "" {
		t.Skip("HORT_TEST_SERVER is not set")
	}
	p := &faultProxy{target: strings.TrimRight(target, "/")}
	srv := httptest.NewTLSServer(p)
	defer srv.Close()
	defer func(c *http.Client) { api.HTTPClient = c }(api.HTTPClient)
	api.HTTPClient = srv.Client()
	errs := captureStderr(t)
	t.Setenv("HORT_PASSPHRASE", "synthetic-remote-passphrase")

	a, b, c := t.TempDir(), t.TempDir(), t.TempDir()
	use(t, a)
	if err := CmdInit(srv.URL, "dev-a", ""); err != nil {
		t.Fatal(err)
	}
	if !body(t, a).Sync.Registered {
		t.Fatalf("init did not register: %s", errs.text())
	}
	info, err := vault.ReadInfo(primary(t))
	if err != nil {
		t.Fatal(err)
	}
	accountID := vault.FormatAccountID(info.AccountID)
	secretKey, err := os.ReadFile(filepath.Join(a, ".hort", "secret-key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HORT_SECRET_KEY", strings.TrimSpace(string(secretKey)))

	// enroll refuses any existing vault.enc before asking anything.
	occupied := t.TempDir()
	if err := os.MkdirAll(filepath.Join(occupied, ".hort"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(occupied, ".hort", "vault.enc"), []byte("synthetic-v3"), 0600); err != nil {
		t.Fatal(err)
	}
	use(t, occupied)
	if err := CmdEnroll(accountID, srv.URL, "dev-x"); err == nil || err.Error() != enrollExists {
		t.Fatalf("enroll over a vault: %v", err)
	}

	use(t, b)
	if err := CmdEnroll(accountID, srv.URL, "dev-b"); err != nil {
		t.Fatal(err)
	}

	// Both devices write, auto-sync after each write and before each read.
	mark := errs.mark()
	use(t, a)
	must(t, CmdSet("alpha", "", "a-value", "", "", "from a"))
	use(t, b)
	must(t, CmdSet("beta", "", "b-value", "prod", "", ""))
	use(t, a)
	wantGet(t, a, "beta", "prod", "b-value")
	use(t, b)
	wantGet(t, b, "alpha", "", "a-value")
	if n := strings.Count(errs.since(mark), `notice: new device "dev-b" enrolled`); n != 1 {
		t.Fatalf("new device notice on a: %d times; stderr %s", n, errs.since(mark))
	}

	// A delete on one side reaches the other.
	must(t, CmdDelete("alpha", "", "", ""))
	use(t, a)
	syncOK(t)
	if _, err := store.New(primary(t), session(t)).GetSecret("alpha", "", "", ""); err == nil {
		t.Fatal("alpha survived the delete on b")
	}

	// Interrupted between pull and push: the merge is stored, the revision
	// stays pending, and the next sync pushes it once.
	setLocal(t, "gamma", "g-value")
	p.fail("POST /api/v1/revisions", "refuse")
	if _, err := syncVault(primary(t), session(t), ""); err == nil {
		t.Fatal("sync with a refused push succeeded")
	}
	if len(body(t, a).Sync.Pending) != 1 {
		t.Fatal("gamma left pending without a push")
	}
	syncOK(t)
	if len(body(t, a).Sync.Pending) != 0 {
		t.Fatal("gamma still pending after a successful push")
	}

	// Push without an answer: the server stored delta but a never heard so.
	setLocal(t, "delta", "d-value")
	p.fail("POST /api/v1/revisions", "drop")
	if _, err := syncVault(primary(t), session(t), ""); err == nil {
		t.Fatal("sync with a lost push answer succeeded")
	}
	if len(body(t, a).Sync.Pending) != 1 {
		t.Fatal("delta left pending without an answer")
	}
	report := syncOK(t)
	if report.Pushed != 1 || len(body(t, a).Sync.Pending) != 0 {
		t.Fatalf("resent push: %+v", report)
	}
	use(t, b)
	syncOK(t)
	for _, home := range []string{a, b} {
		use(t, home)
		wantGet(t, home, "gamma", "", "g-value")
		wantGet(t, home, "delta", "", "d-value")
		for _, name := range []string{"gamma", "delta"} {
			if h, err := store.New(primary(t), session(t)).History(name); err != nil || len(h.Revisions) != 1 {
				t.Fatalf("%s history on %s: %+v, %v", name, home, h, err)
			}
		}
	}

	// Envelopes that do not open or fail decoding: one warning each, never merged.
	data, acct, err := vault.OpenAccount(primary(t), session(t))
	must(t, err)
	noise, bogus := "00000000000000000000000000000001", "00000000000000000000000000000002"
	bogusCT, err := vault.SealRevision(acct.Keys.RK, acct.ID, "bogus", vault.Revision{ID: bogus, Op: "rename"})
	must(t, err)
	if _, _, err := deviceClient(acct, data.Device).Push([]api.Envelope{{ID: noise, CT: make([]byte, 40)}, {ID: bogus, CT: bogusCT}}); err != nil {
		t.Fatal(err)
	}
	mark = errs.mark()
	report = syncOK(t)
	got := errs.since(mark)
	if report.SkippedInvalid != 2 || strings.Count(got, "skipped revision "+noise) != 1 || strings.Count(got, "skipped revision "+bogus) != 1 {
		t.Fatalf("skipped: %+v; stderr %s", report, got)
	}
	if _, ok := body(t, b).Secrets["bogus"]; ok {
		t.Fatal("an invalid revision was merged")
	}

	// The own device cannot be revoked.
	use(t, a)
	if err := CmdRevokeDevice(body(t, a).Device.ID); err == nil {
		t.Fatal("revoked the own device")
	}

	// A third device: each other device notices it once, and its revocation once.
	use(t, c)
	must(t, CmdEnroll(accountID, srv.URL, "dev-c"))
	cID := body(t, c).Device.ID
	mark = errs.mark()
	use(t, b)
	syncOK(t)
	use(t, a)
	syncOK(t)
	must(t, CmdRevokeDevice(cID))
	syncOK(t)
	use(t, b)
	syncOK(t)
	syncOK(t)
	use(t, a)
	syncOK(t)
	got = errs.since(mark)
	if strings.Count(got, `notice: new device "dev-c" enrolled`) != 2 || strings.Count(got, `notice: device "dev-c" revoked`) != 1 {
		t.Fatalf("notices for dev-c: %s", got)
	}
	use(t, c)
	if _, err := syncVault(primary(t), session(t), ""); err == nil || !strings.Contains(err.Error(), "device revoked") {
		t.Fatalf("revoked device synced: %v", err)
	}

	// A new passphrase on a reaches b at its next sync; only it unlocks b then.
	sk, err := vault.ParseSecretKey(strings.TrimSpace(string(secretKey)))
	must(t, err)
	unlocksWith := func(home, pass string) bool {
		t.Helper()
		use(t, home)
		_, err := vault.UnlockVault(primary(t), []byte(pass), sk)
		if err != nil && !errors.Is(err, vault.ErrWrongPassphrase) {
			t.Fatal(err)
		}
		return err == nil
	}
	use(t, a)
	t.Setenv("HORT_PASSPHRASE", "synthetic-second-passphrase")
	must(t, CmdPassphrase())
	mark = errs.mark()
	use(t, b)
	syncOK(t)
	syncOK(t)
	if n := strings.Count(errs.since(mark), "passphrase was changed on another device"); n != 1 {
		t.Fatalf("slot notice on b: %d times", n)
	}
	if unlocksWith(b, "synthetic-remote-passphrase") || !unlocksWith(b, "synthetic-second-passphrase") {
		t.Fatal("b does not unlock with exactly the new passphrase")
	}

	// A passphrase push that does not arrive goes again with the next sync.
	use(t, b)
	t.Setenv("HORT_PASSPHRASE", "synthetic-third-passphrase")
	p.fail("PUT /api/v1/slots/passphrase", "refuse")
	must(t, CmdPassphrase())
	use(t, a)
	syncOK(t)
	if !unlocksWith(a, "synthetic-second-passphrase") {
		t.Fatal("a took a slot the server never got")
	}
	use(t, b)
	syncOK(t)
	use(t, a)
	syncOK(t)
	if unlocksWith(a, "synthetic-second-passphrase") || !unlocksWith(a, "synthetic-third-passphrase") {
		t.Fatal("the resent slot did not reach a")
	}

	use(t, a)
	var st Status
	out := stdout(t, func() error { return CmdStatus(true) })
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.LastSyncAt == "" || st.Registered == nil || !*st.Registered {
		t.Fatalf("status: %s, %v", out, err)
	}
}

// faultProxy forwards to the Worker; a fault set for "METHOD PATH" applies to
// the next such request: "refuse" never forwards it, "drop" forwards it and
// loses the answer.
type faultProxy struct {
	target string
	mu     sync.Mutex
	faults map[string]string
}

func (p *faultProxy) fail(route, mode string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.faults == nil {
		p.faults = map[string]string{}
	}
	p.faults[route] = mode
}

func (p *faultProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := r.Method + " " + r.URL.Path
	p.mu.Lock()
	mode := p.faults[route]
	delete(p.faults, route)
	p.mu.Unlock()
	if mode == "refuse" {
		http.Error(w, "proxy: refused", http.StatusServiceUnavailable)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out, err := http.NewRequest(r.Method, p.target+r.URL.RequestURI(), bytes.NewReader(data))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out.Header = r.Header.Clone()
	out.Header.Del("Accept-Encoding") // let the client below decompress
	res, err := http.DefaultClient.Do(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	answer, err := io.ReadAll(res.Body)
	if err != nil || mode == "drop" {
		http.Error(w, "proxy: answer lost", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", res.Header.Get("Content-Type"))
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(answer)
}

func use(t *testing.T, home string) {
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func primary(t *testing.T) vault.VaultRef {
	t.Helper()
	ref, err := vault.PrimaryRef()
	must(t, err)
	return ref
}

func session(t *testing.T) []byte {
	t.Helper()
	key, err := vault.LoadSessionFor(primary(t))
	must(t, err)
	return key
}

func body(t *testing.T, home string) *vault.VaultData {
	t.Helper()
	use(t, home)
	data, _, err := vault.LoadVault(primary(t), session(t))
	must(t, err)
	return data
}

func syncOK(t *testing.T) SyncReport {
	t.Helper()
	report, err := syncVault(primary(t), session(t), "")
	must(t, err)
	return report
}

// setLocal writes without the automatic sync, leaving the revision pending.
func setLocal(t *testing.T, name, value string) {
	t.Helper()
	must(t, store.New(primary(t), session(t)).SetSecret(name, "", value, "", "", ""))
}

func wantGet(t *testing.T, home, name, env, want string) {
	t.Helper()
	use(t, home)
	if got := stdout(t, func() error { return CmdGet(name, "", env, "") }); got != want {
		t.Fatalf("get %s on %s: %q, want %q", name, home, got, want)
	}
}

func stdout(t *testing.T, run func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	must(t, err)
	orig := os.Stdout
	os.Stdout = w
	runErr := run()
	os.Stdout = orig
	_ = w.Close()
	out, _ := io.ReadAll(r)
	must(t, runErr)
	return string(out)
}

// stderrLog collects everything written to os.Stderr during a test, including
// late warnings of an auto-sync that outlived its limit.
type stderrLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *stderrLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(b)
}

func (l *stderrLog) text() string { l.mu.Lock(); defer l.mu.Unlock(); return l.buf.String() }
func (l *stderrLog) mark() int    { return len(l.text()) }

// since waits until everything written so far has passed the pipe.
func (l *stderrLog) since(m int) string {
	sentinel := fmt.Sprintf("-- stderr checkpoint %d --\n", time.Now().UnixNano())
	fmt.Fprint(os.Stderr, sentinel)
	for !strings.Contains(l.text(), sentinel) {
		time.Sleep(time.Millisecond)
	}
	return l.text()[m:]
}

func captureStderr(t *testing.T) *stderrLog {
	r, w, err := os.Pipe()
	must(t, err)
	orig := os.Stderr
	os.Stderr = w
	log := &stderrLog{}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.MultiWriter(log, orig), r); close(done) }()
	t.Cleanup(func() {
		os.Stderr = orig
		_ = w.Close()
		<-done
	})
	return log
}

// TestInvitations needs a Worker that was started with an admin token:
//
//	cd server && npx wrangler dev -c wrangler.dev.jsonc --persist-to "$(mktemp -d)" --var ADMIN_TOKEN:synthetic-admin-token
//	HORT_TEST_INVITE_SERVER=http://localhost:8787 go test ./internal/cli -run TestInvitations -count=1 -v
func TestInvitations(t *testing.T) {
	target := os.Getenv("HORT_TEST_INVITE_SERVER")
	if target == "" {
		t.Skip("HORT_TEST_INVITE_SERVER is not set")
	}
	const admin = "synthetic-admin-token"
	srv := httptest.NewTLSServer(&faultProxy{target: strings.TrimRight(target, "/")})
	defer srv.Close()
	defer func(c *http.Client) { api.HTTPClient = c }(api.HTTPClient)
	api.HTTPClient = srv.Client()
	errs := captureStderr(t)
	t.Setenv("HORT_PASSPHRASE", "synthetic-remote-passphrase")

	// The operator commands need HORT_ADMIN_TOKEN, and the right one.
	t.Setenv("HORT_ADMIN_TOKEN", "")
	if err := CmdInviteCreate(srv.URL); err == nil || !strings.Contains(err.Error(), "HORT_ADMIN_TOKEN is not set") {
		t.Fatalf("create without token: %v", err)
	}
	t.Setenv("HORT_ADMIN_TOKEN", "synthetic-wrong-token")
	if err := CmdInviteList(srv.URL); err == nil || !strings.Contains(err.Error(), "invalid admin token") {
		t.Fatalf("list with a wrong token: %v", err)
	}
	t.Setenv("HORT_ADMIN_TOKEN", admin)
	link := strings.TrimSpace(stdout(t, func() error { return CmdInviteCreate(srv.URL) }))
	code, ok := strings.CutPrefix(link, srv.URL+"/invite#")
	if !ok || len(code) != 32 {
		t.Fatalf("invite link %q", link)
	}

	// Without a code init warns with the server message and the vault stays usable.
	a := t.TempDir()
	use(t, a)
	must(t, CmdInit(srv.URL, "dev-a", ""))
	if body(t, a).Sync.Registered {
		t.Fatal("registered without an invitation")
	}
	if out := errs.since(0); !strings.Contains(out, "needs an invitation") {
		t.Fatalf("server message missing: %s", out)
	}
	must(t, CmdSet("alpha", "", "a-value", "", "", ""))
	if got, err := readStore().GetSecret("alpha", "", "", ""); err != nil || got != "a-value" {
		t.Fatalf("local read: %q %v", got, err)
	}

	// A wrong code is refused.
	if err := CmdSync(false, strings.Repeat("0", 32)); err == nil || !strings.Contains(err.Error(), "not valid or was already used") {
		t.Fatalf("sync with a wrong code: %v", err)
	}

	// The first sync with the code registers; the code works only once.
	must(t, CmdSync(false, code))
	if !body(t, a).Sync.Registered {
		t.Fatal("sync did not register with the code")
	}
	b := t.TempDir()
	use(t, b)
	must(t, CmdInit(srv.URL, "dev-b", code))
	if body(t, b).Sync.Registered {
		t.Fatal("a second account registered with a used code")
	}

	// init registers with a fresh code; revoke refuses a used one.
	fresh := strings.TrimPrefix(strings.TrimSpace(stdout(t, func() error { return CmdInviteCreate(srv.URL) })), srv.URL+"/invite#")
	c := t.TempDir()
	use(t, c)
	must(t, CmdInit(srv.URL, "dev-c", fresh))
	if !body(t, c).Sync.Registered {
		t.Fatalf("init did not register: %s", errs.text())
	}
	listed := stdout(t, func() error { return CmdInviteList(srv.URL) })
	if strings.Count(listed, " used ") < 2 || strings.Contains(listed, code) || strings.Contains(listed, fresh) {
		t.Fatalf("list: %s", listed)
	}
	id := strings.Fields(listed)[0]
	if err := CmdInviteRevoke(srv.URL, id); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("revoke of a used invitation: %v", err)
	}

	// Codes and the admin token reach neither stderr nor any file under a home.
	for _, secret := range []string{code, fresh, admin} {
		if strings.Contains(errs.since(0), secret) {
			t.Fatalf("%q on stderr", secret)
		}
		for _, home := range []string{a, b, c} {
			_ = filepath.Walk(home, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				if data, _ := os.ReadFile(p); bytes.Contains(data, []byte(secret)) {
					t.Errorf("%q in %s", secret, p)
				}
				return nil
			})
		}
	}
}
