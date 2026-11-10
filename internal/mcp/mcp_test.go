package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/cli"
	"github.com/gefuege/hort/internal/mcp"
	"github.com/gefuege/hort/internal/store"
	"github.com/gefuege/hort/internal/vault"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// rig is one unlocked account on the dev Worker plus what stands in for the
// browser: the passkey session and the fulfill call.
type rig struct {
	t       *testing.T
	target  string
	ref     vault.VaultRef
	vk      []byte
	acct    vault.Account
	dev     api.Client
	cookie  string
	secrets []string // every value entered, for the "never in any output" check

	syncFails    atomic.Bool // makes the tool's sync fail
	fulfillNoSet atomic.Bool // makes the next fulfill carry no set revision

	mu   sync.Mutex
	seen []string // every JSON the tool returned to a client
}

// TestRequestSecret runs the tool against the Worker:
//
//	cd server && npx wrangler dev -c wrangler.dev.jsonc --port 8788 --persist-to "$(mktemp -d)"
//	HORT_TEST_SERVER=http://localhost:8788 go test ./internal/mcp -count=1 -v
//
// The CLI speaks https only, so a local TLS proxy forwards to the Worker. The
// passkey and fulfill helper imitate the browser on this path; /r itself is
// not tested here. The test creates one account on the dev Worker.
func TestRequestSecret(t *testing.T) {
	target := strings.TrimRight(os.Getenv("HORT_TEST_SERVER"), "/")
	if target == "" {
		t.Skip("HORT_TEST_SERVER is not set")
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(u))
	defer srv.Close()
	defer func(c *http.Client) { api.HTTPClient = c }(api.HTTPClient)
	api.HTTPClient = srv.Client()
	defer mcp.SetPolling(50*time.Millisecond, 3*time.Second)()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("HORT_PASSPHRASE", "synthetic-mcp-passphrase")
	if err := cli.CmdInit(srv.URL, "dev-mcp", ""); err != nil {
		t.Fatal(err)
	}
	ref, err := vault.PrimaryRef()
	if err != nil {
		t.Fatal(err)
	}
	vk, err := vault.LoadSessionFor(ref)
	if err != nil {
		t.Fatal(err)
	}
	data, acct, err := vault.OpenAccount(ref, vk)
	if err != nil {
		t.Fatal(err)
	}
	if !data.Sync.Registered {
		t.Fatal("init did not register the account")
	}
	r := &rig{t: t, target: target, ref: ref, vk: vk, acct: acct}
	r.dev = api.Client{Server: acct.Server, AccountID: acct.ID, Device: data.Device.ID, Key: data.Device.Key()}
	ak := api.Client{Server: target, AccountID: acct.ID, Device: vault.AKDeviceID, Key: acct.Keys.AK}
	r.cookie = browserSession(t, target, ak)

	t.Run("one tool, no more", func(t *testing.T) {
		cs := r.connect(nil)
		tools, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(tools.Tools) != 1 || tools.Tools[0].Name != "request_secret" {
			t.Fatalf("tools: %+v", tools.Tools)
		}
	})

	t.Run("validation error", func(t *testing.T) {
		cs := r.connect(nil)
		for _, args := range []map[string]any{
			{"name": "Bad Name!", "description": "x"},
			{"name": "valid-name", "description": ""},
			{"name": "valid-name", "description": "x", "fields": []string{"bad field"}},
		} {
			res := r.call(cs, args)
			if !res.IsError {
				t.Fatalf("%v accepted: %s", args, r.last())
			}
		}
		if n := r.pending(); n != 0 {
			t.Fatalf("invalid calls created %d requests", n)
		}
	})

	t.Run("locked vault", func(t *testing.T) {
		if err := vault.ClearSessionFor(ref); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := vault.SaveSessionFor(ref, vk); err != nil {
				t.Fatal(err)
			}
		}()
		res := r.call(r.connect(nil), map[string]any{"name": "locked-one", "description": "x"})
		if !res.IsError || !strings.Contains(r.last(), "Hort is locked; ask the user to run `hort unlock`") {
			t.Fatalf("locked: %s", r.last())
		}
		if n := r.pending(); n != 0 {
			t.Fatalf("locked call created %d requests", n)
		}
	})

	t.Run("no url mode: pending with text, reuse, then stored", func(t *testing.T) {
		cs := r.connect(nil)
		args := map[string]any{"name": "nourl-secret", "description": "Without URL mode", "env": "prod"}
		first := r.output(r.call(cs, args))
		text := r.last()
		if first.Status != "pending" || first.RequestID == "" || !strings.Contains(text, "/r/"+first.RequestID) {
			t.Fatalf("first call: %+v %s", first, text)
		}
		second := r.output(r.call(cs, args))
		if second.RequestID != first.RequestID || second.Status != "pending" {
			t.Fatalf("repeated call: %+v, want the request %s", second, first.RequestID)
		}
		if n := r.pending(); n != 1 {
			t.Fatalf("%d pending requests, want 1", n)
		}
		r.fulfill(first.RequestID, "nourl-value-1")
		done := r.output(r.call(cs, args))
		if done.Status != "stored" || done.RequestID != first.RequestID {
			t.Fatalf("after fulfill: %+v", done)
		}
		r.wantStored("nourl-secret", "", "prod", "nourl-value-1")
	})

	t.Run("a call that differs only in case is the same request", func(t *testing.T) {
		cs := r.connect(nil)
		first := r.output(r.call(cs, map[string]any{"name": "Case-Secret", "description": "Case", "env": "Prod"}))
		again := map[string]any{"name": "case-SECRET", "description": "Case", "env": "PROD"}
		if second := r.output(r.call(cs, again)); second.RequestID != first.RequestID || second.Status != "pending" {
			t.Fatalf("second call: %+v, want the request %s", second, first.RequestID)
		}
		r.fulfill(first.RequestID, "case-value")
		if done := r.output(r.call(cs, again)); done.Status != "stored" || done.RequestID != first.RequestID {
			t.Fatalf("after fulfill: %+v", done)
		}
		r.wantStored("CASE-secret", "", "prod", "case-value")
	})

	t.Run("two fields: one request in any order, stored only once both are", func(t *testing.T) {
		cs := r.connect(nil)
		first := r.output(r.call(cs, map[string]any{"name": "stripe", "description": "Payments", "fields": []string{"client_id", "secret"}, "env": "prod"}))
		if first.Status != "pending" || len(first.Fields) != 2 {
			t.Fatalf("first call: %+v", first)
		}
		again := map[string]any{"name": "Stripe", "description": "Payments", "fields": []string{"secret", "client_id"}, "env": "PROD"}
		if second := r.output(r.call(cs, again)); second.RequestID != first.RequestID || second.Status != "pending" {
			t.Fatalf("same set in another order, name and env in another case: %+v, want the request %s", second, first.RequestID)
		}
		subset := r.output(r.call(cs, map[string]any{"name": "stripe", "description": "Payments", "fields": []string{"secret"}, "env": "prod"}))
		if subset.RequestID == first.RequestID {
			t.Fatal("a subset of the fields found the same request")
		}
		r.fulfill(first.RequestID, "stripe-client-1", "stripe-secret-1")
		done := r.output(r.call(cs, again))
		if done.Status != "stored" || done.RequestID != first.RequestID {
			t.Fatalf("after fulfill: %+v", done)
		}
		r.wantStored("stripe", "client_id", "prod", "stripe-client-1")
		r.wantStored("stripe", "secret", "prod", "stripe-secret-1")

		// A fulfill that stores only one of the two fields is not stored.
		args := map[string]any{"name": "half-secret", "description": "Half", "fields": []string{"user", "password"}}
		half := r.output(r.call(cs, args))
		r.fulfill(half.RequestID, "half-user-1")
		if res := r.call(cs, args); !res.IsError || !strings.Contains(r.last(), "does not match") {
			t.Fatalf("half fulfill: %s", r.last())
		}
	})

	t.Run("url mode: accept, fulfilled, stored, complete notification", func(t *testing.T) {
		var id string
		cs := r.connect(&client{onElicit: func(req *sdk.ElicitRequest) *sdk.ElicitResult {
			if req.Params.Mode != "url" || !strings.HasSuffix(req.Params.URL, "/r/"+req.Params.ElicitationID) {
				t.Errorf("elicitation: %+v", req.Params)
			}
			id = req.Params.ElicitationID
			r.fulfill(id, "url-value-1")
			return &sdk.ElicitResult{Action: "accept"}
		}})
		out := r.output(r.call(cs, map[string]any{"name": "url-secret", "description": "With URL mode", "fields": []string{"token"}, "context": "acme"}))
		if out.Status != "stored" || out.RequestID != id || out.URL != "" {
			t.Fatalf("result: %+v", out)
		}
		r.wantStoredAt("url-secret", "token", "", "acme", "url-value-1")
		if got := cs.completed(); len(got) != 1 || got[0] != id {
			t.Fatalf("complete notifications: %v, want [%s]", got, id)
		}
	})

	t.Run("a client offering 2026-07-28 first still gets URL elicitation on 2025-11-25", func(t *testing.T) {
		asked := 0
		cs := r.connect(&client{onElicit: func(*sdk.ElicitRequest) *sdk.ElicitResult {
			asked++
			return &sdk.ElicitResult{Action: "cancel"}
		}})
		if v := cs.InitializeResult().ProtocolVersion; v != "2025-11-25" {
			t.Fatalf("negotiated %s", v)
		}
		if v := cs.InitializeResult().ServerInfo.Version; v != "9.9.9" {
			t.Fatalf("server reports version %s", v)
		}
		out := r.output(r.call(cs, map[string]any{"name": "negotiate-secret", "description": "Negotiation"}))
		if asked != 1 || out.Status != "pending" || out.URL == "" {
			t.Fatalf("asked %d times: %+v", asked, out)
		}
	})

	t.Run("a second call does not wait for the first one's elicitation", func(t *testing.T) {
		release := make(chan struct{})
		started := make(chan struct{})
		var once sync.Once
		cs := r.connect(&client{onElicit: func(req *sdk.ElicitRequest) *sdk.ElicitResult {
			first := false
			once.Do(func() { first = true })
			if first {
				close(started)
				<-release
				return &sdk.ElicitResult{Action: "cancel"}
			}
			r.fulfill(req.Params.ElicitationID, "parallel-value-1")
			return &sdk.ElicitResult{Action: "accept"}
		}})
		blocked := make(chan error, 1)
		go func() {
			_, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "request_secret", Arguments: map[string]any{"name": "parallel-a", "description": "Blocked"}})
			blocked <- err
		}()
		<-started
		done := make(chan mcp.Output, 1)
		go func() { done <- r.output(r.call(cs, map[string]any{"name": "parallel-b", "description": "Free"})) }()
		select {
		case out := <-done:
			if out.Status != "stored" {
				t.Fatalf("second call: %+v", out)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the second call waits for the first one's elicitation")
		}
		close(release)
		if err := <-blocked; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a mismatch frees the tuple, a failed sync keeps the request", func(t *testing.T) {
		cs := r.connect(nil)
		args := map[string]any{"name": "mismatch-secret", "description": "Mismatch"}
		first := r.output(r.call(cs, args))
		r.fulfillNoSet.Store(true)
		r.fulfill(first.RequestID, "mismatch-value-1")
		r.syncFails.Store(true)
		if res := r.call(cs, args); !res.IsError {
			t.Fatalf("sync failure not reported: %s", r.last())
		}
		r.syncFails.Store(false)
		if res := r.call(cs, args); !res.IsError || !strings.Contains(r.last(), "does not match") {
			t.Fatalf("mismatch not reported: %s", r.last())
		}
		again := r.output(r.call(cs, args))
		if again.Status != "pending" || again.RequestID == first.RequestID {
			t.Fatalf("tuple stayed blocked: %+v, first %s", again, first.RequestID)
		}
	})

	t.Run("cancel keeps the request pending, the next call reuses it", func(t *testing.T) {
		action := "cancel"
		var ids []string
		cs := r.connect(&client{onElicit: func(req *sdk.ElicitRequest) *sdk.ElicitResult {
			ids = append(ids, req.Params.ElicitationID)
			if action == "accept" {
				r.fulfill(req.Params.ElicitationID, "cancel-value-1")
			}
			return &sdk.ElicitResult{Action: action}
		}})
		args := map[string]any{"name": "cancel-secret", "description": "Cancelled once"}
		first := r.output(r.call(cs, args))
		if first.Status != "pending" || first.URL == "" || !strings.HasSuffix(first.URL, "/r/"+first.RequestID) {
			t.Fatalf("after cancel: %+v", first)
		}
		if st, err := r.dev.GetRequest(first.RequestID); err != nil || st.Status != api.RequestPending {
			t.Fatalf("server state after cancel: %+v %v", st, err)
		}
		action = "accept"
		second := r.output(r.call(cs, args))
		if second.RequestID != first.RequestID || second.Status != "stored" || len(ids) != 2 || ids[0] != ids[1] {
			t.Fatalf("second call: %+v, elicitations %v", second, ids)
		}
		r.wantStored("cancel-secret", "", "", "cancel-value-1")
	})

	t.Run("decline is final on the server", func(t *testing.T) {
		var id string
		cs := r.connect(&client{onElicit: func(req *sdk.ElicitRequest) *sdk.ElicitResult {
			id = req.Params.ElicitationID
			return &sdk.ElicitResult{Action: "decline"}
		}})
		out := r.output(r.call(cs, map[string]any{"name": "decline-secret", "description": "Declined"}))
		if out.Status != "declined" || out.RequestID != id || out.URL != "" {
			t.Fatalf("result: %+v", out)
		}
		if st, err := r.dev.GetRequest(id); err != nil || st.Status != api.RequestDeclined {
			t.Fatalf("server state: %+v %v", st, err)
		}
		if _, err := store.New(ref, vk).GetSecret("decline-secret", "", "", ""); err == nil {
			t.Fatal("a declined request stored a value")
		}
	})

	t.Run("accepted but never entered: pending after the timeout", func(t *testing.T) {
		cs := r.connect(&client{onElicit: func(*sdk.ElicitRequest) *sdk.ElicitResult {
			return &sdk.ElicitResult{Action: "accept"}
		}})
		restore := mcp.SetPolling(20*time.Millisecond, 200*time.Millisecond)
		defer restore()
		out := r.output(r.call(cs, map[string]any{"name": "timeout-secret", "description": "Not entered"}))
		if out.Status != "pending" || out.URL == "" {
			t.Fatalf("result: %+v", out)
		}
	})

	t.Run("conflict: a newer competing revision wins", func(t *testing.T) {
		cs := r.connect(&client{onElicit: func(req *sdk.ElicitRequest) *sdk.ElicitResult {
			r.fulfill(req.Params.ElicitationID, "conflict-mine")
			r.pushCompeting("conflict-secret", "", "conflict-newer")
			return &sdk.ElicitResult{Action: "accept"}
		}})
		res := r.call(cs, map[string]any{"name": "conflict-secret", "description": "Raced"})
		out := r.output(res)
		if out.Status != "conflict" || !strings.Contains(r.last(), "check with `hort history`") {
			t.Fatalf("result: %+v %s", out, r.last())
		}
		r.wantStored("conflict-secret", "", "", "conflict-newer")
	})

	t.Run("no entered value in any output", func(t *testing.T) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.seen) == 0 || len(r.secrets) == 0 {
			t.Fatal("nothing recorded")
		}
		for _, v := range r.secrets {
			for _, s := range r.seen {
				if strings.Contains(s, v) {
					t.Fatalf("value %q appears in a tool result: %s", v, s)
				}
			}
		}
	})
}

// TestFieldsRefused checks the fields rule before anything else runs: an
// empty home would answer "locked" if validation let the call through.
func TestFieldsRefused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, ct := sdk.NewInMemoryTransports()
	ss, err := mcp.New(mcp.Deps{Version: "9.9.9"}).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	seventeen := make([]string, 17)
	for i := range seventeen {
		seventeen[i] = fmt.Sprintf("f%d", i)
	}
	for _, c := range []struct {
		fields []string
		want   string
	}{
		{seventeen, "1 to 16 fields"},
		{[]string{"api-key", "API-Key"}, "appears twice"},
		{[]string{"", ""}, "appears twice"},
		{[]string{"ok", "Bad Field"}, "must match"},
	} {
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "request_secret", Arguments: map[string]any{"name": "x", "description": "y", "fields": c.fields}})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(res)
		if !res.IsError || !strings.Contains(string(raw), c.want) {
			t.Fatalf("%v: %s, want %q", c.fields, raw, c.want)
		}
	}
}

// TestOldFieldArgumentRefused: an agent that still sends the single "field"
// of an older Hort gets an error, not a request for the default field.
func TestOldFieldArgumentRefused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, ct := sdk.NewInMemoryTransports()
	ss, err := mcp.New(mcp.Deps{Version: "9.9.9"}).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "request_secret", Arguments: map[string]any{"name": "x", "description": "y", "field": "token"}})
	raw, _ := json.Marshal(res)
	if err == nil && (!res.IsError || strings.Contains(string(raw), "Hort is locked")) {
		t.Fatalf("old field argument: %s", raw)
	}
}

// TestStdioBinary starts the real `hort mcp` on stdio: the one tool is listed,
// and an empty home answers as a locked vault (no network involved).
func TestStdioBinary(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "hort")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "github.com/gefuege/hort/cmd/hort")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	home := t.TempDir()
	cmd := exec.Command(bin, "mcp")
	cmd.Env = append(os.Environ(), "HOME="+home, "USERPROFILE="+home)
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(context.Background(), &sdk.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "request_secret" {
		t.Fatalf("tools: %+v %v", tools, err)
	}
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "request_secret", Arguments: map[string]any{"name": "x", "description": "y"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if !res.IsError || !strings.Contains(string(raw), "Hort is locked") {
		t.Fatalf("locked: %s", raw)
	}
}

// client is the scripted MCP client. A nil onElicit is a client without URL mode.
type client struct {
	onElicit func(*sdk.ElicitRequest) *sdk.ElicitResult
	mu       sync.Mutex
	done     []string
}

type session struct {
	*sdk.ClientSession
	c *client
}

func (s session) completed() []string {
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	return append([]string(nil), s.c.done...)
}

// connect serves a fresh tool server to a scripted client over an in-memory
// pipe, which carries the same JSON-RPC messages as stdio.
func (r *rig) connect(c *client) session {
	r.t.Helper()
	if c == nil {
		c = &client{}
	}
	opts := &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}}
	if c.onElicit != nil {
		opts.Capabilities.Elicitation = &sdk.ElicitationCapabilities{URL: &sdk.URLElicitationCapabilities{}}
		opts.ElicitationHandler = func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			return c.onElicit(req), nil
		}
		opts.ElicitationCompleteHandler = func(_ context.Context, req *sdk.ElicitationCompleteNotificationRequest) {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.done = append(c.done, req.Params.ElicitationID)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.t.Cleanup(cancel)
	st, ct := sdk.NewInMemoryTransports()
	server := mcp.New(mcp.Deps{Sync: func(vault.VaultRef, []byte) error {
		if r.syncFails.Load() {
			return errors.New("synthetic sync failure")
		}
		return cli.CmdSync(false, "")
	}, Version: "9.9.9"})
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = ss.Close() })
	// The SDK client offers its newest version (2026-07-28) first, as Claude Code does.
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, opts).Connect(ctx, ct, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = cs.Close() })
	return session{cs, c}
}

func (r *rig) call(cs session, args map[string]any) *sdk.CallToolResult {
	r.t.Helper()
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "request_secret", Arguments: args})
	if err != nil {
		r.t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	r.mu.Lock()
	r.seen = append(r.seen, string(raw))
	r.mu.Unlock()
	return res
}

func (r *rig) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen[len(r.seen)-1]
}

func (r *rig) output(res *sdk.CallToolResult) mcp.Output {
	r.t.Helper()
	if res.IsError {
		r.t.Fatalf("tool error: %s", r.last())
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		r.t.Fatal(err)
	}
	var out mcp.Output
	if err := json.Unmarshal(raw, &out); err != nil || out.Status == "" {
		r.t.Fatalf("structured output %s: %v", raw, err)
	}
	return out
}

func (r *rig) pending() int {
	r.t.Helper()
	list, err := r.dev.PendingRequests()
	if err != nil {
		r.t.Fatal(err)
	}
	return len(list)
}

// fulfill is the browser: the id is the last part of the request URL, one value per requested field.
func (r *rig) fulfill(id string, values ...string) {
	r.t.Helper()
	id = path.Base(id)
	data, _, err := vault.LoadVault(r.ref, r.vk)
	if err != nil {
		r.t.Fatal(err)
	}
	r.mu.Lock()
	r.secrets = append(r.secrets, values...)
	r.mu.Unlock()
	browserFulfill(r.t, r.target, r.cookie, data, r.acct, r.dev, id, values, r.fulfillNoSet.Swap(false))
}

// pushCompeting is another device writing the same value a moment later.
func (r *rig) pushCompeting(name, field, value string) {
	r.t.Helper()
	later := time.Now().UTC().Add(2 * time.Second)
	rev := vault.Revision{ID: randomHex(), RecordedAt: &later, Op: "set", Field: field, Key: vault.MakeLookupKey("", ""), Value: value}
	ct, err := vault.SealRevision(r.acct.Keys.RK, r.acct.ID, name, rev)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, _, err := r.dev.Push([]api.Envelope{{ID: rev.ID, CT: ct}}); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) wantStored(name, field, env, want string) { r.wantStoredAt(name, field, env, "", want) }

// wantStoredAt reads the value like `hort get` does; an empty want only checks that none exists at that scope.
func (r *rig) wantStoredAt(name, field, env, context, want string) {
	r.t.Helper()
	got, err := store.New(r.ref, r.vk).GetSecret(name, field, env, context)
	if want == "" {
		if err == nil && got != "" {
			r.t.Fatalf("%s/%s/%s holds %q, want none", name, field, env, got)
		}
		return
	}
	if err != nil || got != want {
		r.t.Fatalf("%s/%s/%s/%s: %q, %v; want %q", name, field, env, context, got, err, want)
	}
}
