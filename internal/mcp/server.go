// Package mcp is `hort mcp`: an MCP stdio server with one tool, request_secret
// (contract §7). It asks the user to enter a value on the Hort web app and
// reports only name and status. A value never passes through this package.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/vault"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Polling after the user accepted the URL elicitation (§7.2 step 4). Tests shorten them.
var (
	pollEvery = 2 * time.Second
	pollFor   = 60 * time.Second
)

// maxMetaBytes is the server's limit for meta_ct (server/README.md).
const maxMetaBytes = 16 << 10

const (
	errLocked    = "Hort is locked; ask the user to run `hort unlock`"
	errMismatch  = "the fulfilled request does not match; nothing confirmed"
	noteConflict = "The value was stored, but a newer revision for this secret exists; check with `hort history`"
)

// Deps are the parts of the CLI the tool needs.
type Deps struct {
	// Sync runs one full sync of the unlocked primary vault.
	Sync func(ref vault.VaultRef, vk []byte) error
	// Version is the Hort version the server reports to its client.
	Version string
}

// Input is the tool's arguments (§7.1).
type Input struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Fields      []string `json:"fields,omitempty"`
	Env         string   `json:"env,omitempty"`
	Context     string   `json:"context,omitempty"`
}

// Output is the tool's result (§7.1): name and status, never a value.
type Output struct {
	RequestID string   `json:"request_id"`
	Status    string   `json:"status"`
	Name      string   `json:"name"`
	Fields    []string `json:"fields,omitempty"`
	Env       string   `json:"env,omitempty"`
	Context   string   `json:"context,omitempty"`
	URL       string   `json:"url,omitempty"`
}

var toolSchemas = struct{ in, out map[string]any }{
	in: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"name":        map[string]any{"type": "string", "description": "Secret name in Hort"},
			"description": map[string]any{"type": "string", "description": "What the secret is for"},
			"fields":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Up to 16 named fields of this secret, for example api-key and api-secret; omit for the default field"},
			"env":         map[string]any{"type": "string", "description": "Environment, for example prod"},
			"context":     map[string]any{"type": "string", "description": "Context, for example a tenant"},
		},
		"required":             []string{"name", "description"},
		"additionalProperties": false,
	},
	out: map[string]any{
		"type": "object",
		"properties": map[string]any{
			"request_id": map[string]any{"type": "string"},
			"status":     map[string]any{"enum": []string{"stored", "pending", "declined", "expired", "conflict"}},
			"name":       map[string]any{"type": "string"},
			"fields":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"env":        map[string]any{"type": "string"},
			"context":    map[string]any{"type": "string"},
			"url":        map[string]any{"type": "string"},
		},
		"required": []string{"request_id", "status", "name"},
	},
}

type server struct {
	deps Deps
	mu   sync.Mutex
	// open maps a tuple to the request this process created or reused. The server
	// lists only pending requests, so a request the user fulfilled after the
	// polling ended is found again only through this map.
	open map[tuple]string
}

// tuple is a request's name, set of fields and lookup key, each folded by
// vault.FoldKey: tuples that differ only in case or field order are the same
// request. fields joins the sorted folded fields with "\n", which the field
// rule excludes.
type tuple struct{ name, fields, key string }

func makeTuple(name string, fields []string, env, context string) tuple {
	folded := make([]string, len(fields))
	for i, f := range fields {
		folded[i] = vault.FoldKey(f)
	}
	sort.Strings(folded)
	return tuple{vault.FoldKey(name), strings.Join(folded, "\n"), vault.FoldKey(vault.MakeLookupKey(env, context))}
}

// New returns the MCP server with its one tool.
func New(deps Deps) *sdk.Server {
	s := &server{deps: deps, open: map[tuple]string{}}
	// URL elicitation is a server-initiated request, which protocol 2026-07-28 forbids
	// while a tool runs. Claude Code tries server/discover first; without that
	// version in the list it falls back to initialize 2025-11-25 with elicitation.url.
	srv := sdk.NewServer(&sdk.Implementation{Name: "hort", Version: deps.Version}, &sdk.ServerOptions{
		SupportedProtocolVersions: []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"},
	})
	sdk.AddTool(srv, &sdk.Tool{
		Name:         "request_secret",
		Description:  "Ask the user to enter a secret in Hort without the value entering the chat. Use this instead of asking for a secret in chat. Ask for related parts of one secret, such as api-key and api-secret, in one request with fields. Returns only name and status; read the value later with `hort get`.",
		InputSchema:  toolSchemas.in,
		OutputSchema: toolSchemas.out,
	}, s.requestSecret)
	return srv
}

// Serve runs the server on stdin and stdout until the client disconnects.
func Serve(ctx context.Context, deps Deps) error {
	return New(deps).Run(ctx, &sdk.StdioTransport{})
}

// validate checks the arguments; in.Fields is already normalized to at least one entry.
func validate(in Input) error {
	if in.Description == "" {
		return errors.New("description must not be empty")
	}
	key := vault.MakeLookupKey(in.Env, in.Context)
	for _, err := range []error{vault.ValidateName(in.Name), vault.ValidateRequestFields(in.Fields), vault.ValidateKey(key)} {
		if err != nil {
			return err
		}
	}
	for _, f := range in.Fields {
		if err := vault.ValidateField(f); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) requestSecret(ctx context.Context, req *sdk.CallToolRequest, in Input) (*sdk.CallToolResult, Output, error) {
	out := Output{Status: "pending", Name: in.Name, Fields: in.Fields, Env: in.Env, Context: in.Context}
	if len(in.Fields) == 0 {
		in.Fields = []string{""}
	}
	if err := validate(in); err != nil {
		return nil, Output{}, err
	}
	ref, err := vault.PrimaryRef()
	if err != nil {
		return nil, Output{}, err
	}
	vk, err := vault.LoadSessionFor(ref)
	if err != nil {
		return nil, Output{}, errors.New(errLocked)
	}
	data, acct, err := vault.OpenAccount(ref, vk)
	if err != nil {
		return nil, Output{}, err
	}
	if !data.Sync.Registered {
		return nil, Output{}, fmt.Errorf("this vault is not registered on %s yet; run `hort sync`", acct.Server)
	}
	c := api.Client{Server: acct.Server, AccountID: acct.ID, Device: data.Device.ID, Key: data.Device.Key()}
	key := makeTuple(in.Name, in.Fields, in.Env, in.Context)

	id, state, err := s.findOrCreate(c, acct, in, key)
	if err != nil {
		return nil, out, err
	}
	out.RequestID = id
	out.URL = strings.TrimRight(acct.Server, "/") + "/r/" + id
	ss := req.Session
	urlMode := canElicitURL(ss)

	if state == api.RequestPending && urlMode {
		state, urlMode, err = s.elicit(ctx, c, ss, id, in.Name, out.URL)
		if err != nil {
			return nil, out, err
		}
	}
	switch state {
	case api.RequestPending:
		if urlMode {
			return nil, out, nil
		}
		return textResult("Ask the user to open " + out.URL + " and enter the value there. Call request_secret again with the same arguments to check the status."), out, nil
	case api.RequestFulfilled:
		return s.finish(ctx, ss, urlMode, ref, vk, c, id, in, key, out)
	case api.RequestDeclined, api.RequestExpired:
		s.forget(key)
		out.Status, out.URL = state, ""
		return nil, out, nil
	}
	return nil, out, fmt.Errorf("server reported the unknown request state %q", state)
}

// findOrCreate returns the request for the tuple and its current state:
// the one this process holds, a pending one the server lists (§7.2 step 2),
// or a new one (step 3).
func (s *server) findOrCreate(c api.Client, acct vault.Account, in Input, key tuple) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.open[key]; ok {
		st, err := c.GetRequest(id)
		if err != nil {
			return "", "", err
		}
		if st.Status == api.RequestPending || st.Status == api.RequestFulfilled {
			return id, st.Status, nil
		}
		delete(s.open, key)
		if st.Status == api.RequestDeclined {
			return id, st.Status, nil
		}
	}
	pending, err := c.PendingRequests()
	if err != nil {
		return "", "", err
	}
	for _, p := range pending {
		m, err := vault.OpenRequestMeta(acct.Keys.RK, acct.ID, p.ID, p.MetaCT)
		if err == nil && makeTuple(m.Name, m.Fields, m.Env, m.Context) == key {
			s.open[key] = p.ID
			return p.ID, api.RequestPending, nil
		}
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", "", err
	}
	id := hex.EncodeToString(raw[:])
	meta, err := vault.SealRequestMeta(acct.Keys.RK, acct.ID, id, vault.RequestMeta{Name: in.Name, Description: in.Description, Fields: in.Fields, Env: in.Env, Context: in.Context})
	if err != nil {
		return "", "", err
	}
	if len(meta) > maxMetaBytes {
		return "", "", errors.New("description is too long")
	}
	if err := c.CreateRequest(id, meta); err != nil {
		return "", "", err
	}
	s.open[key] = id
	return id, api.RequestPending, nil
}

func (s *server) forget(key tuple) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, key)
}

func canElicitURL(ss *sdk.ServerSession) bool {
	p := ss.InitializeParams()
	return p != nil && p.Capabilities != nil && p.Capabilities.Elicitation != nil && p.Capabilities.Elicitation.URL != nil
}

// elicit asks the client to open the URL and, once the user accepted, polls
// the request (§7.2 step 4). It returns the request's state; pending covers
// cancel (also what headless clients send) and the poll timeout. The bool is
// false when the client could not be asked (a protocol version that forbids
// server-initiated requests, a failing client): the caller then answers with
// the fallback text.
func (s *server) elicit(ctx context.Context, c api.Client, ss *sdk.ServerSession, id, name, url string) (string, bool, error) {
	res, err := ss.Elicit(ctx, &sdk.ElicitParams{Mode: "url", Message: fmt.Sprintf("Enter %q in Hort", name), URL: url, ElicitationID: id})
	if err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		return api.RequestPending, false, nil
	}
	switch res.Action {
	case "decline":
		if err := c.DeclineRequest(id); err != nil {
			return "", true, err
		}
		return api.RequestDeclined, true, nil
	case "accept":
		state, err := poll(ctx, c, id)
		return state, true, err
	}
	return api.RequestPending, true, nil
}

func poll(ctx context.Context, c api.Client, id string) (string, error) {
	deadline := time.NewTimer(pollFor)
	defer deadline.Stop()
	tick := time.NewTicker(pollEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return api.RequestPending, nil
		case <-tick.C:
			st, err := c.GetRequest(id)
			if err != nil {
				return "", err
			}
			if st.Status != api.RequestPending {
				return st.Status, nil
			}
		}
	}
}

// finish is the verification after fulfilled (§7.2 step 7).
func (s *server) finish(ctx context.Context, ss *sdk.ServerSession, urlMode bool, ref vault.VaultRef, vk []byte, c api.Client, id string, in Input, key tuple, out Output) (*sdk.CallToolResult, Output, error) {
	st, err := c.GetRequest(id)
	if err != nil {
		return nil, out, err
	}
	if err := s.deps.Sync(ref, vk); err != nil {
		return nil, out, fmt.Errorf("sync after the fulfilled request: %w", err)
	}
	data, _, err := vault.LoadVault(ref, vk)
	if err != nil {
		return nil, out, err
	}
	status, err := verify(data, st.RevisionIDs, in.Fields, key)
	if err != nil {
		// A mismatch will not heal on a repeat call; do not keep the tuple blocked.
		s.forget(key)
		return nil, out, err
	}
	s.forget(key)
	out.Status, out.URL = status, ""
	if urlMode {
		_ = ss.NotifyElicitationComplete(ctx, &sdk.ElicitationCompleteParams{ElicitationID: id})
	}
	if status == "conflict" {
		return textResult(noteConflict), out, nil
	}
	return nil, out, nil
}

// verify checks that every revision of the request is merged, that for each
// requested field one of them sets that field at the tuple's key and that the
// reduction resolves each to its value. A lost reduction is a conflict,
// anything else a mismatch.
func verify(data *vault.VaultData, ids, fields []string, key tuple) (string, error) {
	known := map[string]vault.Revision{}
	for _, entry := range data.Secrets {
		for _, r := range entry.Revisions {
			known[r.ID] = r
		}
	}
	sets := map[string]vault.Revision{} // the first set per folded field
	for _, id := range ids {
		r, ok := known[id]
		if !ok {
			return "", errors.New(errMismatch)
		}
		field := vault.FoldKey(r.Field)
		if _, seen := sets[field]; r.Op == "set" && vault.FoldKey(r.Key) == key.key && !seen {
			sets[field] = r
		}
	}
	_, entry, _ := data.Entry(key.name)
	values, _, _ := entry.Current()
	status := "stored"
	for _, f := range fields {
		field := vault.FoldKey(f)
		set, ok := sets[field]
		if !ok || !holdsRevision(entry, set.ID) {
			return "", errors.New(errMismatch)
		}
		if v, ok := values[entry.Spelling(vault.ValueKey{Field: field, Key: key.key})]; !ok || v != set.Value {
			status = "conflict"
		}
	}
	return status, nil
}

func holdsRevision(e vault.Entry, id string) bool {
	for _, r := range e.Revisions {
		if r.ID == id {
			return true
		}
	}
	return false
}

func textResult(text string) *sdk.CallToolResult {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}
}
