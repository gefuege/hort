// Package api is the client of the Hort server API (contract §6.2, §6.3).
// It moves ciphertext, public keys and signatures; it never sees plaintext.
package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/gefuege/hort/internal/vault"
)

// HTTPClient sends every request. Tests replace it to trust a local TLS proxy.
// It follows no redirect: a 3xx is an answer like any other non-2xx, so no
// request leaves the server URL from the vault header.
var HTTPClient = &http.Client{
	Timeout:       60 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// Limits of the server (contract §6.6) that the client splits pushes by.
const (
	MaxPushRevisions = 500
	MaxPushBodyBytes = 4 * 1024 * 1024
)

// Client signs requests for one account, with a device key or with AK.
type Client struct {
	Server    string // server URL from the vault header
	AccountID []byte
	Device    string // lowercase hex device ID, or vault.AKDeviceID
	Key       ed25519.PrivateKey

	// Invite is the invitation code, sent as Hort-Invite when not empty;
	// only account registration sets it (§5.1).
	Invite string
}

// Error is a non-2xx answer: the HTTP status and the server's one-line message.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Do sends a signed request with a JSON body (nil for none) and decodes a
// JSON answer into out (nil to ignore it).
func (c Client) Do(method, path string, body, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.Server, "/")+"/api/v1"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	device := []byte(c.Device)
	if c.Device != vault.AKDeviceID {
		if device, err = hex.DecodeString(c.Device); err != nil || len(device) != 16 {
			return fmt.Errorf("invalid device ID %q", c.Device)
		}
	}
	ts := uint64(time.Now().Unix())
	signed := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		signed += "?" + req.URL.RawQuery
	}
	sig := ed25519.Sign(c.Key, vault.RequestMessage(c.AccountID, device, method, signed, ts, raw))
	req.Header.Set("Hort-Account", vault.FormatAccountID(c.AccountID))
	req.Header.Set("Hort-Device", c.Device)
	req.Header.Set("Hort-Timestamp", strconv.FormatUint(ts, 10))
	req.Header.Set("Hort-Signature", base64.StdEncoding.EncodeToString(sig))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Invite != "" {
		req.Header.Set("Hort-Invite", c.Invite)
	}
	return send(req, out)
}

// latest holds the Hort-Latest header of the last server answer, any status.
var latest atomic.Value

// Latest returns the release the server last stated, or "" if it stated none.
func Latest() string {
	v, _ := latest.Load().(string)
	return v
}

func send(req *http.Request, out any) error {
	res, err := HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if v := res.Header.Get("Hort-Latest"); v != "" {
		latest.Store(v)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		msg := strings.TrimSpace(string(data))
		if msg == "" || len(msg) > 300 {
			msg = res.Status
		}
		// The message reaches the terminal: no control character from the server.
		msg = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return '\uFFFD'
			}
			return r
		}, msg)
		return &Error{Status: res.StatusCode, Message: "server: " + msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("server answer: %w", err)
	}
	return nil
}

// Slot is the passphrase slot on the wire; ID is set only where the server expects it.
type Slot struct {
	ID      string `json:"id,omitempty"`
	Version uint64 `json:"version"`
	Bytes   []byte `json:"bytes"`
	AKSig   []byte `json:"ak_sig"`
}

// NewDevice is a device as POST /accounts carries it.
type NewDevice struct {
	ID   string `json:"id"`
	Pub  []byte `json:"pub"`
	Name string `json:"name"`
}

// CreateAccount registers the account, signed with AK (§5.1).
func (c Client) CreateAccount(akPub []byte, slot Slot, device NewDevice) (devicesVersion uint64, err error) {
	slot.ID = vault.PassphraseSlotID
	body := map[string]any{"account_id": vault.FormatAccountID(c.AccountID), "ak_pub": akPub, "slot": slot, "device": device}
	var out struct {
		DevicesVersion uint64 `json:"devices_version"`
	}
	err = c.Do("POST", "/accounts", body, &out)
	return out.DevicesVersion, err
}

// FetchSlot reads an account's passphrase slot and ak_pub without authentication (§5.3 step 3).
func FetchSlot(server string, accountID []byte) (akPub []byte, slot Slot, err error) {
	req, err := http.NewRequest("GET", strings.TrimRight(server, "/")+"/api/v1/accounts/"+vault.FormatAccountID(accountID)+"/slot", nil)
	if err != nil {
		return nil, Slot{}, err
	}
	var out struct {
		AKPub []byte `json:"ak_pub"`
		Slot  Slot   `json:"slot"`
	}
	if err := send(req, &out); err != nil {
		return nil, Slot{}, err
	}
	if out.Slot.ID != vault.PassphraseSlotID {
		return nil, Slot{}, fmt.Errorf("server answer: not a passphrase slot")
	}
	return out.AKPub, out.Slot, nil
}

// PutSlot replaces the account's passphrase slot, signed with AK (§2.2); the
// server answers 409 unless the version is higher than the stored one.
func (c Client) PutSlot(slot Slot) error {
	slot.ID = ""
	return c.Do("PUT", "/slots/"+vault.PassphraseSlotID, slot, nil)
}

// EnrollDevice registers a device, signed with AK (§5.3 step 5).
func (c Client) EnrollDevice(id string, pub []byte, name string) error {
	return c.Do("POST", "/devices", map[string]any{"device_id": id, "pub": pub, "name": name}, nil)
}

// DeviceInfo is one device as GET /devices lists it; times are Unix seconds.
type DeviceInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	CreatedAt  int64  `json:"created_at"`
	LastSeenAt *int64 `json:"last_seen_at"`
	RevokedAt  *int64 `json:"revoked_at"`
}

// PasskeyInfo is one passkey as GET /devices lists it; prf tells whether it
// unlocks the vault. Times are Unix seconds.
type PasskeyInfo struct {
	ID         string `json:"id"`
	PRF        bool   `json:"prf"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at"`
	RevokedAt  *int64 `json:"revoked_at"`
}

// Devices is the answer of GET /devices.
type Devices struct {
	Devices        []DeviceInfo  `json:"devices"`
	Passkeys       []PasskeyInfo `json:"passkeys"`
	DevicesVersion uint64        `json:"devices_version"`
}

// ListDevices lists the account's devices.
func (c Client) ListDevices() (Devices, error) {
	var out Devices
	err := c.Do("GET", "/devices", nil, &out)
	return out, err
}

// RevokeDevice ends a device's server access.
func (c Client) RevokeDevice(id string) error {
	return c.Do("DELETE", "/devices/"+id, nil, nil)
}

// Envelope is one revision envelope on the wire (§6.4).
type Envelope struct {
	ID string `json:"id"`
	CT []byte `json:"ct"`
}

// Push sends envelopes; the server answers which IDs it stored and which it had.
func (c Client) Push(envelopes []Envelope) (accepted, duplicate []string, err error) {
	var out struct {
		Accepted  []string `json:"accepted"`
		Duplicate []string `json:"duplicate"`
	}
	err = c.Do("POST", "/revisions", map[string]any{"revisions": envelopes}, &out)
	return out.Accepted, out.Duplicate, err
}

// Page is one answer of GET /revisions.
type Page struct {
	Revisions []struct {
		Seq uint64 `json:"seq"`
		Envelope
	} `json:"revisions"`
	Cursor         uint64 `json:"cursor"`
	More           bool   `json:"more"`
	DevicesVersion uint64 `json:"devices_version"`
	SlotVersion    uint64 `json:"slot_version"`
}

// Pull reads the page of revisions after cursor.
func (c Client) Pull(after uint64) (Page, error) {
	var out Page
	err := c.Do("GET", fmt.Sprintf("/revisions?after=%d&limit=%d", after, MaxPushRevisions), nil, &out)
	return out, err
}
