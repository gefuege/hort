package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/vault"
)

// syncLimit bounds the automatic sync around reads and writes (contract §4):
// a slow server must not hold up a local read. Stopping is safe, all writes
// are atomic.
const syncLimit = 2 * time.Second

func limitSync[T any](limit time.Duration, run func() (T, error)) (T, error) {
	type outcome struct {
		result T
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := run()
		done <- outcome{result, err}
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case o := <-done:
		return o.result, o.err
	case <-timer.C:
		var zero T
		return zero, fmt.Errorf("no answer within %s", limit)
	}
}

// SyncReport is the result of one sync (contract §4).
type SyncReport struct {
	Pulled         int    `json:"pulled"`
	Pushed         int    `json:"pushed"`
	SkippedInvalid int    `json:"skipped_invalid"`
	Cursor         uint64 `json:"cursor"`
}

// RevokeNote is stated by `hort devices revoke` and its help (contract §4).
const RevokeNote = "Revoking ends server access for that device. It does not protect against anyone who already holds your vault key; in that case create a new account (see `hort help recovery`)."

// errUnchanged ends an UpdateVault mutation without writing the vault.
var errUnchanged = errors.New("unchanged")

func updateIfChanged(ref vault.VaultRef, vk []byte, mutate func(*vault.VaultData) error) error {
	if err := vault.UpdateVault(ref, vk, mutate); err != nil && !errors.Is(err, errUnchanged) {
		return err
	}
	return nil
}

func deviceClient(acct vault.Account, d vault.Device) api.Client {
	return api.Client{Server: acct.Server, AccountID: acct.ID, Device: d.ID, Key: d.Key()}
}

func akClient(acct vault.Account) api.Client {
	return api.Client{Server: acct.Server, AccountID: acct.ID, Device: vault.AKDeviceID, Key: acct.Keys.AK}
}

func publicKey(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

// lastSyncPath holds the time of the last complete sync for `hort status`.
// It is local state outside the vault, so a sync that finds nothing new
// leaves vault.enc untouched.
func lastSyncPath(ref vault.VaultRef) string {
	return filepath.Join(filepath.Dir(ref.Path), "last-sync")
}

func writeLastSync(ref vault.VaultRef) {
	stamp := time.Now().UTC().Format(time.RFC3339) + "\n"
	if err := os.WriteFile(lastSyncPath(ref), []byte(stamp), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: recording the sync time: %v\n", err)
	}
}

func readLastSync(ref vault.VaultRef) string {
	raw, err := os.ReadFile(lastSyncPath(ref))
	if err != nil {
		return ""
	}
	stamp := strings.TrimSpace(string(raw))
	if _, err := time.Parse(time.RFC3339, stamp); err != nil {
		return ""
	}
	return stamp
}

// register creates the account on the server, signed with AK (§5.1), and
// records it with this device as the only known one.
func register(ref vault.VaultRef, vk []byte, data *vault.VaultData, acct vault.Account) error {
	d := data.Device
	slot := api.Slot{Version: acct.Slot.Version, Bytes: acct.Slot.Bytes, AKSig: acct.Slot.AKSig}
	c := akClient(acct)
	c.RegistrationToken = os.Getenv("HORT_REGISTRATION_TOKEN")
	version, err := c.CreateAccount(publicKey(acct.Keys.AK), slot, api.NewDevice{ID: d.ID, Pub: publicKey(d.Key()), Name: d.Name})
	if err != nil {
		return fmt.Errorf("registering the account on %s: %w", acct.Server, err)
	}
	return updateIfChanged(ref, vk, func(data *vault.VaultData) error {
		if data.Sync.Registered {
			return errUnchanged
		}
		data.Sync.Registered = true
		data.Sync.DevicesVersion = version
		data.Sync.KnownDevices = []string{data.Device.ID}
		return nil
	})
}

// pullAll reads every page after cursor and returns the last one without its
// revisions, for its cursor and versions. An envelope that does not open or
// fails decoding gets one warning naming its ID and is never merged (§3.4).
func pullAll(c api.Client, acct vault.Account, cursor uint64) (pulled []vault.Pulled, last api.Page, skipped int, err error) {
	for {
		page, err := c.Pull(cursor)
		if err != nil {
			return nil, api.Page{}, 0, err
		}
		if page.Cursor < cursor || (page.More && len(page.Revisions) == 0) {
			return nil, api.Page{}, 0, errors.New("server answer: inconsistent revision page")
		}
		for _, r := range page.Revisions {
			name, rev, err := vault.OpenRevision(acct.Keys.RK, acct.ID, r.ID, r.CT)
			p := vault.Pulled{Name: name, Revision: rev}
			if err == nil {
				err = vault.ValidatePulled(p)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipped revision %s from the server: %v\n", r.ID, err)
				skipped++
				continue
			}
			pulled = append(pulled, p)
		}
		cursor = page.Cursor
		if !page.More {
			page.Revisions = nil
			return pulled, page, skipped, nil
		}
	}
}

// recordDevices stores the devices and passkeys of a list as seen: active
// ones in known_devices, revoked ones in known_revoked. An ID outside the
// body's ID rule is not stored.
func recordDevices(st *vault.SyncState, list api.Devices) {
	st.KnownDevices, st.KnownRevoked = []string{}, []string{}
	add := func(id string, revoked bool) {
		switch {
		case !vault.ValidKnownID(id):
		case revoked:
			st.KnownRevoked = append(st.KnownRevoked, id)
		default:
			st.KnownDevices = append(st.KnownDevices, id)
		}
	}
	for _, d := range list.Devices {
		add(d.ID, d.RevokedAt != nil)
	}
	for _, p := range list.Passkeys {
		add(p.ID, p.RevokedAt != nil)
	}
}

// applyDevices records the server's list of devices and passkeys once its
// devices_version is newer and returns one notice per change since (§4). An
// entry enrolled and revoked between two syncs gets both notices; an entry
// whose ID breaks the ID rule is neither noticed nor stored.
func applyDevices(data *vault.VaultData, list api.Devices) []string {
	if list.DevicesVersion <= data.Sync.DevicesVersion {
		return nil
	}
	active, revoked := make(map[string]bool), make(map[string]bool)
	for _, id := range data.Sync.KnownDevices {
		active[id] = true
	}
	for _, id := range data.Sync.KnownRevoked {
		revoked[id] = true
	}
	var notices []string
	note := func(id, what, added string, createdAt int64, isRevoked bool) {
		enrolled := fmt.Sprintf("notice: new %s %s %s", what, added, time.Unix(createdAt, 0).UTC().Format(time.RFC3339))
		gone := fmt.Sprintf("notice: %s revoked", what)
		switch {
		case !vault.ValidKnownID(id):
		case !isRevoked:
			if !active[id] && id != data.Device.ID {
				notices = append(notices, enrolled)
			}
		case revoked[id]:
		case active[id]:
			notices = append(notices, gone)
		default:
			notices = append(notices, enrolled, gone)
		}
	}
	for _, d := range list.Devices {
		note(d.ID, fmt.Sprintf("device %q", d.Name), "enrolled", d.CreatedAt, d.RevokedAt != nil)
	}
	for _, p := range list.Passkeys {
		note(p.ID, fmt.Sprintf("passkey %q", shortID(p.ID)), "registered", p.CreatedAt, p.RevokedAt != nil)
	}
	recordDevices(&data.Sync, list)
	data.Sync.DevicesVersion = list.DevicesVersion
	return notices
}

// shortID names a passkey in notices; `hort devices` shows the full ID.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// errSlotConflict is the server's 409 on PUT /slots: it holds a version at
// least as high.
var errSlotConflict = errors.New("the server holds a passphrase slot at least as new")

// pushSlot sends the local passphrase slot, signed with AK.
func pushSlot(acct vault.Account) error {
	err := akClient(acct).PutSlot(api.Slot{Version: acct.Slot.Version, Bytes: acct.Slot.Bytes, AKSig: acct.Slot.AKSig})
	var apiErr *api.Error
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
		return errSlotConflict
	}
	return err
}

// syncSlot brings the passphrase slot to the newer side (§2.2). The server's
// slot_version decides; 0 means the server did not report one. A higher
// version is fetched and replaces the local slot only once it checks out; a
// slot that does not is ignored with a warning. A lower version means a
// `hort passphrase` whose push did not arrive, so the local slot goes again.
func syncSlot(ref vault.VaultRef, vk []byte, acct vault.Account, serverVersion uint64) error {
	switch {
	case serverVersion == 0 || serverVersion == acct.Slot.Version:
		return nil
	case serverVersion < acct.Slot.Version:
		err := pushSlot(acct)
		if errors.Is(err, errSlotConflict) {
			fmt.Fprintf(os.Stderr, "warning: %v; the next sync takes it\n", err)
			return nil
		}
		return err
	}
	akPub, s, err := api.FetchSlot(acct.Server, acct.ID)
	if err != nil {
		return fmt.Errorf("fetching the passphrase slot: %w", err)
	}
	if err := vault.ReplaceSlot(ref, vk, vault.Slot{Version: s.Version, Bytes: s.Bytes, AKSig: s.AKSig}, akPub); err != nil {
		fmt.Fprintf(os.Stderr, "warning: ignored the passphrase slot from the server: %v\n", err)
		return nil
	}
	fmt.Fprintln(os.Stderr, "notice: the passphrase was changed on another device; this device now unlocks with the new one")
	return nil
}

// pendingRevisions returns the revisions in sync.pending; an ID the vault no
// longer holds is returned as gone, so it leaves pending.
func pendingRevisions(data *vault.VaultData) (revs []vault.Pulled, gone []string) {
	byID := make(map[string]vault.Pulled)
	for name, entry := range data.Secrets {
		for _, r := range entry.Revisions {
			byID[r.ID] = vault.Pulled{Name: name, Revision: r}
		}
	}
	for _, id := range data.Sync.Pending {
		if p, ok := byID[id]; ok {
			revs = append(revs, p)
		} else {
			gone = append(gone, id)
		}
	}
	return revs, gone
}

// pushAll seals and pushes revisions in batches within the server limits and
// returns every ID the server accepted or already held.
func pushAll(c api.Client, acct vault.Account, revs []vault.Pulled) (acked []string, err error) {
	var batch []api.Envelope
	size := 0
	flush := func() error {
		accepted, duplicate, err := c.Push(batch)
		acked = append(append(acked, accepted...), duplicate...)
		batch, size = nil, 0
		return err
	}
	for _, p := range revs {
		ct, err := vault.SealRevision(acct.Keys.RK, acct.ID, p.Name, p.Revision)
		if err != nil {
			return acked, err
		}
		n := base64.StdEncoding.EncodedLen(len(ct)) + len(p.Revision.ID) + 64 // JSON framing
		if len(batch) == api.MaxPushRevisions || (len(batch) > 0 && size+n > api.MaxPushBodyBytes-64) {
			if err := flush(); err != nil {
				return acked, err
			}
		}
		batch = append(batch, api.Envelope{ID: p.Revision.ID, CT: ct})
		size += n
	}
	if len(batch) > 0 {
		err = flush()
	}
	return acked, err
}

// syncVault runs one sync in the order of §6.6: pull until the last page,
// merge under the vault lock, push pending, then record pushed IDs and the
// cursor. Network I/O stays outside the lock. An interrupted sync loses
// nothing: merged revisions are union-idempotent, pending leaves only on the
// server's answer, and the cursor moves only after the merge is stored.
func syncVault(ref vault.VaultRef, vk []byte) (SyncReport, error) {
	var report SyncReport
	data, acct, err := vault.OpenAccount(ref, vk)
	if err != nil {
		return report, err
	}
	if !data.Sync.Registered {
		if err := register(ref, vk, data, acct); err != nil {
			return report, err
		}
		if data, acct, err = vault.OpenAccount(ref, vk); err != nil {
			return report, err
		}
	}
	c := deviceClient(acct, data.Device)
	pulled, last, skipped, err := pullAll(c, acct, data.Sync.Cursor)
	if err != nil {
		return report, err
	}
	cursor := last.Cursor
	report.SkippedInvalid = skipped
	var devices *api.Devices
	if last.DevicesVersion > data.Sync.DevicesVersion {
		list, err := c.ListDevices()
		if err != nil {
			return report, err
		}
		devices = &list
	}

	var notices, conflicts []string
	var push []vault.Pulled
	var gone []string
	err = updateIfChanged(ref, vk, func(d *vault.VaultData) error {
		report.Pulled, conflicts = d.MergePulled(pulled)
		before := d.Sync.DevicesVersion
		if devices != nil {
			notices = applyDevices(d, *devices)
		}
		push, gone = pendingRevisions(d)
		if report.Pulled == 0 && d.Sync.DevicesVersion == before {
			return errUnchanged
		}
		return nil
	})
	if err != nil {
		return report, err
	}
	for _, id := range conflicts {
		fmt.Fprintf(os.Stderr, "warning: the server holds revision %s with other content; keeping the local one\n", id)
	}
	for _, n := range notices {
		fmt.Fprintln(os.Stderr, n)
	}

	acked, pushErr := pushAll(c, acct, push)
	report.Pushed = len(acked)
	done := make(map[string]bool)
	for _, id := range append(acked, gone...) {
		done[id] = true
	}
	err = updateIfChanged(ref, vk, func(d *vault.VaultData) error {
		keep := []string{}
		for _, id := range d.Sync.Pending {
			if !done[id] {
				keep = append(keep, id)
			}
		}
		if len(keep) == len(d.Sync.Pending) && cursor <= d.Sync.Cursor {
			report.Cursor = d.Sync.Cursor
			return errUnchanged
		}
		d.Sync.Pending = keep
		d.Sync.Cursor = max(d.Sync.Cursor, cursor)
		report.Cursor = d.Sync.Cursor
		return nil
	})
	if pushErr != nil {
		return report, pushErr
	}
	if err != nil {
		return report, err
	}
	if err := syncSlot(ref, vk, acct, last.SlotVersion); err != nil {
		return report, err
	}
	writeLastSync(ref)
	return report, nil
}

// autoSync runs one sync bounded by syncLimit when the vault is registered.
// A failure is one warning and never changes the exit code (§4).
func autoSync(ref vault.VaultRef, vk []byte) {
	data, _, err := vault.LoadVault(ref, vk)
	if err != nil || !data.Sync.Registered {
		return
	}
	if _, err := limitSync(syncLimit, func() (SyncReport, error) { return syncVault(ref, vk) }); err != nil {
		fmt.Fprintf(os.Stderr, "warning: sync: %v\n", err)
	}
}

// CmdSync syncs without a time limit; the first run registers the account.
func CmdSync(jsonOutput bool) error {
	ref, key := requireKey()
	report, err := syncVault(ref, key)
	if err != nil {
		return err
	}
	if jsonOutput {
		out, _ := json.Marshal(report)
		fmt.Println(string(out))
		return nil
	}
	fmt.Fprintf(os.Stderr, "Synced: %d pulled, %d pushed, %d skipped as invalid.\n", report.Pulled, report.Pushed, report.SkippedInvalid)
	return nil
}

// enrollExists is the refusal of §4 for any existing vault.enc.
const enrollExists = "a vault already exists here; enroll only on a device without one. To bring a v3 vault along, run `hort migrate` on one device and enroll the others fresh after moving `~/.hort/vault.enc` away"

// CmdEnroll adds this device to an existing account (§5.3).
func CmdEnroll(accountIDText, server, name string) error {
	ref, err := vault.PrimaryRef()
	if err != nil {
		return err
	}
	if exists, err := vault.RefExists(ref); err != nil {
		return err
	} else if exists {
		return errors.New(enrollExists)
	}
	if err := vault.CheckNewVault(ref); err != nil {
		return err
	}
	accountID, err := vault.ParseAccountID(accountIDText)
	if err != nil {
		return err
	}
	if server == "" {
		server = vault.DefaultServer
	}
	if err := vault.CheckServerURL(server); err != nil {
		return err
	}
	if name == "" {
		name = defaultDeviceName()
	}
	secretKey, err := promptSecretKey()
	if err != nil {
		return err
	}
	pass, err := ReadPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}
	akPub, s, err := api.FetchSlot(server, accountID)
	if err != nil {
		return fmt.Errorf("fetching the account's passphrase slot: %w", err)
	}
	slot := vault.Slot{Version: s.Version, Bytes: s.Bytes, AKSig: s.AKSig}
	vk, err := vault.OpenServerSlot(accountID, slot, akPub, string(pass), secretKey)
	if err != nil {
		return err
	}
	keys, err := vault.DeriveAccountKeys(vk, accountID)
	if err != nil {
		return err
	}
	acct := vault.Account{ID: accountID, Server: server, Keys: keys, Slot: slot}
	data, err := vault.NewBody(name)
	if err != nil {
		return err
	}
	if err := akClient(acct).EnrollDevice(data.Device.ID, publicKey(data.Device.Key()), name); err != nil {
		return fmt.Errorf("enrolling this device: %w", err)
	}
	c := deviceClient(acct, data.Device)
	pulled, last, _, err := pullAll(c, acct, 0)
	if err != nil {
		return fmt.Errorf("pulling the vault: %w", err)
	}
	devices, err := c.ListDevices()
	if err != nil {
		return fmt.Errorf("pulling the vault: %w", err)
	}
	added, _ := data.MergePulled(pulled)
	data.Sync.Registered, data.Sync.Cursor, data.Sync.DevicesVersion = true, last.Cursor, devices.DevicesVersion
	recordDevices(&data.Sync, devices)
	if err := vault.WriteEnrolledVault(ref, server, accountID, slot, vk, secretKey, data); err != nil {
		return err
	}
	if err := vault.SaveSessionFor(ref, vk); err != nil {
		return err
	}
	writeLastSync(ref)
	fmt.Fprintf(os.Stderr, "Device %q enrolled and unlocked; %d revisions pulled.\n", name, added)
	return nil
}

// registeredAccount opens the unlocked vault for a server command.
func registeredAccount() (vault.VaultRef, []byte, *vault.VaultData, vault.Account, error) {
	ref, key := requireKey()
	data, acct, err := vault.OpenAccount(ref, key)
	if err == nil && !data.Sync.Registered {
		err = fmt.Errorf("this vault is not registered on %s yet; run `hort sync`", acct.Server)
	}
	return ref, key, data, acct, err
}

// CmdDevices lists the account's devices.
func CmdDevices(jsonOutput bool) error {
	_, _, data, acct, err := registeredAccount()
	if err != nil {
		return err
	}
	list, err := deviceClient(acct, data.Device).ListDevices()
	if err != nil {
		return err
	}
	if jsonOutput {
		out, _ := json.MarshalIndent(map[string]any{"devices": list.Devices, "passkeys": list.Passkeys}, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	stamp := func(t int64) string { return time.Unix(t, 0).UTC().Format(time.RFC3339) }
	for _, d := range list.Devices {
		line := fmt.Sprintf("%q  %-24q enrolled %s", d.ID, d.Name, stamp(d.CreatedAt))
		if d.RevokedAt != nil {
			line += "  revoked " + stamp(*d.RevokedAt)
		}
		if d.ID == data.Device.ID {
			line += "  (this device)"
		}
		fmt.Println(line)
	}
	for _, p := range list.Passkeys {
		kind := "passkey for sign-in"
		if p.PRF {
			kind = "passkey that unlocks"
		}
		line := fmt.Sprintf("%q  %s, registered %s", p.ID, kind, stamp(p.CreatedAt))
		if p.RevokedAt != nil {
			line += "  revoked " + stamp(*p.RevokedAt)
		}
		fmt.Println(line)
	}
	return nil
}

// CmdRevokeDevice ends another device's server access.
func CmdRevokeDevice(id string) error {
	ref, key, data, acct, err := registeredAccount()
	if err != nil {
		return err
	}
	if id == data.Device.ID {
		return errors.New("this is the device you are using; revoke it from another device")
	}
	if err := deviceClient(acct, data.Device).RevokeDevice(id); err != nil {
		return err
	}
	// This device knows of the revocation, so its next sync prints no notice for it.
	if err := vault.UpdateVault(ref, key, func(d *vault.VaultData) error {
		keep := []string{}
		for _, known := range d.Sync.KnownDevices {
			if known != id {
				keep = append(keep, known)
			}
		}
		d.Sync.KnownDevices = keep
		if vault.ValidKnownID(id) && !slices.Contains(d.Sync.KnownRevoked, id) {
			d.Sync.KnownRevoked = append(d.Sync.KnownRevoked, id)
		}
		return nil
	}); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Device revoked. "+RevokeNote)
	return nil
}
