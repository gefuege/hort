package cli

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/gefuege/hort/internal/api"
	"github.com/gefuege/hort/internal/vault"
)

func TestApplyDevicesNoticesEachChangeOnce(t *testing.T) {
	data, err := vault.NewBody("self")
	if err != nil {
		t.Fatal(err)
	}
	self := data.Device.ID
	laptop, phone, gone := strings.Repeat("b", 32), strings.Repeat("c", 32), strings.Repeat("d", 32)
	known, fresh := strings.Repeat("1", 64), strings.Repeat("2", 64)
	data.Sync.KnownDevices = []string{self, laptop, knownMark(known, false)}
	data.Sync.DevicesVersion = 2
	revoked := int64(1)
	list := api.Devices{DevicesVersion: 4,
		Devices: []api.DeviceInfo{
			{ID: self, Name: "self"},
			{ID: laptop, Name: "laptop", RevokedAt: &revoked},
			{ID: phone, Name: "phone\x1b[2J"},
			{ID: gone, Name: "gone", RevokedAt: &revoked},
		},
		Passkeys: []api.PasskeyInfo{
			{ID: known, PRF: true, RevokedAt: &revoked},
			{ID: fresh, CreatedAt: 60},
		},
	}
	got := applyDevices(data, list)
	want := []string{
		`notice: device "laptop" revoked`,
		`notice: new device "phone\x1b[2J" enrolled 1970-01-01T00:00:00Z`,
		`notice: new device "gone" enrolled 1970-01-01T00:00:00Z`,
		`notice: device "gone" revoked`,
		`notice: passkey "11111111" revoked`,
		`notice: new passkey "22222222" registered 1970-01-01T00:01:00Z`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("notices %q, want %q", got, want)
	}
	if data.Sync.DevicesVersion != 4 {
		t.Fatalf("devices_version %d", data.Sync.DevicesVersion)
	}
	for _, m := range data.Sync.KnownDevices {
		if b, err := hex.DecodeString(m); err != nil || len(b) != 16 || hex.EncodeToString(b) != m {
			t.Fatalf("known_devices entry %q breaks the body's ID rule", m)
		}
	}
	if again := applyDevices(data, list); again != nil {
		t.Fatalf("second application: %q", again)
	}
	// A later change notices only itself, not the revoked entries again.
	list.DevicesVersion = 5
	list.Devices[2].RevokedAt = &revoked
	if got := applyDevices(data, list); !reflect.DeepEqual(got, []string{`notice: device "phone\x1b[2J" revoked`}) {
		t.Fatalf("later change: %q", got)
	}
}
