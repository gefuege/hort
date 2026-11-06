package cli

import (
	"reflect"
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
	data.Sync.KnownDevices, data.Sync.DevicesVersion = []string{self, "b"}, 2
	revoked := int64(1)
	list := api.Devices{DevicesVersion: 4, Devices: []api.DeviceInfo{
		{ID: self, Name: "self"},
		{ID: "b", Name: "laptop", RevokedAt: &revoked},
		{ID: "c", Name: "phone\x1b[2J", CreatedAt: 0},
		{ID: "d", Name: "gone", RevokedAt: &revoked},
	}}
	got := applyDevices(data, list)
	want := []string{`notice: device "laptop" revoked`, `notice: new device "phone\x1b[2J" enrolled 1970-01-01T00:00:00Z`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("notices %q, want %q", got, want)
	}
	if !reflect.DeepEqual(data.Sync.KnownDevices, []string{self, "c"}) || data.Sync.DevicesVersion != 4 {
		t.Fatalf("sync state %+v", data.Sync)
	}
	if again := applyDevices(data, list); again != nil {
		t.Fatalf("second application: %q", again)
	}
}
