package portforward

import (
	"context"
	"errors"
	"testing"

	"runman-agent/db"
)

func TestFormatTargetAddress(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int
		want string
	}{
		{name: "IPv4", ip: "10.91.0.2", port: 22, want: "10.91.0.2:22"},
		{name: "IPv6", ip: "2001:db8:100::2", port: 22, want: "[2001:db8:100::2]:22"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatTargetAddress(tc.ip, tc.port); got != tc.want {
				t.Fatalf("formatTargetAddress(%q, %d) = %q, want %q", tc.ip, tc.port, got, tc.want)
			}
		})
	}
}

func TestValidateHostPortPolicy(t *testing.T) {
	tests := []struct {
		name        string
		port        int
		allowLegacy bool
		wantErr     error
	}{
		{name: "new minimum is inclusive", port: MinNewPort},
		{name: "new maximum is inclusive", port: MaxPort},
		{name: "legacy port can be restored", port: MinNewPort - 1, allowLegacy: true},
		{name: "new low port is rejected", port: MinNewPort - 1, wantErr: ErrNewHostPortBelowFloor},
		{name: "privileged ports remain invalid", port: MinPort - 1, allowLegacy: true, wantErr: ErrHostPortOutOfRange},
		{name: "port above range is invalid", port: MaxPort + 1, allowLegacy: true, wantErr: ErrHostPortOutOfRange},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHostPort(tc.port, tc.allowLegacy)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("validateHostPort(%d, %t) error = %v, want %v", tc.port, tc.allowLegacy, err, tc.wantErr)
			}
		})
	}
}

func TestAddMappingRejectsNewLowHostPortBeforeTouchingRuntime(t *testing.T) {
	manager := &Manager{}
	err := manager.AddMapping(context.Background(), "vm-a", "tcp", MinNewPort-1, 22, "")
	if !errors.Is(err, ErrNewHostPortBelowFloor) {
		t.Fatalf("AddMapping low host port error = %v, want %v", err, ErrNewHostPortBelowFloor)
	}
}

func TestAddMappingKeepsExistingLowPortIdempotent(t *testing.T) {
	entry := &Entry{VMID: "vm-a", Protocol: "tcp", HostPort: 2222, GuestPort: 22, Description: "ssh"}
	manager := &Manager{mappings: map[string][]*Entry{"vm-a": {entry}}}
	if err := manager.AddMapping(context.Background(), "vm-a", "tcp", 2222, 22, "ssh"); err != nil {
		t.Fatalf("idempotent legacy mapping was rejected: %v", err)
	}
}

func TestSyncRejectsNewLowPortBeforeRemovingExistingMappings(t *testing.T) {
	database, err := db.Init(":memory:")
	if err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	entry := &Entry{VMID: "vm-a", Protocol: "tcp", HostPort: 22000, GuestPort: 22}
	manager := &Manager{db: database, mappings: map[string][]*Entry{"vm-a": {entry}}}
	err = manager.SyncForVM(context.Background(), "vm-a", []DesiredRule{{Protocol: "tcp", HostPort: 19999, GuestPort: 22}})
	if !errors.Is(err, ErrNewHostPortBelowFloor) {
		t.Fatalf("SyncForVM low host port error = %v, want %v", err, ErrNewHostPortBelowFloor)
	}
	if len(manager.mappings["vm-a"]) != 1 || manager.mappings["vm-a"][0] != entry {
		t.Fatal("invalid low-port request changed an existing mapping before rejection")
	}
}

func TestSyncKeepsPersistedLegacyPort(t *testing.T) {
	database, err := db.Init(":memory:")
	if err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	if err := database.SavePortForward(&db.PortForward{VMID: "vm-a", Protocol: "tcp", HostPort: 2222, GuestPort: 22, Description: "ssh"}); err != nil {
		t.Fatalf("save existing legacy mapping: %v", err)
	}
	entry := &Entry{VMID: "vm-a", Protocol: "tcp", HostPort: 2222, GuestPort: 22, Description: "ssh"}
	manager := &Manager{db: database, mappings: map[string][]*Entry{"vm-a": {entry}}}
	err = manager.SyncForVM(context.Background(), "vm-a", []DesiredRule{{Protocol: "tcp", HostPort: 2222, GuestPort: 22, Description: "ssh"}})
	if err != nil {
		t.Fatalf("existing persisted low-port mapping was rejected: %v", err)
	}
	if len(manager.mappings["vm-a"]) != 1 || manager.mappings["vm-a"][0] != entry {
		t.Fatal("sync did not preserve the existing legacy mapping")
	}
}
