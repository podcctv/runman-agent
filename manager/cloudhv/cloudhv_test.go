package cloudhv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"runman-agent/db"
	"runman-agent/proto/agent"
)

// Run as a subprocess behind the same Unix socket and HTTP interface as the VMM.
func TestCloudHVFixture(t *testing.T) {
	if os.Getenv("RUNMAN_TEST_CLOUDHV_FIXTURE") != "1" {
		return
	}
	socket := strings.TrimPrefix(os.Args[len(os.Args)-1], "path=")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	handler := http.NewServeMux()
	handler.HandleFunc("PUT /api/v1/vm.create", func(w http.ResponseWriter, r *http.Request) {
		var config vmCreateReq
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(config.Disks) != 2 || config.Disks[0].ImageType != "Raw" ||
			config.Disks[1].ImageType != "Raw" || !config.Disks[1].Readonly {
			http.Error(w, "both disks must specify Raw and seed must be read-only", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("PUT /api/v1/vm.boot", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "fixture boot failure", http.StatusBadRequest)
	})
	if err := http.Serve(listener, handler); err != nil {
		t.Fatal(err)
	}
}

// Execute inside a disposable network namespace on an amd64 host with KVM.
func TestBootCloudHVOnKVM(t *testing.T) {
	binary := os.Getenv("RUNMAN_TEST_KVM_BINARY")
	imageDir := os.Getenv("RUNMAN_TEST_KVM_IMAGES")
	if binary == "" || imageDir == "" {
		t.Skip("requires a Cloud Hypervisor binary and fixture image")
	}
	dir := t.TempDir()
	database, err := db.Init(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	manager := Manager{
		binary: binary, imageDir: imageDir, instDir: dir, runDir: dir,
		db: database, ipv6Mode: "none",
	}
	if err := manager.ensureBridge(); err != nil {
		t.Fatal(err)
	}
	slot, err := database.NextCloudHVIdx()
	if err != nil {
		t.Fatal(err)
	}
	manager.binary = cloudHVFixture(t, dir)
	err = manager.CreateVM(context.Background(), &agent.CmdCreateVM{
		VmId: "failed", OsImage: "alpine", Cpu: 1, RamMb: 512, DiskGb: 3,
		RootPassword: "CloudHV-fixture-only",
	})
	if err == nil || !strings.Contains(err.Error(), "fixture boot failure") {
		t.Fatalf("expected fixture boot failure, got %v", err)
	}
	for _, path := range []string{
		manager.pidFile("failed"),
		manager.sockPath("failed"),
		filepath.Join(dir, "failed"),
		filepath.Join("/sys/class/net", fmt.Sprintf("%s%d", tapBase, slot)),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("failed VM left %s behind: %v", path, err)
		}
	}
	if next, err := database.NextCloudHVIdx(); next != slot || err != nil {
		t.Fatalf("failed VM retained its address/slot: got %d, want %d (%v)", next, slot, err)
	}
	manager.binary = binary
	id := "kvm"
	t.Cleanup(func() {
		if t.Failed() {
			if log, err := os.ReadFile(filepath.Join(dir, id+".log")); err == nil {
				t.Logf("Cloud Hypervisor:\n%s", log)
			}
		}
		if err := manager.DeleteVM(context.Background(), id); err != nil {
			t.Error(err)
		}
	})
	if err := manager.CreateVM(context.Background(), &agent.CmdCreateVM{
		VmId: id, OsImage: "alpine", Cpu: 1, RamMb: 512, DiskGb: 3,
		RootPassword: "CloudHV-fixture-only",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := manager.getNetworkConfig(id)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(75 * time.Second); time.Now().Before(deadline); {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.IPv4, "22"), time.Second)
		if err == nil {
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			var prefix [8]byte
			_, readErr := io.ReadFull(connection, prefix[:])
			_ = connection.Close()
			if readErr == nil && string(prefix[:]) == "SSH-2.0-" {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("guest at %s did not present an SSH banner", cfg.IPv4)
}

func cloudHVFixture(t *testing.T, dir string) string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNMAN_TEST_CLOUDHV_FIXTURE", "1")
	t.Setenv("RUNMAN_TEST_CLOUDHV_BINARY", binary)
	launcher := filepath.Join(dir, "fixture")
	if err := os.WriteFile(launcher, []byte(
		"#!/bin/sh\nexec \"$RUNMAN_TEST_CLOUDHV_BINARY\" -test.run '^TestCloudHVFixture$' -- \"$@\"\n",
	), 0700); err != nil {
		t.Fatal(err)
	}
	return launcher
}

func TestBootFailureCleansUpNewProcess(t *testing.T) {
	dir := t.TempDir()
	launcher := cloudHVFixture(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "cloudinit.img"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	manager := Manager{binary: launcher, runDir: dir}
	err := manager.bootNewProcess("vm", &vmCreateReq{Disks: buildDisks(dir, 0)})
	if err == nil || !strings.Contains(err.Error(), "vm.boot") ||
		!strings.Contains(err.Error(), "fixture boot failure") {
		t.Fatalf("expected a boot failure after successful disk validation, got %v", err)
	}
	for _, path := range []string{manager.pidFile("vm"), manager.sockPath("vm"), manager.serialSockPath("vm")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("failed VM left %s behind: %v", path, err)
		}
	}
}
