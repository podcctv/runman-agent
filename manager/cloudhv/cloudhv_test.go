package cloudhv

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestBootFailureCleansUpNewProcess(t *testing.T) {
	dir := t.TempDir()
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
	if err := os.WriteFile(filepath.Join(dir, "cloudinit.img"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	manager := Manager{binary: launcher, runDir: dir}
	err = manager.bootNewProcess("vm", &vmCreateReq{Disks: buildDisks(dir, 0)})
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
