//go:build linux

package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"runman-agent/firewall/hostpolicy"
)

const FirewallSocketPath = "/run/narwhal-agent/firewall.sock"

type FirewallController interface {
	Apply(context.Context, hostpolicy.Policy) error
	DeleteManualRule(context.Context, hostpolicy.RuleReadback) error
	Events(context.Context, string, int) (hostpolicy.EventPage, error)
	Readback(context.Context) (hostpolicy.Readback, error)
	Summary() string
}

type firewallResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func ListenAndServeFirewall(path string, manager FirewallController) error {
	if path == "" || manager == nil {
		return errors.New("host firewall local control is not configured")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create local control directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("secure local control directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket control path %q", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return fmt.Errorf("host firewall control socket is already active: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale firewall control socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on host firewall control socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("secure firewall control socket: %w", err)
	}
	server := &http.Server{Handler: newFirewallHandler(manager), ReadHeaderTimeout: 5 * time.Second}
	return server.Serve(listener)
}

func newFirewallHandler(manager FirewallController) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/firewall/events", func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		if len(cursor) > 160 {
			writeFirewallResult(w, http.StatusBadRequest, false, "invalid firewall event cursor")
			return
		}
		limit := 100
		if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
			parsedLimit, err := strconv.Atoi(rawLimit)
			if err != nil || parsedLimit < 1 || parsedLimit > 100 {
				writeFirewallResult(w, http.StatusBadRequest, false, "firewall event limit must be between 1 and 100")
				return
			}
			limit = parsedLimit
		}
		page, err := manager.Events(r.Context(), cursor, limit)
		if err != nil {
			if errors.Is(err, hostpolicy.ErrRFWEventsUnsupported) {
				writeFirewallResult(w, http.StatusNotFound, false, "RFW build does not expose an events API")
				return
			}
			writeFirewallResult(w, http.StatusServiceUnavailable, false, "RFW event telemetry is unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(page)
	})
	mux.HandleFunc("GET /v1/firewall/readback", func(w http.ResponseWriter, r *http.Request) {
		readback, err := manager.Readback(r.Context())
		if err != nil {
			writeFirewallResult(w, http.StatusServiceUnavailable, false, "RFW live rule readback is unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(readback)
	})
	mux.HandleFunc("DELETE /v1/firewall/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.Atoi(r.PathValue("id"))
		if err != nil || id < 1 {
			writeFirewallResult(w, http.StatusBadRequest, false, "invalid RFW rule ID")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
		if err != nil || len(body) > 16*1024 {
			writeFirewallResult(w, http.StatusBadRequest, false, "invalid or oversized RFW rule identity")
			return
		}
		var expected hostpolicy.RuleReadback
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&expected); err != nil {
			writeFirewallResult(w, http.StatusBadRequest, false, "invalid RFW rule identity JSON")
			return
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			writeFirewallResult(w, http.StatusBadRequest, false, "RFW rule identity must contain one JSON object")
			return
		}
		if expected.ID != id {
			writeFirewallResult(w, http.StatusBadRequest, false, "RFW rule ID does not match the requested path")
			return
		}
		if err := manager.DeleteManualRule(r.Context(), expected); err != nil {
			writeFirewallResult(w, http.StatusConflict, false, err.Error())
			return
		}
		writeFirewallResult(w, http.StatusOK, true, "RFW manual rule deleted or already absent")
	})
	mux.HandleFunc("POST /v1/firewall/policy", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 128*1024+1))
		if err != nil || len(body) > 128*1024 {
			writeFirewallResult(w, http.StatusBadRequest, false, "invalid or oversized policy request")
			return
		}
		var policy hostpolicy.Policy
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&policy); err != nil {
			writeFirewallResult(w, http.StatusBadRequest, false, "invalid firewall policy JSON")
			return
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			writeFirewallResult(w, http.StatusBadRequest, false, "firewall policy must contain one JSON object")
			return
		}
		if err := manager.Apply(r.Context(), policy); err != nil {
			writeFirewallResult(w, http.StatusConflict, false, err.Error())
			return
		}
		writeFirewallResult(w, http.StatusOK, true, manager.Summary())
	})
	return mux
}

func writeFirewallResult(w http.ResponseWriter, status int, ok bool, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(firewallResult{OK: ok, Message: message})
}
