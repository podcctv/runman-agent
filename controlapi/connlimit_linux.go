//go:build linux

package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"runman-agent/firewall/connlimit"
)

const ConnlimitSocketPath = "/run/narwhal-agent/connlimit.sock"

type Target struct {
	Managed    bool
	Running    bool
	InstanceID string
	IPs        []string
}

type Resolver func(context.Context, string, string) (Target, error)

type connlimitRequest struct {
	Action         string `json:"action"`
	PolicyID       string `json:"policy_id"`
	ContainerName  string `json:"container_name"`
	Project        string `json:"project"`
	InstanceID     string `json:"instance_id"`
	MaxConnections int    `json:"max_connections"`
	ExpiresAt      int64  `json:"expires_at"`
}

type result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func ListenAndServe(path string, resolver Resolver, limiter *connlimit.Manager) error {
	if path == "" || resolver == nil || limiter == nil {
		return errors.New("connection-limit local control is not configured")
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
			return fmt.Errorf("connection-limit control socket is already active: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale control socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen on local control socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("secure local control socket: %w", err)
	}
	server := &http.Server{Handler: newHandler(resolver, limiter), ReadHeaderTimeout: 5 * time.Second}
	return server.Serve(listener)
}

func newHandler(resolver Resolver, limiter *connlimit.Manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/connlimit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeResult(w, http.StatusMethodNotAllowed, false, "POST required")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8193))
		if err != nil || len(body) > 8192 {
			writeResult(w, http.StatusBadRequest, false, "invalid or oversized request")
			return
		}
		var req connlimitRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeResult(w, http.StatusBadRequest, false, "invalid JSON request")
			return
		}
		if req.Project != "default" || req.ContainerName == "" {
			writeResult(w, http.StatusBadRequest, false, "only a named default-project Incus instance is supported")
			return
		}
		switch req.Action {
		case "apply":
			target, err := resolver(r.Context(), req.ContainerName, req.Project)
			if err != nil {
				writeResult(w, http.StatusConflict, false, "managed Incus target could not be verified: "+err.Error())
				return
			}
			if !target.Managed || !target.Running {
				writeResult(w, http.StatusConflict, false, "target is not a running Runman-managed Incus instance")
				return
			}
			if target.InstanceID == "" || target.InstanceID != req.InstanceID {
				writeResult(w, http.StatusConflict, false, "Incus instance identity changed; no firewall rule was applied")
				return
			}
			p := connlimit.Policy{ID: req.PolicyID, VMID: req.ContainerName, InstanceID: req.InstanceID,
				Max: req.MaxConnections, ExpiresAt: req.ExpiresAt, IPs: target.IPs}
			if err := limiter.Apply(p); err != nil {
				writeResult(w, http.StatusConflict, false, err.Error())
				return
			}
			writeResult(w, http.StatusOK, true, "temporary per-instance TCP connection limit applied")
		case "release":
			if err := limiter.Release(req.PolicyID, req.ContainerName, req.InstanceID); err != nil {
				writeResult(w, http.StatusConflict, false, err.Error())
				return
			}
			writeResult(w, http.StatusOK, true, "per-instance TCP connection limit released")
		default:
			writeResult(w, http.StatusBadRequest, false, "action must be apply or release")
		}
	})
	return mux
}

func ReconcileLoop(ctx context.Context, resolver Resolver, limiter *connlimit.Manager) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	reconcile := func() {
		err := limiter.Reconcile(ctx, func(ctx context.Context, vmID string) (connlimit.Target, error) {
			target, err := resolver(ctx, vmID, "default")
			return connlimit.Target{Managed: target.Managed, Running: target.Running,
				InstanceID: target.InstanceID, IPs: target.IPs}, err
		})
		if err != nil {
			log.Printf("[connlimit] reconciliation incomplete: %v", err)
		}
	}
	reconcile()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

func writeResult(w http.ResponseWriter, status int, ok bool, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result{OK: ok, Message: message})
}
