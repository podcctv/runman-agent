//go:build linux

package incus

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
)

const (
	gracefulStopSeconds = 30
	lifecycleTimeout    = 60 * time.Second
)

func stopRequest(force bool) api.InstanceStatePut {
	request := api.InstanceStatePut{Action: "stop", Force: force}
	if !force {
		request.Timeout = gracefulStopSeconds
	}
	return request
}

func connectLifecycle(ctx context.Context) (incus.InstanceServer, error) {
	// A separate client keeps the deadline off the shared client. HTTP waits
	// on this connection inherit the same deadline as the request submission.
	return incus.ConnectIncusUnixWithContext(ctx, SocketPath, &incus.ConnectionArgs{SkipGetEvents: true})
}

func changeInstanceState(ctx context.Context, name string, request api.InstanceStatePut) error {
	ctx, cancel := context.WithTimeout(ctx, lifecycleTimeout)
	defer cancel()

	client, err := connectLifecycle(ctx)
	if err != nil {
		return fmt.Errorf("connect for Incus %s of %s: %w", request.Action, name, err)
	}
	defer client.Disconnect()

	if err := checkLifecycleOperations(client, name); err != nil {
		return err
	}
	if request.Action == "stop" {
		instance, _, err := client.GetInstance(name)
		if err != nil {
			return fmt.Errorf("read Incus instance %s before stop: %w", name, err)
		}
		if instance.StatusCode == api.Stopped {
			return nil
		}
	}
	return submitInstanceState(client, name, request)
}

func removeInstance(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, lifecycleTimeout)
	defer cancel()

	client, err := connectLifecycle(ctx)
	if err != nil {
		return fmt.Errorf("connect for Incus deletion of %s: %w", name, err)
	}
	defer client.Disconnect()

	if err := checkLifecycleOperations(client, name); err != nil {
		return err
	}
	instance, _, err := client.GetInstance(name)
	if api.StatusErrorCheck(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Incus instance %s before delete: %w", name, err)
	}
	if instance.StatusCode != api.Stopped {
		if err := submitInstanceState(client, name, stopRequest(true)); err != nil {
			return err
		}
		// Check again because an external caller could have started an
		// operation while we were waiting for the stop to complete.
		if err := checkLifecycleOperations(client, name); err != nil {
			return err
		}
	}

	op, err := client.DeleteInstance(name)
	if api.StatusErrorCheck(err, http.StatusNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("submit Incus delete for %s: %w", name, err)
	}
	return waitLifecycleOperation(client, op.Get().ID, name, "delete")
}

func submitInstanceState(client incus.InstanceServer, name string, request api.InstanceStatePut) error {
	op, err := client.UpdateInstanceState(name, request, "")
	if err != nil {
		return fmt.Errorf("submit Incus %s for %s: %w", request.Action, name, err)
	}
	return waitLifecycleOperation(client, op.Get().ID, name, request.Action)
}

func waitLifecycleOperation(client incus.InstanceServer, id, name, action string) error {
	// The HTTP request context bounds the wait without cancelling the Incus
	// operation. A caller can use the operation ID to inspect it later.
	result, _, err := client.GetOperationWait(id, -1)
	if err != nil {
		return fmt.Errorf("wait for Incus %s of %s (operation %s): %w", action, name, id, err)
	}
	if result.StatusCode != api.Success {
		return fmt.Errorf("Incus %s of %s (operation %s) returned %s (%d): %s",
			action, name, id, result.Status, result.StatusCode, result.Err)
	}
	return nil
}

func checkLifecycleOperations(client incus.InstanceServer, name string) error {
	operations, err := client.GetOperations()
	if err != nil {
		return fmt.Errorf("check Incus operations before changing %s: %w", name, err)
	}
	for _, op := range operations {
		if op.StatusCode.IsFinal() {
			continue
		}
		switch op.Description {
		case "Creating instance", "Starting instance", "Stopping instance", "Restarting instance",
			"Deleting instance", "Rebuilding instance", "Renaming instance", "Migrating instance",
			"Live-migrating instance", "Freezing instance", "Unfreezing instance", "Updating instance",
			"Restoring snapshot":
		default:
			continue
		}

		knownTarget := false
		for _, kind := range []string{"instances", "containers", "virtual-machines"} {
			for _, resource := range op.Resources[kind] {
				target, err := url.Parse(resource)
				if err != nil {
					continue
				}
				parts := strings.Split(strings.TrimPrefix(target.EscapedPath(), "/"), "/")
				if len(parts) != 3 || parts[0] != "1.0" || parts[1] != kind {
					continue
				}
				instanceName, err := url.PathUnescape(parts[2])
				if err != nil || instanceName == "" {
					continue
				}
				if instanceName == name {
					return fmt.Errorf("Incus instance %s already has %q in progress (operation %s)", name, op.Description, op.ID)
				}
				knownTarget = true
			}
		}
		if !knownTarget {
			return fmt.Errorf("cannot change Incus instance %s while %q has an unknown target (operation %s)", name, op.Description, op.ID)
		}
	}
	return nil
}
