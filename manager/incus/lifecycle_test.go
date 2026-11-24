//go:build linux

package incus

import (
	"context"
	"errors"
	"strings"
	"testing"

	incus "github.com/lxc/incus/v6/client"
	"github.com/lxc/incus/v6/shared/api"
)

type lifecycleTestClient struct {
	incus.InstanceServer
	operations []api.Operation
	listErr    error
	result     *api.Operation
	waitErr    error
}

func (c lifecycleTestClient) GetOperations() ([]api.Operation, error) {
	return c.operations, c.listErr
}

func (c lifecycleTestClient) GetOperationWait(string, int) (*api.Operation, string, error) {
	return c.result, "", c.waitErr
}

func TestCheckLifecycleOperations(t *testing.T) {
	for _, test := range []struct {
		name, description, resource string
		status                      api.StatusCode
		blocked                     bool
	}{
		{"running stop on target", "Stopping instance", "/1.0/instances/test?project=default", api.Running, true},
		{"pending restart on target", "Restarting instance", "/1.0/instances/test", api.Pending, true},
		{"finished stop", "Stopping instance", "/1.0/instances/test", api.Failure, false},
		{"similar instance name", "Stopping instance", "/1.0/instances/test-other", api.Running, false},
		{"missing stop target", "Stopping instance", "", api.Running, true},
		{"exec on target", "Executing command", "/1.0/instances/test", api.Running, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			op := api.Operation{ID: "existing-id", Description: test.description, StatusCode: test.status}
			if test.resource != "" {
				op.Resources = map[string][]string{"instances": {test.resource}}
			}
			err := checkLifecycleOperations(lifecycleTestClient{operations: []api.Operation{op}}, "test")
			if test.blocked {
				if err == nil || !strings.Contains(err.Error(), op.ID) {
					t.Fatalf("expected a conflict with operation %s, got %v", op.ID, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}

	err := checkLifecycleOperations(lifecycleTestClient{listErr: context.DeadlineExceeded}, "test")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected operation list timeout, got %v", err)
	}
}

func TestWaitLifecycleOperation(t *testing.T) {
	for _, test := range []struct {
		name   string
		status api.StatusCode
		err    error
	}{
		{"finished successfully", api.Success, nil},
		{"still running", api.Running, nil},
		{"failed", api.Failure, nil},
		{"request timed out", 0, context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := lifecycleTestClient{
				result:  &api.Operation{StatusCode: test.status, Status: test.status.String()},
				waitErr: test.err,
			}
			err := waitLifecycleOperation(client, "submitted-id", "test", "stop")
			if test.status == api.Success {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "submitted-id") {
				t.Fatalf("expected error with operation ID, got %v", err)
			}
			if test.err != nil && !errors.Is(err, test.err) {
				t.Fatalf("expected wrapped %v, got %v", test.err, err)
			}
		})
	}
}
