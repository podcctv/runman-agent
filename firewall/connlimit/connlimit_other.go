//go:build !linux

package connlimit

import (
	"context"
	"errors"
)

type Policy struct {
	ID         string   `json:"id"`
	VMID       string   `json:"vm_id"`
	InstanceID string   `json:"instance_id"`
	Max        int      `json:"max_connections"`
	ExpiresAt  int64    `json:"expires_at"`
	IPs        []string `json:"ips"`
	RemoveOnly bool     `json:"remove_only,omitempty"`
}

type Target struct {
	Managed    bool
	Running    bool
	InstanceID string
	IPs        []string
}

type Resolver func(context.Context, string) (Target, error)
type Manager struct{}

func New(string, string, string) *Manager { return &Manager{} }
func (*Manager) Apply(Policy) error       { return errors.New("container connection limits require Linux") }
func (*Manager) Release(string, string, string) error {
	return errors.New("container connection limits require Linux")
}
func (*Manager) Expire(string) error { return errors.New("container connection limits require Linux") }
func (*Manager) Reconcile(context.Context, Resolver) error {
	return errors.New("container connection limits require Linux")
}
