//go:build !linux

package controlapi

import (
	"context"
	"errors"
)

const ConnlimitSocketPath = ""

type Target struct {
	Managed    bool
	Running    bool
	InstanceID string
	IPs        []string
}

type Resolver func(context.Context, string, string) (Target, error)

func ListenAndServe(string, Resolver, any) error {
	return errors.New("connection-limit local control requires Linux")
}

func ReconcileLoop(context.Context, Resolver, any) {}
