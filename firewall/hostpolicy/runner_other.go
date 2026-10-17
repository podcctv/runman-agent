//go:build !linux

package hostpolicy

import (
	"context"
	"errors"
)

func commandRunner(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("host firewall control requires Linux")
}

func ipv6Available() bool { return false }

func linuxBridgeExists(string) bool { return false }
