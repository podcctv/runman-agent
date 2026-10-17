//go:build !linux

package controlapi

import (
	"errors"

	"runman-agent/firewall/hostpolicy"
)

const FirewallSocketPath = ""

func ListenAndServeFirewall(string, *hostpolicy.Manager) error {
	return errors.New("host firewall local control requires Linux")
}
