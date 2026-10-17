//go:build linux

package hostpolicy

import (
	"context"
	"os"
	"os/exec"
)

func commandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func ipv6Available() bool {
	if _, err := exec.LookPath("ip6tables"); err != nil {
		return false
	}
	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

func linuxBridgeExists(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/bridge")
	return err == nil
}
