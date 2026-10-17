package hostpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const abuseChain = "NARWHAL_RFW_ABUSE"
const abuseChainMarker = "narwhal-agent-managed-v1"

func validateBridgeInterfaces(policy AbusePolicy, isBridge func(string) bool) error {
	if !(policy.Speedtest || policy.Mining || policy.BT) {
		return nil
	}
	if isBridge == nil {
		return errors.New("Linux bridge verification is unavailable")
	}
	for _, iface := range policy.Interfaces {
		if !isBridge(iface) {
			return fmt.Errorf("%q is not an existing Linux bridge; no host firewall changes were made", iface)
		}
	}
	return nil
}

func applyAbusePolicy(ctx context.Context, run Runner, policy AbusePolicy, withIPv6 bool, isBridge func(string) bool) error {
	if run == nil {
		return errors.New("firewall command runner is unavailable")
	}
	if err := validateBridgeInterfaces(policy, isBridge); err != nil {
		if cleanupErr := applyAbuseFamily(ctx, run, "iptables", AbusePolicy{}); cleanupErr != nil {
			return fmt.Errorf("%v; remove old IPv4 policy: %w", err, cleanupErr)
		}
		if withIPv6 {
			if cleanupErr := applyAbuseFamily(ctx, run, "ip6tables", AbusePolicy{}); cleanupErr != nil {
				return fmt.Errorf("%v; remove old IPv6 policy: %w", err, cleanupErr)
			}
		}
		return err
	}
	if err := applyAbuseFamily(ctx, run, "iptables", policy); err != nil {
		return fmt.Errorf("IPv4: %w", err)
	}
	if withIPv6 {
		if err := applyAbuseFamily(ctx, run, "ip6tables", policy); err != nil {
			return fmt.Errorf("IPv6: %w", err)
		}
	}
	return nil
}

func applyAbuseFamily(ctx context.Context, run Runner, binary string, policy AbusePolicy) error {
	enabled := policy.Speedtest || policy.Mining || policy.BT
	chainState, chainErr := run(ctx, binary, "-w", "-t", "filter", "-S", abuseChain)
	chainExists := chainErr == nil
	if chainExists && !strings.Contains(string(chainState), abuseChainMarker) {
		return errors.New("refusing to modify an existing unowned firewall chain")
	}
	if !enabled {
		if !chainExists {
			return nil // The managed chain has never been installed.
		}
		for {
			if _, err := run(ctx, binary, "-w", "-t", "filter", "-C", "FORWARD", "-j", abuseChain); err != nil {
				break
			}
			if _, err := run(ctx, binary, "-w", "-t", "filter", "-D", "FORWARD", "-j", abuseChain); err != nil {
				return fmt.Errorf("remove managed FORWARD jump: %w", err)
			}
		}
		if _, err := run(ctx, binary, "-w", "-t", "filter", "-F", abuseChain); err != nil {
			return fmt.Errorf("flush managed chain: %w", err)
		}
		if _, err := run(ctx, binary, "-w", "-t", "filter", "-X", abuseChain); err != nil {
			return fmt.Errorf("remove managed chain: %w", err)
		}
		return nil
	}

	created := false
	if _, err := run(ctx, binary, "-w", "-t", "filter", "-N", abuseChain); err != nil {
		if state, existsErr := run(ctx, binary, "-w", "-t", "filter", "-S", abuseChain); existsErr != nil || !strings.Contains(string(state), abuseChainMarker) {
			return fmt.Errorf("create managed chain: %w", err)
		}
	} else {
		created = true
	}
	if !created {
		if _, err := run(ctx, binary, "-w", "-t", "filter", "-F", abuseChain); err != nil {
			return fmt.Errorf("reset managed chain: %w", err)
		}
	}
	if _, err := run(ctx, binary, "-w", "-t", "filter", "-A", abuseChain, "-m", "comment", "--comment", abuseChainMarker, "-j", "RETURN"); err != nil {
		if created {
			_, _ = run(ctx, binary, "-w", "-t", "filter", "-X", abuseChain)
		}
		return fmt.Errorf("mark managed chain ownership: %w", err)
	}
	insertRule := func(iface string, args ...string) error {
		full := []string{"-w", "-t", "filter", "-I", abuseChain, "1", "-i", iface}
		full = append(full, args...)
		if _, err := run(ctx, binary, full...); err != nil {
			return fmt.Errorf("add managed abuse rule: %w", err)
		}
		return nil
	}
	for _, iface := range policy.Interfaces {
		if policy.Speedtest {
			if err := insertRule(iface, "-p", "tcp", "--dport", "5201", "-j", "REJECT", "--reject-with", "tcp-reset"); err != nil {
				return err
			}
			if err := insertRule(iface, "-p", "udp", "--dport", "5201", "-j", "DROP"); err != nil {
				return err
			}
		}
		if policy.Mining {
			if err := insertRule(iface, "-p", "tcp", "-m", "multiport", "--dports", "3333,4444,5555,6666,7777,8888,9999,14433,14444", "-j", "REJECT", "--reject-with", "tcp-reset"); err != nil {
				return err
			}
		}
		if policy.BT {
			for _, protocol := range []string{"tcp", "udp"} {
				for _, port := range []string{"6881:6889", "6969", "51413", "4662,4672"} {
					args := []string{"-p", protocol}
					if port == "4662,4672" {
						args = append(args, "-m", "multiport", "--dports", port)
					} else {
						args = append(args, "--dport", port)
					}
					args = append(args, "-j", "DROP")
					if err := insertRule(iface, args...); err != nil {
						return err
					}
				}
			}
		}
	}
	if _, err := run(ctx, binary, "-w", "-t", "filter", "-C", "FORWARD", "-j", abuseChain); err != nil {
		if _, insertErr := run(ctx, binary, "-w", "-t", "filter", "-I", "FORWARD", "1", "-j", abuseChain); insertErr != nil {
			return fmt.Errorf("attach managed chain to container-forward path: %w", insertErr)
		}
	}
	return nil
}
