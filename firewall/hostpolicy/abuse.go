package hostpolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const abuseChain = "NARWHAL_RFW_ABUSE"
const abuseChainMarker = "narwhal-agent-managed-v1"

func validateBridgeInterfaces(policy AbusePolicy, isBridge func(string) bool) error {
	if !(policy.enabled()) {
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
	enabled := policy.enabled()
	chainState, chainErr := run(ctx, binary, "-w", "-t", "filter", "-S", abuseChain)
	chainExists := chainErr == nil
	if chainExists && !ownsAbuseChain(parseAbuseRules(chainState, abuseChain)) {
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

	want := abuseRules(policy)
	if !chainExists {
		if _, err := run(ctx, binary, "-w", "-t", "filter", "-N", abuseChain); err != nil {
			return fmt.Errorf("create managed chain: %w", err)
		}
		marker := want[len(want)-1].args
		if _, err := run(ctx, binary, append([]string{"-w", "-t", "filter", "-A", abuseChain}, marker...)...); err != nil {
			_, _ = run(ctx, binary, "-w", "-t", "filter", "-X", abuseChain)
			return fmt.Errorf("mark managed chain ownership: %w", err)
		}
		chainState = []byte("-A " + abuseChain + " " + strings.Join(marker, " "))
	}
	live := parseAbuseRules(chainState, abuseChain)
	if !sameAbuseRules(live, want) {
		marker := want[len(want)-1].args
		if len(live) == 0 || !slices.Equal(live[len(live)-1].args, marker) {
			if _, err := run(ctx, binary, append([]string{"-w", "-t", "filter", "-A", abuseChain}, marker...)...); err != nil {
				return fmt.Errorf("restore abuse chain terminator: %w", err)
			}
			live = append(live, abuseRule{args: marker})
		}
		// Insert the new policy ahead of the existing rules before removing the
		// old rules. Leave the ownership marker in place throughout.
		for i, rule := range want[:len(want)-1] {
			args := append([]string{"-w", "-t", "filter", "-I", abuseChain, strconv.Itoa(i + 1)}, rule.args...)
			if _, err := run(ctx, binary, args...); err != nil {
				for position := i; position > 0; position-- {
					if _, rollback := run(ctx, binary, "-w", "-t", "filter", "-D", abuseChain, strconv.Itoa(position)); rollback != nil {
						return errors.Join(fmt.Errorf("add managed abuse rule: %w", err), fmt.Errorf("roll back additions: %w", rollback))
					}
				}
				return fmt.Errorf("add managed abuse rule: %w", err)
			}
		}
		for i := len(live) - 1; i >= 0; i-- {
			if slices.Equal(live[i].args, want[len(want)-1].args) && i == len(live)-1 {
				continue
			}
			if _, err := run(ctx, binary, "-w", "-t", "filter", "-D", abuseChain, strconv.Itoa(len(want)+i)); err != nil {
				return fmt.Errorf("remove old abuse rule: %w", err)
			}
		}
	}
	if _, err := run(ctx, binary, "-w", "-t", "filter", "-C", "FORWARD", "-j", abuseChain); err != nil {
		if _, err := run(ctx, binary, "-w", "-t", "filter", "-I", "FORWARD", "1", "-j", abuseChain); err != nil {
			return fmt.Errorf("attach managed chain to container-forward path: %w", err)
		}
	}
	return nil
}

type abuseRule struct {
	iface, category, transport, ports, signature string
	args                                         []string
	packets, bytes                               uint64
}

func (p AbusePolicy) enabled() bool {
	return p.Speedtest || p.Mining || p.BT || p.SMTP || p.ObserveMining || p.ObserveBT
}

func abuseRules(policy AbusePolicy) []abuseRule {
	var rules []abuseRule
	for _, iface := range policy.Interfaces {
		add := func(category, transport, ports string, multiport, reset bool) {
			args := []string{"-i", iface, "-p", transport}
			if multiport {
				args = append(args, "-m", "multiport", "--dports", ports)
			} else {
				args = append(args, "--dport", ports)
			}
			if reset {
				args = append(args, "-j", "REJECT", "--reject-with", "tcp-reset")
			} else {
				args = append(args, "-j", "DROP")
			}
			rules = append(rules, abuseRule{iface: iface, category: category, transport: transport, ports: ports, args: args})
		}
		if policy.Speedtest {
			add("speedtest", "tcp", "5201", false, true)
			add("speedtest", "udp", "5201", false, false)
		}
		if policy.Mining {
			add("mining", "tcp", "3333,4444,5555,6666,7777,8888,9999,14433,14444", true, true)
		}
		if policy.BT {
			for _, protocol := range []string{"tcp", "udp"} {
				for _, port := range []string{"6881:6889", "6969", "51413"} {
					add("bt", protocol, port, false, false)
				}
				add("bt", protocol, "4662,4672", true, false)
			}
		}
		if policy.SMTP {
			add("smtp", "tcp", "25,465,587,2525", true, true)
		}
	}
	// Preserve the order produced by previous versions inserting at position 1.
	slices.Reverse(rules)
	var observers []abuseRule
	for _, iface := range policy.Interfaces {
		add := func(category, transport, signature string, matches ...string) {
			args := []string{"-i", iface, "-p", transport}
			for i := 0; i < len(matches); i += 2 {
				args = append(args, "-m", "string", matches[i], matches[i+1], "--algo", "kmp", "--from", "28", "--to", "256")
			}
			// A rule without a target increments its counter and continues.
			observers = append(observers, abuseRule{iface: iface, category: category, transport: transport, signature: signature, args: args})
		}
		if policy.ObserveMining {
			add("mining", "tcp", "stratum_subscribe", "--string", `"method"`, "--string", `"mining.subscribe"`)
			add("mining", "tcp", "stratum_authorize", "--string", `"method"`, "--string", `"mining.authorize"`)
		}
		if policy.ObserveBT {
			add("bt", "tcp", "bittorrent_handshake", "--hex-string", "|13426974546f7272656e742070726f746f636f6c|")
			add("bt", "udp", "dht_get_peers", "--string", "d1:ad2:id20:", "--string", "e1:q9:get_peers1:t", "--string", "1:y1:qe")
			add("bt", "udp", "dht_announce_peer", "--string", "d1:ad2:id20:", "--string", "e1:q13:announce_peer1:t", "--string", "1:y1:qe")
		}
	}
	return append(append(observers, rules...), abuseRule{args: abuseMarkerArgs})
}

func parseAbuseRules(data []byte, chain string) []abuseRule {
	var rules []abuseRule
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "-A" || fields[1] != chain {
			continue
		}
		var rule abuseRule
		for i := 2; i < len(fields); i++ {
			switch {
			case fields[i] == "-c" && i+2 < len(fields):
				rule.packets, _ = strconv.ParseUint(fields[i+1], 10, 64)
				rule.bytes, _ = strconv.ParseUint(fields[i+2], 10, 64)
				i += 2
			case fields[i] == "-m" && i+1 < len(fields) && (fields[i+1] == "tcp" || fields[i+1] == "udp"):
				i++ // iptables prints the implicit transport match explicitly.
			default:
				value := fields[i]
				if decoded, err := strconv.Unquote(value); err == nil && strings.HasPrefix(value, "\"") {
					value = decoded
				}
				rule.args = append(rule.args, value)
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

func sameAbuseRules(live, want []abuseRule) bool {
	return slices.EqualFunc(live, want, func(a, b abuseRule) bool { return slices.Equal(a.args, b.args) })
}

type AbuseFamilyReadback struct {
	Family       string              `json:"family"`
	Status       string              `json:"status"`
	ChainPresent bool                `json:"chain_present"`
	ForwardJump  bool                `json:"forward_jump"`
	Rules        []AbuseRuleReadback `json:"rules"`
}

type AbuseRuleReadback struct {
	Interface        string `json:"interface"`
	Category         string `json:"category"`
	Transport        string `json:"transport"`
	DestinationPorts string `json:"destination_ports"`
	Signature        string `json:"signature,omitempty"`
	Present          bool   `json:"present"`
	Packets          uint64 `json:"packets"`
	Bytes            uint64 `json:"bytes"`
}

var abuseMarkerArgs = []string{"-m", "comment", "--comment", abuseChainMarker, "-j", "RETURN"}

func ownsAbuseChain(rules []abuseRule) bool {
	return slices.ContainsFunc(rules, func(r abuseRule) bool { return slices.Equal(r.args, abuseMarkerArgs) })
}

func readAbuse(ctx context.Context, run Runner, policy AbusePolicy, ipv6 bool) []AbuseFamilyReadback {
	if run == nil {
		return nil
	}
	want := abuseRules(policy)
	families := []AbuseFamilyReadback{readAbuseFamily(ctx, run, "iptables", "ipv4", want)}
	if ipv6 {
		families = append(families, readAbuseFamily(ctx, run, "ip6tables", "ipv6", want))
	}
	return families
}

func readAbuseFamily(ctx context.Context, run Runner, tool, family string, want []abuseRule) AbuseFamilyReadback {
	result := AbuseFamilyReadback{Family: family, Status: "unavailable", Rules: make([]AbuseRuleReadback, 0, len(want)-1)}
	data, err := run(ctx, tool, "-w", "-t", "filter", "-S", "-v")
	if err != nil {
		return result
	}
	live := parseAbuseRules(data, abuseChain)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if slices.Equal(fields, []string{"-N", abuseChain}) {
			result.ChainPresent = true
		}
	}
	result.ForwardJump = slices.ContainsFunc(parseAbuseRules(data, "FORWARD"), func(r abuseRule) bool {
		return slices.Equal(r.args, []string{"-j", abuseChain})
	})
	if len(want) == 1 && !result.ChainPresent && !result.ForwardJump {
		result.Status = "disabled"
		return result
	}
	result.Status = "drifted"
	if result.ChainPresent && !ownsAbuseChain(live) {
		result.Status = "unowned"
		live = nil
	}
	if len(want) > 1 && result.ChainPresent && result.ForwardJump && sameAbuseRules(live, want) {
		result.Status = "in_sync"
	}
	for _, expected := range want[:len(want)-1] {
		row := AbuseRuleReadback{
			Interface: expected.iface, Category: expected.category, Transport: expected.transport, DestinationPorts: expected.ports, Signature: expected.signature,
		}
		if i := slices.IndexFunc(live, func(r abuseRule) bool { return slices.Equal(r.args, expected.args) }); i >= 0 {
			row.Present, row.Packets, row.Bytes = true, live[i].packets, live[i].bytes
		}
		result.Rules = append(result.Rules, row)
	}
	return result
}
