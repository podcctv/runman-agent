//go:build linux

package connlimit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	commands    [][]string
	chains      map[string]map[string]bool
	rules       map[string]map[string][][]string
	failDeletes bool
	failTimer   bool
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{chains: map[string]map[string]bool{}, rules: map[string]map[string][][]string{}}
}

func (f *fakeRunner) run(name string, args ...string) ([]byte, error) {
	f.commands = append(f.commands, append([]string{name}, args...))
	if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
		return nil, errors.New("inactive")
	}
	if name == "systemd-run" && f.failTimer {
		return nil, errors.New("simulated timer failure")
	}
	if name == "systemctl" || name == "systemd-run" {
		return nil, nil
	}
	if name != "iptables" && name != "ip6tables" {
		return nil, errors.New("unexpected binary")
	}
	if len(args) < 5 || args[0] != "-w" || args[2] != "-t" || args[3] != "filter" {
		return nil, errors.New("unexpected firewall args")
	}
	args = args[4:]
	if f.chains[name] == nil {
		f.chains[name] = map[string]bool{"FORWARD": true}
		f.rules[name] = map[string][][]string{"FORWARD": {}}
	}
	if len(args) < 2 {
		return nil, errors.New("short firewall command")
	}
	op, chain := args[0], args[1]
	rest := args[2:]
	switch op {
	case "-N":
		if f.chains[name][chain] {
			return nil, errors.New("chain exists")
		}
		f.chains[name][chain] = true
		f.rules[name][chain] = nil
		return nil, nil
	case "-S":
		if !f.chains[name][chain] {
			return nil, errors.New("chain missing")
		}
		return nil, nil
	case "-C":
		if containsRule(f.rules[name][chain], rest) {
			return nil, nil
		}
		return nil, errors.New("rule missing")
	case "-A":
		f.rules[name][chain] = append(f.rules[name][chain], append([]string(nil), rest...))
		return nil, nil
	case "-I":
		if len(rest) < 2 || rest[0] != "1" {
			return nil, errors.New("unexpected insert position")
		}
		f.rules[name][chain] = append([][]string{append([]string(nil), rest[1:]...)}, f.rules[name][chain]...)
		return nil, nil
	case "-D":
		if f.failDeletes {
			return nil, errors.New("simulated delete failure")
		}
		for i, rule := range f.rules[name][chain] {
			if equalArgs(rule, rest) {
				f.rules[name][chain] = append(f.rules[name][chain][:i], f.rules[name][chain][i+1:]...)
				return nil, nil
			}
		}
		return nil, errors.New("rule missing")
	default:
		return nil, errors.New("unexpected firewall operation")
	}
}

func containsRule(rules [][]string, wanted []string) bool {
	for _, rule := range rules {
		if equalArgs(rule, wanted) {
			return true
		}
	}
	return false
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func testPolicy(id string) Policy {
	return Policy{ID: id, VMID: "vm-a", InstanceID: "8b81822b-4779-4f12-9a12-6ea4cd777d10", Max: 500,
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(), IPs: []string{"192.0.2.10", "2001:db8::10"}}
}

func TestApplyReleaseAreScopedAndIdempotent(t *testing.T) {
	runner := newFakeRunner()
	m := newManager(filepath.Join(t.TempDir(), "state.json"), "/etc/runman/config.json", "/usr/local/bin/runman-agent", runner.run)
	p := testPolicy(strings.Repeat("a", 32))
	if err := m.Apply(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(p); err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	if got := len(runner.rules["iptables"][chainName]); got != 2 {
		t.Fatalf("IPv4 rules=%d, want ingress and egress", got)
	}
	if got := len(runner.rules["ip6tables"][chainName]); got != 2 {
		t.Fatalf("IPv6 rules=%d, want ingress and egress", got)
	}
	for _, family := range []string{"iptables", "ip6tables"} {
		for _, rule := range runner.rules[family][chainName] {
			inbound := containsArg(rule, "--comment", "narwhal-climit:"+p.ID+":in")
			outbound := containsArg(rule, "--comment", "narwhal-climit:"+p.ID+":out")
			if !inbound && !outbound {
				t.Fatalf("rule lacks owned policy marker: %v", rule)
			}
			if !containsArg(rule, "--connlimit-above", "500") {
				t.Fatalf("rule lacks requested limit: %v", rule)
			}
		}
	}
	if err := m.Release(p.ID, p.VMID, p.InstanceID); err != nil {
		t.Fatal(err)
	}
	if got := len(runner.rules["iptables"][chainName]) + len(runner.rules["ip6tables"][chainName]); got != 0 {
		t.Fatalf("release left %d per-instance rules", got)
	}
	if err := m.Release(p.ID, p.VMID, p.InstanceID); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	info, err := os.Stat(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode=%#o, want 0600", info.Mode().Perm())
	}
}

func TestApplyRejectsUnsafeOrConflictingPolicies(t *testing.T) {
	runner := newFakeRunner()
	m := newManager(filepath.Join(t.TempDir(), "state.json"), "/etc/runman/config.json", "/usr/local/bin/runman-agent", runner.run)
	p := testPolicy(strings.Repeat("b", 32))
	invalid := p
	invalid.IPs = []string{"0.0.0.0"}
	if err := m.Apply(invalid); err == nil {
		t.Fatal("unspecified address unexpectedly accepted")
	}
	if err := m.Apply(p); err != nil {
		t.Fatal(err)
	}
	other := p
	other.ID = strings.Repeat("c", 32)
	if err := m.Apply(other); err == nil {
		t.Fatal("second active policy for the same instance unexpectedly accepted")
	}
	if err := m.Release(p.ID, "another-vm", p.InstanceID); err == nil {
		t.Fatal("release for a different target unexpectedly accepted")
	}
}

func TestExpireRemovesOnlySelectedPolicy(t *testing.T) {
	runner := newFakeRunner()
	m := newManager(filepath.Join(t.TempDir(), "state.json"), "/etc/runman/config.json", "/usr/local/bin/runman-agent", runner.run)
	p := testPolicy(strings.Repeat("d", 32))
	if err := m.Apply(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Expire(p.ID); err != nil {
		t.Fatal(err)
	}
	if got := len(runner.rules["iptables"][chainName]) + len(runner.rules["ip6tables"][chainName]); got != 0 {
		t.Fatalf("expire left %d rules", got)
	}
	if err := m.Expire(p.ID); err != nil {
		t.Fatalf("repeated expiry: %v", err)
	}
}

func TestReleaseKeepsRetryableStateWhenRuleRemovalFails(t *testing.T) {
	runner := newFakeRunner()
	m := newManager(filepath.Join(t.TempDir(), "state.json"), "/etc/runman/config.json", "/usr/local/bin/runman-agent", runner.run)
	p := testPolicy(strings.Repeat("f", 32))
	if err := m.Apply(p); err != nil {
		t.Fatal(err)
	}
	runner.failDeletes = true
	if err := m.Release(p.ID, p.VMID, p.InstanceID); err == nil {
		t.Fatal("release unexpectedly succeeded despite firewall deletion failure")
	}
	st, err := m.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Policies) != 1 || !st.Policies[0].RemoveOnly {
		t.Fatalf("failed cleanup did not preserve retryable remove-only state: %+v", st.Policies)
	}
	runner.failDeletes = false
	if err := m.Reconcile(context.Background(), func(context.Context, string) (Target, error) {
		t.Fatal("remove-only cleanup should not resolve or reapply the target")
		return Target{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err = m.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Policies) != 0 {
		t.Fatalf("successful retry left policy state: %+v", st.Policies)
	}
	if got := len(runner.rules["iptables"][chainName]) + len(runner.rules["ip6tables"][chainName]); got != 0 {
		t.Fatalf("successful retry left %d firewall rules", got)
	}
}

func TestApplyRollsBackWhenAutomaticExpiryCannotBeScheduled(t *testing.T) {
	runner := newFakeRunner()
	runner.failTimer = true
	m := newManager(filepath.Join(t.TempDir(), "state.json"), "/etc/runman/config.json", "/usr/local/bin/runman-agent", runner.run)
	p := testPolicy(strings.Repeat("1", 32))
	if err := m.Apply(p); err == nil {
		t.Fatal("apply unexpectedly succeeded without an automatic-expiry timer")
	}
	st, err := m.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Policies) != 0 {
		t.Fatalf("failed apply left policy state: %+v", st.Policies)
	}
	if got := len(runner.rules["iptables"][chainName]) + len(runner.rules["ip6tables"][chainName]); got != 0 {
		t.Fatalf("failed apply left %d firewall rules", got)
	}
}

func TestReconcileRebindsOnlySameManagedInstance(t *testing.T) {
	runner := newFakeRunner()
	m := newManager(filepath.Join(t.TempDir(), "state.json"), "/etc/runman/config.json", "/usr/local/bin/runman-agent", runner.run)
	p := testPolicy(strings.Repeat("e", 32))
	if err := m.Apply(p); err != nil {
		t.Fatal(err)
	}
	err := m.Reconcile(context.Background(), func(_ context.Context, vmID string) (Target, error) {
		if vmID != p.VMID {
			t.Fatalf("resolver vm=%q", vmID)
		}
		return Target{Managed: true, Running: true, InstanceID: p.InstanceID, IPs: []string{"192.0.2.11"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := runner.rules["iptables"][chainName]
	if len(rules) != 2 {
		t.Fatalf("reconciled IPv4 rules=%d, want 2", len(rules))
	}
	if containsArg(rules[0], "-d", "192.0.2.10") || containsArg(rules[1], "-s", "192.0.2.10") {
		t.Fatalf("old address still guarded: %v", rules)
	}
	data, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "192.0.2.11") {
		t.Fatalf("state did not follow verified IP change: %s", data)
	}
}

func containsArg(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}
