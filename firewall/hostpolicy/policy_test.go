package hostpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type fakeFirewallRunner struct {
	commands [][]string
	chains   map[string]bool
	rules    map[string][][]string
}

func newFakeFirewallRunner() *fakeFirewallRunner {
	return &fakeFirewallRunner{
		chains: map[string]bool{"FORWARD": true, "INPUT": true, "OUTPUT": true},
		rules:  map[string][][]string{"FORWARD": {}, "INPUT": {}, "OUTPUT": {}},
	}
}

func (f *fakeFirewallRunner) run(_ context.Context, binary string, args ...string) ([]byte, error) {
	command := append([]string{binary}, args...)
	f.commands = append(f.commands, command)
	if len(args) < 5 || args[0] != "-w" || args[1] != "-t" || args[2] != "filter" {
		return nil, errors.New("unexpected firewall command")
	}
	op, chain, rest := args[3], args[4], args[5:]
	switch op {
	case "-N":
		if f.chains[chain] {
			return nil, errors.New("chain exists")
		}
		f.chains[chain] = true
		f.rules[chain] = nil
	case "-S":
		if !f.chains[chain] {
			return nil, errors.New("chain missing")
		}
		for _, rule := range f.rules[chain] {
			if strings.Contains(strings.Join(rule, " "), abuseChainMarker) {
				return []byte("-A " + chain + " -m comment --comment " + abuseChainMarker + " -j RETURN\n"), nil
			}
		}
	case "-C":
		if !hasArgs(f.rules[chain], rest) {
			return nil, errors.New("rule missing")
		}
	case "-A":
		f.rules[chain] = append(f.rules[chain], append([]string(nil), rest...))
	case "-I":
		if len(rest) < 2 || rest[0] != "1" {
			return nil, errors.New("unexpected insert")
		}
		f.rules[chain] = append([][]string{append([]string(nil), rest[1:]...)}, f.rules[chain]...)
	case "-D":
		for i, rule := range f.rules[chain] {
			if equalArgs(rule, rest) {
				f.rules[chain] = append(f.rules[chain][:i], f.rules[chain][i+1:]...)
				return nil, nil
			}
		}
		return nil, errors.New("rule missing")
	case "-F":
		if !f.chains[chain] {
			return nil, errors.New("chain missing")
		}
		f.rules[chain] = nil
	case "-X":
		if !f.chains[chain] {
			return nil, errors.New("chain missing")
		}
		delete(f.chains, chain)
		delete(f.rules, chain)
	default:
		return nil, errors.New("unexpected firewall operation: " + op)
	}
	return nil, nil
}

func hasArgs(rows [][]string, wanted []string) bool {
	for _, row := range rows {
		if equalArgs(row, wanted) {
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

func TestApplyOwnsOnlyWatcherRulesAndForwardAbuseChain(t *testing.T) {
	var rows = []map[string]any{{"id": 1, "priority": 10, "protocol": "tcp", "port_start": 22}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	mux.HandleFunc("POST /api/rules", func(w http.ResponseWriter, r *http.Request) {
		var rule map[string]any
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			t.Errorf("decode RFW create: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := rule["key"]; ok {
			t.Error("Watcher ownership key leaked to RFW API")
		}
		rule["id"] = 2
		rows = append(rows, rule)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 2})
	})
	mux.HandleFunc("DELETE /api/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		kept := rows[:0]
		for _, row := range rows {
			if int(row["id"].(int)) != id {
				kept = append(kept, row)
			}
		}
		rows = kept
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	runner := newFakeFirewallRunner()
	m := &Manager{path: filepath.Join(t.TempDir(), "host-firewall.json"), rfwURL: server.URL,
		client: server.Client(), run: runner.run, ipv6: func() bool { return false }, bridge: func(name string) bool { return name == "incusbr0" }}
	if err := m.load(); err != nil {
		t.Fatal(err)
	}
	portEnd := 443
	policy := Policy{Revision: 1, Abuse: AbusePolicy{Speedtest: true, Interfaces: []string{"incusbr0"}}, Rules: []Rule{{
		Key: "watcher-rule-1", Priority: 100, Direction: "in", Protocol: "tcp", Action: "block",
		Enabled: true, PortStart: 443, PortEnd: &portEnd, IPType: "any",
	}}}
	if err := m.Apply(context.Background(), policy); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || int(rows[0]["id"].(int)) != 1 || int(rows[1]["id"].(int)) != 2 {
		t.Fatalf("unexpected RFW rules after apply: %#v", rows)
	}
	if !hasArgs(runner.rules["FORWARD"], []string{"-j", abuseChain}) {
		t.Fatal("container-forward jump was not installed")
	}
	if !hasArgs(runner.rules[abuseChain], []string{"-i", "incusbr0", "-p", "tcp", "--dport", "5201", "-j", "REJECT", "--reject-with", "tcp-reset"}) {
		t.Fatalf("abuse policy was not scoped to the selected container bridge: %#v", runner.rules[abuseChain])
	}
	for _, command := range runner.commands {
		joined := strings.Join(command, " ")
		if strings.Contains(joined, " INPUT ") || strings.Contains(joined, " OUTPUT ") {
			t.Fatalf("abuse policy unexpectedly modified host INPUT/OUTPUT: %v", command)
		}
	}

	if err := m.Apply(context.Background(), Policy{Revision: 2, Abuse: AbusePolicy{}}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || int(rows[0]["id"].(int)) != 1 {
		t.Fatalf("manual RFW rule was removed or managed rule remained: %#v", rows)
	}
	if runner.chains[abuseChain] || hasArgs(runner.rules["FORWARD"], []string{"-j", abuseChain}) {
		t.Fatal("disabled abuse policy left the managed forward chain installed")
	}
	if err := m.Apply(context.Background(), policy); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("old policy revision should be rejected, got %v", err)
	}
}

func TestLoopbackOnlyRfwAddress(t *testing.T) {
	for _, address := range []string{"example.com:7734", "192.0.2.1:7734", "http://127.0.0.1:7734"} {
		if _, err := loopbackBaseURL(address); err == nil {
			t.Errorf("accepted non-loopback or malformed RFW address %q", address)
		}
	}
	if _, err := loopbackBaseURL("127.0.0.1:7734"); err != nil {
		t.Fatalf("valid loopback address rejected: %v", err)
	}
}

func TestValidatePolicyRejectsOutboundDpiAndDuplicateKeys(t *testing.T) {
	base := Policy{Revision: 1, Rules: []Rule{{Key: "a", Priority: 100, Direction: "out", Protocol: "quic", Action: "block", Enabled: true, PortStart: 0, IPType: "any"}}}
	if _, err := validatePolicy(base); err == nil {
		t.Fatal("outbound DPI rule unexpectedly accepted")
	}
	base.Rules = append(base.Rules, base.Rules[0])
	if _, err := validatePolicy(base); err == nil {
		t.Fatal("duplicate rule key unexpectedly accepted")
	}
}

func TestAbusePolicyRequiresValidBridgeAndRefusesUnownedChain(t *testing.T) {
	policy := Policy{Revision: 1, Abuse: AbusePolicy{BT: true, Interfaces: []string{"eth0"}}}
	if _, err := validatePolicy(policy); err != nil {
		t.Fatalf("valid explicit bridge rejected: %v", err)
	}
	policy.Abuse.Interfaces = []string{"eth0;iptables"}
	if _, err := validatePolicy(policy); err == nil {
		t.Fatal("unsafe interface name was accepted")
	}
	policy.Abuse.Interfaces = nil
	if _, err := validatePolicy(policy); err == nil {
		t.Fatal("enabled abuse rule without an explicit bridge was accepted")
	}

	runner := newFakeFirewallRunner()
	runner.chains[abuseChain] = true
	runner.rules[abuseChain] = [][]string{{"-p", "tcp", "--dport", "1234", "-j", "DROP"}}
	if err := applyAbuseFamily(context.Background(), runner.run, "iptables", AbusePolicy{BT: true, Interfaces: []string{"incusbr0"}}); err == nil {
		t.Fatal("unowned existing chain was modified")
	}
	if !hasArgs(runner.rules[abuseChain], []string{"-p", "tcp", "--dport", "1234", "-j", "DROP"}) {
		t.Fatal("existing unowned chain was changed")
	}
}

func TestInvalidBridgePersistsDesiredPolicyWithoutChangingRFW(t *testing.T) {
	rows := []map[string]any{{"id": 1, "priority": 10, "protocol": "tcp", "port_start": 22}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	runner := newFakeFirewallRunner()
	m := &Manager{path: filepath.Join(t.TempDir(), "host-firewall.json"), rfwURL: server.URL,
		client: server.Client(), run: runner.run, ipv6: func() bool { return false }, bridge: func(string) bool { return false }}
	policy := Policy{Revision: 1, Abuse: AbusePolicy{Speedtest: true, Interfaces: []string{"incusbr0"}}, Rules: []Rule{{
		Key: "watcher-rule-1", Priority: 100, Direction: "in", Protocol: "tcp", Action: "block",
		Enabled: true, PortStart: 443, IPType: "any",
	}}}
	if err := m.Apply(context.Background(), policy); err == nil || !strings.Contains(err.Error(), "existing Linux bridge") {
		t.Fatalf("missing bridge should reject application, got %v", err)
	}
	if m.state.Revision != 1 {
		t.Fatalf("desired policy was not preserved for retry: %#v", m.state)
	}
	if len(rows) != 1 {
		t.Fatalf("RFW was modified even though the bridge preflight failed: %#v", rows)
	}
	if err := m.Reconcile(context.Background()); err == nil {
		t.Fatal("reconcile unexpectedly accepted the missing Linux bridge")
	}
	if len(rows) != 1 {
		t.Fatalf("background reconciliation modified RFW despite an invalid bridge: %#v", rows)
	}
}
