package hostpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
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
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_version": "0.1.0",
		})
	})
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

func TestDeleteManualRFWRuleRequiresFreshExactIdentity(t *testing.T) {
	rows := []rfwRule{{
		ID: 7, Priority: 100, Direction: "in", Protocol: "tcp", Action: "block", Enabled: true,
		PortStart: 443, PortEnd: 443, IPType: "any",
	}}
	deleted := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	mux.HandleFunc("DELETE /api/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		kept := rows[:0]
		for _, row := range rows {
			if row.ID != id {
				kept = append(kept, row)
			}
		}
		rows = kept
		deleted++
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	m := &Manager{rfwURL: server.URL, client: server.Client()}
	expected := RuleReadback{
		ID: 7, Priority: 100, Direction: "in", Protocol: "tcp", Action: "block", Enabled: true,
		PortStart: 443, PortEnd: 443, IPType: "any", Origin: "manual", SyncState: "manual",
	}
	if err := m.DeleteManualRule(context.Background(), expected); err != nil {
		t.Fatalf("fresh manual RFW rule was rejected: %v", err)
	}
	if deleted != 1 || len(rows) != 0 {
		t.Fatalf("expected exactly one selected RFW rule to be deleted, deleted=%d rows=%#v", deleted, rows)
	}
	if err := m.DeleteManualRule(context.Background(), expected); err != nil || deleted != 1 {
		t.Fatalf("idempotent retry should not delete another rule: err=%v deleted=%d", err, deleted)
	}
}

func TestDeleteManualRFWRuleRejectsChangedOrManagedRule(t *testing.T) {
	rows := []rfwRule{{
		ID: 7, Priority: 100, Direction: "in", Protocol: "tcp", Action: "block", Enabled: true,
		PortStart: 443, PortEnd: 443, IPType: "any",
	}}
	deleted := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	mux.HandleFunc("DELETE /api/rules/{id}", func(w http.ResponseWriter, _ *http.Request) {
		deleted++
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	expected := RuleReadback{
		ID: 7, Priority: 100, Direction: "in", Protocol: "tcp", Action: "block", Enabled: true,
		PortStart: 444, PortEnd: 444, IPType: "any", Origin: "manual", SyncState: "manual",
	}
	m := &Manager{rfwURL: server.URL, client: server.Client()}
	if err := m.DeleteManualRule(context.Background(), expected); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("stale rule identity was not rejected: %v", err)
	}
	if deleted != 0 {
		t.Fatal("stale identity deleted a changed RFW rule")
	}

	expected.PortStart = 443
	m.state.Rules = []managedRule{{Key: "managed-rule", ID: 7, Fingerprint: "expected"}}
	if err := m.DeleteManualRule(context.Background(), expected); err == nil || !strings.Contains(err.Error(), "platform-managed") {
		t.Fatalf("platform-managed rule was directly deleted: %v", err)
	}
	if deleted != 0 {
		t.Fatal("platform-managed RFW rule was deleted outside its desired policy")
	}
}

func TestApplyRequiresConfirmedRFWMtprotoCapability(t *testing.T) {
	for _, test := range []struct {
		name       string
		statusBody map[string]any
		wantError  string
	}{
		{
			name:       "capability missing",
			statusBody: map[string]any{"api_version": "0.1.0", "supported_protocols": []string{"all", "tcp", "udp", "socks", "wireguard"}},
			wantError:  `does not support protocol "mtproto"`,
		},
		{
			name:       "published v0.1.0 API omits capability list",
			statusBody: map[string]any{"api_version": "0.1.0", "iface": "eth0", "rule_count": 0},
			wantError:  `does not support protocol "mtproto"`,
		},
		{
			name:      "capability unknown",
			wantError: "capabilities are unknown",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			created := false
			mux := http.NewServeMux()
			if test.statusBody != nil {
				mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
					_ = json.NewEncoder(w).Encode(test.statusBody)
				})
			}
			mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode([]any{})
			})
			mux.HandleFunc("POST /api/rules", func(w http.ResponseWriter, _ *http.Request) {
				created = true
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(`{"id":1}`))
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			m := &Manager{path: filepath.Join(t.TempDir(), "host-firewall.json"), rfwURL: server.URL,
				client: server.Client(), run: newFakeFirewallRunner().run,
				ipv6: func() bool { return false }, bridge: func(string) bool { return true }}
			if err := m.load(); err != nil {
				t.Fatal(err)
			}
			policy := Policy{Revision: 1, Rules: []Rule{{
				Key: "mtproto-cn-out", Priority: 100, Direction: "out", Protocol: "mtproto", Action: "block",
				Enabled: true, PortStart: 0, IPType: "geoip", Countries: []string{"CN"},
			}}}
			err := m.Apply(context.Background(), policy)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("expected capability error containing %q, got %v", test.wantError, err)
			}
			if created {
				t.Fatal("RFW rule was created despite missing/unknown MTProto capability")
			}
		})
	}
}

func TestRFWV010CapabilitiesMatchPublishedOpenAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"iface": "eth0", "api_version": "0.1.0", "rule_count": 3,
		})
	}))
	defer server.Close()
	m := &Manager{rfwURL: server.URL, client: server.Client()}

	version, supported, known := m.rfwProtocolCapabilities(context.Background())
	if !known || version != "0.1.0" {
		t.Fatalf("published RFW v0.1.0 capabilities were not recognized: version=%q known=%v", version, known)
	}
	want := []string{"all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic"}
	if len(supported) != len(want) {
		t.Fatalf("unexpected protocol capabilities: %#v", supported)
	}
	for _, protocol := range want {
		if !supported[protocol] {
			t.Errorf("published RFW v0.1.0 capability %q is missing", protocol)
		}
	}
	if supported["mtproto"] {
		t.Fatal("MTProto is not part of the published RFW v0.1.0 OpenAPI enum")
	}
}

func TestReadbackDistinguishesManualManagedDriftAndMissingRules(t *testing.T) {
	rows := []map[string]any{
		{"id": 1, "priority": 10, "enabled": true, "direction": "in", "protocol": "tcp", "action": "block", "port_start": 22, "port_end": 22, "ip_type": "any"},
		{"id": 2, "priority": 100, "enabled": true, "direction": "out", "protocol": "wireguard", "action": "block", "port_start": 0, "port_end": 0, "ip_type": "geoip", "countries": []string{"CN"}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_version": "0.1.0",
		})
	})
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	policy := Policy{Revision: 4, Rules: []Rule{{
		Key: "cn-wg-out", Priority: 100, Direction: "out", Protocol: "wireguard", Action: "block",
		Enabled: true, PortStart: 0, IPType: "geoip", Countries: []string{"CN"},
	}}}
	fingerprint, err := ruleFingerprint(policy.Rules[0])
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		rfwURL: server.URL, client: server.Client(),
		state: persistedState{Revision: policy.Revision, Policy: policy,
			Rules: []managedRule{{Key: "cn-wg-out", ID: 2, Fingerprint: fingerprint}}},
	}

	readback, err := m.Readback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if readback.Status != "in_sync" || readback.RuleCount != 2 || readback.ManagedRuleCount != 1 || readback.DriftCount != 0 || readback.MissingCount != 0 {
		t.Fatalf("unexpected in-sync readback: %#v", readback)
	}
	if !readback.CapabilitiesKnown || readback.RFWAPIVersion != "0.1.0" ||
		!slices.Contains(readback.SupportedProtocols, "wireguard") || slices.Contains(readback.SupportedProtocols, "mtproto") {
		t.Fatalf("RFW protocol capabilities were not surfaced in readback: %#v", readback)
	}
	if readback.Rules[0].Origin != "manual" || readback.Rules[1].Origin != "platform" || readback.Rules[1].SyncState != "in_sync" {
		t.Fatalf("manual/platform ownership was not distinguished: %#v", readback.Rules)
	}

	rows[1]["action"] = "pass"
	readback, err = m.Readback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if readback.Status != "drifted" || readback.DriftCount != 1 || readback.Rules[1].SyncState != "drifted" {
		t.Fatalf("modified managed rule was not reported as drift: %#v", readback)
	}

	rows = rows[:1]
	readback, err = m.Readback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if readback.Status != "drifted" || readback.MissingCount != 1 || readback.ExpectedRules[0].SyncState != "missing" {
		t.Fatalf("missing managed rule was not reported: %#v", readback)
	}
}

func TestReconcileRepairsDriftedManagedRuleWithoutTouchingManualRules(t *testing.T) {
	rows := []map[string]any{
		{"id": 1, "priority": 10, "enabled": true, "direction": "in", "protocol": "tcp", "action": "block", "port_start": 22, "port_end": 22, "ip_type": "any"},
		{"id": 2, "priority": 100, "enabled": true, "direction": "out", "protocol": "wireguard", "action": "pass", "port_start": 0, "port_end": 0, "ip_type": "geoip", "countries": []string{"CN"}},
	}
	nextID := 3
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(rows)
	})
	mux.HandleFunc("POST /api/rules", func(w http.ResponseWriter, r *http.Request) {
		var rule map[string]any
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			t.Errorf("decode replacement rule: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id := nextID
		nextID++
		rule["id"] = id
		rows = append(rows, rule)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
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

	desired := Rule{
		Key: "wg-cn-out", Priority: 100, Direction: "out", Protocol: "wireguard", Action: "block",
		Enabled: true, PortStart: 0, IPType: "geoip", Countries: []string{"CN"},
	}
	fingerprint, err := ruleFingerprint(desired)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{Revision: 2, Rules: []Rule{desired}}
	m := &Manager{
		path: filepath.Join(t.TempDir(), "host-firewall.json"), rfwURL: server.URL,
		client: server.Client(), run: newFakeFirewallRunner().run, ipv6: func() bool { return false },
		bridge: linuxBridgeExists,
		state: persistedState{Revision: policy.Revision, Policy: policy,
			Rules: []managedRule{{Key: desired.Key, ID: 2, Fingerprint: fingerprint}}},
	}
	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || int(rows[0]["id"].(int)) != 1 || int(rows[1]["id"].(int)) != 3 || rows[1]["action"] != "block" {
		t.Fatalf("drift repair changed manual rules or failed to restore the managed rule: %#v", rows)
	}
	readback, err := m.Readback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if readback.Status != "in_sync" || readback.ManagedRuleCount != 1 || readback.DriftCount != 0 {
		t.Fatalf("reconciled rule is not reported in sync: %#v", readback)
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
	base.Rules = []Rule{{Key: "wg-cn-out", Priority: 100, Direction: "out", Protocol: "wireguard", Action: "block", Enabled: true, PortStart: 0, IPType: "geoip", Countries: []string{"cn"}}}
	if _, err := validatePolicy(base); err != nil {
		t.Fatalf("supported outbound WireGuard rule rejected: %v", err)
	}
	base.Rules = []Rule{{Key: "mtproto-cn-out", Priority: 100, Direction: "out", Protocol: "mtproto", Action: "block", Enabled: true, PortStart: 0, IPType: "geoip", Countries: []string{"cn"}}}
	if _, err := validatePolicy(base); err != nil {
		t.Fatalf("supported outbound MTProto rule rejected: %v", err)
	}
	base.Rules = append(base.Rules, base.Rules[0])
	if _, err := validatePolicy(base); err == nil {
		t.Fatal("duplicate rule key unexpectedly accepted")
	}
}

func TestValidatePolicyMatchesRfwRuleCapacity(t *testing.T) {
	policy := Policy{Revision: 1}
	for i := 0; i < maxRules+1; i++ {
		policy.Rules = append(policy.Rules, Rule{
			Key: "rule-" + strconv.Itoa(i), Priority: i, Direction: "in",
			Protocol: "wireguard", Action: "block", Enabled: true,
			PortStart: 0, IPType: "any",
		})
	}
	if _, err := validatePolicy(policy); err == nil || !strings.Contains(err.Error(), "64") {
		t.Fatalf("expected 65-rule policy to be rejected at the RFW capacity, got %v", err)
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

func TestEventsReadsBoundedRFWCursorAndRejectsMalformedRows(t *testing.T) {
	var sawCursor string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		sawCursor = r.URL.Query().Get("cursor")
		if r.URL.Query().Get("limit") != "25" {
			t.Errorf("unexpected page limit: %q", r.URL.Query().Get("limit"))
		}
		_ = json.NewEncoder(w).Encode(EventPage{
			InstanceID: "boot-1", NextCursor: "boot-1:8",
			Events: []Event{{Sequence: 8, Cursor: "boot-1:8", ObservedAt: 1792380000,
				SourceIP: "203.0.113.2", SourcePort: 50000, DestinationIP: "192.0.2.4", DestinationPort: 443,
				Transport: "tcp", AppProtocol: "socks", Direction: "in", Action: "pass", RuleCountries: []string{"CN"}}},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	m := &Manager{rfwURL: server.URL, client: server.Client()}

	page, err := m.Events(context.Background(), "boot-1:7", 25)
	if err != nil {
		t.Fatal(err)
	}
	if sawCursor != "boot-1:7" || page.NextCursor != "boot-1:8" || len(page.Events) != 1 {
		t.Fatalf("unexpected event page or cursor: cursor=%q page=%#v", sawCursor, page)
	}
	if page.Events[0].AppProtocol != "socks" || page.Events[0].RuleCountries[0] != "CN" {
		t.Fatalf("event attribution was not retained: %#v", page.Events[0])
	}

	bad := http.NewServeMux()
	bad.HandleFunc("GET /api/events", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(EventPage{InstanceID: "boot-1", Events: []Event{{
			Sequence: 1, Cursor: "boot-1:1", ObservedAt: 1792380000,
			SourceIP: "not-an-ip", DestinationIP: "192.0.2.4", Direction: "in", Action: "pass",
		}}})
	})
	badServer := httptest.NewServer(bad)
	defer badServer.Close()
	m.rfwURL = badServer.URL
	if _, err := m.Events(context.Background(), "", 25); err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Fatalf("malformed RFW event was accepted: %v", err)
	}
}

func TestEventsReportsUnsupportedWhenRFWHasNoEventsRoute(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	m := &Manager{rfwURL: server.URL, client: server.Client()}
	if _, err := m.Events(context.Background(), "", 25); !errors.Is(err, ErrRFWEventsUnsupported) {
		t.Fatalf("expected explicit unsupported result for absent RFW events route, got %v", err)
	}
}
