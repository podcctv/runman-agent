package hostpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Keep the management API limit aligned with rfw-common::MAX_RULES.
const maxRules = 64

// ErrRFWEventsUnsupported is returned when the RFW build has no HTTP event
// endpoint. The current upstream v0.1.0 API exposes status and rules only.
var ErrRFWEventsUnsupported = errors.New("RFW event API is not supported")

var rfwV010SupportedProtocols = []string{
	"all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic",
}

var ruleKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// Policy is a host-scoped desired state. Rule keys are Watcher identities and
// are never sent to the RFW API.
type Policy struct {
	Revision int64       `json:"revision"`
	Rules    []Rule      `json:"rules"`
	Abuse    AbusePolicy `json:"abuse"`
}

type Event struct {
	Sequence        uint64   `json:"sequence"`
	Cursor          string   `json:"cursor"`
	ObservedAt      int64    `json:"observed_at"`
	SourceIP        string   `json:"source_ip"`
	SourcePort      uint16   `json:"source_port"`
	DestinationIP   string   `json:"destination_ip"`
	DestinationPort uint16   `json:"destination_port"`
	Transport       string   `json:"transport"`
	AppProtocol     string   `json:"app_protocol"`
	Direction       string   `json:"direction"`
	Action          string   `json:"action"`
	RuleIndex       uint8    `json:"rule_index"`
	RuleID          *uint64  `json:"rule_id"`
	RuleProtocol    *string  `json:"rule_protocol"`
	RuleAction      *string  `json:"rule_action"`
	RuleCountries   []string `json:"rule_countries"`
}

type EventPage struct {
	InstanceID   string  `json:"instance_id"`
	NextCursor   string  `json:"next_cursor"`
	CursorReset  bool    `json:"cursor_reset"`
	Dropped      uint64  `json:"dropped"`
	DroppedTotal uint64  `json:"dropped_total"`
	Events       []Event `json:"events"`
}

type Rule struct {
	Key       string   `json:"key"`
	Priority  int      `json:"priority"`
	Direction string   `json:"direction"`
	Protocol  string   `json:"protocol"`
	Action    string   `json:"action"`
	Enabled   bool     `json:"enabled"`
	PortStart int      `json:"port_start"`
	PortEnd   *int     `json:"port_end,omitempty"`
	IPType    string   `json:"ip_type"`
	IP        string   `json:"ip,omitempty"`
	Countries []string `json:"countries,omitempty"`
}

type AbusePolicy struct {
	Speedtest  bool     `json:"speedtest"`
	Mining     bool     `json:"mining"`
	BT         bool     `json:"bt"`
	Interfaces []string `json:"interfaces"`
}

type managedRule struct {
	Key         string `json:"key"`
	ID          int    `json:"id"`
	Fingerprint string `json:"fingerprint"`
}

// RuleReadback is a live rule returned by RFW. Ownership comes only from
// Runman's persisted ID map; rules without a mapping remain manual.
type RuleReadback struct {
	ID         int      `json:"id"`
	Priority   int      `json:"priority"`
	Direction  string   `json:"direction"`
	Protocol   string   `json:"protocol"`
	Action     string   `json:"action"`
	Enabled    bool     `json:"enabled"`
	PortStart  int      `json:"port_start"`
	PortEnd    int      `json:"port_end"`
	IPType     string   `json:"ip_type"`
	IP         string   `json:"ip,omitempty"`
	Countries  []string `json:"countries,omitempty"`
	Origin     string   `json:"origin"`
	ManagedKey string   `json:"managed_key,omitempty"`
	SyncState  string   `json:"sync_state"`
}

type ExpectedRuleReadback struct {
	Key       string `json:"key"`
	ID        int    `json:"id,omitempty"`
	SyncState string `json:"sync_state"`
}

// Readback is RFW's current userspace rule table, compared with Runman's
// persisted desired state. It does not claim a direct eBPF-map inspection.
type Readback struct {
	Status             string                 `json:"status"`
	ObservedAt         int64                  `json:"observed_at"`
	RFWAPIVersion      string                 `json:"rfw_api_version,omitempty"`
	CapabilitiesKnown  bool                   `json:"capabilities_known"`
	SupportedProtocols []string               `json:"supported_protocols"`
	PolicyRevision     int64                  `json:"policy_revision"`
	RuleCount          int                    `json:"rule_count"`
	ManagedRuleCount   int                    `json:"managed_rule_count"`
	DriftCount         int                    `json:"drift_count"`
	MissingCount       int                    `json:"missing_count"`
	Rules              []RuleReadback         `json:"rules"`
	ExpectedRules      []ExpectedRuleReadback `json:"expected_rules"`
}

type rfwRule struct {
	ID        int      `json:"id"`
	Priority  int      `json:"priority"`
	Direction string   `json:"direction"`
	Protocol  string   `json:"protocol"`
	Action    string   `json:"action"`
	Enabled   bool     `json:"enabled"`
	PortStart int      `json:"port_start"`
	PortEnd   int      `json:"port_end"`
	IPType    string   `json:"ip_type"`
	IP        string   `json:"ip"`
	Countries []string `json:"countries"`
}

type persistedState struct {
	Revision int64         `json:"revision"`
	Policy   Policy        `json:"policy"`
	Rules    []managedRule `json:"managed_rules,omitempty"`
}

// Runner is injectable so firewall behavior can be tested without changing
// the host's packet filter.
type Runner func(context.Context, string, ...string) ([]byte, error)

type Manager struct {
	path   string
	rfwURL string
	client *http.Client
	run    Runner
	ipv6   func() bool
	bridge func(string) bool
	mu     sync.Mutex
	state  persistedState
}

// New creates a host policy manager. RFW is required to listen on loopback;
// the local UDS must never become a proxy to an arbitrary network target.
func New(path, rfwAddr string) (*Manager, error) {
	rfwURL, err := loopbackBaseURL(rfwAddr)
	if err != nil {
		return nil, err
	}
	m := &Manager{path: path, rfwURL: rfwURL, run: commandRunner, ipv6: ipv6Available, bridge: linuxBridgeExists,
		client: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func loopbackBaseURL(addr string) (string, error) {
	if strings.Contains(addr, "://") {
		return "", errors.New("RFW address must be a loopback host:port, without a URL scheme")
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", fmt.Errorf("invalid RFW loopback address: %w", err)
	}
	if portNumber, err := strconv.Atoi(port); err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("RFW port must be between 1 and 65535")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("RFW API must be bound to loopback")
		}
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

func validatePolicy(policy Policy) (Policy, error) {
	if policy.Revision < 1 {
		return Policy{}, errors.New("policy revision must be positive")
	}
	if len(policy.Rules) > maxRules {
		return Policy{}, fmt.Errorf("at most %d RFW rules are allowed", maxRules)
	}
	normalized := policy
	normalized.Rules = make([]Rule, len(policy.Rules))
	keys := make(map[string]bool, len(policy.Rules))
	for i, rule := range policy.Rules {
		if !ruleKeyPattern.MatchString(rule.Key) || keys[rule.Key] {
			return Policy{}, fmt.Errorf("RFW rule %d has a missing, invalid, or duplicate key", i+1)
		}
		keys[rule.Key] = true
		if rule.Priority < 0 || rule.Priority > 100000 {
			return Policy{}, fmt.Errorf("RFW rule %q priority is out of range", rule.Key)
		}
		if rule.Direction != "in" && rule.Direction != "out" {
			return Policy{}, fmt.Errorf("RFW rule %q direction must be in or out", rule.Key)
		}
		protocol := strings.ToLower(rule.Protocol)
		switch protocol {
		case "all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto":
		default:
			return Policy{}, fmt.Errorf("RFW rule %q has an unsupported protocol", rule.Key)
		}
		if rule.Direction == "out" && protocol != "all" && protocol != "tcp" && protocol != "udp" &&
			protocol != "socks" && protocol != "fet" && protocol != "wireguard" && protocol != "mtproto" {
			return Policy{}, fmt.Errorf("RFW protocol %q is not supported for outbound matching", protocol)
		}
		if rule.Action != "block" && rule.Action != "pass" {
			return Policy{}, fmt.Errorf("RFW rule %q action must be block or pass", rule.Key)
		}
		if rule.PortStart < 0 || rule.PortStart > 65535 {
			return Policy{}, fmt.Errorf("RFW rule %q has an invalid start port", rule.Key)
		}
		if rule.PortEnd != nil && (*rule.PortEnd < rule.PortStart || *rule.PortEnd > 65535) {
			return Policy{}, fmt.Errorf("RFW rule %q has an invalid end port", rule.Key)
		}
		ipType := strings.ToLower(rule.IPType)
		if ipType != "any" && ipType != "cidr" && ipType != "geoip" {
			return Policy{}, fmt.Errorf("RFW rule %q has an unsupported IP type", rule.Key)
		}
		rule.Protocol = protocol
		rule.IPType = ipType
		switch ipType {
		case "any":
			rule.IP = ""
			rule.Countries = nil
		case "cidr":
			prefix, err := netip.ParsePrefix(strings.TrimSpace(rule.IP))
			if err != nil {
				return Policy{}, fmt.Errorf("RFW rule %q requires a valid CIDR", rule.Key)
			}
			rule.IP = prefix.Masked().String()
			rule.Countries = nil
		case "geoip":
			if len(rule.Countries) == 0 || len(rule.Countries) > 30 {
				return Policy{}, fmt.Errorf("RFW rule %q requires 1 to 30 country codes", rule.Key)
			}
			countries := make([]string, 0, len(rule.Countries))
			seen := map[string]bool{}
			for _, country := range rule.Countries {
				country = strings.ToUpper(strings.TrimSpace(country))
				if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
					return Policy{}, fmt.Errorf("RFW rule %q has an invalid country code", rule.Key)
				}
				if !seen[country] {
					seen[country] = true
					countries = append(countries, country)
				}
			}
			sort.Strings(countries)
			rule.Countries = countries
			rule.IP = ""
		}
		normalized.Rules[i] = rule
	}
	interfaces := make([]string, 0, len(policy.Abuse.Interfaces))
	seenInterfaces := make(map[string]bool, len(policy.Abuse.Interfaces))
	if len(policy.Abuse.Interfaces) > 16 {
		return Policy{}, errors.New("at most 16 container bridge interfaces are allowed")
	}
	for _, name := range policy.Abuse.Interfaces {
		name = strings.TrimSpace(name)
		if !interfaceNamePattern.MatchString(name) {
			return Policy{}, fmt.Errorf("invalid container bridge interface %q", name)
		}
		if !seenInterfaces[name] {
			interfaces = append(interfaces, name)
			seenInterfaces[name] = true
		}
	}
	if (policy.Abuse.Speedtest || policy.Abuse.Mining || policy.Abuse.BT) && len(interfaces) == 0 {
		return Policy{}, errors.New("container abuse rules require an explicit bridge interface")
	}
	normalized.Abuse.Interfaces = interfaces
	return normalized, nil
}

func (m *Manager) Apply(ctx context.Context, requested Policy) error {
	policy, err := validatePolicy(requested)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if policy.Revision < m.state.Revision {
		return fmt.Errorf("stale firewall policy revision %d; current revision is %d", policy.Revision, m.state.Revision)
	}
	if policy.Revision == m.state.Revision {
		oldJSON, _ := json.Marshal(m.state.Policy)
		newJSON, _ := json.Marshal(policy)
		if !bytes.Equal(oldJSON, newJSON) {
			return errors.New("firewall policy changed without advancing its revision")
		}
	} else {
		m.state.Revision = policy.Revision
		m.state.Policy = policy
		if err := m.save(); err != nil {
			return fmt.Errorf("persist desired firewall policy: %w", err)
		}
	}
	if err := validateBridgeInterfaces(policy.Abuse, m.bridge); err != nil {
		return err
	}
	if err := m.reconcileRFW(ctx); err != nil {
		return fmt.Errorf("sync managed RFW rules: %w", err)
	}
	if err := applyAbusePolicy(ctx, m.run, policy.Abuse, m.ipv6(), m.bridge); err != nil {
		return fmt.Errorf("apply network abuse policy: %w", err)
	}
	return nil
}

func (m *Manager) reconcileRFW(ctx context.Context) error {
	if len(m.state.Policy.Rules) == 0 && len(m.state.Rules) == 0 {
		return nil
	}
	if m.rfwURL == "" {
		return errors.New("RFW API address is not configured")
	}
	if err := m.checkRFWProtocolCapabilities(ctx, m.state.Policy.Rules); err != nil {
		return err
	}
	actual, err := m.listRfwRuleDetails(ctx)
	if err != nil {
		return err
	}
	actualIDs := make(map[int]bool, len(actual))
	actualFingerprints := make(map[int]string, len(actual))
	for _, row := range actual {
		fingerprint, err := rfwRuleFingerprint(row)
		if err != nil {
			return fmt.Errorf("fingerprint RFW rule %d: %w", row.ID, err)
		}
		actualIDs[row.ID] = true
		actualFingerprints[row.ID] = fingerprint
	}
	selected := make(map[int]bool)
	for _, desired := range m.state.Policy.Rules {
		fingerprint, err := ruleFingerprint(desired)
		if err != nil {
			return err
		}
		rfwFingerprint, err := desiredRFWFingerprint(desired)
		if err != nil {
			return err
		}
		found := false
		for _, managed := range m.state.Rules {
			actualFingerprint, exists := actualFingerprints[managed.ID]
			if !selected[managed.ID] && managed.Key == desired.Key && managed.Fingerprint == fingerprint &&
				exists && actualFingerprint == rfwFingerprint {
				selected[managed.ID] = true
				found = true
				break
			}
		}
		if found {
			continue
		}
		id, err := m.createRfwRule(ctx, desired)
		if err != nil {
			return fmt.Errorf("create rule %q: %w", desired.Key, err)
		}
		managed := managedRule{Key: desired.Key, ID: id, Fingerprint: fingerprint}
		m.state.Rules = append(m.state.Rules, managed)
		selected[id] = true
		actualIDs[id] = true
		actualFingerprints[id] = rfwFingerprint
		if err := m.save(); err != nil {
			return fmt.Errorf("persist ownership of created rule %d: %w", id, err)
		}
	}
	for i := 0; i < len(m.state.Rules); {
		managed := m.state.Rules[i]
		if selected[managed.ID] {
			i++
			continue
		}
		if actualIDs[managed.ID] {
			if err := m.deleteRfwRule(ctx, managed.ID); err != nil {
				return fmt.Errorf("remove obsolete managed rule %d: %w", managed.ID, err)
			}
		}
		m.state.Rules = append(m.state.Rules[:i], m.state.Rules[i+1:]...)
		if err := m.save(); err != nil {
			return fmt.Errorf("persist removal of managed rule %d: %w", managed.ID, err)
		}
	}
	return nil
}

func ruleFingerprint(rule Rule) (string, error) {
	payload, err := json.Marshal(rfwPayload(rule))
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func rfwPayload(rule Rule) map[string]any {
	payload := map[string]any{
		"priority": rule.Priority, "direction": rule.Direction, "protocol": rule.Protocol,
		"action": rule.Action, "enabled": rule.Enabled, "port_start": rule.PortStart, "ip_type": rule.IPType,
	}
	if rule.PortEnd != nil {
		payload["port_end"] = *rule.PortEnd
	}
	if rule.IPType == "cidr" {
		payload["ip"] = rule.IP
	}
	if rule.IPType == "geoip" {
		payload["countries"] = rule.Countries
	}
	return payload
}

func (m *Manager) listRfwRuleDetails(ctx context.Context) ([]rfwRule, error) {
	body, status, err := m.request(ctx, "GET", "/api/rules", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("RFW list returned HTTP %d: %s", status, shortBody(body))
	}
	var rows []rfwRule
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("decode RFW rule list: %w", err)
	}
	if len(rows) > 256 {
		return nil, errors.New("RFW rule list exceeds the 256-rule readback limit")
	}
	seen := make(map[int]bool, len(rows))
	for _, row := range rows {
		if row.ID < 1 || seen[row.ID] {
			return nil, errors.New("RFW rule list contains an invalid or duplicate ID")
		}
		seen[row.ID] = true
	}
	return rows, nil
}

func (m *Manager) rfwProtocolCapabilities(ctx context.Context) (string, map[string]bool, bool) {
	body, status, err := m.request(ctx, "GET", "/api/status", nil)
	if err != nil || status != http.StatusOK {
		return "", nil, false
	}
	var response struct {
		APIVersion         string   `json:"api_version"`
		SupportedProtocols []string `json:"supported_protocols"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.APIVersion) > 64 {
		return "", nil, false
	}
	apiVersion := strings.TrimSpace(response.APIVersion)
	if apiVersion == "" {
		return "", nil, false
	}
	if response.SupportedProtocols == nil {
		// RFW's published v0.1.0 OpenAPI contract does not include
		// supported_protocols in /api/status. Derive capabilities from that
		// exact contract instead of treating every application rule as unknown.
		if apiVersion != "0.1.0" {
			return apiVersion, nil, false
		}
		supported := make(map[string]bool, len(rfwV010SupportedProtocols))
		for _, protocol := range rfwV010SupportedProtocols {
			supported[protocol] = true
		}
		return apiVersion, supported, true
	}
	if len(response.SupportedProtocols) == 0 || len(response.SupportedProtocols) > 32 {
		return apiVersion, nil, false
	}
	supported := make(map[string]bool, len(response.SupportedProtocols))
	for _, protocol := range response.SupportedProtocols {
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		if !validRFWProtocol(protocol) || supported[protocol] {
			return "", nil, false
		}
		supported[protocol] = true
	}
	return apiVersion, supported, true
}

func validRFWProtocol(protocol string) bool {
	switch protocol {
	case "all", "tcp", "udp", "http", "tls", "socks", "ssh", "fet", "wireguard", "openvpn", "quic", "mtproto":
		return true
	default:
		return false
	}
}

func (m *Manager) checkRFWProtocolCapabilities(ctx context.Context, rules []Rule) error {
	if len(rules) == 0 {
		return nil
	}
	apiVersion, supported, known := m.rfwProtocolCapabilities(ctx)
	for _, rule := range rules {
		if known {
			if !supported[rule.Protocol] {
				return fmt.Errorf("RFW API %s does not support protocol %q; update RFW before applying this policy", apiVersion, rule.Protocol)
			}
			continue
		}
		if rule.Protocol == "mtproto" {
			return errors.New("RFW protocol capabilities are unknown; update RFW before applying MTProto rules")
		}
	}
	return nil
}

func rfwRuleFingerprint(row rfwRule) (string, error) {
	var portEnd *int
	if row.PortEnd != row.PortStart {
		portEnd = &row.PortEnd
	}
	countries := append([]string(nil), row.Countries...)
	for i := range countries {
		countries[i] = strings.ToUpper(strings.TrimSpace(countries[i]))
	}
	sort.Strings(countries)
	return ruleFingerprint(Rule{
		Key: "live-readback", Priority: row.Priority, Direction: strings.ToLower(row.Direction),
		Protocol: strings.ToLower(row.Protocol), Action: strings.ToLower(row.Action), Enabled: row.Enabled,
		PortStart: row.PortStart, PortEnd: portEnd, IPType: strings.ToLower(row.IPType),
		IP: strings.TrimSpace(row.IP), Countries: countries,
	})
}

func desiredRFWFingerprint(rule Rule) (string, error) {
	canonical := rule
	if rule.PortEnd != nil && *rule.PortEnd == rule.PortStart {
		canonical.PortEnd = nil
	}
	return ruleFingerprint(canonical)
}

// Readback fetches RFW's current rule table and compares it with Runman's
// persisted ownership map and desired policy. It is read-only; manual rules
// are visible but are never claimed or deleted by this method.
func (m *Manager) Readback(ctx context.Context) (Readback, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows, err := m.listRfwRuleDetails(ctx)
	if err != nil {
		return Readback{}, err
	}
	apiVersion, supportedProtocols, capabilitiesKnown := m.rfwProtocolCapabilities(ctx)
	managedByID := make(map[int]managedRule, len(m.state.Rules))
	desiredByKey := make(map[string]Rule, len(m.state.Policy.Rules))
	for _, managed := range m.state.Rules {
		managedByID[managed.ID] = managed
	}
	for _, desired := range m.state.Policy.Rules {
		desiredByKey[desired.Key] = desired
	}
	actualByID := make(map[int]rfwRule, len(rows))
	actualFingerprints := make(map[int]string, len(rows))
	result := Readback{
		Status: "in_sync", ObservedAt: time.Now().Unix(), RFWAPIVersion: apiVersion,
		CapabilitiesKnown: capabilitiesKnown, SupportedProtocols: make([]string, 0, len(supportedProtocols)),
		PolicyRevision: m.state.Revision,
		RuleCount:      len(rows), Rules: make([]RuleReadback, 0, len(rows)),
		ExpectedRules: make([]ExpectedRuleReadback, 0, len(m.state.Policy.Rules)),
	}
	for protocol := range supportedProtocols {
		result.SupportedProtocols = append(result.SupportedProtocols, protocol)
	}
	sort.Strings(result.SupportedProtocols)
	for _, row := range rows {
		fingerprint, err := rfwRuleFingerprint(row)
		if err != nil {
			return Readback{}, fmt.Errorf("fingerprint RFW rule %d: %w", row.ID, err)
		}
		actualByID[row.ID] = row
		actualFingerprints[row.ID] = fingerprint
		item := RuleReadback{
			ID: row.ID, Priority: row.Priority, Direction: strings.ToLower(row.Direction),
			Protocol: strings.ToLower(row.Protocol), Action: strings.ToLower(row.Action), Enabled: row.Enabled,
			PortStart: row.PortStart, PortEnd: row.PortEnd, IPType: strings.ToLower(row.IPType),
			IP: row.IP, Countries: append([]string(nil), row.Countries...), Origin: "manual", SyncState: "manual",
		}
		if managed, ok := managedByID[row.ID]; ok {
			item.Origin = "platform"
			item.ManagedKey = managed.Key
			result.ManagedRuleCount++
			if desired, exists := desiredByKey[managed.Key]; !exists {
				item.SyncState = "orphaned"
				result.DriftCount++
				result.Status = "drifted"
			} else {
				desiredFingerprint, err := desiredRFWFingerprint(desired)
				if err != nil {
					return Readback{}, fmt.Errorf("fingerprint desired RFW rule %q: %w", managed.Key, err)
				}
				storedFingerprint, err := ruleFingerprint(desired)
				if err != nil {
					return Readback{}, fmt.Errorf("fingerprint stored RFW rule %q: %w", managed.Key, err)
				}
				if managed.Fingerprint != storedFingerprint || fingerprint != desiredFingerprint {
					item.SyncState = "drifted"
					result.Status = "drifted"
				} else {
					item.SyncState = "in_sync"
				}
			}
		}
		result.Rules = append(result.Rules, item)
	}
	for _, desired := range m.state.Policy.Rules {
		desiredFingerprint, err := desiredRFWFingerprint(desired)
		if err != nil {
			return Readback{}, fmt.Errorf("fingerprint desired RFW rule %q: %w", desired.Key, err)
		}
		storedFingerprint, err := ruleFingerprint(desired)
		if err != nil {
			return Readback{}, fmt.Errorf("fingerprint stored RFW rule %q: %w", desired.Key, err)
		}
		status := "missing"
		id := 0
		for _, managed := range m.state.Rules {
			if managed.Key != desired.Key {
				continue
			}
			id = managed.ID
			if row, exists := actualByID[managed.ID]; exists {
				fingerprint, err := rfwRuleFingerprint(row)
				if err != nil {
					return Readback{}, fmt.Errorf("fingerprint RFW rule %d: %w", managed.ID, err)
				}
				if managed.Fingerprint == storedFingerprint && fingerprint == desiredFingerprint {
					status = "in_sync"
				} else {
					status = "drifted"
				}
			}
			break
		}
		if status == "missing" {
			result.MissingCount++
			result.Status = "drifted"
		} else if status == "drifted" {
			result.DriftCount++
			result.Status = "drifted"
		}
		result.ExpectedRules = append(result.ExpectedRules, ExpectedRuleReadback{Key: desired.Key, ID: id, SyncState: status})
	}
	return result, nil
}

func (m *Manager) createRfwRule(ctx context.Context, rule Rule) (int, error) {
	body, err := json.Marshal(rfwPayload(rule))
	if err != nil {
		return 0, err
	}
	response, status, err := m.request(ctx, "POST", "/api/rules", body)
	if err != nil {
		return 0, err
	}
	if status < 200 || status >= 300 {
		return 0, fmt.Errorf("RFW create returned HTTP %d: %s", status, shortBody(response))
	}
	var result struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(response, &result); err != nil || result.ID < 1 {
		return 0, errors.New("RFW create response did not include a valid rule ID")
	}
	return result.ID, nil
}

func (m *Manager) deleteRfwRule(ctx context.Context, id int) error {
	if id < 1 {
		return errors.New("invalid owned RFW rule ID")
	}
	body, status, err := m.request(ctx, "DELETE", "/api/rules/"+strconv.Itoa(id), nil)
	if err != nil {
		return err
	}
	if status != 200 && status != 204 && status != 404 {
		return fmt.Errorf("RFW delete returned HTTP %d: %s", status, shortBody(body))
	}
	return nil
}

func (m *Manager) request(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, m.rfwURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("RFW API unavailable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(data) > 64*1024 {
		return nil, resp.StatusCode, errors.New("RFW API response exceeds 64 KiB")
	}
	return data, resp.StatusCode, nil
}

// Events returns bounded RFW DPI events through its loopback-only API. The
// caller cursor is opaque and is validated again by RFW before use.
func (m *Manager) Events(ctx context.Context, cursor string, limit int) (EventPage, error) {
	if len(cursor) > 160 || limit < 1 || limit > 100 {
		return EventPage{}, errors.New("invalid RFW event cursor or page size")
	}
	query := url.Values{}
	query.Set("cursor", cursor)
	query.Set("limit", strconv.Itoa(limit))
	body, status, err := m.request(ctx, "GET", "/api/events?"+query.Encode(), nil)
	if err != nil {
		return EventPage{}, err
	}
	if status == http.StatusNotFound {
		return EventPage{}, ErrRFWEventsUnsupported
	}
	if status != http.StatusOK {
		return EventPage{}, fmt.Errorf("RFW events returned HTTP %d: %s", status, shortBody(body))
	}
	var page EventPage
	if err := json.Unmarshal(body, &page); err != nil {
		return EventPage{}, fmt.Errorf("decode RFW event page: %w", err)
	}
	if page.InstanceID == "" || len(page.InstanceID) > 80 || len(page.NextCursor) > 160 || len(page.Events) > limit {
		return EventPage{}, errors.New("RFW event page exceeded its bounds")
	}
	for i := range page.Events {
		event := &page.Events[i]
		if event.Sequence == 0 || len(event.Cursor) > 160 || event.ObservedAt <= 0 {
			return EventPage{}, errors.New("RFW event is missing bounded identity or time")
		}
		if _, err := netip.ParseAddr(event.SourceIP); err != nil {
			return EventPage{}, errors.New("RFW event has an invalid source IP")
		}
		if _, err := netip.ParseAddr(event.DestinationIP); err != nil {
			return EventPage{}, errors.New("RFW event has an invalid destination IP")
		}
		if event.Direction != "in" && event.Direction != "out" {
			return EventPage{}, errors.New("RFW event has an invalid direction")
		}
		if event.Action != "pass" && event.Action != "block" {
			return EventPage{}, errors.New("RFW event has an invalid action")
		}
		if event.Transport != "tcp" && event.Transport != "udp" && event.Transport != "unknown" {
			return EventPage{}, errors.New("RFW event has an invalid transport")
		}
		if len(event.RuleCountries) > 30 {
			return EventPage{}, errors.New("RFW event has too many matched countries")
		}
	}
	return page, nil
}

func shortBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		text = text[:300]
	}
	return text
}

func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.Revision == 0 {
		return nil
	}
	if err := validateBridgeInterfaces(m.state.Policy.Abuse, m.bridge); err != nil {
		if cleanupErr := applyAbusePolicy(ctx, m.run, m.state.Policy.Abuse, m.ipv6(), m.bridge); cleanupErr != nil {
			return fmt.Errorf("%v; cleanup stale container-forward policy: %w", err, cleanupErr)
		}
		return err
	}
	if err := m.reconcileRFW(ctx); err != nil {
		return err
	}
	return applyAbusePolicy(ctx, m.run, m.state.Policy.Abuse, m.ipv6(), m.bridge)
}

func (m *Manager) ReconcileLoop(ctx context.Context) {
	if err := m.Reconcile(ctx); err != nil {
		log.Printf("[host-firewall] initial reconciliation incomplete: %v", err)
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Reconcile(ctx); err != nil {
				log.Printf("[host-firewall] reconciliation incomplete: %v", err)
			}
		}
	}
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &m.state); err != nil {
		return fmt.Errorf("decode persisted host firewall policy: %w", err)
	}
	if m.state.Revision > 0 {
		policy, err := validatePolicy(m.state.Policy)
		if err != nil {
			return fmt.Errorf("persisted host firewall policy is invalid: %w", err)
		}
		if policy.Revision != m.state.Revision {
			return errors.New("persisted host firewall revision mismatch")
		}
		m.state.Policy = policy
	}
	for _, rule := range m.state.Rules {
		if !ruleKeyPattern.MatchString(rule.Key) || rule.ID < 1 || rule.Fingerprint == "" {
			return errors.New("persisted managed RFW rule ownership is invalid")
		}
	}
	return nil
}

func (m *Manager) save() error {
	dir := filepath.Dir(m.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".host-firewall-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, m.path)
}

// Summary is safe to return through the local socket; it contains no host
// identifiers or RFW credentials.
func (m *Manager) Summary() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("policy_revision=%d; managed_rfw_rules=%d; abuse_ports=%s", m.state.Revision, len(m.state.Policy.Rules), abuseSummary(m.state.Policy.Abuse))
}

func abuseSummary(policy AbusePolicy) string {
	var enabled []string
	if policy.Speedtest {
		enabled = append(enabled, "speedtest")
	}
	if policy.Mining {
		enabled = append(enabled, "mining")
	}
	if policy.BT {
		enabled = append(enabled, "bt")
	}
	if len(enabled) == 0 {
		return "off"
	}
	return strings.Join(enabled, ",")
}
