//go:build linux

package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"runman-agent/firewall/hostpolicy"
)

type firewallEventTestController struct {
	cursor  string
	limit   int
	err     error
	deleted []hostpolicy.RuleReadback
}

func (f *firewallEventTestController) Apply(context.Context, hostpolicy.Policy) error { return nil }
func (f *firewallEventTestController) DeleteManualRule(_ context.Context, rule hostpolicy.RuleReadback) error {
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, rule)
	return nil
}
func (f *firewallEventTestController) Summary() string { return "ready" }
func (f *firewallEventTestController) Readback(context.Context) (hostpolicy.Readback, error) {
	if f.err != nil {
		return hostpolicy.Readback{}, f.err
	}
	return hostpolicy.Readback{
		Status: "drifted", ObservedAt: 1792380000, PolicyRevision: 3,
		RuleCount: 2, ManagedRuleCount: 1, DriftCount: 1,
		Rules: []hostpolicy.RuleReadback{{ID: 7, Protocol: "wireguard", Origin: "platform", SyncState: "drifted"}},
	}, nil
}
func (f *firewallEventTestController) Events(_ context.Context, cursor string, limit int) (hostpolicy.EventPage, error) {
	f.cursor, f.limit = cursor, limit
	if f.err != nil {
		return hostpolicy.EventPage{}, f.err
	}
	return hostpolicy.EventPage{InstanceID: "boot-1", NextCursor: "boot-1:4", Events: []hostpolicy.Event{{
		Sequence: 4, Cursor: "boot-1:4", ObservedAt: 1792380000, SourceIP: "203.0.113.5", DestinationIP: "192.0.2.5",
		Transport: "udp", AppProtocol: "wireguard", Direction: "in", Action: "block",
	}}}, nil
}

func TestFirewallReadbackIsReadOnlyAndNoStore(t *testing.T) {
	controller := &firewallEventTestController{}
	handler := newFirewallHandler(controller)
	request := httptest.NewRequest(http.MethodGet, "/v1/firewall/readback", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", response.Code, response.Body.String())
	}
	var readback hostpolicy.Readback
	if err := json.Unmarshal(response.Body.Bytes(), &readback); err != nil {
		t.Fatal(err)
	}
	if readback.Status != "drifted" || readback.PolicyRevision != 3 || readback.DriftCount != 1 || len(readback.Rules) != 1 {
		t.Fatalf("unexpected readback payload: %#v", readback)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("sensitive readback must not be cached: %q", response.Header().Get("Cache-Control"))
	}
}

func TestFirewallManualRuleDeleteRequiresExactRuleIdentity(t *testing.T) {
	controller := &firewallEventTestController{}
	handler := newFirewallHandler(controller)
	expected := hostpolicy.RuleReadback{
		ID: 7, Priority: 100, Direction: "in", Protocol: "tcp", Action: "block", Enabled: true,
		PortStart: 443, PortEnd: 443, IPType: "any", Origin: "manual", SyncState: "manual",
	}
	body, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/v1/firewall/rules/7", strings.NewReader(string(body))))
	if response.Code != http.StatusOK || len(controller.deleted) != 1 || controller.deleted[0].ID != 7 {
		t.Fatalf("manual RFW delete was not forwarded: status=%d body=%s deleted=%#v", response.Code, response.Body.String(), controller.deleted)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/v1/firewall/rules/8", strings.NewReader(string(body))))
	if response.Code != http.StatusBadRequest || len(controller.deleted) != 1 {
		t.Fatalf("mismatched path/body ID was accepted: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestFirewallManualRuleDeleteReportsControllerFailure(t *testing.T) {
	controller := &firewallEventTestController{err: errors.New("private RFW API response")}
	handler := newFirewallHandler(controller)
	expected := hostpolicy.RuleReadback{ID: 7, Origin: "manual", SyncState: "manual"}
	body, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/v1/firewall/rules/7", strings.NewReader(string(body))))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "private RFW API response") {
		t.Fatalf("manual delete failure was not returned to the local caller: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestFirewallEventsReadOnlyBoundedEndpoint(t *testing.T) {
	controller := &firewallEventTestController{}
	handler := newFirewallHandler(controller)
	request := httptest.NewRequest(http.MethodGet, "/v1/firewall/events?cursor=boot-1%3A3&limit=25", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", response.Code, response.Body.String())
	}
	if controller.cursor != "boot-1:3" || controller.limit != 25 {
		t.Fatalf("event cursor/limit not forwarded safely: %q %d", controller.cursor, controller.limit)
	}
	var page hostpolicy.EventPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].AppProtocol != "wireguard" || page.Events[0].Action != "block" {
		t.Fatalf("unexpected event response: %#v", page)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("sensitive events must not be cached: %q", response.Header().Get("Cache-Control"))
	}
}

func TestFirewallEventsRejectsInvalidBoundsAndHidesUpstreamError(t *testing.T) {
	controller := &firewallEventTestController{err: errors.New("secret upstream detail")}
	handler := newFirewallHandler(controller)
	for _, target := range []string{
		"/v1/firewall/events?limit=101",
		"/v1/firewall/events?cursor=" + strings.Repeat("a", 161),
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid query %q accepted: %d", target, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/firewall/events", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() == "" ||
		strings.Contains(response.Body.String(), "secret upstream detail") {
		t.Fatalf("upstream failure was not safely redacted: %d %s", response.Code, response.Body.String())
	}
}

func TestFirewallEventsReportsUnsupportedRFWBuild(t *testing.T) {
	controller := &firewallEventTestController{err: hostpolicy.ErrRFWEventsUnsupported}
	handler := newFirewallHandler(controller)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/firewall/events", nil))
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "unavailable") {
		t.Fatalf("missing upstream events API should be reported as unsupported: %d %s", response.Code, response.Body.String())
	}
}
