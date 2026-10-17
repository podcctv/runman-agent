//go:build linux

package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"runman-agent/firewall/connlimit"
)

func TestHandlerRejectsUnsupportedTargetBeforeResolving(t *testing.T) {
	called := false
	resolver := func(context.Context, string, string) (Target, error) {
		called = true
		return Target{}, nil
	}
	handler := newHandler(resolver, connlimit.New(t.TempDir()+"/state.json", "/config", "/agent"))
	req := httptest.NewRequest(http.MethodPost, "/v1/connlimit", strings.NewReader(`{"action":"apply","project":"other","container_name":"x"}`))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if called {
		t.Fatal("resolver ran for an unsupported project")
	}
}

func TestHandlerRejectsNonPost(t *testing.T) {
	handler := newHandler(func(context.Context, string, string) (Target, error) {
		t.Fatal("resolver should not run")
		return Target{}, nil
	}, connlimit.New(t.TempDir()+"/state.json", "/config", "/agent"))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/v1/connlimit", nil))
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", res.Code)
	}
}
