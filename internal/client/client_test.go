package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "hallpass_at_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

func newTestClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{Endpoint: srv.URL, Token: testToken, UserAgent: "terraform-provider-hallpass/test", MaxRetries: 3,
		MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, code, title string, fields []FieldError) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "https://hallpass.dev/problems/" + code, "title": title, "status": status,
		"code": code, "instance": "/x", "errors": fields})
}

// dropConnection closes the TCP connection without a response, simulating a network failure after the server
// processed the request.
func dropConnection(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("no hijacker")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func TestNewValidatesConfig(t *testing.T) {
	for _, tc := range []struct{ endpoint, token, wantErr string }{
		{"https://hallpass.example.com", "porch_at_x", "hallpass_at_"},
		{"https://hallpass.example.com", "hallpass_at_short", "malformed"},
		{"https://hallpass.example.com", testToken[:len(testToken)-1] + " ", "malformed"},
		{"hallpass.example.com", testToken, "absolute"},
		{"https://user:pw@hallpass.example.com", testToken, "credentials"},
		{"https://hallpass.example.com?x=1", testToken, "query"},
	} {
		_, err := New(Config{Endpoint: tc.endpoint, Token: tc.token})
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("New(%q, %q) = %v, want error containing %q", tc.endpoint, tc.token, err, tc.wantErr)
		}
		if err != nil && strings.Contains(err.Error(), testToken) {
			t.Errorf("error leaks the token: %v", err)
		}
	}
	for _, ep := range []string{"https://hallpass.example.com", "https://hallpass.example.com/", "https://hallpass.example.com/api/v1"} {
		c, err := New(Config{Endpoint: ep, Token: testToken})
		if err != nil || c.Endpoint() != "https://hallpass.example.com" {
			t.Errorf("%s: %v %v", ep, c, err)
		}
	}
}

// Creates carry one Idempotency-Key reused across retries after a dropped connection; updates send the version as
// If-Match and are not retried after a network error (the change may have been applied).
func TestRetriesAndHeaders(t *testing.T) {
	var creates, patches atomic.Int32
	var keys []string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Origin") != "" {
			t.Errorf("headers: %v", r.Header)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agents":
			keys = append(keys, r.Header.Get("Idempotency-Key"))
			if creates.Add(1) == 1 {
				dropConnection(t, w)
				return
			}
			writeJSON(w, http.StatusCreated, Agent{ID: "agt_1", Name: "ci", Version: 1})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/agents/agt_1":
			patches.Add(1)
			if r.Header.Get("If-Match") != `"7"` {
				t.Errorf("If-Match %q", r.Header.Get("If-Match"))
			}
			dropConnection(t, w)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	a, err := c.CreateAgent(context.Background(), AgentInput{Name: "ci"})
	if err != nil || a.ID != "agt_1" {
		t.Fatalf("create: %+v %v", a, err)
	}
	if len(keys) != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("idempotency keys %v", keys)
	}
	if _, err := c.UpdateAgent(context.Background(), "agt_1", 7, AgentInput{Name: "ci"}); err == nil {
		t.Fatal("update after a dropped connection succeeded")
	}
	if patches.Load() != 1 {
		t.Fatalf("update retried %d times", patches.Load())
	}
}

func TestProblemsAndDeletedObjects(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/servers":
			writeProblem(w, http.StatusUnprocessableEntity, "invalid", "validation failed", []FieldError{{Field: "alias", Message: "is reserved"}})
		case "/api/v1/servers/srv_gone":
			writeJSON(w, http.StatusOK, Server{ID: "srv_gone", Alias: "web1", DeletedAt: "2026-10-24T00:00:00Z"})
		case "/api/v1/roles/rol_x":
			writeProblem(w, http.StatusNotFound, "not_found", "role not found", nil)
		default:
			writeProblem(w, http.StatusTooManyRequests, "rate_limited", "slow down", nil)
		}
	}))
	ctx := context.Background()
	_, err := c.CreateServer(ctx, ServerInput{Alias: "list"})
	if err == nil || !strings.Contains(err.Error(), "422 invalid: validation failed (alias: is reserved)") {
		t.Fatalf("problem: %v", err)
	}
	if _, err := c.GetServer(ctx, "srv_gone"); !IsNotFound(err) {
		t.Fatalf("deleted server: %v", err)
	}
	if _, err := c.GetRole(ctx, "rol_x"); !IsNotFound(err) {
		t.Fatalf("missing role: %v", err)
	}
	if _, err := c.ListGroups(ctx); !HasCode(err, "rate_limited") {
		t.Fatalf("rate limit after retries: %v", err)
	}
}
