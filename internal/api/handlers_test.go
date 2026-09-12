package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unrandoms/callback-ledger/internal/store"
)

func newTestRouter() (*http.ServeMux, *store.Store) {
	s := store.New()
	mux, _ := NewRouter(s, "canary.example.com", "127.0.0.1", 8080, false, "test-admin")
	return mux, s
}

func TestTokenEndpoint(t *testing.T) {
	mux, _ := newTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	rr := httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer test-admin")
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp tokenResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(resp.Token) != 32 {
		t.Errorf("expected 32-char token, got %d: %q", len(resp.Token), resp.Token)
	}
	if !strings.Contains(resp.HTTPURL, resp.Token) {
		t.Errorf("HTTP URL %q does not contain token %q", resp.HTTPURL, resp.Token)
	}
	if !strings.HasPrefix(resp.DNSHost, resp.Token) {
		t.Errorf("DNS host %q does not start with token %q", resp.DNSHost, resp.Token)
	}
}

func TestTokenEndpoint_wrongMethod(t *testing.T) {
	mux, _ := newTestRouter()
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	rr := httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer test-admin")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestCheckEndpoint_notFound(t *testing.T) {
	mux, _ := newTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/check/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", nil)
	rr := httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer test-admin")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown token, got %d", rr.Code)
	}
}

func TestCheckEndpoint_seen(t *testing.T) {
	mux, s := newTestRouter()

	// Generate token.
	tok := s.GenerateToken()

	// Check before callback — should be not seen.
	req := httptest.NewRequest(http.MethodGet, "/check/"+tok, nil)
	rr := httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer test-admin")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp checkResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Seen {
		t.Error("expected seen=false before callback")
	}

	// Record a callback.
	s.RecordCallback(tok, store.CallbackRequest{Protocol: "http", SourceIP: "1.2.3.4"})

	// Check after callback — should be seen.
	req2 := httptest.NewRequest(http.MethodGet, "/check/"+tok, nil)
	rr2 := httptest.NewRecorder()
	req2.Header.Set("Authorization", "Bearer test-admin")
	mux.ServeHTTP(rr2, req2)
	var resp2 checkResponse
	json.NewDecoder(rr2.Body).Decode(&resp2)
	if !resp2.Seen {
		t.Error("expected seen=true after callback")
	}
	if len(resp2.Requests) != 1 {
		t.Errorf("expected 1 request, got %d", len(resp2.Requests))
	}
}

func TestListEndpoint(t *testing.T) {
	mux, s := newTestRouter()
	s.GenerateToken()
	s.GenerateToken()

	req := httptest.NewRequest(http.MethodGet, "/list", nil)
	rr := httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer test-admin")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var entries []store.TokenEntry
	json.NewDecoder(rr.Body).Decode(&entries)
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestClearEndpoint(t *testing.T) {
	mux, s := newTestRouter()
	s.GenerateToken()

	req := httptest.NewRequest(http.MethodPost, "/clear", nil)
	rr := httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer test-admin")
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if entries := s.List(); len(entries) != 0 {
		t.Errorf("expected 0 entries after clear, got %d", len(entries))
	}
}
