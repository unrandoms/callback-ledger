package server

import (
	"github.com/gorilla/websocket"
	"github.com/unrandoms/callback-ledger/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCaptureBoundsAndRedaction(t *testing.T) {
	s := store.New()
	tok := s.GenerateToken()
	h := logAllRequests(s, NewWSHub(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequest("POST", "/"+tok, strings.NewReader(strings.Repeat("a", 20000)))
	r.Header.Set("Authorization", "secret")
	r.Header.Set("Cookie", "session=secret")
	h.ServeHTTP(httptest.NewRecorder(), r)
	e, _ := s.Get(tok)
	if len(e.Requests) != 1 {
		t.Fatal(e)
	}
	cb := e.Requests[0]
	if !cb.BodyTruncated || len(cb.Body) != 16384 || cb.Headers["Authorization"] != "[redacted]" || cb.Headers["Cookie"] != "[redacted]" {
		t.Fatal("capture limits/redaction failed")
	}
	r = httptest.NewRequest("GET", "/list?token="+tok, nil)
	r.Header.Set("Authorization", "admin-secret")
	h.ServeHTTP(httptest.NewRecorder(), r)
	e, _ = s.Get(tok)
	if len(e.Requests) != 1 {
		t.Fatal("management request captured")
	}
}
func TestDNSDomainBoundary(t *testing.T) {
	tok := strings.Repeat("a", 32)
	if extractDNSToken(tok+".evilcanary.example.com", "canary.example.com") != "" {
		t.Fatal("accepted unrelated domain")
	}
	if extractDNSToken(tok+".canary.example.com", "canary.example.com") != tok {
		t.Fatal("rejected valid domain")
	}
}

func TestConcurrentWebsocketBroadcast(t *testing.T) {
	hub := NewWSHub()
	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Registration happens after the upgrade response; acquire the hub lock to observe it.
	deadline := time.Now().Add(time.Second)
	for {
		hub.mu.RLock()
		n := len(hub.clients)
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client not registered")
		}
		time.Sleep(time.Millisecond)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) { defer wg.Done(); hub.Broadcast(map[string]int{"n": n}) }(i)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 20; i++ {
		if _, _, err := conn.ReadMessage(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
