package store

import (
	"testing"
	"time"
)

func TestGenerateToken_format(t *testing.T) {
	s := New()
	token := s.GenerateToken()
	if len(token) != 32 {
		t.Fatalf("expected 32-char token, got %d chars: %q", len(token), token)
	}
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex character %q in token %q", c, token)
		}
	}
}

func TestGenerateToken_unique(t *testing.T) {
	s := New()
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		tok := s.GenerateToken()
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token generated on iteration %d: %q", i, tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestExists(t *testing.T) {
	s := New()
	tok := s.GenerateToken()
	if !s.Exists(tok) {
		t.Errorf("Exists(%q) = false, want true", tok)
	}
	if s.Exists("00000000000000000000000000000000") {
		t.Errorf("Exists on non-existent token returned true")
	}
}

func TestRecordCallback(t *testing.T) {
	s := New()
	tok := s.GenerateToken()

	cb := CallbackRequest{
		Timestamp: time.Now(),
		SourceIP:  "1.2.3.4:9999",
		Protocol:  "http",
		Method:    "GET",
		Path:      "/" + tok,
	}
	ok := s.RecordCallback(tok, cb)
	if !ok {
		t.Fatal("RecordCallback returned false for a valid token")
	}

	entry, found := s.Get(tok)
	if !found {
		t.Fatal("Get returned false after RecordCallback")
	}
	if !entry.Seen {
		t.Error("entry.Seen = false after RecordCallback")
	}
	if len(entry.Requests) != 1 {
		t.Errorf("expected 1 request, got %d", len(entry.Requests))
	}
	if entry.Requests[0].SourceIP != "1.2.3.4:9999" {
		t.Errorf("unexpected source IP: %q", entry.Requests[0].SourceIP)
	}
}

func TestRecordCallback_unknownToken(t *testing.T) {
	s := New()
	ok := s.RecordCallback("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", CallbackRequest{})
	if ok {
		t.Error("RecordCallback returned true for unknown token")
	}
}

func TestMultipleCallbacks(t *testing.T) {
	s := New()
	tok := s.GenerateToken()
	for i := 0; i < 5; i++ {
		s.RecordCallback(tok, CallbackRequest{
			Timestamp: time.Now(),
			SourceIP:  "10.0.0.1:1234",
			Protocol:  "http",
		})
	}
	entry, _ := s.Get(tok)
	if len(entry.Requests) != 5 {
		t.Errorf("expected 5 requests, got %d", len(entry.Requests))
	}
}

func TestList(t *testing.T) {
	s := New()
	s.GenerateToken()
	s.GenerateToken()
	s.GenerateToken()
	entries := s.List()
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestClear(t *testing.T) {
	s := New()
	s.GenerateToken()
	s.GenerateToken()
	s.Clear()
	if entries := s.List(); len(entries) != 0 {
		t.Errorf("expected 0 entries after Clear, got %d", len(entries))
	}
}

func TestDelete(t *testing.T) {
	s := New()
	tok := s.GenerateToken()
	s.Delete(tok)
	if s.Exists(tok) {
		t.Errorf("token still exists after Delete")
	}
}

func TestTTLReap(t *testing.T) {
	s := NewWithTTL(1 * time.Millisecond)
	tok := s.GenerateToken()
	time.Sleep(5 * time.Millisecond)
	s.reap()
	if s.Exists(tok) {
		t.Error("expired token still exists after reap")
	}
}

func TestGetCopyIsolation(t *testing.T) {
	s := New()
	tok := s.GenerateToken()
	s.RecordCallback(tok, CallbackRequest{SourceIP: "1.1.1.1"})

	copy1, _ := s.Get(tok)
	// Mutate the copy's slice.
	copy1.Requests[0].SourceIP = "mutated"

	copy2, _ := s.Get(tok)
	if copy2.Requests[0].SourceIP == "mutated" {
		t.Error("mutating returned copy affected internal store state")
	}
}
