package store

import (
	"errors"
	"testing"
	"time"
)

func TestRetentionAndLabels(t *testing.T) {
	s := New()
	s.maxTokens = 1
	s.maxEvents = 2
	tok, err := s.CreateToken("login-check")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateToken("overflow"); !errors.Is(err, ErrCapacity) {
		t.Fatal("capacity not enforced")
	}
	for i := 0; i < 4; i++ {
		s.RecordCallback(tok, CallbackRequest{Protocol: "http"})
	}
	e, _ := s.Get(tok)
	if e.Label != "login-check" || len(e.Requests) != 2 || e.Dropped != 2 || !e.Seen {
		t.Fatalf("bad retention: %+v", e)
	}
}
func TestExpiredSessionRejectedWithoutReap(t *testing.T) {
	s := New()
	tok := s.GenerateToken()
	s.tokens[tok].ExpiresAt = time.Now().Add(-time.Second)
	if s.Exists(tok) {
		t.Fatal("expired token exists")
	}
	if _, ok := s.Get(tok); ok {
		t.Fatal("expired token readable")
	}
	if s.RecordCallback(tok, CallbackRequest{}) || len(s.List()) != 0 {
		t.Fatal("expired token used")
	}
}
func TestHeadersIsolated(t *testing.T) {
	s := New()
	tok := s.GenerateToken()
	h := map[string]string{"X-Test": "original"}
	s.RecordCallback(tok, CallbackRequest{Headers: h})
	h["X-Test"] = "changed"
	e, _ := s.Get(tok)
	if e.Requests[0].Headers["X-Test"] != "original" {
		t.Fatal("input aliased")
	}
	e.Requests[0].Headers["X-Test"] = "changed"
	listed := s.List()
	listed[0].Requests[0].Headers["X-Test"] = "changed"
	e, _ = s.Get(tok)
	if e.Requests[0].Headers["X-Test"] != "original" {
		t.Fatal("output aliased")
	}
}
func TestInvalidLabels(t *testing.T) {
	for _, v := range []string{"bad\nlabel", string([]byte{255})} {
		if _, err := New().CreateToken(v); !errors.Is(err, ErrLabel) {
			t.Fatal("invalid label accepted")
		}
	}
}
