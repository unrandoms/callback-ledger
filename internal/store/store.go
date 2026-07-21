package store

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CallbackRequest holds details of a single incoming callback.
type CallbackRequest struct {
	Timestamp time.Time         `json:"timestamp"`
	SourceIP  string            `json:"source_ip"`
	Protocol  string            `json:"protocol"` // "http" or "dns"
	Method    string            `json:"method,omitempty"`
	Path      string            `json:"path,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Query     string            `json:"query,omitempty"`
}

// TokenEntry tracks all callbacks received for a unique token.
type TokenEntry struct {
	Token     string            `json:"token"`
	CreatedAt time.Time         `json:"created_at"`
	Seen      bool              `json:"seen"`
	Requests  []CallbackRequest `json:"requests"`
}

// Store is a thread-safe in-memory token store.
type Store struct {
	mu     sync.RWMutex
	tokens map[string]*TokenEntry
	ttl    time.Duration
}

// New creates a Store with a default TTL of 1 hour and starts background cleanup.
func New() *Store {
	s := &Store{
		tokens: make(map[string]*TokenEntry),
		ttl:    time.Hour,
	}
	go s.reapLoop()
	return s
}

// NewWithTTL creates a Store with a custom TTL.
func NewWithTTL(ttl time.Duration) *Store {
	s := &Store{
		tokens: make(map[string]*TokenEntry),
		ttl:    ttl,
	}
	go s.reapLoop()
	return s
}

// GenerateToken mints a new 16-byte hex token, stores it, and returns it.
func (s *Store) GenerateToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback: use time-based bytes (should never happen)
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(now >> uint(i*8))
		}
	}
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.tokens[token] = &TokenEntry{
		Token:     token,
		CreatedAt: time.Now(),
		Requests:  []CallbackRequest{},
	}
	s.mu.Unlock()
	return token
}

// Exists reports whether the token is tracked.
func (s *Store) Exists(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tokens[token]
	return ok
}

// RecordCallback logs a callback for the given token and marks it as seen.
// Returns false if the token is not tracked.
func (s *Store) RecordCallback(token string, req CallbackRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.tokens[token]
	if !ok {
		return false
	}
	entry.Seen = true
	entry.Requests = append(entry.Requests, req)
	return true
}

// Get returns a copy of the entry for the given token.
func (s *Store) Get(token string) (TokenEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.tokens[token]
	if !ok {
		return TokenEntry{}, false
	}
	// Return a shallow copy to avoid races on the slice.
	cp := *entry
	cp.Requests = make([]CallbackRequest, len(entry.Requests))
	copy(cp.Requests, entry.Requests)
	return cp, true
}

// List returns copies of all token entries.
func (s *Store) List() []TokenEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TokenEntry, 0, len(s.tokens))
	for _, entry := range s.tokens {
		cp := *entry
		cp.Requests = make([]CallbackRequest, len(entry.Requests))
		copy(cp.Requests, entry.Requests)
		out = append(out, cp)
	}
	return out
}

// Clear removes all token entries.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]*TokenEntry)
}

// Delete removes a single token entry.
func (s *Store) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

// reapLoop periodically removes expired entries.
func (s *Store) reapLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.reap()
	}
}

func (s *Store) reap() {
	cutoff := time.Now().Add(-s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, entry := range s.tokens {
		if entry.CreatedAt.Before(cutoff) {
			delete(s.tokens, token)
		}
	}
}
