package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrCapacity = errors.New("token capacity reached")
var ErrLabel = errors.New("label must be valid text of at most 128 bytes without control characters")

type CallbackRequest struct {
	Timestamp     time.Time         `json:"timestamp"`
	SourceIP      string            `json:"source_ip"`
	Protocol      string            `json:"protocol"`
	Method        string            `json:"method,omitempty"`
	Path          string            `json:"path,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	BodyTruncated bool              `json:"body_truncated"`
	Query         string            `json:"query,omitempty"`
}

type TokenEntry struct {
	Token     string            `json:"token"`
	Label     string            `json:"label"`
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Seen      bool              `json:"seen"`
	Dropped   uint64            `json:"dropped_events"`
	MaxEvents int               `json:"max_events"`
	Requests  []CallbackRequest `json:"requests"`
}

type Store struct {
	mu                   sync.RWMutex
	tokens               map[string]*TokenEntry
	ttl                  time.Duration
	maxTokens, maxEvents int
}

func New() *Store { return NewWithTTL(time.Hour) }
func NewWithTTL(ttl time.Duration) *Store {
	return &Store{tokens: make(map[string]*TokenEntry), ttl: ttl, maxTokens: 1024, maxEvents: 64}
}

// CreateToken allocates a bounded, expiring session. Randomness failures are returned.
func (s *Store) CreateToken(label string) (string, error) {
	if !utf8.ValidString(label) || len(label) > 128 {
		return "", ErrLabel
	}
	for _, c := range label {
		if unicode.IsControl(c) {
			return "", ErrLabel
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reapLocked()
	if len(s.tokens) >= s.maxTokens {
		return "", ErrCapacity
	}
	for {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		token := hex.EncodeToString(b[:])
		if _, exists := s.tokens[token]; exists {
			continue
		}
		now := time.Now().UTC()
		s.tokens[token] = &TokenEntry{Token: token, Label: label, CreatedAt: now, ExpiresAt: now.Add(s.ttl), MaxEvents: s.maxEvents, Requests: []CallbackRequest{}}
		return token, nil
	}
}

// GenerateToken is retained for internal compatibility; an empty value signals failure.
func (s *Store) GenerateToken() string { token, _ := s.CreateToken(""); return token }

func (s *Store) Exists(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.tokens[token]
	return ok && time.Now().Before(e.ExpiresAt)
}

func cloneRequest(r CallbackRequest) CallbackRequest {
	if r.Headers != nil {
		headers := make(map[string]string, len(r.Headers))
		for k, v := range r.Headers {
			headers[k] = v
		}
		r.Headers = headers
	}
	return r
}
func cloneEntry(e *TokenEntry) TokenEntry {
	cp := *e
	cp.Requests = make([]CallbackRequest, len(e.Requests))
	for i, r := range e.Requests {
		cp.Requests[i] = cloneRequest(r)
	}
	return cp
}

// RecordCallback retains the first MaxEvents callbacks; overflow is counted.
func (s *Store) RecordCallback(token string, req CallbackRequest) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tokens[token]
	if !ok || !time.Now().Before(e.ExpiresAt) {
		return false
	}
	e.Seen = true
	if len(e.Requests) >= e.MaxEvents {
		e.Dropped++
		return false
	}
	e.Requests = append(e.Requests, cloneRequest(req))
	return true
}
func (s *Store) Get(token string) (TokenEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.tokens[token]
	if !ok || !time.Now().Before(e.ExpiresAt) {
		return TokenEntry{}, false
	}
	return cloneEntry(e), true
}
func (s *Store) List() []TokenEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TokenEntry, 0, len(s.tokens))
	now := time.Now()
	for _, e := range s.tokens {
		if now.Before(e.ExpiresAt) {
			out = append(out, cloneEntry(e))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Token < out[j].Token
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}
func (s *Store) Clear()              { s.mu.Lock(); defer s.mu.Unlock(); s.tokens = make(map[string]*TokenEntry) }
func (s *Store) Delete(token string) { s.mu.Lock(); defer s.mu.Unlock(); delete(s.tokens, token) }
func (s *Store) reap()               { s.mu.Lock(); defer s.mu.Unlock(); s.reapLocked() }
func (s *Store) reapLocked() {
	now := time.Now()
	for token, e := range s.tokens {
		if !now.Before(e.ExpiresAt) {
			delete(s.tokens, token)
		}
	}
}
