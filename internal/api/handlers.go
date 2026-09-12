package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/unrandoms/callback-ledger/internal/server"
	"github.com/unrandoms/callback-ledger/internal/store"
)

// tokenResponse is returned by GET /token.
type tokenResponse struct {
	Token   string `json:"token"`
	HTTPURL string `json:"http_url"`
	DNSHost string `json:"dns_host"`
}

// checkResponse is returned by GET /check/:token.
type checkResponse struct {
	Seen     bool                    `json:"seen"`
	Requests []store.CallbackRequest `json:"requests"`
}

// NewRouter builds and returns the API ServeMux and the WebSocket hub.
func NewRouter(s *store.Store, domain, serverIP string, httpPort int, tls bool, adminToken string) (*http.ServeMux, *server.WSHub) {
	hub := server.NewWSHub()
	mux := http.NewServeMux()
	register := func(path string, handler http.HandlerFunc) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			expected := sha256.Sum256([]byte("Bearer " + adminToken))
			supplied := sha256.Sum256([]byte(r.Header.Get("Authorization")))
			w.Header().Set("Cache-Control", "no-store")
			if adminToken == "" || subtle.ConstantTimeCompare(expected[:], supplied[:]) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			handler(w, r)
		})
	}

	scheme := "http"
	if tls {
		scheme = "https"
	}

	ip := serverIP
	if ip == "" {
		ip = "127.0.0.1"
	}

	baseURL := fmt.Sprintf("%s://%s:%d", scheme, ip, httpPort)

	// GET /token — mint a new canary token.
	register("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token, err := s.CreateToken(r.URL.Query().Get("label"))
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, store.ErrLabel) {
				status = http.StatusBadRequest
			}
			if errors.Is(err, store.ErrCapacity) {
				status = http.StatusTooManyRequests
			}
			http.Error(w, err.Error(), status)
			return
		}
		resp := tokenResponse{
			Token:   token,
			HTTPURL: fmt.Sprintf("%s/%s", baseURL, token),
			DNSHost: fmt.Sprintf("%s.%s", token, domain),
		}
		writeJSON(w, http.StatusOK, resp)
		log.Printf("[api] issued token %s", token)
	})

	// GET /check/{token} — poll for callbacks.
	register("/check/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, "/check/")
		token = strings.TrimSuffix(token, "/")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		entry, ok := s.Get(token)
		if !ok {
			http.Error(w, "token not found", http.StatusNotFound)
			return
		}
		resp := checkResponse{
			Seen:     entry.Seen,
			Requests: entry.Requests,
		}
		writeJSON(w, http.StatusOK, resp)
	})

	// GET /list — list all tokens and their status.
	register("/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entries := s.List()
		writeJSON(w, http.StatusOK, entries)
	})

	// POST /clear — remove all tokens.
	register("/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.Clear()
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		log.Printf("[api] store cleared")
	})

	// Exports include retention metadata so a partial record cannot appear complete.
	register("/export/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", 405)
			return
		}
		entry, ok := s.Get(strings.TrimPrefix(r.URL.Path, "/export/"))
		if !ok {
			http.Error(w, "token not found", 404)
			return
		}
		format := r.URL.Query().Get("format")
		if format != "" && format != "json" && format != "ndjson" {
			http.Error(w, "format must be json or ndjson", 400)
			return
		}
		if format == "ndjson" {
			w.Header().Set("Content-Type", "application/x-ndjson")
			events := entry.Requests
			entry.Requests = []store.CallbackRequest{}
			enc := json.NewEncoder(w)
			if enc.Encode(map[string]interface{}{"type": "session", "schema_version": 1, "session": entry}) != nil {
				return
			}
			for _, event := range events {
				if enc.Encode(map[string]interface{}{"type": "callback", "request": event}) != nil {
					return
				}
			}
			return
		}
		writeJSON(w, 200, map[string]interface{}{"schema_version": 1, "session": entry})
	})

	// GET /ws — authenticated WebSocket upgrade.
	register("/ws", hub.ServeWS)

	// Catch-all — used by callback middleware in http.go; return 200 so targets don't retry.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux, hub
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[api] json encode error: %v", err)
	}
}
