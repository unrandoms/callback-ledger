package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/unrandoms/ssrf-canary/internal/server"
	"github.com/unrandoms/ssrf-canary/internal/store"
)

// tokenResponse is returned by GET /token.
type tokenResponse struct {
	Token   string `json:"token"`
	HTTPURL string `json:"http_url"`
	DNSHost string `json:"dns_host"`
}

// checkResponse is returned by GET /check/:token.
type checkResponse struct {
	Seen     bool                  `json:"seen"`
	Requests []store.CallbackRequest `json:"requests"`
}

// NewRouter builds and returns the API ServeMux and the WebSocket hub.
func NewRouter(s *store.Store, domain, serverIP string, httpPort int, tls bool) (*http.ServeMux, *server.WSHub) {
	hub := server.NewWSHub()
	mux := http.NewServeMux()

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
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		token := s.GenerateToken()
		resp := tokenResponse{
			Token:   token,
			HTTPURL: fmt.Sprintf("%s/%s", baseURL, token),
			DNSHost: fmt.Sprintf("%s.%s", token, domain),
		}
		writeJSON(w, http.StatusOK, resp)
		log.Printf("[api] issued token %s", token)
	})

	// GET /check/{token} — poll for callbacks.
	mux.HandleFunc("/check/", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		entries := s.List()
		writeJSON(w, http.StatusOK, entries)
	})

	// POST /clear — remove all tokens.
	mux.HandleFunc("/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.Clear()
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		log.Printf("[api] store cleared")
	})

	// GET /ws — WebSocket upgrade.
	mux.HandleFunc("/ws", hub.ServeWS)

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
