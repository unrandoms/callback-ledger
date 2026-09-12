package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/unrandoms/callback-ledger/internal/store"
)

// logAllRequests is middleware that logs every HTTP request and records callbacks.
func logAllRequests(s *store.Store, hub *WSHub, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Management requests never enter the evidence capture path.
		first := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)[0]
		switch first {
		case "token", "check", "list", "clear", "export", "ws":
			next.ServeHTTP(w, r)
			return
		}
		token := extractToken(r)
		if token != "" && s.Exists(token) {
			const bodyLimit = 16 * 1024
			var body []byte
			if r.Body != nil {
				var err error
				body, err = io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
				r.Body.Close()
				if err != nil {
					http.Error(w, "unable to read callback", 400)
					return
				}
			}
			truncated := len(body) > bodyLimit
			if truncated {
				body = body[:bodyLimit]
			}
			headers := make(map[string]string)
			for k, v := range r.Header {
				switch strings.ToLower(k) {
				case "authorization", "proxy-authorization", "cookie":
					headers[k] = "[redacted]"
				default:
					headers[k] = strings.Join(v, ", ")
				}
			}
			cb := store.CallbackRequest{Timestamp: time.Now().UTC(), SourceIP: r.RemoteAddr, Protocol: "http", Method: r.Method, Path: r.URL.Path, Headers: headers, Body: string(body), BodyTruncated: truncated, Query: r.URL.RawQuery}
			if s.RecordCallback(token, cb) {
				hub.Broadcast(map[string]interface{}{"type": "callback", "token": token, "request": cb})
			}
		}

		// Serve the actual handler.
		next.ServeHTTP(w, r)
	})
}

// extractToken tries to find a canary token in the request using multiple strategies.
//  1. First path segment (e.g. /abc123def456.../something)
//  2. Query param ?token=
//  3. Header X-Canary-Token
func extractToken(r *http.Request) string {
	// 1. Path segment — first non-empty segment.
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) > 0 && isHexToken(parts[0]) {
		return parts[0]
	}

	// 2. Query param.
	if t := r.URL.Query().Get("token"); t != "" && isHexToken(t) {
		return t
	}

	// 3. Custom header.
	if t := r.Header.Get("X-Canary-Token"); t != "" && isHexToken(t) {
		return t
	}

	return ""
}

// isHexToken reports whether s looks like our 32-char hex token.
func isHexToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// startHTTP starts the HTTP server (or HTTPS if TLS configured).
func startHTTP(cfg Config) error {
	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	handler := logAllRequests(cfg.Store, cfg.Hub, cfg.Mux)
	srv := &http.Server{
		Addr:           addr,
		Handler:        handler,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 16 * 1024,
	}

	if cfg.TLSEnabled {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return fmt.Errorf("--tls requires --cert and --key")
		}
		log.Printf("[http] TLS listening on %s", addr)
		return srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	}

	log.Printf("[http] listening on %s", addr)
	return srv.ListenAndServe()
}
