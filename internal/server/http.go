package server

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/unrandoms/ssrf-canary/internal/store"
)

// logAllRequests is middleware that logs every HTTP request and records callbacks.
func logAllRequests(s *store.Store, hub *WSHub, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip internal API paths from callback matching but still log them.
		token := extractToken(r)

		// Read body (limit to 64 KB to avoid memory abuse).
		var bodyStr string
		if r.Body != nil {
			bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
			if err == nil {
				bodyStr = string(bodyBytes)
			}
			r.Body.Close()
		}

		sourceIP := r.RemoteAddr
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			sourceIP = strings.Split(fwd, ",")[0] + " (via " + r.RemoteAddr + ")"
		}

		log.Printf("[http] %s %s %s token=%q body_len=%d",
			r.Method, r.URL.Path, sourceIP, token, len(bodyStr))

		if token != "" && s.Exists(token) {
			headers := make(map[string]string)
			for k, v := range r.Header {
				headers[k] = strings.Join(v, ", ")
			}
			cb := store.CallbackRequest{
				Timestamp: time.Now(),
				SourceIP:  r.RemoteAddr,
				Protocol:  "http",
				Method:    r.Method,
				Path:      r.URL.Path,
				Headers:   headers,
				Body:      bodyStr,
				Query:     r.URL.RawQuery,
			}
			s.RecordCallback(token, cb)

			event := map[string]interface{}{
				"type":    "callback",
				"token":   token,
				"request": cb,
			}
			hub.Broadcast(event)
			log.Printf("[http] token %s marked seen", token)
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
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
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
