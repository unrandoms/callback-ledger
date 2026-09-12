package server

import (
	"net/http"

	"github.com/unrandoms/callback-ledger/internal/store"
)

// Config holds all runtime configuration for the server.
type Config struct {
	HTTPPort   int
	DNSPort    int
	Domain     string
	ServerIP   string
	TLSEnabled bool
	CertFile   string
	KeyFile    string
	Store      *store.Store
	Mux        *http.ServeMux
	Hub        *WSHub
}

// Run starts the HTTP and DNS servers concurrently.
// It blocks until one of them returns an error.
func Run(cfg Config) error {
	errc := make(chan error, 2)

	go func() {
		errc <- startHTTP(cfg)
	}()

	go func() {
		errc <- startDNS(cfg)
	}()

	// Return on first fatal error.
	return <-errc
}
