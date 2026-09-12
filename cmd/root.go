package cmd

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/unrandoms/callback-ledger/internal/api"
	"github.com/unrandoms/callback-ledger/internal/server"
	"github.com/unrandoms/callback-ledger/internal/store"
)

var (
	httpPort   int
	dnsPort    int
	domain     string
	serverIP   string
	tlsEnabled bool
	certFile   string
	keyFile    string
	ttl        time.Duration
)

var rootCmd = &cobra.Command{
	Use:   "callback-ledger",
	Short: "Collect labeled HTTP/DNS callbacks and export test evidence",
	Long: `callback-ledger collects labeled HTTP/DNS callbacks in bounded, expiring sessions.
Management endpoints require CALLBACK_LEDGER_ADMIN_TOKEN. Export JSON or NDJSON before expiry.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().DurationVar(&ttl, "ttl", time.Hour, "Session lifetime")
	rootCmd.Flags().IntVar(&httpPort, "http-port", 8080, "HTTP listener port")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 5353, "DNS listener port")
	rootCmd.Flags().StringVar(&domain, "domain", "canary.example.com", "Base domain for DNS callbacks")
	rootCmd.Flags().StringVar(&serverIP, "ip", "127.0.0.1", "IPv4 address advertised in callback URLs and DNS A records")
	rootCmd.Flags().BoolVar(&tlsEnabled, "tls", false, "Enable TLS for HTTP server")
	rootCmd.Flags().StringVar(&certFile, "cert", "", "TLS certificate file (PEM)")
	rootCmd.Flags().StringVar(&keyFile, "key", "", "TLS private key file (PEM)")
}

func run() error {
	adminToken := os.Getenv("CALLBACK_LEDGER_ADMIN_TOKEN")
	if len(adminToken) < 32 {
		return fmt.Errorf("set CALLBACK_LEDGER_ADMIN_TOKEN to at least 32 characters")
	}
	if ttl <= 0 {
		return fmt.Errorf("--ttl must be positive")
	}
	if ip := net.ParseIP(serverIP); ip == nil || ip.To4() == nil {
		return fmt.Errorf("--ip requires an IPv4 address")
	}
	s := store.NewWithTTL(ttl)

	cfg := server.Config{
		HTTPPort:   httpPort,
		DNSPort:    dnsPort,
		Domain:     domain,
		ServerIP:   serverIP,
		TLSEnabled: tlsEnabled,
		CertFile:   certFile,
		KeyFile:    keyFile,
		Store:      s,
	}

	mux, hub := api.NewRouter(s, cfg.Domain, cfg.ServerIP, cfg.HTTPPort, cfg.TLSEnabled, adminToken)
	cfg.Mux = mux
	cfg.Hub = hub

	return server.Run(cfg)
}
