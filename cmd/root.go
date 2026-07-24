package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/unrandoms/ssrf-canary/internal/api"
	"github.com/unrandoms/ssrf-canary/internal/server"
	"github.com/unrandoms/ssrf-canary/internal/store"
)

var (
	httpPort   int
	dnsPort    int
	domain     string
	serverIP   string
	tlsEnabled bool
	certFile   string
	keyFile    string
)

var rootCmd = &cobra.Command{
	Use:   "ssrf-canary",
	Short: "Out-of-band callback server for SSRF, XXE, and SSTI validation",
	Long: `ssrf-canary is a self-hosted OOB callback server that replaces Burp Collaborator
in automated security testing. It tracks unique tokens via HTTP and DNS callbacks.`,
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
	rootCmd.Flags().IntVar(&httpPort, "http-port", 8080, "HTTP listener port")
	rootCmd.Flags().IntVar(&dnsPort, "dns-port", 5353, "DNS listener port")
	rootCmd.Flags().StringVar(&domain, "domain", "canary.example.com", "Base domain for DNS callbacks")
	rootCmd.Flags().StringVar(&serverIP, "ip", "", "Public IP to advertise in DNS A records (auto-detected if empty)")
	rootCmd.Flags().BoolVar(&tlsEnabled, "tls", false, "Enable TLS for HTTP server")
	rootCmd.Flags().StringVar(&certFile, "cert", "", "TLS certificate file (PEM)")
	rootCmd.Flags().StringVar(&keyFile, "key", "", "TLS private key file (PEM)")
}

func run() error {
	s := store.New()

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

	mux, hub := api.NewRouter(s, cfg.Domain, cfg.ServerIP, cfg.HTTPPort, cfg.TLSEnabled)
	cfg.Mux = mux
	cfg.Hub = hub

	return server.Run(cfg)
}
