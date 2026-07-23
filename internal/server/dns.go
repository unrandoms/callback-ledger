package server

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/unrandoms/ssrf-canary/internal/store"
)

// dnsHandler implements dns.Handler and resolves all A queries for *.domain
// back to the server's own IP, logging and recording canary tokens.
type dnsHandler struct {
	domain   string
	serverIP net.IP
	store    *store.Store
	hub      *WSHub
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	sourceIP := w.RemoteAddr().String()

	for _, q := range r.Question {
		name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		log.Printf("[dns] query type=%d name=%s from=%s", q.Qtype, name, sourceIP)

		// Extract token from the leftmost label (e.g. <token>.canary.example.com).
		token := extractDNSToken(name, h.domain)

		if token != "" && h.store.Exists(token) {
			cb := store.CallbackRequest{
				Timestamp: time.Now(),
				SourceIP:  sourceIP,
				Protocol:  "dns",
				Query:     name,
			}
			h.store.RecordCallback(token, cb)

			event := map[string]interface{}{
				"type":  "callback",
				"token": token,
				"request": map[string]interface{}{
					"protocol":  "dns",
					"source_ip": sourceIP,
					"query":     name,
					"timestamp": cb.Timestamp,
				},
			}
			h.hub.Broadcast(event)
			log.Printf("[dns] token %s marked seen", token)
		}

		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: h.serverIP,
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("[dns] write error: %v", err)
	}
}

// extractDNSToken returns the leftmost DNS label if it matches our hex token format
// and the rest of the name is the configured domain.
func extractDNSToken(name, domain string) string {
	suffix := "." + strings.ToLower(domain)
	if !strings.HasSuffix(name, strings.ToLower(domain)) {
		return ""
	}
	label := strings.TrimSuffix(name, suffix)
	// Reject names with additional dots (nested subdomains).
	if strings.Contains(label, ".") {
		// Take only the first label.
		label = strings.SplitN(label, ".", 2)[0]
	}
	if isHexToken(label) {
		return label
	}
	return ""
}

// resolvePublicIP attempts to determine the server's outbound IP.
func resolvePublicIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// startDNS starts the DNS UDP server.
func startDNS(cfg Config) error {
	ip := net.ParseIP(cfg.ServerIP)
	if ip == nil {
		ip = resolvePublicIP()
		log.Printf("[dns] auto-detected server IP: %s", ip)
	}

	handler := &dnsHandler{
		domain:   cfg.Domain,
		serverIP: ip.To4(),
		store:    cfg.Store,
		hub:      cfg.Hub,
	}

	addr := fmt.Sprintf(":%d", cfg.DNSPort)
	srv := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: handler,
	}
	log.Printf("[dns] listening on %s/udp for *.%s", addr, cfg.Domain)
	return srv.ListenAndServe()
}
