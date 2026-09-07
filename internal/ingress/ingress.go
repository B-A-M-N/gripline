// Package ingress provides trusted source identity resolution (P0.6).
// It derives canonical source identity from the TCP peer, with optional
// trusted-proxy forwarding-header support.
package ingress

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Peer represents the network peer that connected to Gripline.
type Peer struct {
	// IP is the canonical peer IP (without port).
	IP netip.Addr
	// Port is the peer port (0 if unknown).
	Port uint16
}

// ExtractPeer extracts the peer IP from a request's RemoteAddr.
// P0.6: Uses canonical netip.Addr, stripping the ephemeral port so that
// reconnecting from the same IP on another port is recognized as the same source.
func ExtractPeer(remoteAddr string) (Peer, error) {
	// RemoteAddr is "host:port" for TCP. Strip the port.
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Try parsing as bare IP (no port).
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return Peer{}, err
	}
	var port uint16
	if portStr != "" {
		p, err := net.LookupPort("tcp", portStr)
		if err == nil {
			port = uint16(p)
		}
	}
	return Peer{IP: ip, Port: port}, nil
}

// PeerIP extracts just the IP string from RemoteAddr, suitable for
// pseudonymization and source-key derivation.
func PeerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.Split(host, "%")[0] // strip zone for IPv6
}
