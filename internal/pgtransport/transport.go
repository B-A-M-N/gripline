// Package pgtransport contains the common PostgreSQL transport policy used by
// every security-authoritative PostgreSQL adapter.
package pgtransport

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrInsecureTransport identifies a remote PostgreSQL connection that is not
// authenticated by TLS. Local Unix-socket and loopback fixtures are explicit
// deployment boundaries and may remain plaintext.
var ErrInsecureTransport = errors.New("remote PostgreSQL requires authenticated TLS")

// Validate rejects libpq/pgx's default "prefer" fallback for remote
// authorities. Every possible fallback is checked because a multi-host DSN
// must not become secure merely because its first host happened to be local.
func Validate(config *pgxpool.Config) error {
	if config == nil {
		return errors.New("nil PostgreSQL connection config")
	}
	configs := []*pgconn.Config{{
		Host:      config.ConnConfig.Host,
		Port:      config.ConnConfig.Port,
		TLSConfig: config.ConnConfig.TLSConfig,
	}}
	for _, fallback := range config.ConnConfig.Fallbacks {
		configs = append(configs, &pgconn.Config{Host: fallback.Host, Port: fallback.Port, TLSConfig: fallback.TLSConfig})
	}
	for _, candidate := range configs {
		if candidate == nil {
			continue
		}
		network, _ := pgconn.NetworkAddress(candidate.Host, candidate.Port)
		if network == "unix" || isLoopbackHost(candidate.Host) {
			continue
		}
		if candidate.TLSConfig == nil || (candidate.TLSConfig.InsecureSkipVerify && candidate.TLSConfig.VerifyPeerCertificate == nil) {
			return fmt.Errorf("%w: host %q", ErrInsecureTransport, candidate.Host)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
