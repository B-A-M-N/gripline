// Command gripline-test-pg-writer is a repository-owned PostgreSQL writer
// endpoint for the HA qualification lab. It selects the instance whose
// pg_is_in_recovery() is false and proxies PostgreSQL wire connections to it.
// It is deliberately a test fixture, not a production connection pool.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
)

type dsnList []string

func (d *dsnList) String() string { return strings.Join(*d, ",") }
func (d *dsnList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("empty backend DSN")
	}
	*d = append(*d, value)
	return nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:25434", "writer endpoint listen address")
	var backends dsnList
	flag.Var(&backends, "backend-dsn", "PostgreSQL backend DSN; repeat for each candidate")
	interval := flag.Duration("health-interval", 250*time.Millisecond, "writer health-check interval")
	flag.Parse()
	if len(backends) < 2 || *interval <= 0 {
		log.Fatal("at least two -backend-dsn values and a positive -health-interval are required")
	}
	addresses := make([]string, 0, len(backends))
	for _, dsn := range backends {
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			log.Fatalf("parse backend DSN: %v", err)
		}
		addresses = append(addresses, net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	}
	var active atomic.Value
	active.Store("")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(*interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				selected := ""
				for index, dsn := range backends {
					probeCtx, probeCancel := context.WithTimeout(ctx, 750*time.Millisecond)
					conn, err := pgx.Connect(probeCtx, dsn)
					if err == nil {
						var recovery bool
						err = conn.QueryRow(probeCtx, "SELECT pg_is_in_recovery()").Scan(&recovery)
						_ = conn.Close(probeCtx)
						if err == nil && !recovery {
							selected = addresses[index]
							probeCancel()
							break
						}
					} else {
						probeCancel()
						continue
					}
					probeCancel()
				}
				previous, _ := active.Load().(string)
				if selected != previous {
					log.Printf("active backend=%q", selected)
				}
				active.Store(selected)
			}
		}
	}()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		cancel()
	}()
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go proxyConnection(ctx, client, &active)
	}
}

func proxyConnection(ctx context.Context, client net.Conn, active *atomic.Value) {
	defer client.Close()
	var server net.Conn
	deadline := time.Now().Add(30 * time.Second)
	for server == nil && time.Now().Before(deadline) {
		if raw, ok := active.Load().(string); ok && raw != "" {
			var err error
			server, err = net.DialTimeout("tcp", raw, 2*time.Second)
			if err != nil {
				server = nil
			}
		}
		if server == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if server == nil {
		return
	}
	defer server.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(server, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, server); done <- struct{}{} }()
	<-done
}
