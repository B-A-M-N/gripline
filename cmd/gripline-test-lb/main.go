// Command gripline-test-lb is a deliberately small process-level load
// balancer for the PostgreSQL cluster acceptance harness. Traffic enters this
// process and is round-robined across independently running Gripline nodes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type backendList []string

func (b *backendList) String() string { return strings.Join(*b, ",") }
func (b *backendList) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("backend address cannot be empty")
	}
	*b = append(*b, value)
	return nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:18080", "load balancer listen address")
	var addresses backendList
	flag.Var(&addresses, "backend", "Gripline backend URL; repeat for each node")
	flag.Parse()
	if len(addresses) < 3 {
		log.Fatal("at least three -backend URLs are required")
	}
	proxies := make([]*httputil.ReverseProxy, 0, len(addresses))
	for _, raw := range addresses {
		target, err := url.Parse(raw)
		if err != nil || target.Scheme != "http" || target.Host == "" {
			log.Fatalf("invalid backend URL %q", raw)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("backend proxy: %v", err)
			http.Error(w, "load balancer backend unavailable", http.StatusBadGateway)
		}
		proxies = append(proxies, proxy)
	}
	var next atomic.Uint64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := next.Add(1) - 1
		proxies[index%uint64(len(proxies))].ServeHTTP(w, r)
	})
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("load balancer: %v", err)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
