// Command gripline-test-http2 exercises cancellation on a real TLS/HTTP/2
// connection. It is intentionally small: the qualification harness owns the
// server and backend, while this client creates independent streams, cancels
// them, and proves that a subsequent request still succeeds.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	endpoint := flag.String("url", "", "HTTPS endpoint")
	caPath := flag.String("ca", "", "CA PEM path")
	bearer := flag.String("bearer", "", "gateway bearer")
	count := flag.Int("count", 32, "number of canceled streams")
	streamTimeout := flag.Duration("stream-timeout", 25*time.Millisecond, "per-stream cancellation deadline")
	backendDelay := flag.Duration("backend-delay", 250*time.Millisecond, "qualification backend delay")
	flag.Parse()
	if *endpoint == "" || *caPath == "" || *bearer == "" || *count < 1 || *streamTimeout <= 0 || *backendDelay <= 0 {
		fatal("-url, -ca, -bearer, positive -count, and positive durations are required")
	}
	u, err := url.Parse(*endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		fatal("invalid HTTPS endpoint")
	}
	caBytes, err := os.ReadFile(*caPath)
	if err != nil {
		fatal("read CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		fatal("parse CA certificate")
	}
	transport := &http2.Transport{TLSClientConfig: &tls.Config{ // #nosec G402 -- qualification CA and endpoint are explicit local inputs.
		RootCAs:    roots,
		ServerName: u.Hostname(),
		MinVersion: tls.VersionTLS12,
	}}
	client := &http.Client{Transport: transport}
	payload := []byte(`{"model":"local-qualification-cancel","prompt":"http2-cancellation-qualification"}`)
	var canceled atomic.Int64
	var unexpected atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < *count; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), *streamTimeout)
			defer cancel()
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
			if reqErr != nil {
				unexpected.Add(1)
				return
			}
			req.Header.Set("Authorization", "Bearer "+*bearer)
			req.Header.Set("Content-Type", "application/json")
			resp, doErr := client.Do(req)
			if doErr != nil {
				if ctx.Err() != nil {
					canceled.Add(1)
					return
				}
				unexpected.Add(1)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				// A very fast or already-buffered response is valid, but it is not
				// evidence of cancellation. Count it separately for diagnostics.
				return
			}
			unexpected.Add(1)
		}(i)
	}
	wg.Wait()
	if unexpected.Load() != 0 || canceled.Load() == 0 {
		fatal("canceled streams=%d unexpected=%d", canceled.Load(), unexpected.Load())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	recoveryPayload := []byte(`{"model":"local-qualification-recovery","prompt":"http2-recovery-qualification"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(recoveryPayload))
	if err != nil {
		fatal("build recovery request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+*bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fatal("recovery request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fatal("recovery request status=%d", resp.StatusCode)
	}
	fmt.Printf("http2 cancellation qualification: canceled=%d recovery_status=%d\n", canceled.Load(), resp.StatusCode)
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "http2 qualification client: "+format+"\n", args...)
	os.Exit(1)
}
