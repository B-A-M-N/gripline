// Command gripline-test-load drives a persistent HTTP client pool for the
// repository-owned capacity qualification lab. It intentionally reports only
// bounded, aggregate measurements; request bodies and credentials never enter
// the result.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxLatencySamples = 100_000
const maxLoadResponseDrain = 1 << 20

type percentileSet struct {
	P50Milliseconds float64 `json:"p50_ms"`
	P95Milliseconds float64 `json:"p95_ms"`
	P99Milliseconds float64 `json:"p99_ms"`
}

// failureSample is deliberately limited to status/protocol metadata. It is
// diagnostic qualification evidence, not a request/response capture, so no
// body or credential material enters the result.
type failureSample struct {
	Status    int    `json:"status"`
	Reason    string `json:"gripline_reason,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

type result struct {
	DurationSeconds float64          `json:"duration_seconds"`
	Workers         int              `json:"workers"`
	Total           int64            `json:"total"`
	Successful      int64            `json:"successful"`
	TotalRPS        float64          `json:"total_rps"`
	SuccessfulRPS   float64          `json:"successful_rps"`
	SuccessRatio    float64          `json:"success_ratio"`
	StatusCounts    map[string]int64 `json:"status_counts"`
	Latency         struct {
		All        percentileSet `json:"all"`
		Successful percentileSet `json:"successful"`
	} `json:"latency"`
	// Keep the original top-level fields for consumers of the first fixture
	// format. They describe all completed attempts; the structured latency
	// object above is authoritative for new qualification gates.
	P50Milliseconds float64         `json:"p50_ms"`
	P95Milliseconds float64         `json:"p95_ms"`
	P99Milliseconds float64         `json:"p99_ms"`
	FailureSamples  []failureSample `json:"failure_samples,omitempty"`
}

type samples struct {
	mu                  sync.Mutex
	counts              map[string]int64
	latencies           []int64
	successfulLatencies []int64
	seen                int64
	successfulSeen      int64
	rng                 *rand.Rand
}

func (s *samples) record(status string, latency int64, successful bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[status]++
	s.seen++
	if len(s.latencies) < maxLatencySamples {
		s.latencies = append(s.latencies, latency)
	} else {
		index := s.rng.Int63n(s.seen)
		if index < maxLatencySamples {
			s.latencies[index] = latency
		}
	}
	if !successful {
		return
	}
	s.successfulSeen++
	if len(s.successfulLatencies) < maxLatencySamples {
		s.successfulLatencies = append(s.successfulLatencies, latency)
		return
	}
	index := s.rng.Int63n(s.successfulSeen)
	if index < maxLatencySamples {
		s.successfulLatencies[index] = latency
	}
}

func percentile(values []int64, percent int) float64 {
	if len(values) == 0 {
		return 0
	}
	index := (len(values)*percent + 99) / 100
	if index < 1 {
		index = 1
	}
	if index > len(values) {
		index = len(values)
	}
	return float64(values[index-1]) / float64(time.Millisecond)
}

func main() {
	url := flag.String("url", "", "qualified data-plane URL")
	secret := flag.String("secret", "", "disposable bearer credential")
	secrets := flag.String("secrets", "", "comma-separated disposable bearer credentials to distribute across workers")
	duration := flag.Duration("duration", 30*time.Second, "load duration")
	workers := flag.Int("workers", 16, "concurrent persistent clients")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	userAgent := flag.String("user-agent", "", "optional deterministic User-Agent header")
	localAddressPrefix := flag.String("local-address-prefix", "", "optional IPv4 prefix for per-worker source addresses, for example 127.0.0.")
	forwardedForPrefix := flag.String("forwarded-for-prefix", "", "optional trusted X-Forwarded-For IPv4 prefix per worker, for example 11.0.0.")
	flag.Parse()
	credentials := []string{*secret}
	if *secrets != "" {
		credentials = strings.Split(*secrets, ",")
	}
	for _, credential := range credentials {
		if credential == "" {
			fatal("credentials must not contain empty values")
		}
	}
	if *url == "" || len(credentials) == 0 || *duration <= 0 || *workers <= 0 || *timeout <= 0 {
		fatal("url, secret, duration, workers, and timeout must be valid")
	}

	clients := make([]*http.Client, *workers)
	transports := make([]*http.Transport, *workers)
	for worker := 0; worker < *workers; worker++ {
		localAddress := ""
		if *localAddressPrefix != "" {
			localAddress = fmt.Sprintf("%s%d", *localAddressPrefix, worker+2)
			parsed := net.ParseIP(localAddress)
			if parsed == nil || parsed.To4() == nil {
				fatal("local-address-prefix must produce valid IPv4 addresses; worker %d produced %q", worker, localAddress)
			}
		}
		transport := newLoadTransport(*workers, *timeout, localAddress)
		transports[worker] = transport
		clients[worker] = &http.Client{Transport: transport}
	}
	defer func() {
		for _, transport := range transports {
			transport.CloseIdleConnections()
		}
	}()

	// #nosec G404 -- deterministic reservoir sampling only; this is never used for security or credential material.
	stats := &samples{counts: make(map[string]int64), rng: rand.New(rand.NewSource(1))}
	var failureMu sync.Mutex
	failureSamples := make([]failureSample, 0, 8)
	deadline := time.Now().Add(*duration)
	var wg sync.WaitGroup
	for worker := 0; worker < *workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			client := clients[worker]
			credential := credentials[worker%len(credentials)]
			for time.Now().Before(deadline) {
				ctx, cancel := context.WithTimeout(context.Background(), *timeout)
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, *url, bytes.NewReader([]byte("{}")))
				if err != nil {
					cancel()
					stats.record("request_error", 0, false)
					continue
				}
				request.Header.Set("Authorization", "Bearer "+credential)
				request.Header.Set("Content-Type", "application/json")
				if *userAgent != "" {
					request.Header.Set("User-Agent", *userAgent)
				}
				if *forwardedForPrefix != "" {
					request.Header.Set("X-Forwarded-For", fmt.Sprintf("%s%d", *forwardedForPrefix, worker+1))
				}
				started := time.Now()
				response, err := client.Do(request)
				latency := time.Since(started).Nanoseconds()
				status := "request_error"
				successful := false
				if err == nil {
					status = fmt.Sprintf("%d", response.StatusCode)
					if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
						failureMu.Lock()
						if len(failureSamples) < cap(failureSamples) {
							failureSamples = append(failureSamples, failureSample{
								Status:    response.StatusCode,
								Reason:    response.Header.Get("X-Gripline-Reason"),
								RequestID: response.Header.Get("X-Gripline-Request-ID"),
							})
						}
						failureMu.Unlock()
					}
					read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxLoadResponseDrain+1))
					closeErr := response.Body.Close()
					if readErr != nil || closeErr != nil || read > maxLoadResponseDrain {
						status = "response_error"
					} else {
						successful = response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices
					}
				}
				cancel()
				stats.record(status, latency, successful)
			}
		}(worker)
	}
	wg.Wait()

	stats.mu.Lock()
	counts := make(map[string]int64, len(stats.counts))
	for status, count := range stats.counts {
		counts[status] = count
	}
	latencies := append([]int64(nil), stats.latencies...)
	successfulLatencies := append([]int64(nil), stats.successfulLatencies...)
	seen := stats.seen
	successfulSeen := stats.successfulSeen
	stats.mu.Unlock()
	failureMu.Lock()
	resultFailures := append([]failureSample(nil), failureSamples...)
	failureMu.Unlock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	sort.Slice(successfulLatencies, func(i, j int) bool { return successfulLatencies[i] < successfulLatencies[j] })
	successful := int64(0)
	for code, count := range counts {
		var statusCode int
		if _, err := fmt.Sscanf(code, "%d", &statusCode); err == nil && statusCode >= http.StatusOK && statusCode < http.StatusMultipleChoices {
			successful += count
		}
	}
	seconds := duration.Seconds()
	output := result{
		DurationSeconds: seconds,
		Workers:         *workers,
		Total:           seen,
		Successful:      successful,
		TotalRPS:        float64(seen) / seconds,
		SuccessfulRPS:   float64(successful) / seconds,
		SuccessRatio:    float64(successful) / float64(seen),
		StatusCounts:    counts,
		P50Milliseconds: percentile(latencies, 50),
		P95Milliseconds: percentile(latencies, 95),
		P99Milliseconds: percentile(latencies, 99),
		FailureSamples:  resultFailures,
	}
	output.Latency.All = percentileSet{
		P50Milliseconds: percentile(latencies, 50),
		P95Milliseconds: percentile(latencies, 95),
		P99Milliseconds: percentile(latencies, 99),
	}
	if successfulSeen > 0 {
		output.Latency.Successful = percentileSet{
			P50Milliseconds: percentile(successfulLatencies, 50),
			P95Milliseconds: percentile(successfulLatencies, 95),
			P99Milliseconds: percentile(successfulLatencies, 99),
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fatal("encode result: %v", err)
	}
}

func newLoadTransport(workers int, timeout time.Duration, localAddress string) *http.Transport {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if localAddress != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localAddress)}
	}
	return &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          workers * 2,
		MaxIdleConnsPerHost:   workers * 2,
		MaxConnsPerHost:       workers * 2,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: time.Second,
		DialContext:           dialer.DialContext,
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "load generator: "+format+"\n", args...)
	os.Exit(2)
}
