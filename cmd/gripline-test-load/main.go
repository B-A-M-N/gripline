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
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxLatencySamples = 100_000

type result struct {
	DurationSeconds float64          `json:"duration_seconds"`
	Workers         int              `json:"workers"`
	Total           int64            `json:"total"`
	Successful      int64            `json:"successful"`
	TotalRPS        float64          `json:"total_rps"`
	SuccessfulRPS   float64          `json:"successful_rps"`
	StatusCounts    map[string]int64 `json:"status_counts"`
	P50Milliseconds float64          `json:"p50_ms"`
	P95Milliseconds float64          `json:"p95_ms"`
	P99Milliseconds float64          `json:"p99_ms"`
}

type samples struct {
	mu        sync.Mutex
	counts    map[string]int64
	latencies []int64
	seen      int64
	rng       *rand.Rand
}

func (s *samples) record(status string, latency int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counts[status]++
	s.seen++
	if len(s.latencies) < maxLatencySamples {
		s.latencies = append(s.latencies, latency)
		return
	}
	index := s.rng.Int63n(s.seen)
	if index < maxLatencySamples {
		s.latencies[index] = latency
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

	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          *workers * 2,
		MaxIdleConnsPerHost:   *workers * 2,
		MaxConnsPerHost:       *workers * 2,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: *timeout,
		TLSHandshakeTimeout:   *timeout,
		ExpectContinueTimeout: time.Second,
	}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()

	stats := &samples{counts: make(map[string]int64), rng: rand.New(rand.NewSource(1))}
	deadline := time.Now().Add(*duration)
	var wg sync.WaitGroup
	for worker := 0; worker < *workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			credential := credentials[worker%len(credentials)]
			for time.Now().Before(deadline) {
				ctx, cancel := context.WithTimeout(context.Background(), *timeout)
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, *url, bytes.NewReader([]byte("{}")))
				if err != nil {
					cancel()
					stats.record("request_error", 0)
					continue
				}
				request.Header.Set("Authorization", "Bearer "+credential)
				request.Header.Set("Content-Type", "application/json")
				started := time.Now()
				response, err := client.Do(request)
				latency := time.Since(started).Nanoseconds()
				status := "request_error"
				if err == nil {
					status = fmt.Sprintf("%d", response.StatusCode)
					response.Body.Close()
				}
				cancel()
				stats.record(status, latency)
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
	seen := stats.seen
	stats.mu.Unlock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	successful := counts["200"]
	seconds := duration.Seconds()
	output := result{
		DurationSeconds: seconds,
		Workers:         *workers,
		Total:           seen,
		Successful:      successful,
		TotalRPS:        float64(seen) / seconds,
		SuccessfulRPS:   float64(successful) / seconds,
		StatusCounts:    counts,
		P50Milliseconds: percentile(latencies, 50),
		P95Milliseconds: percentile(latencies, 95),
		P99Milliseconds: percentile(latencies, 99),
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fatal("encode result: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "load generator: "+format+"\n", args...)
	os.Exit(2)
}
