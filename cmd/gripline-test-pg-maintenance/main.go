// Command gripline-test-pg-maintenance runs one bounded PostgreSQL authority
// maintenance pass and emits sanitized statistics for the qualification lab.
// It opens the serving schema read/write path without migration privileges and
// does not register a membership node, so it is safe to run alongside live
// Gripline nodes as an operator-style maintenance invocation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	"github.com/B-A-M-N/gripline/internal/statepg"
)

type result struct {
	StartedAt   string                   `json:"started_at"`
	FinishedAt  string                   `json:"finished_at"`
	DurationMS  int64                    `json:"duration_ms"`
	Maintenance statepg.MaintenanceStats `json:"maintenance"`
}

func main() {
	dsn := flag.String("dsn", "", "PostgreSQL authority DSN")
	timeout := flag.Duration("timeout", 10*time.Second, "maintenance operation timeout")
	batchSize := flag.Int("batch-size", 256, "maximum rows deleted per maintenance category")
	flag.Parse()
	if *dsn == "" || *timeout <= 0 || *batchSize <= 0 {
		log.Fatal("-dsn, positive -timeout, and positive -batch-size are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	store, err := statepg.Open(ctx, statepg.Options{
		DSN: *dsn, OperationTimeout: *timeout,
		Maintenance: statepg.MaintenanceOptions{BatchSize: *batchSize},
	})
	if err != nil {
		log.Fatalf("open authority: %v", err)
	}
	defer store.Close()
	start := time.Now().UTC()
	stats, err := store.RunMaintenance(ctx)
	if err != nil {
		log.Fatalf("run maintenance: %v", err)
	}
	end := time.Now().UTC()
	if err := json.NewEncoder(os.Stdout).Encode(result{
		StartedAt: start.Format(time.RFC3339Nano), FinishedAt: end.Format(time.RFC3339Nano),
		DurationMS: end.Sub(start).Milliseconds(), Maintenance: stats,
	}); err != nil {
		log.Fatalf("encode maintenance result: %v", err)
	}
}
