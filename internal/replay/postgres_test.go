package replay

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/verify"
)

func TestPostgresReplayGuardParallelAcrossInstances(t *testing.T) {
	dsn := os.Getenv("GRIPLINE_REPLAY_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set GRIPLINE_REPLAY_POSTGRES_DSN for PostgreSQL replay qualification")
	}
	ctx := context.Background()
	first, err := OpenPostgresGuard(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenPostgresGuard(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := first.pool.Exec(ctx, "TRUNCATE TABLE gripline_replay_claims"); err != nil {
		t.Fatal(err)
	}
	claim := verify.ReplayClaim{Issuer: "gripline", Audience: "qualification", JTI: fmt.Sprintf("parallel-%d", time.Now().UnixNano()), ExpiresAt: time.Now().Add(time.Minute)}
	guards := []*PostgresGuard{first, second}
	var wg sync.WaitGroup
	results := make(chan bool, len(guards)*32)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func(guard *PostgresGuard) {
			defer wg.Done()
			accepted, err := guard.Accept(ctx, claim)
			if err != nil {
				t.Errorf("accept: %v", err)
				return
			}
			results <- accepted
		}(guards[i%len(guards)])
	}
	wg.Wait()
	close(results)
	accepted := 0
	for result := range results {
		if result {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted=%d, want exactly one across independent guards", accepted)
	}
}
