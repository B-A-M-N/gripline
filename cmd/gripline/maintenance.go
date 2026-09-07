package main

import (
	"log"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/statebolt"
)

// startStateMaintenance runs bounded global evidence cleanup for the durable
// single-node authority. The loop is stopped and joined before the database is
// closed, so a shutdown cannot race a bbolt transaction.
func startStateMaintenance(state *statebolt.Store) func() error {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := state.SweepExpiredEvidence(time.Now(), 256); err != nil {
					log.Printf("gripline: evidence sweep: %v", err)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() error {
		close(stop)
		wg.Wait()
		return nil
	}
}
