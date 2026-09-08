// Package evidence (durable extension) provides the LEGACY Gob compatibility
// Store. It holds evidence in memory and writes gob-encoded snapshots to disk
// atomically (temp file + rename) on a background flush interval and on Close.
// Production deployments use internal/statebolt as the single transactional
// authority; this backend is retained only for explicitly ephemeral or legacy
// compatibility use.
//
// It satisfies the same Store contract as memoryStore: atomic append (all or
// nothing), dedup by EvidenceId, consistent expiration semantics.
package evidence

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func init() {
	gob.Register(Evidence{})
}

// DurableConfig configures a durable evidence store.
type DurableConfig struct {
	Path          string
	FlushInterval time.Duration
}

type durableStore struct {
	mu        sync.Mutex
	cfg       DurableConfig
	data      map[string][]Evidence // "scope/id" -> evidence items
	pending   int
	done      chan struct{}
	lastFlush error // last flush error (for diagnostics)
}

func NewDurableStore(cfg DurableConfig) (Store, func() error, error) {
	if cfg.Path == "" {
		return nil, nil, errors.New("evidence durable: path required")
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}

	if dir := filepath.Dir(cfg.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, nil, err
		}
	}

	ds := &durableStore{
		cfg:  cfg,
		data: make(map[string][]Evidence),
		done: make(chan struct{}),
	}

	_, statErr := os.Stat(cfg.Path)
	switch {
	case statErr == nil:
		// File exists: recover prior state.
		if err := ds.loadLocked(); err != nil {
			return nil, nil, err
		}
	case errors.Is(statErr, os.ErrNotExist):
		// File genuinely absent: start empty rather than treating a real
		// failure as absence.
	default:
		// Any other stat failure (permissions, ENOTDIR from a path rooted in
		// a file, etc.) must be surfaced, never silently treated as "no file".
		return nil, nil, statErr
	}

	go ds.flushLoop()

	return ds, func() error { return ds.close() }, nil
}

// Append implements Store.Append with atomic all-or-nothing semantics and the
// same merge/expiry/dedup/priority-compaction contract as the memory and Bolt
// stores. The legacy Gob backend remains only for ephemeral compatibility.
func (d *durableStore) Append(items ...Evidence) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 1) Structural validation for the WHOLE batch (P0.9B). No mutation yet.
	for _, ev := range items {
		if err := validate(ev); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidEvidence, err)
		}
	}

	bySubject := make(map[string][]Evidence)
	for _, ev := range items {
		k := subjectKey(SubjectKey{Scope: ev.Scope, ID: ev.SubjectID})
		bySubject[k] = append(bySubject[k], ev)
	}
	for k, incoming := range bySubject {
		merged := MergeSubject(d.data[k], incoming, time.Now())
		if len(merged) == 0 {
			delete(d.data, k)
		} else {
			d.data[k] = merged
		}
		d.pending++
	}
	return nil
}

func (d *durableStore) AppendContext(ctx context.Context, items ...Evidence) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	return d.Append(items...)
}

// Snapshot implements Store.Snapshot with the same evaluation semantics as
// the memory and Bolt stores, including rejecting future-created evidence.
func (d *durableStore) Snapshot(subjects []SubjectKey, now time.Time) ([]Evidence, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []Evidence
	for _, sk := range subjects {
		k := subjectKey(sk)
		for _, ev := range d.data[k] {
			if ev.Valid(now) {
				out = append(out, ev)
			}
		}
	}
	return out, nil
}

func (d *durableStore) SnapshotContext(ctx context.Context, subjects []SubjectKey, now time.Time) ([]Evidence, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	return d.Snapshot(subjects, now)
}

// Prune implements Store.Prune with the same evaluation semantics as the
// memory and Bolt stores.
func (d *durableStore) Prune(subjects []SubjectKey, now time.Time) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	pruned := 0
	for _, sk := range subjects {
		k := subjectKey(sk)
		var kept []Evidence
		changed := false
		for _, ev := range d.data[k] {
			if ev.Valid(now) {
				kept = append(kept, ev)
			} else {
				pruned++
				changed = true
			}
		}
		if len(kept) == 0 {
			if _, exists := d.data[k]; exists {
				delete(d.data, k)
				changed = true
			}
		} else {
			d.data[k] = kept
		}
		if changed {
			// Pruning is a durable mutation too. Without marking it pending,
			// a process that prunes and immediately restarts resurrects rows
			// that were already reported as removed.
			d.pending++
		}
	}
	return pruned, nil
}

func (d *durableStore) PruneContext(ctx context.Context, subjects []SubjectKey, now time.Time) (int, error) {
	if err := contextErr(ctx); err != nil {
		return 0, err
	}
	return d.Prune(subjects, now)
}

func (d *durableStore) flushLoop() {
	ticker := time.NewTicker(d.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.mu.Lock()
			if d.pending > 0 {
				// P0.9D: On flush failure, keep pending non-zero so the next
				// tick retries. Only clear pending on success.
				if err := d.flushLocked(); err != nil {
					d.lastFlush = err
				} else {
					d.pending = 0
					d.lastFlush = nil
				}
			}
			d.mu.Unlock()
		case <-d.done:
			return
		}
	}
}

// flushLocked writes the current in-memory state to disk atomically.
// Caller must hold d.mu.
func (d *durableStore) flushLocked() error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(d.data); err != nil {
		return err
	}
	tmp := d.cfg.Path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, d.cfg.Path)
}

func (d *durableStore) loadLocked() error {
	data, err := os.ReadFile(d.cfg.Path)
	if err != nil {
		return err
	}
	var items map[string][]Evidence
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&items); err != nil {
		return err
	}
	if len(items) > 0 {
		d.data = items
	}
	return nil
}

func (d *durableStore) close() error {
	close(d.done)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending > 0 {
		d.lastFlush = d.flushLocked()
	}
	return d.lastFlush
}
