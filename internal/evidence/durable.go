// Package evidence (durable extension) provides a file-backed Store for
// restart safety (BETA-09). The durable store holds evidence in memory and
// writes gob-encoded snapshots to disk atomically (temp file + rename) on a
// background flush interval and on Close.
//
// It satisfies the same Store contract as memoryStore: atomic append (all or
// nothing), dedup by EvidenceId, consistent expiration semantics.
package evidence

import (
	"bytes"
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
	mu       sync.Mutex
	cfg      DurableConfig
	data     map[string][]Evidence // "scope/id" -> evidence items
	pending  int
	done     chan struct{}
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

// Append implements Store.Append with atomic all-or-nothing semantics.
// The ENTIRE batch is preflighted before any mutation: if any item is
// structurally invalid, is rejected as a duplicate, or would push a subject
// over maxEvidencePerSubject, the whole batch is rejected and no in-memory
// state or pending-flush count changes (P0.9A/P0.9B).
func (d *durableStore) Append(items ...Evidence) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 1) Structural validation for the WHOLE batch (P0.9B). No mutation yet.
	for _, ev := range items {
		if err := validate(ev); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidEvidence, err)
		}
	}

	// 2) Preflight projected per-subject counts. projected[k] is the number of
	//    items subject k would hold AFTER this batch. Within-batch duplicates
	//    are tracked per (subject, EvidenceID) so the projected count exactly
	//    matches what the mutation phase will append for each subject: an ID
	//    intended for a different subject can never under-count a near-cap
	//    subject and silently let it overflow.
	projected := make(map[string]int, len(d.data))
	for k, v := range d.data {
		projected[k] = len(v)
	}
	seen := make(map[string]struct{}) // "subjectKey/EvidenceID"
	for _, ev := range items {
		k := subjectKey(SubjectKey{Scope: ev.Scope, ID: ev.SubjectID})
		dedupKey := k + "/" + ev.EvidenceID
		if _, dup := seen[dedupKey]; dup {
			continue // this ID already counted for this subject in this batch
		}
		if d.hasIDLocked(k, ev.EvidenceID) {
			continue // already stored for this subject (idempotent append)
		}
		seen[dedupKey] = struct{}{}
		// Durable store bounds a subject by a hard cap (no eviction path), so
		// overshoot must reject the whole batch atomically.
		if projected[k]+1 > maxEvidencePerSubject {
			return fmt.Errorf("evidence: per-subject cap reached for %s", k)
		}
		projected[k]++
	}

	// 3) All checks passed — apply the whole batch.
	for _, ev := range items {
		k := subjectKey(SubjectKey{Scope: ev.Scope, ID: ev.SubjectID})
		if d.hasIDLocked(k, ev.EvidenceID) {
			continue // already stored (covers items appended earlier this batch)
		}
		d.data[k] = append(d.data[k], ev)
		d.pending++
	}
	return nil
}

// hasIDLocked reports whether a subject key already holds an EvidenceID.
// Caller must hold d.mu.
func (d *durableStore) hasIDLocked(k string, id string) bool {
	for i := range d.data[k] {
		if d.data[k][i].EvidenceID == id {
			return true
		}
	}
	return false
}

// Snapshot implements Store.Snapshot with consistent expiration semantics.
func (d *durableStore) Snapshot(subjects []SubjectKey, now time.Time) ([]Evidence, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var out []Evidence
	for _, sk := range subjects {
		k := subjectKey(sk)
		for _, ev := range d.data[k] {
			// P0.9 fix: match memoryStore expiration semantics exactly.
			// Expired when now >= ExpiresAt (not ExpiresAt.Before(now)).
			if !ev.ExpiresAt.IsZero() && !ev.ExpiresAt.After(now) {
				continue
			}
			out = append(out, ev)
		}
	}
	return out, nil
}

// Prune implements Store.Prune with consistent expiration semantics.
func (d *durableStore) Prune(subjects []SubjectKey, now time.Time) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	pruned := 0
	for _, sk := range subjects {
		k := subjectKey(sk)
		var kept []Evidence
		for _, ev := range d.data[k] {
			if !ev.ExpiresAt.IsZero() && !ev.ExpiresAt.After(now) {
				pruned++
				continue
			}
			kept = append(kept, ev)
		}
		if len(kept) == 0 {
			delete(d.data, k)
		} else {
			d.data[k] = kept
		}
	}
	return pruned, nil
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
