package proxy

import (
	"errors"
	"sync"
)

// ErrSpoolBudgetExhausted distinguishes aggregate spool saturation from a
// malformed request or an unavailable filesystem.
var ErrSpoolBudgetExhausted = errors.New("proxy: aggregate spool budget exhausted")

// SpoolBudget is a process-wide weighted budget for admitted unknown-length
// bodies. It reserves the configured per-request maximum before reading starts,
// preventing many concurrent streams from multiplying the body cap into an
// unbounded disk or memory claim.
type SpoolBudget struct {
	mu       sync.Mutex
	maxBytes int64
	maxFiles int
	bytes    int64
	files    int
}

// NewSpoolBudget creates an aggregate spool budget. A zero bound is unlimited
// for that dimension; the per-request body limit remains independently active.
func NewSpoolBudget(maxBytes int64, maxFiles int) *SpoolBudget {
	if maxBytes < 0 {
		maxBytes = 0
	}
	if maxFiles < 0 {
		maxFiles = 0
	}
	return &SpoolBudget{maxBytes: maxBytes, maxFiles: maxFiles}
}

// SpoolReservation owns one aggregate body reservation and releases it once.
type SpoolReservation struct {
	budget *SpoolBudget
	bytes  int64
	once   sync.Once
}

// Acquire reserves bytes and one in-flight spool. Callers must release the
// returned handle through spooledBody.Close or Release on an error path.
func (b *SpoolBudget) Acquire(bytes int64) (*SpoolReservation, error) {
	if b == nil {
		return nil, nil
	}
	if bytes < 0 {
		bytes = 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxBytes > 0 && (bytes > b.maxBytes || b.bytes > b.maxBytes-bytes) {
		return nil, ErrSpoolBudgetExhausted
	}
	if b.maxFiles > 0 && b.files >= b.maxFiles {
		return nil, ErrSpoolBudgetExhausted
	}
	b.bytes += bytes
	b.files++
	return &SpoolReservation{budget: b, bytes: bytes}, nil
}

// Release returns this reservation to its budget. It is safe to call more than
// once, including when an upstream body and an explicit error path both close.
func (r *SpoolReservation) Release() {
	if r == nil || r.budget == nil {
		return
	}
	r.once.Do(func() {
		r.budget.mu.Lock()
		if r.budget.bytes >= r.bytes {
			r.budget.bytes -= r.bytes
		} else {
			r.budget.bytes = 0
		}
		if r.budget.files > 0 {
			r.budget.files--
		}
		r.budget.mu.Unlock()
	})
}

// SpoolStats reports current aggregate utilization for operational checks.
type SpoolStats struct {
	Bytes    int64
	Files    int
	MaxBytes int64
	MaxFiles int
}

func (b *SpoolBudget) Stats() SpoolStats {
	if b == nil {
		return SpoolStats{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return SpoolStats{Bytes: b.bytes, Files: b.files, MaxBytes: b.maxBytes, MaxFiles: b.maxFiles}
}
