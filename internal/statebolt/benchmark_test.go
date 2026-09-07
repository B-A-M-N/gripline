package statebolt

import (
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
)

// BenchmarkDurableCredentialLookup measures the bbolt-backed authentication
// lookup used by the persistent runtime. The in-memory terminator benchmark is
// useful for algorithmic regressions, but this one keeps durable I/O visible.
func BenchmarkDurableCredentialLookup(b *testing.B) {
	store, err := Open(b.TempDir()+"/state.db", Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	verifier := []byte("durable-benchmark-verifier-32-bytes!!")
	if err := store.Insert(&credential.CredentialRecord{
		CredentialID: "durable-benchmark", AccountID: "benchmark-account",
		Verifier: verifier, VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "gripline-default-v1", PlanID: "benchmark-plan",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec, ok := store.FindByVerifier(verifier, 1)
		if !ok || rec == nil {
			b.Fatal("durable credential lookup failed")
		}
	}
}
