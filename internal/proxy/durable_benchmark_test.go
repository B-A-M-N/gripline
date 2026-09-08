package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/anomaly"
	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/producers"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/statebolt"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

type durablePath struct {
	dp      *DataPlane
	state   *statebolt.Store
	backend *httptest.Server
	secret  string
}

func newDurablePath(t testing.TB) *durablePath {
	t.Helper()
	state, err := statebolt.Open(t.TempDir()+"/state.db", statebolt.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	pepper := &credential.PepperKey{Version: 1, Key: []byte("durable-path-benchmark-pepper-32!")}
	raw := "sk-durable-benchmark-secret"
	if err := state.Insert(&credential.CredentialRecord{
		CredentialID: "durable-bench", AccountID: "durable-account", PolicyID: policy.DefaultPolicyID,
		PlanID: "durable-plan", Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pepper),
		VerifierVersion: 1, PepperVersion: 1, Status: credential.StatusNormal,
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, err := terminator.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	pol := policy.Default()
	// Keep the benchmark focused on durable-path cost rather than exhausting
	// the example policy's intentionally small request window.
	pol.Limits.Normal.Requests = policy.BucketConfig{Capacity: 100000, RefillPer: 100000, RefillIn: time.Second}
	pol.Limits.Constrained.Requests = pol.Limits.Normal.Requests
	producersList := []producers.Producer{
		producers.NewSourceNoveltyProducer(time.Now),
		producers.NewResourceVelocityProducer(time.Now),
		producers.NewEnumerationProducer(time.Now),
	}
	for i, name := range []string{"source_novelty", "resource_velocity", "enumeration"} {
		snapshot := producersList[i].(producers.StateSnapshotter)
		persistent, err := producers.NewPersistentProducer(producersList[i], snapshot, state, name)
		if err != nil {
			t.Fatal(err)
		}
		producersList[i] = persistent
	}
	spray, err := anomaly.NewPersistentDetector(time.Now, anomaly.DefaultThresholds(), state, "spray")
	if err != nil {
		t.Fatal(err)
	}
	term, err := terminator.New(terminator.Dependencies{
		Registry: state, Peppers: credential.MustPepperRing(pepper), Lanes: state,
		Policy: pol, Signer: signer, Audience: "durable-benchmark", Evidence: state,
		Resource: resource.NewGovernor(nil), Mode: terminator.ModeEnforce,
		Spray: spray, Producers: producersList,
	})
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(backend.Close)
	backendURL, _ := url.Parse(backend.URL)
	dp, err := New(Config{Terminator: term, BackendURL: backendURL, Audience: "durable-benchmark", MaxBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return &durablePath{dp: dp, state: state, backend: backend, secret: raw}
}

func (p *durablePath) request(t testing.TB) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", bytes.NewReader([]byte(`{"prompt":"durable"}`)))
	req.Header.Set("Authorization", "Bearer "+p.secret)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.dp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("durable path status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// BenchmarkDurableProxyPath exercises bbolt-backed credentials, lanes,
// evidence, producer checkpoints, the real HTTP transport hop, assertion
// issuance, and response streaming. It is intentionally separate from the
// in-memory terminator benchmark.
func BenchmarkDurableProxyPath(b *testing.B) {
	p := newDurablePath(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "http://gateway/v1/chat/completions", bytes.NewReader([]byte(`{"prompt":"durable"}`)))
		req.Header.Set("Authorization", "Bearer "+p.secret)
		rec := httptest.NewRecorder()
		p.dp.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("durable path status=%d", rec.Code)
		}
	}
}

// TestDurableProxyPathPercentiles publishes p50/p95/p99 latency from the
// actual durable path in CI logs. The test uses a conservative failure bound;
// deployers should record these values on their production hardware.
func TestDurableProxyPathPercentiles(t *testing.T) {
	if testing.Short() {
		t.Skip("durable benchmark skipped in -short")
	}
	p := newDurablePath(t)
	const samples = 200
	durations := make([]time.Duration, 0, samples)
	var total time.Duration
	for i := 0; i < samples; i++ {
		start := time.Now()
		p.request(t)
		d := time.Since(start)
		durations = append(durations, d)
		total += d
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p50 := durations[samples/2]
	p95 := durations[samples*95/100]
	p99 := durations[samples*99/100]
	t.Logf("durable proxy path p50=%s p95=%s p99=%s throughput=%0.1f req/s", p50, p95, p99, float64(samples)/total.Seconds())
	if p99 > 2*time.Second {
		t.Fatalf("durable proxy p99=%s exceeds regression bound", p99)
	}
}
