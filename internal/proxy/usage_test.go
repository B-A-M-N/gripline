package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// scriptedUsage is a UsageProvider returning canned estimate/actual values,
// recording the response headers Begin saw and the chunks its session metered.
type scriptedUsage struct {
	est        resource.UsageEstimate
	actual     resource.UsageEstimate
	mu         sync.Mutex
	gotResps   []*http.Response
	gotChunks  [][]byte
	finishErrs []error
}

func (s *scriptedUsage) Estimate(Observation) resource.UsageEstimate { return s.est }

func (s *scriptedUsage) Begin(_ Observation, resp *http.Response) UsageSession {
	s.mu.Lock()
	s.gotResps = append(s.gotResps, resp)
	s.mu.Unlock()
	return &scriptedSession{u: s, actual: s.actual}
}

type scriptedSession struct {
	u      *scriptedUsage
	actual resource.UsageEstimate
}

func (ss *scriptedSession) ObserveChunk(chunk []byte) {
	ss.u.mu.Lock()
	c := make([]byte, len(chunk))
	copy(c, chunk)
	ss.u.gotChunks = append(ss.u.gotChunks, c)
	ss.u.mu.Unlock()
}

func (ss *scriptedSession) Finish(err error) resource.UsageEstimate {
	ss.u.mu.Lock()
	ss.u.finishErrs = append(ss.u.finishErrs, err)
	ss.u.mu.Unlock()
	return ss.actual
}

// P0.3 end-to-end at the proxy: the estimator's Estimate is reserved at
// admission; after the backend responds, the reservation is settled with the
// estimator's Actual — the unused remainder returns to the gauge; on a
// transport error the full hold is cancelled (never settled).
func TestDataPlaneSettlesReservationWithActualUsage(t *testing.T) {
	var requestCount int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("X-Usage-Input-Tokens", "10")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	bu, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	pol := policy.Default()
	// Burst-only token gauge for exact float accounting.
	pol.Limits.Normal.Tokens = policy.BucketConfig{Capacity: 100}

	pep := &credential.PepperKey{Version: 1, Key: []byte("proxy-usage")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('p' + i%26)
	}
	raw := "sk-pu-" + string(rawBytes)
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_pu", AccountID: "acct_pu",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	signer, _ := terminator.GenerateSigner()
	gov := resource.NewGovernor(nil)
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: pol, Signer: signer,
		Audience: "fi-inference", Evidence: evidence.NewMemoryStore(),
		Resource: gov,
	})
	if err != nil {
		t.Fatal(err)
	}

	usage := &scriptedUsage{
		est:    resource.UsageEstimate{Requests: 1, CombinedTokens: 50},
		actual: resource.UsageEstimate{Requests: 1, CombinedTokens: 10},
	}
	dp, err := New(Config{
		Terminator: term, BackendURL: bu, Audience: "fi-inference", Usage: usage,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("proxy must succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(usage.gotResps) != 1 {
		t.Fatalf("Begin must see the backend response once, saw %d", len(usage.gotResps))
	}
	usage.mu.Lock()
	chunks, finishErrs := len(usage.gotChunks), len(usage.finishErrs)
	sawPayload := false
	for _, c := range usage.gotChunks {
		if strings.Contains(string(c), `"ok":true`) {
			sawPayload = true
		}
	}
	var finishErr error
	if finishErrs == 1 {
		finishErr = usage.finishErrs[0]
	}
	usage.mu.Unlock()
	if chunks == 0 {
		t.Fatal("metering session must observe the streamed body chunks")
	}
	if !sawPayload {
		t.Fatal("metering session must see the final usage-bearing payload chunk")
	}
	if finishErrs != 1 || finishErr != nil {
		t.Fatalf("Finish must be called exactly once with nil stream error, got n=%d err=%v", finishErrs, finishErr)
	}

	// Actual usage was charged: 100 - 10 = 90 available (est 50 was refunded).
	avail, ok := gov.AvailableFor(resource.DimCombinedTokens, resource.ScopeCredential, "cred_pu")
	if !ok {
		t.Fatal("token gauge must exist")
	}
	if avail != 90 {
		t.Fatalf("P0.3: settle(actual 10) must leave 90, got %v", avail)
	}

	// Transport failure: no settle → deferred Release cancels the full hold.
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	fail.Close()                              // closed server guarantees a transport error
	fbu, _ := url.Parse("http://127.0.0.1:1") // nothing listens
	_ = fail
	dpFail, err := New(Config{
		Terminator: term, BackendURL: fbu, Audience: "fi-inference", Usage: usage,
		Transport: &http.Transport{}, // fresh transport, immediate dial error
	})
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{"x":1}`))
	req2.Header.Set("Authorization", "Bearer "+raw)
	rec2 := httptest.NewRecorder()
	dpFail.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusBadGateway {
		t.Fatalf("dead backend must map to 502, got %d", rec2.Code)
	}
	avail2, _ := gov.AvailableFor(resource.DimCombinedTokens, resource.ScopeCredential, "cred_pu")
	if avail2 != 90 {
		t.Fatalf("P0.36: failed request must refund its full estimate hold; avail = %v, want 90", avail2)
	}
	_ = requestCount
}
