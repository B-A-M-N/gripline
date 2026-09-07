package proxy

import (
	"errors"
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
	"github.com/B-A-M-N/gripline/internal/producers"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

// stubCompletionProducer emits one fixed completion signal so the observer test
// can drive evidence minting deterministically (no velocity-baseline tuning).
type stubCompletionProducer struct{}

func (stubCompletionProducer) ObserveAdmission(producers.AdmissionBehavior) []producers.Signal {
	return nil
}

func (stubCompletionProducer) ObserveCompletion(producers.CompletionBehavior) []producers.Signal {
	return []producers.Signal{{Code: "TOKEN_VELOCITY_OVER_4X_BASELINE"}}
}

// failingEvidenceStore is an evidence.Store whose Append always fails, so
// completion persistence takes the error path.
type failingEvidenceStore struct {
	inner evidence.Store
}

func (f *failingEvidenceStore) Append(items ...evidence.Evidence) error {
	return errors.New("evidence store unavailable")
}
func (f *failingEvidenceStore) Snapshot(s []evidence.SubjectKey, n time.Time) ([]evidence.Evidence, error) {
	return f.inner.Snapshot(s, n)
}
func (f *failingEvidenceStore) Prune(s []evidence.SubjectKey, n time.Time) (int, error) {
	return f.inner.Prune(s, n)
}

// recordingObserver captures CompletionEvents.
type recordingObserver struct {
	mu    sync.Mutex
	event CompletionEvent
	got   bool
}

func (r *recordingObserver) ObserveCompletion(ev CompletionEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.event, r.got = ev, true
}

func (r *recordingObserver) snapshot() (CompletionEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.event, r.got
}

// P0.9: the proxy must not silently discard the Outcome.Complete result. When
// completion evidence cannot be persisted, the configured DecisionObserver sees
// the failure (codes, Persisted=false, Err) while the client response is
// unchanged.
func TestObserverSeesCompletionPersistenceFailure(t *testing.T) {
	pep := &credential.PepperKey{Version: 1, Key: []byte("obs-pepper")}
	rawBytes := make([]byte, 32)
	for i := range rawBytes {
		rawBytes[i] = byte('o' + i%26)
	}
	raw := "sk-obs-" + string(rawBytes)
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "cred_obs", AccountID: "acct_obs",
		Verifier: credential.Verifier(secret.NewFromBytes([]byte(raw)), pep), VerifierVersion: 1, PepperVersion: 1,
		Status: credential.StatusNormal, PolicyID: "fi-default-v1", PlanID: "plan-a",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	bu, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	memEvidence := evidence.NewMemoryStore()
	signer, _ := terminator.GenerateSigner()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: policy.Default(), Signer: signer,
		Audience: testAudience, Evidence: &failingEvidenceStore{inner: memEvidence},
		Resource: resource.NewGovernor(nil),
		Producers: []producers.Producer{
			stubCompletionProducer{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	obs := &recordingObserver{}
	dp, err := New(Config{
		Terminator: term, BackendURL: bu, Audience: testAudience, Observer: obs,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	dp.ServeHTTP(rec, req)

	// The CLIENT response is unaffected: 200 with the backend body.
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("observer failure must not change the delivered response, got %d %q", rec.Code, rec.Body.String())
	}

	ev, got := obs.snapshot()
	if !got {
		t.Fatal("DecisionObserver must see the completion event")
	}
	if len(ev.EvidenceCodes) != 1 || ev.EvidenceCodes[0] != "TOKEN_VELOCITY_OVER_4X_BASELINE" {
		t.Fatalf("event must carry the minted code, got %v", ev.EvidenceCodes)
	}
	if ev.Persisted {
		t.Fatal("Persisted must be false when the append fails")
	}
	if ev.Err == nil {
		t.Fatal("event must carry the persistence error")
	}
	if ev.StreamOK != true {
		t.Fatal("StreamOK must be true for a clean stream")
	}

	// Healthy path: with a working store, the observer sees Persisted=true, nil Err.
	term2, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pep),
		Lanes: lane.NewStore(nil, time.Now), Policy: policy.Default(), Signer: signer,
		Audience: testAudience, Evidence: memEvidence,
		Resource: resource.NewGovernor(nil),
		Producers: []producers.Producer{
			stubCompletionProducer{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs2 := &recordingObserver{}
	dp2, err := New(Config{Terminator: term2, BackendURL: bu, Audience: testAudience, Observer: obs2})
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest("POST", "http://gripline.local/v1/messages", strings.NewReader(`{"x":1}`))
	req2.Header.Set("Authorization", "Bearer "+raw)
	dp2.ServeHTTP(httptest.NewRecorder(), req2)
	ev2, got2 := obs2.snapshot()
	if !got2 {
		t.Fatal("observer must fire on the healthy path too")
	}
	if !ev2.Persisted || ev2.Err != nil {
		t.Fatalf("healthy path: Persisted=true, Err=nil, got %v %v", ev2.Persisted, ev2.Err)
	}
}
