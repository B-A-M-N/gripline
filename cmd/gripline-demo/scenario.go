package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/B-A-M-N/gripline/internal/credential"
	"github.com/B-A-M-N/gripline/internal/evidence"
	"github.com/B-A-M-N/gripline/internal/ingress"
	"github.com/B-A-M-N/gripline/internal/lane"
	"github.com/B-A-M-N/gripline/internal/policy"
	"github.com/B-A-M-N/gripline/internal/producers"
	"github.com/B-A-M-N/gripline/internal/proxy"
	"github.com/B-A-M-N/gripline/internal/pseudonym"
	"github.com/B-A-M-N/gripline/internal/resource"
	"github.com/B-A-M-N/gripline/internal/secret"
	"github.com/B-A-M-N/gripline/internal/terminator"
)

const (
	demoAudience = "gripline-demo-backend"
	// This value exists only inside the local demonstration. It is never
	// serialized into the UI, timeline, assertion, evidence, or backend hop.
	demoRawCredential = "demo-reusable-credential-7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c" // #nosec G101 -- intentionally local demo fixture.
)

type Scenario struct {
	mu                sync.Mutex
	baseline          *httptest.Server
	backend           *httptest.Server
	protected         *http.Server
	protectedListener net.Listener
	protectedURL      string
	clients           map[string]*http.Client
	obs               *demoObserver
	baseStats         *baselineStats
	backendStats      *backendStats
	barrier           *demoBarrier
	raw               string
	fingerprint       string
}

// NewScenario builds all authorities once and connects the real data plane to
// them. Calling this is also the RESET operation: a fresh producer, evidence
// store, lane store, credential registry, signer, and backend are created.
func NewScenario() (*Scenario, error) {
	s := &Scenario{clients: make(map[string]*http.Client), raw: demoRawCredential,
		fingerprint: credentialFingerprint(demoRawCredential)}
	if err := s.build(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Scenario) build() error {
	pepper := &credential.PepperKey{Version: 1, Key: []byte("gripline-demo-pepper-material-32-bytes!!")}
	sealed := secret.NewFromBytes([]byte(s.raw))
	verifier := credential.Verifier(sealed, pepper)
	sealed.Zero()
	reg := credential.NewMemoryRegistry()
	if err := reg.Insert(&credential.CredentialRecord{
		CredentialID: "demo-credential", AccountID: "demo-account", Verifier: verifier,
		VerifierVersion: 1, PepperVersion: pepper.Version, Status: credential.StatusNormal,
		PolicyID: "gripline-demo-v1", PlanID: "demo-plan",
		CreatedAt: time.Now().Add(-time.Hour), Revision: 1,
	}); err != nil {
		return fmt.Errorf("credential: %w", err)
	}
	for i := range verifier {
		verifier[i] = 0
	}

	pol := policy.Default()
	pol.ID, pol.Revision = "gripline-demo-v1", 1
	pol.Learning.AllowNewLanes = true
	pol.LaneLimits = lane.DefaultLimits()
	pol.LaneLimits.MaxActiveLanesPerCredential = 8
	// Keep the first location novelty below the lane-suspicion threshold. The
	// coordinated burst then contributes the stock 4x concurrency signal and
	// crosses the block threshold from real producer evidence.
	pol.LaneSecurity = lane.SecurityHysteresis{SuspectThresh: 40, BlockThresh: 40,
		ClearThresh: 10, ClearDwell: time.Minute, SuspectObs: 1, EnableAutomaticBlock: true}

	keyring, err := terminator.NewKeyring()
	if err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	laneStore := lane.NewStore(nil, time.Now)
	evidenceStore := evidence.NewMemoryStore()
	term, err := terminator.New(terminator.Dependencies{
		Registry: reg, Peppers: credential.MustPepperRing(pepper), Lanes: laneStore,
		Policy: pol, Signer: keyring, Audience: demoAudience, Evidence: evidenceStore,
		Resource: resource.NewGovernor(nil), Mode: terminator.ModeEnforce,
		Producers: []producers.Producer{
			producers.NewSourceNoveltyProducer(time.Now),
			producers.NewResourceVelocityProducer(time.Now),
			producers.NewEnumerationProducer(time.Now),
		},
	})
	if err != nil {
		return fmt.Errorf("terminator: %w", err)
	}

	s.obs, s.baseStats, s.backendStats = newDemoObserver(), &baselineStats{}, &backendStats{}
	s.barrier = newDemoBarrier()
	protectedBackend, err := newProtectedBackend(keyring, demoAudience, s.backendStats, s.barrier)
	if err != nil {
		return fmt.Errorf("protected backend verifier: %w", err)
	}
	s.backend = httptest.NewServer(protectedBackend)
	backendURL, _ := url.Parse(s.backend.URL)
	demoRing, err := pseudonym.NewRing(&pseudonym.Key{Version: 1, Secret: []byte("gripline-demo-ingress-key-material-32!!")})
	if err != nil {
		return fmt.Errorf("pseudonyms: %w", err)
	}
	resolver := &ingress.Resolver{Pseudonyms: demoPseudonymAdapter{ring: demoRing}, Networks: demoNetworkMetadata{}}
	dp, err := proxy.New(proxy.Config{Terminator: term, BackendURL: backendURL, Audience: demoAudience,
		Sources: proxy.NewIngressSourceResolver(resolver), Features: proxy.HeaderFeatures{},
		Admission: s.obs, MaxBodyBytes: 1 << 20})
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	s.baseline = httptest.NewServer(newBaselineBackend(s.baseStats, s.raw))
	s.protectedListener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("protected listener: %w", err)
	}
	s.protectedURL = "http://" + s.protectedListener.Addr().String()
	s.protected = &http.Server{
		Handler:           dp,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}
	protectedServer, protectedListener := s.protected, s.protectedListener
	go func() { _ = protectedServer.Serve(protectedListener) }()
	s.clients["legit"], s.clients["attacker"] = demoClient("127.0.0.2"), demoClient("127.0.0.3")
	return nil
}

func (s *Scenario) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.closeLocked() }
func (s *Scenario) closeLocked() error {
	if s.protected != nil {
		_ = s.protected.Close()
		s.protected = nil
	}
	if s.protectedListener != nil {
		_ = s.protectedListener.Close()
		s.protectedListener = nil
	}
	if s.baseline != nil {
		s.baseline.Close()
		s.baseline = nil
	}
	if s.backend != nil {
		s.backend.Close()
		s.backend = nil
	}
	return nil
}
func (s *Scenario) resetLocked() error {
	if err := s.closeLocked(); err != nil {
		return err
	}
	s.clients = make(map[string]*http.Client)
	return s.build()
}
func (s *Scenario) Reset() error { s.mu.Lock(); defer s.mu.Unlock(); return s.resetLocked() }

// RunNormal proves that legitimate traffic reaches both backends.
func (s *Scenario) RunNormal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requestLocked("baseline", "legit"); err != nil {
		return err
	}
	_, err := s.requestLocked("protected", "legit")
	return err
}

// StealKeyAndAttack models reuse of the exact same external key from a second
// source. The first protected attack reaches; the second crosses the real
// producer/evidence/lane threshold and is denied before forwarding.
func (s *Scenario) StealKeyAndAttack() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.requestLocked("baseline", "attacker"); err != nil {
		return err
	}
	if _, err := s.requestLocked("protected", "attacker"); err != nil {
		return err
	}
	if _, err := s.requestLocked("protected", "attacker"); err != nil {
		return err
	}
	return s.attackBurstLocked("attacker", 3)
}
func (s *Scenario) LegitAfterContainment() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.requestLocked("protected", "legit")
	return err
}

func (s *Scenario) DirectRawBackendAttempt() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp, err := s.clients["attacker"].Do(s.requestURL(s.backend.URL, "direct"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == http.StatusOK {
		return fmt.Errorf("protected backend accepted direct raw-credential attempt")
	}
	_ = resp.Body.Close()
	// A syntactically present but forged/wrong assertion must fail too.
	forged, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(s.backend.URL, "/")+"/v1/messages", nil)
	if err != nil {
		return err
	}
	forged.Header.Set("X-Gripline-Assertion", "forged-demo-assertion")
	resp, err = s.clients["attacker"].Do(forged)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return fmt.Errorf("protected backend accepted forged assertion")
	}
	return nil
}

func (s *Scenario) RunFullDemo() error {
	if err := s.Reset(); err != nil {
		return err
	}
	if err := s.RunNormal(); err != nil {
		return fmt.Errorf("normal traffic: %w", err)
	}
	if err := s.StealKeyAndAttack(); err != nil {
		return fmt.Errorf("stolen-key attack: %w", err)
	}
	if err := s.LegitAfterContainment(); err != nil {
		return fmt.Errorf("legitimate recovery traffic: %w", err)
	}
	if err := s.DirectRawBackendAttempt(); err != nil {
		return fmt.Errorf("direct backend proof: %w", err)
	}
	return s.assertions()
}

func (s *Scenario) requestLocked(kind, actor string) (int, error) {
	target := s.protectedURL
	if kind == "baseline" {
		target = s.baseline.URL
	}
	if kind != "baseline" && kind != "protected" {
		return 0, fmt.Errorf("unknown target %q", kind)
	}
	resp, err := s.clients[actor].Do(s.requestURL(target, actor))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if kind == "protected" {
		s.obs.MarkResponse(resp.Header.Get("X-Gripline-Request-ID"), actor, resp.StatusCode < 500, resp.Header.Get("X-Demo-Assertion-Verified") == "true")
	}
	return resp.StatusCode, nil
}

// attackBurstLocked holds the scenario lifecycle lock while coordinating a
// real concurrent request burst. The backend deliberately keeps admitted
// requests in flight long enough for the resource-velocity producer to observe
// live lane concurrency rather than a synthetic demo signal.
func (s *Scenario) attackBurstLocked(actor string, count int) error {
	if count < 1 {
		return fmt.Errorf("attack burst: count must be positive")
	}
	s.barrier.begin(count)
	defer s.barrier.releaseAll()
	start := make(chan struct{})
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.requestLocked("protected", actor)
			errs <- err
		}()
	}
	close(start)
	if !s.barrier.waitFor(count, 3*time.Second) {
		return fmt.Errorf("attack burst: only %d/%d real HTTP requests reached the backend barrier", s.barrier.count(), count)
	}
	// The follow-up request is also real HTTP traffic. It runs while the first
	// three requests are held by the backend, so the stock producer observes a
	// live concurrency ramp and crosses its 4x rule; no governor/evidence state
	// is preloaded by the demo.
	followup := make(chan error, 1)
	go func() {
		_, err := s.requestLocked("protected", actor)
		followup <- err
	}()
	if err := <-followup; err != nil {
		return err
	}
	s.barrier.releaseAll()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Scenario) requestURL(base, actor string) *http.Request {
	ua := "gripline-demo-legit"
	if actor == "attacker" {
		ua = "curl/8.0 gripline-demo-stealer"
	}
	req, _ := http.NewRequest(http.MethodPost, strings.TrimSuffix(base, "/")+"/v1/messages", strings.NewReader(`{"model":"demo","input":"bounded demo request"}`))
	req.Header.Set("Authorization", "Bearer "+s.raw)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func (s *Scenario) assertions() error {
	snap := s.Snapshot()
	if snap.Baseline.LegitimateAccepted < 1 {
		return fmt.Errorf("baseline legitimate request did not reach backend")
	}
	if snap.Baseline.AttackerAccepted < 1 {
		return fmt.Errorf("baseline accepted stolen-key attack is missing")
	}
	if snap.Protected.LegitimateReached < 2 {
		return fmt.Errorf("protected legitimate traffic did not reach before and after containment")
	}
	if snap.Protected.AttackerReached < 1 {
		return fmt.Errorf("attacker never reached protected backend before containment")
	}
	if snap.Protected.AttackerBlocked < 1 {
		return fmt.Errorf("attacker was never blocked after the real threshold")
	}
	if snap.Protected.RawAuthorization != 0 || snap.Protected.RawAPIKey != 0 {
		return fmt.Errorf("raw credential crossed protected boundary")
	}
	if snap.Protected.ValidAssertions < 1 || snap.Protected.InvalidOrForged < 1 {
		return fmt.Errorf("assertion verification proof is incomplete")
	}
	if snap.Protected.DirectRawRejected < 1 {
		return fmt.Errorf("direct raw backend rejection proof is missing")
	}
	if !snap.Proof.RealEvidence || !snap.Proof.ConcurrencyEvidence || !snap.Proof.SecurityTransition {
		return fmt.Errorf("timeline does not show real evidence and security transitions")
	}
	return nil
}

type demoPseudonymAdapter struct{ ring *pseudonym.Ring }

func (a demoPseudonymAdapter) Derive(family, raw []byte) (string, error) {
	return a.ring.Derive(pseudonym.Family(family), raw)
}

type demoNetworkMetadata struct{}

func (demoNetworkMetadata) Resolve(ip netip.Addr) (string, string, string, bool) {
	switch ip.String() {
	case "127.0.0.2":
		return "AS64501", "residential", "US", true
	case "127.0.0.3":
		return "AS64599", "hosting", "DE", true
	default:
		return "", "", "", false
	}
}

func demoClient(ip string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}).DialContext(ctx, network, address)
	}}}
}
func credentialFingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("sha256:%x", sum[:6])
}
