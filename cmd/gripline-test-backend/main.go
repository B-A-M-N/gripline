// Command gripline-test-backend is a minimal private-backend fixture for the
// release harness. It deliberately imports only the public verify package, so
// the compiled black-box test exercises the same trust boundary a provider
// service is expected to use.
package main

import (
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/B-A-M-N/gripline/internal/replay"
	"github.com/B-A-M-N/gripline/verify"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18081", "private backend listen address")
	tlsCert := flag.String("tls-cert", "", "optional TLS serving certificate PEM path")
	tlsKey := flag.String("tls-key", "", "optional TLS serving private key PEM path")
	clientCA := flag.String("client-ca", "", "optional CA PEM path for required client certificates")
	requireClientDNS := flag.String("require-client-dns", "", "require this exact verified client-certificate DNS identity")
	keysPath := flag.String("keys", "", "public Gripline key-set JSON path")
	audience := flag.String("audience", "", "expected assertion audience")
	minPolicyRev := flag.Int("min-policy-rev", 0, "minimum accepted policy revision for test freshness checks")
	policyEpochFile := flag.String("policy-epoch-file", "", "optional file containing the current accepted policy activation epoch")
	verifierControlPath := flag.String("verifier-control", "", "optional private path for candidate verifier publication and canary acceptance")
	verifierControlToken := flag.String("verifier-control-token", "", "optional dedicated control-plane token for verifier publication")
	replayDSN := flag.String("replay-dsn", "", "optional shared PostgreSQL replay-guard DSN")
	controlOnly := flag.Bool("control-only", false, "serve only the verifier-control path (plus healthz)")
	capturePath := flag.String("capture", "", "optional accepted-request header capture path")
	assertionPath := flag.String("assertion-path", "", "optional path receiving the latest assertion for test inspection")
	workDelay := flag.Duration("work-delay", 0, "duration for /v1/work before completing")
	activePath := flag.String("active", "", "optional file containing current accepted backend work")
	peakPath := flag.String("peak", "", "optional file containing peak accepted backend work")
	flag.Parse()
	if *keysPath == "" || *audience == "" {
		log.Fatal("-keys and -audience are required")
	}
	keysFile, err := os.Open(*keysPath)
	if err != nil {
		log.Fatalf("open key set: %v", err)
	}
	keySet, err := verify.LoadKeySet(keysFile)
	_ = keysFile.Close()
	if err != nil {
		log.Fatalf("load key set: %v", err)
	}
	verifier, err := verify.New(keySet, *audience)
	if err != nil {
		log.Fatalf("construct verifier: %v", err)
	}
	var transportTrust verify.TransportTrust
	if strings.TrimSpace(*requireClientDNS) != "" {
		if *tlsCert == "" || *tlsKey == "" || *clientCA == "" {
			log.Fatal("-require-client-dns requires -tls-cert, -tls-key, and -client-ca")
		}
		transportTrust = verify.RequireMTLS(verify.MTLSOptions{
			AllowedDNSNames: []string{*requireClientDNS},
		})
		verifier.RequireTransportTrust(transportTrust)
	}
	if *verifierControlPath != "" && strings.TrimSpace(*verifierControlToken) == "" && transportTrust == nil {
		log.Fatal("-verifier-control requires -verifier-control-token or -require-client-dns")
	}
	// The fixture defaults to bounded local replay protection, but the
	// qualification lab can point independent backend processes at one shared
	// PostgreSQL guard to prove active/active exactly-once claims.
	verifier.WithReplayGuard(verify.NewMemoryReplayGuard(100000))
	if strings.TrimSpace(*replayDSN) != "" {
		sharedGuard, err := replay.OpenPostgresGuard(context.Background(), *replayDSN)
		if err != nil {
			log.Fatalf("open shared replay guard: %v", err)
		}
		defer sharedGuard.Close()
		verifier.WithReplayGuard(sharedGuard)
	}
	// The verifier-control canary proves signer-key acceptance, not policy
	// freshness. Keep a separate verifier without the workload's policy epoch
	// check so a key rotation cannot be blocked by an unrelated policy rollout.
	controlVerifier, err := verify.New(keySet, *audience)
	if err != nil {
		log.Fatalf("construct verifier control: %v", err)
	}
	if transportTrust != nil {
		controlVerifier.RequireTransportTrust(transportTrust)
	}
	if *policyEpochFile != "" {
		verifier.WithPolicyEpochChecks(policyEpochFileSource{path: *policyEpochFile}, 1)
	}

	var captureMu sync.Mutex
	var statsMu sync.Mutex
	var active atomic.Int64
	var peak atomic.Int64
	writeStat := func(path string, value int64) {
		if path == "" {
			return
		}
		statsMu.Lock()
		defer statsMu.Unlock()
		if err := os.WriteFile(path, []byte(strconv.FormatInt(value, 10)), 0o600); err != nil {
			log.Printf("stats %s: %v", path, err)
		}
	}
	writeAssertion := func(value string) {
		if *assertionPath == "" || value == "" {
			return
		}
		statsMu.Lock()
		defer statsMu.Unlock()
		if err := os.WriteFile(*assertionPath, []byte(value+"\n"), 0o600); err != nil {
			log.Printf("assertion capture: %v", err)
		}
	}
	beginWork := func() func() {
		current := active.Add(1)
		for {
			previous := peak.Load()
			if current <= previous || peak.CompareAndSwap(previous, current) {
				break
			}
		}
		writeStat(*activePath, current)
		writeStat(*peakPath, peak.Load())
		return func() {
			writeStat(*activePath, active.Add(-1))
		}
	}
	capture := func(r *http.Request) {
		if *capturePath == "" {
			return
		}
		captureMu.Lock()
		defer captureMu.Unlock()
		f, err := os.OpenFile(*capturePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("capture: %v", err)
			return
		}
		_, _ = fmt.Fprintf(f, "%s %s host=%s headers=%v\n", r.Method, r.URL.RequestURI(), r.Host, r.Header)
		_ = f.Close()
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject an untrusted mTLS identity before parsing a verifier-control
		// mutation. TLS chain verification alone is not enough: inference and
		// verifier-management listeners must authorize different identities.
		if transportTrust != nil && !transportTrust.Trusted(r) {
			http.Error(w, "untrusted backend transport identity", http.StatusForbidden)
			return
		}
		if *controlOnly && r.URL.Path != "/healthz" && (*verifierControlPath == "" || r.URL.Path != *verifierControlPath) {
			http.NotFound(w, r)
			return
		}
		if *verifierControlPath != "" && r.URL.Path == *verifierControlPath {
			if *verifierControlToken != "" && !validVerifierControlToken(r.Header, *verifierControlToken) {
				http.Error(w, "verifier control authentication required", http.StatusForbidden)
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var controlRequest struct {
				Action          string `json:"action"`
				Protocol        string `json:"protocol"`
				KID             int    `json:"kid"`
				PublicKey       string `json:"public_key"`
				Fingerprint     string `json:"fingerprint"`
				CanaryAssertion string `json:"canary_assertion"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&controlRequest); err != nil || controlRequest.Protocol != "gripline.verifier-control/v1" || controlRequest.KID < 1 || (controlRequest.Action != "publish" && controlRequest.Action != "retire") || controlRequest.Fingerprint == "" {
				http.Error(w, "invalid verifier control request", http.StatusBadRequest)
				return
			}
			if controlRequest.Action == "retire" {
				if controlRequest.PublicKey != "" || controlRequest.CanaryAssertion != "" {
					http.Error(w, "invalid verifier retirement request", http.StatusBadRequest)
					return
				}
				if err := verifier.RetireKey(controlRequest.KID, controlRequest.Fingerprint); err != nil {
					http.Error(w, "verifier control retirement rejected", http.StatusConflict)
					return
				}
				if err := controlVerifier.RetireKey(controlRequest.KID, controlRequest.Fingerprint); err != nil {
					http.Error(w, "verifier control retirement rejected", http.StatusConflict)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"retired": true, "kid": controlRequest.KID})
				return
			}
			if controlRequest.CanaryAssertion == "" {
				http.Error(w, "candidate canary is required", http.StatusBadRequest)
				return
			}
			public, err := base64.StdEncoding.DecodeString(controlRequest.PublicKey)
			if err != nil || len(public) != ed25519.PublicKeySize {
				http.Error(w, "invalid verifier control public key", http.StatusBadRequest)
				return
			}
			sum := sha256.Sum256(public)
			if hex.EncodeToString(sum[:]) != controlRequest.Fingerprint {
				http.Error(w, "verifier control fingerprint mismatch", http.StatusBadRequest)
				return
			}
			if err := verifier.PublishKey(controlRequest.KID, public); err != nil {
				http.Error(w, "verifier control publication rejected", http.StatusConflict)
				return
			}
			if err := controlVerifier.PublishKey(controlRequest.KID, public); err != nil {
				http.Error(w, "verifier control publication rejected", http.StatusConflict)
				return
			}
			r.Header.Set(verify.AssertionHeader, controlRequest.CanaryAssertion)
			claims, err := controlVerifier.VerifyAndStrip(r)
			if err != nil || claims.KeyID != controlRequest.KID {
				http.Error(w, "verifier control canary rejected", http.StatusBadGateway)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true, "kid": controlRequest.KID})
			return
		}
		// A protected backend must never accept a raw external credential, even
		// if a caller reaches this private listener directly.
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
			http.Error(w, "raw credential rejected", http.StatusForbidden)
			return
		}
		capture(r)
		writeAssertion(r.Header.Get(verify.AssertionHeader))
		claims, err := verifier.VerifyAndStrip(r)
		if err != nil {
			http.Error(w, "assertion required", http.StatusUnauthorized)
			return
		}
		if *minPolicyRev > 0 && claims.PolicyRev < *minPolicyRev {
			http.Error(w, "stale policy revision", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/work" {
			releaseWork := beginWork()
			defer releaseWork()
			delay := *workDelay
			if delay <= 0 {
				delay = 2 * time.Second
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
				return
			}
		}
		if r.URL.Path == "/v1/status/429" {
			w.Header().Set("Retry-After", "3")
			http.Error(w, "backend throttled", http.StatusTooManyRequests)
			return
		}
		if r.URL.Path == "/v1/status/500" {
			http.Error(w, "backend failed", http.StatusBadGateway)
			return
		}
		if r.URL.Path == "/v1/gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/octet-stream")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write([]byte("compressed-body-fidelity"))
			_ = gz.Close()
			return
		}
		if r.URL.Path == "/v1/echo" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
			encoder := json.NewEncoder(w)
			encoder.SetEscapeHTML(false)
			_ = encoder.Encode(map[string]any{"path": r.URL.Path, "query": r.URL.RawQuery, "body": string(body)})
			return
		}
		if r.URL.Path == "/v1/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			for _, chunk := range []string{"data: one\n\n", "data: two\n\n", "data: [DONE]\n\n"} {
				if _, err := io.WriteString(w, chunk); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			return
		}
		if r.URL.Path == "/v1/slow" {
			// The fixed content length makes an idle-stream cut observable to a
			// black-box client as a truncated response rather than a clean empty
			// response. Context cancellation also proves the upstream is released
			// when the client disconnects.
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "5")
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
				_, _ = io.WriteString(w, "slow\n")
			case <-r.Context().Done():
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorized":      true,
			"credential_id":   claims.CredID,
			"policy_revision": claims.PolicyRev,
			"policy_epoch":    claims.PolicyEpoch,
		})
	})
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("-tls-cert and -tls-key must be supplied together")
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	if *clientCA != "" {
		caPEM, err := os.ReadFile(*clientCA)
		if err != nil {
			log.Fatalf("read client CA: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			log.Fatal("client CA contains no certificates")
		}
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		}
	}
	go func() {
		var err error
		if *tlsCert != "" {
			err = server.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("backend: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func validVerifierControlToken(headers http.Header, expected string) bool {
	if strings.TrimSpace(expected) == "" {
		return false
	}
	var values []string
	for name, headerValues := range headers {
		if strings.EqualFold(name, "X-Gripline-Verifier-Control") {
			values = append(values, headerValues...)
		}
	}
	return len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) == 1
}

type policyEpochFileSource struct{ path string }

func (s policyEpochFileSource) PolicyEpoch() (uint64, bool) {
	epoch, err := s.read()
	return epoch, err == nil
}

func (s policyEpochFileSource) PolicyEpochContext(ctx context.Context) (uint64, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	return s.read()
}

func (s policyEpochFileSource) read() (uint64, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return 0, err
	}
	epoch, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || epoch == 0 {
		return 0, fmt.Errorf("invalid policy epoch")
	}
	return epoch, nil
}
