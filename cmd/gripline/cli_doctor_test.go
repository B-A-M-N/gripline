package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-A-M-N/gripline/internal/statepg"
)

func TestDoctorCryptoHealthRequiresEveryLiveNodeAcknowledgement(t *testing.T) {
	for _, test := range []struct {
		name         string
		acknowledged int
		ready        bool
		wantOK       bool
		wantDetail   string
	}{
		{name: "one of three", acknowledged: 1, wantDetail: "1/3"},
		{name: "two of three", acknowledged: 2, wantDetail: "2/3"},
		{name: "all three", acknowledged: 3, ready: true, wantOK: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ok, detail := doctorCryptoHealth(statepg.ClusterStatus{
				LiveNodeCount: 3, LocalCryptoReady: test.ready,
				Crypto: statepg.ClusterCryptoStatus{
					Initialized: true, SignerActiveKID: 4, PepperActiveVersion: 2,
					GenerationEpoch: 9,
					Generations: []statepg.ClusterCryptoGenerationStatus{{
						Kind: "signer", Generation: 4, State: "active",
						AcknowledgedNodes: test.acknowledged,
					}},
				},
			})
			if ok != test.wantOK {
				t.Fatalf("doctor crypto health=%v detail=%q, want %v", ok, detail, test.wantOK)
			}
			if test.wantDetail != "" && !strings.Contains(detail, test.wantDetail) {
				t.Fatalf("detail=%q, want acknowledgement ratio %q", detail, test.wantDetail)
			}
		})
	}
}

func TestDoctorMaintenanceHealthWarnsWithoutBlocking(t *testing.T) {
	if ok, detail := doctorMaintenanceHealth(statepg.ClusterMaintenanceStatus{Runs: 3}); !ok || !strings.Contains(detail, "healthy") {
		t.Fatalf("healthy maintenance=%v detail=%q", ok, detail)
	}
	if ok, detail := doctorMaintenanceHealth(statepg.ClusterMaintenanceStatus{Runs: 4, ConsecutiveErrors: 4, BacklogEstimate: 84921}); ok || !strings.Contains(detail, "84921") {
		t.Fatalf("failed maintenance=%v detail=%q, want warning with backlog", ok, detail)
	}
}

func TestDoctorCommandBlocksUnknownClusterAndPolicyState(t *testing.T) {
	const token = "doctor-command-token-0123456789abcdef0123456789"
	tests := []struct {
		name             string
		clusterStatus    int
		clusterBody      map[string]any
		policyStatus     int
		wantReady        bool
		wantBlockingName string
		wantNonblocking  string
	}{
		{
			name:             "cluster and policy forbidden",
			clusterStatus:    http.StatusForbidden,
			policyStatus:     http.StatusForbidden,
			wantBlockingName: "cluster diagnostics",
			wantReady:        false,
		},
		{
			name:             "cluster unavailable",
			clusterStatus:    http.StatusServiceUnavailable,
			policyStatus:     http.StatusOK,
			wantBlockingName: "admin endpoint",
			wantReady:        false,
		},
		{
			name:          "crypto incomplete",
			clusterStatus: http.StatusOK,
			clusterBody: map[string]any{
				"local_membership_ready": true, "local_crypto_ready": false, "live_node_count": 1,
				"crypto": map[string]any{"initialized": true, "signer_active_kid": 1, "pepper_active_version": 1,
					"generations": []map[string]any{{"kind": "signer", "state": "active", "acknowledged_nodes": 0}}},
			},
			policyStatus:     http.StatusOK,
			wantBlockingName: "crypto synchronization",
			wantReady:        false,
		},
		{
			name:          "maintenance warning",
			clusterStatus: http.StatusOK,
			clusterBody: map[string]any{
				"local_membership_ready": true, "local_crypto_ready": true, "live_node_count": 1,
				"crypto":      map[string]any{"initialized": true, "signer_active_kid": 1, "pepper_active_version": 1},
				"maintenance": map[string]any{"runs": 4, "consecutive_errors": 2, "backlog_estimate": 7},
			},
			policyStatus:    http.StatusOK,
			wantReady:       true,
			wantNonblocking: "maintenance",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin/cluster":
					w.WriteHeader(test.clusterStatus)
					if test.clusterStatus == http.StatusOK {
						_ = json.NewEncoder(w).Encode(test.clusterBody)
					}
				case "/admin/policy":
					w.WriteHeader(test.policyStatus)
					if test.policyStatus == http.StatusOK {
						_ = json.NewEncoder(w).Encode(map[string]any{"active": map[string]any{"id": "policy", "revision": 1, "digest": "digest"}})
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer admin.Close()
			configPath := doctorCommandConfig(t, admin.URL, token)
			var runErr error
			output := captureStdout(t, func() {
				runErr = runDoctorCLI(&cliContext{ConfigPath: configPath, Token: token, Output: outputJSON, Timeout: 2 * time.Second})
			})
			var report doctorReport
			if err := json.Unmarshal([]byte(output), &report); err != nil {
				t.Fatalf("doctor output: %v\n%s", err, output)
			}
			if (runErr == nil) == !test.wantReady {
				t.Fatalf("doctor error=%v, ready=%v, want ready=%v", runErr, report.Ready, test.wantReady)
			}
			if report.Ready != test.wantReady {
				t.Fatalf("doctor ready=%v, want %v: %+v", report.Ready, test.wantReady, report)
			}
			if test.wantBlockingName != "" {
				found := false
				for _, check := range report.Checks {
					if check.Name == test.wantBlockingName && check.Blocking && !check.OK {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing blocking check %q: %+v", test.wantBlockingName, report.Checks)
				}
			}
			if test.wantNonblocking != "" {
				found := false
				for _, check := range report.Checks {
					if check.Name == test.wantNonblocking && check.Blocking && !check.OK {
						t.Fatalf("maintenance warning became blocking: %+v", check)
					}
					if check.Name == test.wantNonblocking && !check.OK {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing maintenance warning: %+v", report.Checks)
				}
			}
		})
	}
}

func doctorCommandConfig(t *testing.T, adminURL, token string) string {
	t.Helper()
	dir := t.TempDir()
	adminListen := strings.TrimPrefix(adminURL, "http://")
	value := map[string]any{
		"listen":    "127.0.0.1:0",
		"backend":   map[string]any{"url": "http://backend.internal:80", "trust_mode": "private_network", "timeout": "5s"},
		"server":    map[string]any{"read_timeout": "5s", "write_timeout": "5s", "idle_timeout": "5s", "read_header_timeout": "5s"},
		"identity":  map[string]any{"audience": "doctor-test"},
		"tls":       map[string]any{"terminate_tls_upstream": true},
		"authority": map[string]any{"backend": "postgres", "dsn_env": "DOCTOR_TEST_DSN", "node_id": "doctor-node", "lease_ttl": "10s", "renew_every": "2s"},
		"admin":     map[string]any{"listen": adminListen, "operator_tokens": map[string]string{token: "doctor:cluster.read,policy.read"}},
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	return path
}
