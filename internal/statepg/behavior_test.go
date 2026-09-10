package statepg

import (
	"strings"
	"testing"
	"time"
)

func TestClusterBehaviorDigestCanonicalizesDefaults(t *testing.T) {
	zero := ClusterBehaviorConfig{}
	explicit := ClusterBehaviorConfig{
		LeaseTTL: 30 * time.Second, RenewEvery: 10 * time.Second,
		MaxSourceScopes: 4096, SourceScopeIdle: 10 * time.Minute,
		MaxSourceAliasIdentities: 4096,
		ReleasedLeaseRetention:   24 * time.Hour, CredentialReceiptRetention: 24 * time.Hour,
		ControlOperationRetention: 24 * time.Hour, AdmissionAuditRetention: 90 * 24 * time.Hour,
		SecurityTransitionRetention: 90 * 24 * time.Hour, OperatorAuditRetention: 365 * 24 * time.Hour,
		PolicyAuditRetention: 365 * 24 * time.Hour, MembershipRetention: 24 * time.Hour,
		AdaptiveRetention: 7 * 24 * time.Hour, EvidenceGuardRetention: 24 * time.Hour,
		LaneOperatorAuditRetention: 365 * 24 * time.Hour, PolicyNodeStateRetention: 24 * time.Hour,
		ClusterCryptoAckRetention: 24 * time.Hour, SourceAliasRetention: 7 * 24 * time.Hour,
	}
	zeroDigest, err := zero.Digest()
	if err != nil {
		t.Fatal(err)
	}
	explicitDigest, err := explicit.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if zeroDigest != explicitDigest {
		t.Fatalf("default and explicit behavior digests differ: %s != %s", zeroDigest, explicitDigest)
	}
	if len(zeroDigest) != 64 || strings.Trim(zeroDigest, "0123456789abcdef") != "" {
		t.Fatalf("invalid SHA-256 digest %q", zeroDigest)
	}
	changed := explicit
	changed.MaxSourceScopes++
	changedDigest, err := changed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == explicitDigest {
		t.Fatal("behavior digest did not change when a shared bound changed")
	}
}
