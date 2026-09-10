package statepg

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCryptoGenerationsReadyRequiresExactActiveSet(t *testing.T) {
	base := ClusterCryptoStatus{
		Initialized:             true,
		SignerActiveKID:         2,
		SignerActiveFingerprint: "signer-2",
		PepperActiveVersion:     4,
		PepperActiveFingerprint: "pepper-4",
		Generations: []ClusterCryptoGenerationStatus{
			{Kind: "pepper", Generation: 4, Fingerprint: "pepper-4", State: "active", AcknowledgedNodes: 3},
			{Kind: "signer", Generation: 2, Fingerprint: "signer-2", State: "active", AcknowledgedNodes: 3},
		},
	}
	tests := []struct {
		name   string
		mutate func(*ClusterCryptoStatus)
		want   bool
	}{
		{name: "exact set", want: true},
		{name: "missing signer", mutate: func(status *ClusterCryptoStatus) { status.Generations = status.Generations[:1] }},
		{name: "singleton fingerprint mismatch", mutate: func(status *ClusterCryptoStatus) { status.SignerActiveFingerprint = "other" }},
		{name: "generation fingerprint mismatch", mutate: func(status *ClusterCryptoStatus) { status.Generations[1].Fingerprint = "other" }},
		{name: "unexpected active generation", mutate: func(status *ClusterCryptoStatus) {
			status.Generations = append(status.Generations, ClusterCryptoGenerationStatus{Kind: "pseudonym", Generation: 1, Fingerprint: "pseudo-1", State: "active", AcknowledgedNodes: 3})
		}},
		{name: "incomplete acknowledgement", mutate: func(status *ClusterCryptoStatus) { status.Generations[0].AcknowledgedNodes = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := base
			status.Generations = append([]ClusterCryptoGenerationStatus(nil), base.Generations...)
			if test.mutate != nil {
				test.mutate(&status)
			}
			if got := cryptoGenerationsReady(status, 3); got != test.want {
				t.Fatalf("cryptoGenerationsReady()=%v, want %v: %+v", got, test.want, status)
			}
		})
	}
}

func TestEnforcePublicSearchPath(t *testing.T) {
	config, err := pgxpool.ParseConfig("postgres://user:pass@localhost/db?sslmode=disable&options=-c%20search_path%3Dother")
	if err != nil {
		t.Fatal(err)
	}
	enforcePublicSearchPath(config)
	if got := config.ConnConfig.RuntimeParams["search_path"]; got != "public" {
		t.Fatalf("search_path=%q, want public", got)
	}
}
