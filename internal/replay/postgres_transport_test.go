package replay

import (
	"errors"
	"testing"

	"github.com/B-A-M-N/gripline/internal/pgtransport"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresTransportRejectsRemotePlaintext(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		wantErr bool
	}{
		{name: "loopback plaintext", dsn: "postgres://user@127.0.0.1/db?sslmode=disable"},
		{name: "unix socket plaintext", dsn: "host=/var/run/postgresql user=user dbname=db sslmode=disable"},
		{name: "remote plaintext", dsn: "postgres://user@db.internal/db?sslmode=disable", wantErr: true},
		{name: "remote prefer", dsn: "postgres://user@db.internal/db?sslmode=prefer", wantErr: true},
		{name: "remote verified TLS", dsn: "postgres://user@db.internal/db?sslmode=verify-full", wantErr: false},
		{name: "local then remote fallback", dsn: "postgres://user@localhost,db.internal/db?sslmode=disable", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := pgxpool.ParseConfig(tt.dsn)
			if err != nil {
				t.Fatal(err)
			}
			err = pgtransport.Validate(config)
			if tt.wantErr {
				if !errors.Is(err, pgtransport.ErrInsecureTransport) {
					t.Fatalf("Validate() error = %v, want ErrInsecureTransport", err)
				}
			} else if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}
