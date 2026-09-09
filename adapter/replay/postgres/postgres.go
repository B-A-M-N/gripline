// Package postgres exposes the shared PostgreSQL replay adapter to verifier
// integrations without requiring them to import Gripline internals.
package postgres

import (
	"context"

	internalreplay "github.com/B-A-M-N/gripline/internal/replay"
)

type Guard = internalreplay.PostgresGuard

func Open(ctx context.Context, dsn string) (*Guard, error) {
	return internalreplay.OpenPostgresGuard(ctx, dsn)
}

func Migrate(ctx context.Context, dsn string) error {
	return internalreplay.MigratePostgresGuard(ctx, dsn)
}
