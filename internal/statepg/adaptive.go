package statepg

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

const maxAdaptiveSnapshotBytes = 8 << 20

// LoadDetectorState and SaveDetectorState implement the shared checkpoint
// seam used by anomaly detectors and bounded producers. The snapshots contain
// only pseudonymous/bounded keys; raw credentials never enter this table.
func (s *Store) LoadDetectorState(name string) ([]byte, bool, error) {
	if name == "" {
		return nil, false, errors.New("statepg: adaptive state name required")
	}
	var data []byte
	err := s.pool.QueryRow(context.Background(), `SELECT data FROM gripline_adaptive_state WHERE name=$1`, name).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, mapDBError(err)
	}
	return append([]byte(nil), data...), true, nil
}

func (s *Store) SaveDetectorState(name string, data []byte) error {
	if name == "" {
		return errors.New("statepg: adaptive state name required")
	}
	if len(data) == 0 || len(data) > maxAdaptiveSnapshotBytes {
		return errors.New("statepg: adaptive snapshot exceeds bound")
	}
	_, err := s.pool.Exec(context.Background(), `INSERT INTO gripline_adaptive_state (name, data, updated_at)
		VALUES ($1,$2,$3) ON CONFLICT (name) DO UPDATE SET data=EXCLUDED.data, updated_at=EXCLUDED.updated_at`, name, data, s.now().UTC())
	return mapDBError(err)
}
