package statepg

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/B-A-M-N/gripline/internal/adaptive"
	"github.com/jackc/pgx/v5"
)

const (
	defaultAdaptiveMaxSubjects = 65536
	defaultAdaptiveMaxKeys     = 256
)

// ObserveWindow atomically records one distinct bounded observation in a
// subject/window row set. It intentionally does not read or write the legacy
// whole-detector snapshot table used by standalone bbolt.
func (s *Store) ObserveWindow(ctx context.Context, obs adaptive.WindowObservation) (bool, error) {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if obs.Detector == "" || obs.Subject == "" || obs.Key == "" || obs.Window <= 0 || obs.Cooldown < 0 || obs.Threshold < 0 {
		return false, errors.New("statepg: invalid adaptive window observation")
	}
	if obs.MaxSubjects <= 0 {
		obs.MaxSubjects = defaultAdaptiveMaxSubjects
	}
	if obs.MaxKeys <= 0 {
		obs.MaxKeys = defaultAdaptiveMaxKeys
	}
	var emitted bool
	err := s.withTransactionRetry(ctx, "adaptive window observation", func() error {
		var err error
		emitted, err = s.observeWindowOnce(ctx, obs)
		return err
	})
	return emitted, err
}

func (s *Store) observeWindowOnce(ctx context.Context, obs adaptive.WindowObservation) (bool, error) {
	// Existing subjects are serialized by their own FOR UPDATE row below. A
	// detector-scoped advisory lock is needed only when a new subject changes
	// the bounded-cardinality decision; using SERIALIZABLE for every adaptive
	// observation made unrelated subjects collide on the detector index.
	tx, err := beginResource(ctx, s.pool)
	if err != nil {
		return false, mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return false, err
	}
	if err := s.requireNodeOwnership(ctx, tx, true); err != nil {
		return false, err
	}

	var lockedSubject string
	err = tx.QueryRow(ctx, `SELECT subject FROM gripline_adaptive_window_subjects
		WHERE detector=$1 AND subject=$2 FOR UPDATE`, obs.Detector, obs.Subject).Scan(&lockedSubject)
	if errors.Is(err, pgx.ErrNoRows) {
		tag, err := tx.Exec(ctx, `INSERT INTO gripline_adaptive_window_subjects (detector, subject, last_seen_at)
			VALUES ($1,$2,$3) ON CONFLICT (detector, subject) DO NOTHING`, obs.Detector, obs.Subject, now)
		if err != nil {
			return false, mapDBError(err)
		}
		if err := tx.QueryRow(ctx, `SELECT subject FROM gripline_adaptive_window_subjects
			WHERE detector=$1 AND subject=$2 FOR UPDATE`, obs.Detector, obs.Subject).Scan(&lockedSubject); err != nil {
			return false, mapDBError(err)
		}
		if tag.RowsAffected() != 0 {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, obs.Detector); err != nil {
				return false, mapDBError(err)
			}
			var count int
			if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_adaptive_window_subjects WHERE detector=$1`, obs.Detector).Scan(&count); err != nil {
				return false, mapDBError(err)
			}
			for count > obs.MaxSubjects {
				var evict string
				err := tx.QueryRow(ctx, `SELECT subject FROM gripline_adaptive_window_subjects
					WHERE detector=$1 AND subject<>$2 ORDER BY last_seen_at, subject LIMIT 1 FOR UPDATE`, obs.Detector, obs.Subject).Scan(&evict)
				if errors.Is(err, pgx.ErrNoRows) {
					break
				}
				if err != nil {
					return false, mapDBError(err)
				}
				if _, err := tx.Exec(ctx, `DELETE FROM gripline_adaptive_window_subjects WHERE detector=$1 AND subject=$2`, obs.Detector, evict); err != nil {
					return false, mapDBError(err)
				}
				count--
			}
		}
	} else if err != nil {
		return false, mapDBError(err)
	}
	var lastEmit *time.Time
	if err := tx.QueryRow(ctx, `SELECT last_emit_at FROM gripline_adaptive_window_subjects
		WHERE detector=$1 AND subject=$2 FOR UPDATE`, obs.Detector, obs.Subject).Scan(&lastEmit); err != nil {
		return false, mapDBError(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM gripline_adaptive_window_keys WHERE detector=$1 AND subject=$2 AND observed_at <= $3`, obs.Detector, obs.Subject, now.Add(-obs.Window)); err != nil {
		return false, mapDBError(err)
	}
	tag, err := tx.Exec(ctx, `INSERT INTO gripline_adaptive_window_keys (detector, subject, observation_key, observed_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT (detector, subject, observation_key) DO NOTHING`, obs.Detector, obs.Subject, obs.Key, now)
	if err != nil {
		return false, mapDBError(err)
	}
	isNew := tag.RowsAffected() != 0
	if !isNew {
		if _, err := tx.Exec(ctx, `UPDATE gripline_adaptive_window_keys SET observed_at=$4
			WHERE detector=$1 AND subject=$2 AND observation_key=$3`, obs.Detector, obs.Subject, obs.Key, now); err != nil {
			return false, mapDBError(err)
		}
	}
	if _, err := tx.Exec(ctx, `WITH overflow AS (
		SELECT observation_key FROM gripline_adaptive_window_keys
		WHERE detector=$1 AND subject=$2 ORDER BY observed_at, observation_key OFFSET $3
	) DELETE FROM gripline_adaptive_window_keys k USING overflow o
	WHERE k.detector=$1 AND k.subject=$2 AND k.observation_key=o.observation_key`, obs.Detector, obs.Subject, obs.MaxKeys); err != nil {
		return false, mapDBError(err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM gripline_adaptive_window_keys WHERE detector=$1 AND subject=$2`, obs.Detector, obs.Subject).Scan(&count); err != nil {
		return false, mapDBError(err)
	}
	emitted := isNew && count > obs.Threshold && (lastEmit == nil || !now.Before(lastEmit.Add(obs.Cooldown)))
	if emitted {
		_, err = tx.Exec(ctx, `UPDATE gripline_adaptive_window_subjects SET last_seen_at=$3, last_emit_at=$3
			WHERE detector=$1 AND subject=$2`, obs.Detector, obs.Subject, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE gripline_adaptive_window_subjects SET last_seen_at=$3
			WHERE detector=$1 AND subject=$2`, obs.Detector, obs.Subject, now)
	}
	if err != nil {
		return false, mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, mapDBError(err)
	}
	return emitted, nil
}

// ObserveBaseline atomically updates one subject/metric EMA and evaluates the
// supplied thresholds against the prior EMA. The returned signal is empty
// when the baseline is still warming, the value is normal, or cooldown/floor
// policy suppresses emission.
func (s *Store) ObserveBaseline(ctx context.Context, obs adaptive.BaselineObservation) (string, error) {
	ctx, cancel := s.operationContext(ctx)
	defer cancel()
	if obs.Detector == "" || obs.Subject == "" || obs.Metric == "" || math.IsNaN(obs.Value) || math.IsInf(obs.Value, 0) || obs.Value < 0 || obs.Alpha <= 0 || obs.Alpha > 1 || obs.Cooldown < 0 {
		return "", errors.New("statepg: invalid adaptive baseline observation")
	}
	var signal string
	err := s.withTransactionRetry(ctx, "adaptive baseline observation", func() error {
		var err error
		signal, err = s.observeBaselineOnce(ctx, obs)
		return err
	})
	return signal, err
}

func (s *Store) observeBaselineOnce(ctx context.Context, obs adaptive.BaselineObservation) (string, error) {
	tx, err := beginResource(ctx, s.pool)
	if err != nil {
		return "", mapDBError(err)
	}
	defer tx.Rollback(ctx)
	now, err := dbNow(ctx, tx)
	if err != nil {
		return "", err
	}
	if err := s.requireNodeOwnership(ctx, tx, true); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gripline_adaptive_baselines
		(detector, subject, metric, ema, sample_count, last_seen_at)
		VALUES ($1,$2,$3,0,0,$4) ON CONFLICT (detector, subject, metric) DO NOTHING`, obs.Detector, obs.Subject, obs.Metric, now); err != nil {
		return "", mapDBError(err)
	}
	var ema float64
	var sampleCount int64
	var lastEmit *time.Time
	if err := tx.QueryRow(ctx, `SELECT ema, sample_count, last_emit_at FROM gripline_adaptive_baselines
		WHERE detector=$1 AND subject=$2 AND metric=$3 FOR UPDATE`, obs.Detector, obs.Subject, obs.Metric).Scan(&ema, &sampleCount, &lastEmit); err != nil {
		return "", mapDBError(err)
	}
	sampleCount++
	signal := ""
	if sampleCount >= 3 && ema > 0 {
		if obs.Code10 != "" && obs.Threshold10 > 0 && obs.Value >= ema*obs.Threshold10 {
			signal = obs.Code10
		} else if obs.Code4 != "" && obs.Threshold4 > 0 && obs.Value >= ema*obs.Threshold4 {
			signal = obs.Code4
		}
		if obs.AbsoluteFloor > 0 && obs.Value < obs.AbsoluteFloor {
			signal = ""
		}
		if signal != "" && lastEmit != nil && now.Sub(*lastEmit) < obs.Cooldown {
			signal = ""
		}
	}
	newEMA := ema
	if sampleCount < 3 || ema <= 0 {
		if sampleCount == 1 {
			newEMA = obs.Value
		} else {
			newEMA = obs.Alpha*obs.Value + (1-obs.Alpha)*ema
		}
	} else if !obs.ConcurrencyRamp || obs.Value < ema*2 {
		newEMA = obs.Alpha*obs.Value + (1-obs.Alpha)*ema
	}
	var lastEmitValue any
	if lastEmit != nil {
		lastEmitValue = *lastEmit
	}
	if signal != "" {
		lastEmitValue = now
	}
	if _, err := tx.Exec(ctx, `UPDATE gripline_adaptive_baselines SET ema=$4, sample_count=$5,
		last_seen_at=$6, last_emit_at=$7 WHERE detector=$1 AND subject=$2 AND metric=$3`,
		obs.Detector, obs.Subject, obs.Metric, newEMA, sampleCount, now, lastEmitValue); err != nil {
		return "", mapDBError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", mapDBError(err)
	}
	return signal, nil
}
