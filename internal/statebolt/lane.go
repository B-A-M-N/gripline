package statebolt

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/B-A-M-N/gripline/internal/lane"
)

// persistedLane is the versioned on-disk envelope for one lane row. It
// preserves the FULL authoritative record — trust ladder, security dimension,
// risk, features, feature/classification revisions, clean counters, clean
// window — so a restart reproduces the exact security decision (P0.10).
type persistedLane struct {
	SchemaVersion int             `json:"schema_version"`
	Record        lane.LaneRecord `json:"record"`
}

const laneSchemaVersion = 1

// laneLimits resolves the effective limits for a lane mutation. The store is
// constructed with a fixed limits provider (the runtime compiles it from
// policy); tests may override.
func (s *Store) laneLimits() lane.Limits {
	s.mu.RLock()
	fn := s.laneLimitsFn
	s.mu.RUnlock()
	if fn != nil {
		return fn()
	}
	return lane.DefaultLimits()
}
func laneKey(credID, laneID string) ([]byte, error) {
	if strings.ContainsRune(credID, 0) || strings.ContainsRune(laneID, 0) {
		return nil, errNulInID
	}
	return []byte(credID + "\x00" + laneID), nil
}

func lanePrefix(credID string) ([]byte, error) {
	if strings.ContainsRune(credID, 0) {
		return nil, errNulInID
	}
	return []byte(credID + "\x00"), nil
}

var errNulInID = errNulID{}

type errNulID struct{}

func (errNulID) Error() string { return "statebolt: NUL byte in persisted identifier" }

// compile-time assertion: the Bolt store is a full lane.Repository (P0.10).
var _ lane.Repository = (*Store)(nil)

// loadLanesTx loads one credential's lane rows inside an open transaction,
// deterministically ordered by key. Rows under an unknown future schema fail
// closed (corrupt), never silently skip.
func loadLanesTx(tx *bolt.Tx, credID string) ([]*lane.LaneRecord, error) {
	prefix, err := lanePrefix(credID)
	if err != nil {
		return nil, err
	}
	b := tx.Bucket(bucketLanes)
	var out []*lane.LaneRecord
	c := b.Cursor()
	for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
		var p persistedLane
		if err := json.Unmarshal(v, &p); err != nil {
			return nil, errCorruptLane
		}
		if p.SchemaVersion != laneSchemaVersion {
			return nil, errCorruptLane
		}
		r := p.Record // JSON round-trip already detached the row from the buffer
		out = append(out, &r)
	}
	return out, nil
}

var errCorruptLane = errLaneCorrupt{}

type errLaneCorrupt struct{}

func (errLaneCorrupt) Error() string { return "statebolt: corrupt lane record" }

// SetSecurityHysteresis implements lane.Repository (P0.13): the compiled
// policy's hysteresis is applied to the durable store exactly as to the
// resident one.
func (s *Store) SetSecurityHysteresis(hy lane.SecurityHysteresis) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hy.SuspectThresh > 0 && hy.BlockThresh > 0 {
		s.securityOverride = hy
		return
	}
	s.securityOverride = lane.DefaultSecurityHysteresis()
}

// securityHys returns the effective lane hysteresis: the override (policy)
// wins; configured limits base next; conservative defaults last. Same
// resolution order as the resident store, via the shared
// lane.EffectiveSecurityHysteresis.
func (s *Store) securityHys() lane.SecurityHysteresis {
	s.mu.RLock()
	override := s.securityOverride
	s.mu.RUnlock()
	return lane.EffectiveSecurityHysteresis(override, s.laneLimits().Security)
}

// BorrowOrCreate implements lane.Repository. The whole operation — load the
// credential's bounded lane set, run the PURE lane reducer, apply retention
// deletes and the upsert — is one write transaction, so concurrent admissions
// serialize exactly as the resident store's mutex does and a crash cannot
// leave a half-applied classification.
func (s *Store) BorrowOrCreate(credID, newLaneID string, cand lane.Features, ctx lane.ClassificationContext) (*lane.LaneRecord, bool, error) {
	if err := checkLaneIDs(credID, newLaneID); err != nil {
		return nil, false, err
	}
	var out *lane.LaneRecord
	var created bool
	var domainErr error
	err := s.db.Update(func(tx *bolt.Tx) error {
		records, err := loadLanesTx(tx, credID)
		if err != nil {
			return err
		}
		res, reduceErr := lane.ApplyBorrowOrCreate(records, credID, newLaneID, cand, ctx, s.laneLimits(), s.now())
		// Retention deletions are committed even when the requested borrow is
		// rejected. Keep the domain error outside the transaction so Bolt does
		// not roll the cleanup back with it.
		if err := applyLaneDeletesTx(tx, credID, res.Deletes); err != nil {
			return err
		}
		if reduceErr != nil {
			domainErr = reduceErr
			return nil
		}
		if res.Upsert == nil {
			// Unreachable: every success path sets Upsert.
			return errCorruptLane
		}
		if err := putLaneTx(tx, res.Upsert); err != nil {
			return err
		}
		out = res.Upsert
		created = res.Created
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if domainErr != nil {
		return nil, false, domainErr
	}
	return out, created, nil
}

// Get implements lane.Repository.
func (s *Store) Get(credID, laneID string) (*lane.LaneRecord, bool) {
	key, err := laneKey(credID, laneID)
	if err != nil {
		return nil, false
	}
	var rec *lane.LaneRecord
	_ = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLanes).Get(key)
		if v == nil {
			return nil
		}
		var p persistedLane
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != laneSchemaVersion {
			return errCorruptLane // fail closed: unreadable row is not "absent"
		}
		r := p.Record
		rec = &r
		return nil
	})
	return rec, rec != nil
}

// ObserveRisk implements lane.Repository: risk observation + security-status
// reduction in one write transaction (P0.7).
func (s *Store) ObserveRisk(credID, laneID string, riskScore int, now time.Time) (*lane.LaneRecord, error) {
	return s.ObserveRiskWithRequestID(credID, laneID, riskScore, now, "")
}

// ObserveRiskWithRequestID is the request-correlated durable variant used by
// the terminator when the ingress boundary supplied an id.
func (s *Store) ObserveRiskWithRequestID(credID, laneID string, riskScore int, now time.Time, requestID string) (*lane.LaneRecord, error) {
	key, err := laneKey(credID, laneID)
	if err != nil {
		return nil, err
	}
	var out *lane.LaneRecord
	err = s.db.Update(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLanes).Get(key)
		if v == nil {
			return lane.ErrLaneNotFound
		}
		var p persistedLane
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != laneSchemaVersion {
			return errCorruptLane
		}
		rec := p.Record
		before := rec.Security.Status
		lane.ApplyRiskObservation(&rec, riskScore, s.securityHys(), now)
		if err := putLaneTx(tx, &rec); err != nil {
			return err
		}
		if before != rec.Security.Status {
			if err := appendSecurityTransitionTx(tx, control.SecurityTransitionRecord{
				At: now.UTC(), Kind: "lane_security", RequestID: requestID,
				CredentialID: credID, LaneID: laneID, Before: before.String(), After: rec.Security.Status.String(),
				RiskScore: riskScore, Revision: rec.Revision,
			}); err != nil {
				return err
			}
		}
		out = &rec
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RecordCleanAuthorizedAndPromote implements lane.Repository (P0.25): counters
// + promotion + revision bump in one authoritative transaction.
func (s *Store) RecordCleanAuthorizedAndPromote(credID, laneID string, riskScore int, crit lane.PromotionCriteria, now time.Time) (*lane.LaneRecord, bool, error) {
	return s.RecordCleanAuthorizedAndPromoteWithRequestID(credID, laneID, riskScore, crit, now, "")
}

// RecordCleanAuthorizedAndPromoteWithRequestID persists automatic trust
// promotions and correlates a resulting trust transition with its request.
func (s *Store) RecordCleanAuthorizedAndPromoteWithRequestID(credID, laneID string, riskScore int, crit lane.PromotionCriteria, now time.Time, requestID string) (*lane.LaneRecord, bool, error) {
	var promoted bool
	key, err := laneKey(credID, laneID)
	if err != nil {
		return nil, false, err
	}
	var rec *lane.LaneRecord
	err = s.db.Update(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLanes).Get(key)
		if v == nil {
			return lane.ErrLaneNotFound
		}
		var p persistedLane
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != laneSchemaVersion {
			return errCorruptLane
		}
		r := p.Record
		before := r.State
		promoted = lane.ApplyCleanAuthorizedAndPromote(&r, riskScore, crit, now)
		if err := putLaneTx(tx, &r); err != nil {
			return err
		}
		if before != r.State {
			if err := appendSecurityTransitionTx(tx, control.SecurityTransitionRecord{
				At: now.UTC(), Kind: "lane_trust", RequestID: requestID,
				CredentialID: credID, LaneID: laneID, Before: before.String(), After: r.State.String(), Revision: r.Revision,
			}); err != nil {
				return err
			}
		}
		rec = &r
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return rec, promoted, nil
}

// ListLaneIDs implements lane.Repository: cursor-scan of the credential's key
// prefix.
func (s *Store) ListLaneIDs(credID string) []string {
	prefix, err := lanePrefix(credID)
	if err != nil {
		return nil
	}
	var ids []string
	_ = s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketLanes).Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			laneID := string(k[len(prefix):])
			ids = append(ids, laneID)
		}
		return nil
	})
	return ids
}

// ListLaneRecords returns sanitized, fully decoded lane records for
// administrative consumers. Unlike the lane.Repository compatibility methods,
// it preserves database read errors so an unavailable authority cannot look
// like an empty lane set.
func (s *Store) ListLaneRecords(credID string) ([]*lane.LaneRecord, error) {
	var records []*lane.LaneRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		records, err = loadLanesTx(tx, credID)
		return err
	})
	return records, err
}

// LookupLane is the strict administrative counterpart to Repository.Get. It
// returns the underlying read error instead of collapsing it into ok=false.
func (s *Store) LookupLane(credID, laneID string) (*lane.LaneRecord, bool, error) {
	key, err := laneKey(credID, laneID)
	if err != nil {
		return nil, false, err
	}
	var rec *lane.LaneRecord
	err = s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLanes).Get(key)
		if v == nil {
			return nil
		}
		var p persistedLane
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != laneSchemaVersion {
			return errCorruptLane
		}
		r := p.Record
		rec = &r
		return nil
	})
	return rec, rec != nil, err
}

// putLaneTx writes one lane row inside an open transaction (P0.3-fix
// discipline: the Put error returns from the callback so bbolt rolls back).
func putLaneTx(tx *bolt.Tx, rec *lane.LaneRecord) error {
	key, err := laneKey(rec.CredentialID, rec.LaneID)
	if err != nil {
		return err
	}
	env, err := json.Marshal(persistedLane{SchemaVersion: laneSchemaVersion, Record: *rec})
	if err != nil {
		return err
	}
	return tx.Bucket(bucketLanes).Put(key, env)
}

// applyLaneDeletesTx removes retention-expired rows inside an open transaction.
func applyLaneDeletesTx(tx *bolt.Tx, credID string, ids []string) error {
	for _, id := range ids {
		key, err := laneKey(credID, id)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketLanes).Delete(key); err != nil {
			return err
		}
	}
	return nil
}

// checkLaneIDs validates persisted identifiers up front.
func checkLaneIDs(credID, laneID string) error {
	if credID == "" || laneID == "" {
		return errNulInID // empty ids share the collision-safety error surface
	}
	_, err := laneKey(credID, laneID)
	return err
}

// Unblock clears a BLOCKED lane — the durable operator lifecycle action. The
// state mutation (pure lane.ApplyUnblock) and the lane-side operator-audit
// entry (lane.AuditEntry, JSON-encoded in the operator_audit bucket) commit in
// ONE write transaction (P0.49): a failed audit write fails the unblock and
// vice versa.
func (s *Store) Unblock(credID, laneID, actor, reason string, now time.Time) error {
	key, err := laneKey(credID, laneID)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLanes).Get(key)
		if v == nil {
			return lane.ErrLaneNotFound
		}
		var p persistedLane
		if err := json.Unmarshal(v, &p); err != nil || p.SchemaVersion != laneSchemaVersion {
			return errCorruptLane
		}
		rec := p.Record
		before, err := lane.ApplyUnblock(&rec, now)
		if err != nil {
			return err
		}
		entry := lane.AuditEntry{
			LaneID: laneID, CredentialID: credID, Actor: actor,
			Action: lane.ActionUnblock, Before: before, After: lane.LaneNormal,
			At: now, Reason: reason, Revision: rec.Revision,
		}
		if err := appendLaneAuditTx(tx, entry); err != nil {
			return err // rolls back the whole unblock
		}
		return putLaneTx(tx, &rec)
	})
}

// appendLaneAuditTx writes the lane-side operator audit entry into the
// operator_audit bucket inside an open transaction. The entry is JSON-encoded
// in Detail so the full before/after revision history survives beside the
// control plane's own row.
func appendLaneAuditTx(tx *bolt.Tx, entry lane.AuditEntry) error {
	detail, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return appendOperatorTx(tx, control.OperatorRecord{
		At: entry.At.UTC(), Actor: entry.Actor, Action: "lane." + strings.ToLower(entry.Action.String()),
		Target: entry.CredentialID + "/" + entry.LaneID, Reason: entry.Reason,
		Committed: true, Detail: string(detail),
	})
}
