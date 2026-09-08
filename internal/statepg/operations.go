package statepg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/B-A-M-N/gripline/internal/control"
	"github.com/jackc/pgx/v5"
)

const maxOperationIDBytes = 256

// operatorMutationPayload deliberately excludes timestamps and the observed
// posture. Those values can legitimately differ when a client retries an
// operation after an ambiguous commit; the operator identity, action, target,
// reason, and actual mutation payload must not.
func operatorMutationPayload(audit control.OperatorRecord, mutation any) any {
	return struct {
		Action   string `json:"action"`
		Actor    string `json:"actor"`
		Target   string `json:"target"`
		Reason   string `json:"reason"`
		Mutation any    `json:"mutation"`
	}{
		Action: audit.Action, Actor: audit.Actor, Target: audit.Target,
		Reason: audit.Reason, Mutation: mutation,
	}
}

func claimControlOperation(ctx context.Context, tx pgx.Tx, operationID, action string, payload any, now time.Time) (bool, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" {
		return false, nil
	}
	if len([]byte(operationID)) > maxOperationIDBytes || !utf8.ValidString(operationID) || strings.IndexByte(operationID, 0) >= 0 {
		return false, control.ErrOperationIDInvalid
	}
	raw, err := json.Marshal(struct {
		Action  string `json:"action"`
		Payload any    `json:"payload"`
	}{Action: action, Payload: payload})
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(digest[:])
	result, err := tx.Exec(ctx, `INSERT INTO gripline_control_operations
		(operation_id, action, payload_fingerprint, created_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT (operation_id) DO NOTHING`,
		operationID, action, fingerprint, now.UTC())
	if err != nil {
		return false, mapDBError(err)
	}
	if result.RowsAffected() != 0 {
		return false, nil
	}
	var existingAction, existingFingerprint string
	if err := tx.QueryRow(ctx, `SELECT action, payload_fingerprint
		FROM gripline_control_operations WHERE operation_id=$1 FOR UPDATE`, operationID).
		Scan(&existingAction, &existingFingerprint); err != nil {
		return false, mapDBError(err)
	}
	if existingAction != action || existingFingerprint != fingerprint {
		return false, control.ErrOperationConflict
	}
	return true, nil
}
