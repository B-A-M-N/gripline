package statepg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ClusterNodeStatus is the sanitized operational identity of one membership
// row. It contains no credentials or key material; fingerprints are identity
// checksums suitable for operator diagnostics.
type ClusterNodeStatus struct {
	NodeID     string     `json:"node_id"`
	InstanceID string     `json:"instance_id"`
	NodeEpoch  int64      `json:"node_epoch"`
	Protocol   int        `json:"protocol_version"`
	Schema     int        `json:"schema_version"`
	State      string     `json:"state"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	DrainUntil *time.Time `json:"drain_until,omitempty"`
	Live       bool       `json:"live"`
	Local      bool       `json:"local"`
}

// ClusterCryptoGenerationStatus describes shared generation metadata and the
// number of live acknowledgements. It intentionally omits secret material.
type ClusterCryptoGenerationStatus struct {
	Kind              string    `json:"kind"`
	Generation        int       `json:"generation"`
	Fingerprint       string    `json:"fingerprint"`
	State             string    `json:"state"`
	AcknowledgedNodes int       `json:"acknowledged_nodes"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// ClusterCryptoStatus is the shared crypto activation view exposed to
// operators. Active generation fields are authoritative; the generation list
// shows staged capabilities and their live acknowledgement count.
type ClusterCryptoStatus struct {
	Initialized                bool                            `json:"initialized"`
	SignerActiveKID            int                             `json:"signer_active_kid,omitempty"`
	SignerActiveFingerprint    string                          `json:"signer_active_fingerprint,omitempty"`
	PepperActiveVersion        int                             `json:"pepper_active_version,omitempty"`
	PepperActiveFingerprint    string                          `json:"pepper_active_fingerprint,omitempty"`
	PseudonymActiveVersion     int                             `json:"pseudonym_active_version,omitempty"`
	PseudonymActiveFingerprint string                          `json:"pseudonym_active_fingerprint,omitempty"`
	GenerationEpoch            uint64                          `json:"generation_epoch,omitempty"`
	Generations                []ClusterCryptoGenerationStatus `json:"generations,omitempty"`
}

// ClusterStatus is a point-in-time, database-authoritative view of membership
// and shared cryptographic generations. It is intended for authenticated
// diagnostics and release automation, not admission decisions.
type ClusterStatus struct {
	NodeID     string              `json:"node_id"`
	InstanceID string              `json:"instance_id,omitempty"`
	NodeEpoch  int64               `json:"node_epoch,omitempty"`
	LocalReady bool                `json:"local_ready"`
	Nodes      []ClusterNodeStatus `json:"nodes"`
	Crypto     ClusterCryptoStatus `json:"crypto"`
}

// ClusterStatus returns shared membership and crypto state in one bounded
// read-only operation. A missing crypto singleton is reported as
// initialized=false so a newly migrated authority remains diagnosable.
func (s *Store) ClusterStatus(ctx context.Context) (ClusterStatus, error) {
	var out ClusterStatus
	if s == nil || s.pool == nil {
		return out, errors.New("statepg: authority is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	out.NodeID, out.InstanceID, out.NodeEpoch = s.nodeID, s.instanceID, s.nodeEpoch
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, mapDBError(err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT node_id, instance_id, node_epoch,
		protocol_version, schema_version, state, last_seen_at, drain_until,
		(state IN ('ready','draining') AND last_seen_at > CURRENT_TIMESTAMP -
			($1::double precision * interval '1 second')) AS live
		FROM gripline_membership ORDER BY node_id, node_epoch`, s.leaseTTL.Seconds())
	if err != nil {
		return out, mapDBError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var node ClusterNodeStatus
		var drainUntil *time.Time
		if err := rows.Scan(&node.NodeID, &node.InstanceID, &node.NodeEpoch,
			&node.Protocol, &node.Schema, &node.State, &node.LastSeenAt,
			&drainUntil, &node.Live); err != nil {
			return out, mapDBError(err)
		}
		node.DrainUntil = drainUntil
		node.Local = node.NodeID == s.nodeID && node.InstanceID == s.instanceID && node.NodeEpoch == s.nodeEpoch
		if node.Local {
			out.LocalReady = node.Live && node.State == "ready" && !s.fenced.Load()
		}
		out.Nodes = append(out.Nodes, node)
	}
	if err := rows.Err(); err != nil {
		return out, mapDBError(err)
	}

	var crypto ClusterCryptoStatus
	err = tx.QueryRow(ctx, `SELECT signer_active_kid, signer_active_fingerprint,
		pepper_active_version, pepper_active_fingerprint, pseudonym_version,
		pseudonym_active_fingerprint, generation_epoch
		FROM gripline_cluster_crypto WHERE singleton=TRUE`).Scan(
		&crypto.SignerActiveKID, &crypto.SignerActiveFingerprint,
		&crypto.PepperActiveVersion, &crypto.PepperActiveFingerprint,
		&crypto.PseudonymActiveVersion, &crypto.PseudonymActiveFingerprint,
		&crypto.GenerationEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		out.Crypto = crypto
		return out, nil
	}
	if err != nil {
		return out, mapDBError(err)
	}
	crypto.Initialized = true

	genRows, err := tx.Query(ctx, `SELECT g.kind, g.generation, g.fingerprint,
		g.state, g.updated_at,
		(SELECT COUNT(*) FROM gripline_cluster_crypto_acks a
			JOIN gripline_membership m ON m.node_id=a.node_id AND m.node_epoch=a.node_epoch
			WHERE a.kind=g.kind AND a.generation=g.generation AND a.fingerprint=g.fingerprint
			  AND m.state IN ('ready','draining')
			  AND m.last_seen_at > CURRENT_TIMESTAMP -
				($1::double precision * interval '1 second')) AS acknowledged_nodes
		FROM gripline_cluster_crypto_generations g
		ORDER BY g.kind, g.generation`, s.leaseTTL.Seconds())
	if err != nil {
		return out, mapDBError(err)
	}
	defer genRows.Close()
	for genRows.Next() {
		var generation ClusterCryptoGenerationStatus
		if err := genRows.Scan(&generation.Kind, &generation.Generation,
			&generation.Fingerprint, &generation.State, &generation.UpdatedAt,
			&generation.AcknowledgedNodes); err != nil {
			return out, mapDBError(err)
		}
		crypto.Generations = append(crypto.Generations, generation)
	}
	if err := genRows.Err(); err != nil {
		return out, mapDBError(err)
	}
	out.Crypto = crypto
	if err := tx.Commit(ctx); err != nil {
		return ClusterStatus{}, mapDBError(err)
	}
	return out, nil
}
