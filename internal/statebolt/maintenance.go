package statebolt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// RecoveryManifest binds a backup to the exact bytes that were validated.
// Operators can verify the manifest before restoring, and automation can
// refuse a backup whose hash no longer matches its sidecar.
type RecoveryManifest struct {
	FormatVersion             int       `json:"format_version"`
	SchemaVersion             int       `json:"schema_version"`
	DatabaseSHA256            string    `json:"database_sha256"`
	DatabaseBytes             int64     `json:"database_bytes"`
	PolicyID                  string    `json:"policy_id,omitempty"`
	PolicyRevision            int       `json:"policy_revision,omitempty"`
	PolicyDigest              string    `json:"policy_digest,omitempty"`
	SignerPublicFingerprints  []string  `json:"signer_public_fingerprints,omitempty"`
	RequiredPepperVersions    []int     `json:"required_pepper_versions,omitempty"`
	RequiredPseudonymVersions []int     `json:"required_pseudonym_versions,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
}

// RecoveryMetadata records the non-database inputs required to restore a
// usable authority. It deliberately contains identifiers and public hashes,
// never signer private keys or pepper/pseudonym material.
type RecoveryMetadata struct {
	PolicyID                  string
	PolicyRevision            int
	PolicyDigest              string
	SignerPublicFingerprints  []string
	RequiredPepperVersions    []int
	RequiredPseudonymVersions []int
}

// CheckFile validates a state database without creating or modifying it.
func CheckFile(path string) error {
	if path == "" {
		return errors.New("statebolt: state path required")
	}
	if err := validateStateFile(path, false); err != nil {
		return err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("statebolt: open read-only: %w", err)
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if meta == nil || btoi(meta.Get(keySchemaVersion)) != currentSchemaVersion {
			return fmt.Errorf("statebolt: invalid schema: %w", ErrMigrationRequired)
		}
		for _, bucket := range [][]byte{bucketCredentials, bucketLanes, bucketEvidence, bucketOperatorAudit, bucketSecurityAudit, bucketOperatorState, bucketDetectorState} {
			if tx.Bucket(bucket) == nil {
				return fmt.Errorf("statebolt: missing bucket %q", bucket)
			}
		}
		return nil
	})
}

// Backup writes a consistent bbolt snapshot. It does not copy the live file
// at the filesystem level, so readers never observe a half-written database.
func (s *Store) Backup(path string) error {
	if s == nil || s.db == nil {
		return errors.New("statebolt: store is closed")
	}
	if path == "" {
		return errors.New("statebolt: backup path required")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	if err := s.view(func(tx *bolt.Tx) error { return tx.CopyFile(path, 0o600) }); err != nil {
		return fmt.Errorf("statebolt: consistent backup: %w", err)
	}
	return CheckFile(path)
}

// BackupWithManifest creates a consistent backup and a restricted sidecar
// containing its schema and content hash. The sidecar is written only after
// the backup passes CheckFile.
func (s *Store) BackupWithManifest(path, manifestPath string) error {
	return errors.New("statebolt: recovery metadata is required; use BackupWithRecoveryManifest")
}

// BackupWithRecoveryManifest creates a consistent backup plus a manifest that
// binds the database to the policy and public signing/key-version metadata the
// deployment must restore alongside it.
func (s *Store) BackupWithRecoveryManifest(path, manifestPath string, metadata RecoveryMetadata) error {
	if err := validateRecoveryMetadata(metadata); err != nil {
		return err
	}
	if err := s.Backup(path); err != nil {
		return err
	}
	if manifestPath == "" {
		manifestPath = path + ".manifest.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	manifest, err := json.MarshalIndent(RecoveryManifest{
		FormatVersion: 1, SchemaVersion: currentSchemaVersion,
		DatabaseSHA256: hex.EncodeToString(sum[:]), DatabaseBytes: int64(len(data)),
		PolicyID: metadata.PolicyID, PolicyRevision: metadata.PolicyRevision,
		PolicyDigest:              metadata.PolicyDigest,
		SignerPublicFingerprints:  append([]string(nil), metadata.SignerPublicFingerprints...),
		RequiredPepperVersions:    append([]int(nil), metadata.RequiredPepperVersions...),
		RequiredPseudonymVersions: append([]int(nil), metadata.RequiredPseudonymVersions...),
		CreatedAt:                 time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteRestricted(manifestPath, append(manifest, '\n'))
}

// ValidateRecoveryManifest verifies the mandatory sidecar hash, schema, and
// authority bindings before a restore.
func ValidateRecoveryManifest(backup, manifestPath string) error {
	if backup == "" || manifestPath == "" {
		return errors.New("statebolt: backup and recovery manifest paths required")
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var manifest RecoveryManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("statebolt: parse recovery manifest: %w", err)
	}
	if manifest.FormatVersion != 1 || manifest.SchemaVersion != currentSchemaVersion || manifest.PolicyID == "" || manifest.PolicyRevision < 1 || manifest.PolicyDigest == "" || len(manifest.SignerPublicFingerprints) == 0 || len(manifest.RequiredPepperVersions) == 0 {
		return fmt.Errorf("statebolt: unsupported recovery manifest format/schema: %w", ErrMigrationRequired)
	}
	sum := sha256.Sum256(data)
	if manifest.DatabaseBytes != int64(len(data)) || manifest.DatabaseSHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("statebolt: recovery manifest does not match backup")
	}
	return nil
}

func validateRecoveryMetadata(metadata RecoveryMetadata) error {
	if metadata.PolicyID == "" || metadata.PolicyRevision < 1 || metadata.PolicyDigest == "" {
		return errors.New("statebolt: recovery metadata requires policy id, positive revision, and digest")
	}
	if len(metadata.SignerPublicFingerprints) == 0 || len(metadata.RequiredPepperVersions) == 0 {
		return errors.New("statebolt: recovery metadata requires signer fingerprints and pepper versions")
	}
	return nil
}

func atomicWriteRestricted(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gripline-manifest-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

// RestoreBackup validates the companion recovery manifest, copies a snapshot
// to the target atomically, and validates the installed file. The manifest is
// mandatory for recovery so a database cannot be restored without the policy,
// signer, and secret-version binding recorded beside it.
func RestoreBackup(backup, target string) (err error) {
	return RestoreBackupWithManifest(backup, backup+".manifest.json", target)
}

// RestoreBackupWithManifest validates the recovery sidecar before installing a
// snapshot. The target must be stopped; the writer-lock probe refuses a live
// database path before the atomic install.
func RestoreBackupWithManifest(backup, manifestPath, target string) error {
	if err := ValidateRecoveryManifest(backup, manifestPath); err != nil {
		return err
	}
	return restoreBackup(backup, target)
}

func restoreBackup(backup, target string) (err error) {
	if err := CheckFile(backup); err != nil {
		return fmt.Errorf("statebolt: backup is not usable: %w", err)
	}
	if target == "" {
		return errors.New("statebolt: restore target required")
	}
	if err := validateStateFile(target, true); err != nil {
		return err
	}
	// A filesystem rename over a live bbolt database would leave the running
	// process attached to the old inode while the configured path points at the
	// restored one. Probe the target's writer lock and refuse the operation when
	// another process has it open.
	if _, statErr := os.Stat(target); statErr == nil {
		live, openErr := bolt.Open(target, 0o600, &bolt.Options{Timeout: 10 * time.Millisecond})
		if openErr != nil {
			return fmt.Errorf("statebolt: restore target is active or unavailable: %w", openErr)
		}
		_ = live.Close()
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("statebolt: inspect restore target: %w", statErr)
	}
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gripline-restore-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	src, err := os.Open(backup)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	_, err = io.Copy(tmp, src)
	closeSrcErr := src.Close()
	if err == nil {
		err = closeSrcErr
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = CheckFile(tmpName); err != nil {
		return err
	}
	if err = os.Rename(tmpName, target); err != nil {
		return err
	}
	tmpName = ""
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr := d.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

// CompactFile performs offline bbolt compaction into a validated temporary
// file, then atomically installs it. The source must not be open by a running
// Gripline process.
func CompactFile(path string) (err error) {
	if path == "" {
		return errors.New("statebolt: compact path required")
	}
	src, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 10 * time.Millisecond})
	if err != nil {
		return fmt.Errorf("statebolt: open for compaction: %w", err)
	}
	defer src.Close()
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gripline-compact-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	dst, err := bolt.Open(tmpName, 0o600, &bolt.Options{Timeout: 10 * time.Millisecond})
	if err != nil {
		return err
	}
	err = bolt.Compact(dst, src, 0)
	if err == nil {
		err = dst.Sync()
	}
	closeErr := dst.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("statebolt: compact: %w", err)
	}
	if err = CheckFile(tmpName); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = ""
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	closeErr = d.Close()
	if err == nil {
		err = closeErr
	}
	return err
}
