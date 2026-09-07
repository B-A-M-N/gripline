package statebolt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestSchemaV1MigratesWithPreMigrationBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{bucketMeta, bucketCredentials, bucketCredVerifier, bucketLanes, bucketEvidence, bucketOperatorAudit, bucketSecurityAudit, bucketOperatorState} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return tx.Bucket(bucketMeta).Put(keySchemaVersion, itob(1))
	}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".pre-migration-v1"); err != nil {
		t.Fatalf("pre-migration backup missing: %v", err)
	}
}

func TestBackupRestoreAndCheck(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source.db")
	backupPath := filepath.Join(dir, "backup", "state.db")
	targetPath := filepath.Join(dir, "restored", "state.db")

	store, err := Open(sourcePath, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Backup(backupPath); err != nil {
		_ = store.Close()
		t.Fatalf("backup: %v", err)
	}
	manifestPath := filepath.Join(dir, "backup", "state.manifest.json")
	if err := store.BackupWithRecoveryManifest(backupPath, manifestPath, RecoveryMetadata{
		PolicyID: "gripline-default-v1", PolicyRevision: 1, PolicyDigest: "policy-digest",
		SignerPublicFingerprints: []string{"1:public-fingerprint"},
		RequiredPepperVersions:   []int{1, 2}, RequiredPseudonymVersions: []int{3},
	}); err != nil {
		_ = store.Close()
		t.Fatalf("backup manifest: %v", err)
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest RecoveryManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil || manifest.FormatVersion != 1 || manifest.SchemaVersion != currentSchemaVersion || manifest.PolicyID != "gripline-default-v1" || manifest.PolicyDigest != "policy-digest" || len(manifest.SignerPublicFingerprints) != 1 || len(manifest.RequiredPepperVersions) != 2 || len(manifest.RequiredPseudonymVersions) != 1 {
		t.Fatalf("invalid recovery manifest: %v %+v", err, manifest)
	}
	if err := CheckFile(backupPath); err != nil {
		t.Fatalf("check backup: %v", err)
	}
	if err := ValidateRecoveryManifest(backupPath, manifestPath); err != nil {
		t.Fatalf("validate recovery manifest: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}
	if err := RestoreBackupWithManifest(backupPath, manifestPath, targetPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := CheckFile(targetPath); err != nil {
		t.Fatalf("check restored state: %v", err)
	}
}
