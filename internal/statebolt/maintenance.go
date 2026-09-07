package statebolt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

// CheckFile validates a state database without creating or modifying it.
func CheckFile(path string) error {
	if path == "" {
		return errors.New("statebolt: state path required")
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
		for _, bucket := range [][]byte{bucketCredentials, bucketLanes, bucketEvidence, bucketOperatorAudit, bucketSecurityAudit, bucketOperatorState} {
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
	if err := s.db.View(func(tx *bolt.Tx) error { return tx.CopyFile(path, 0o600) }); err != nil {
		return fmt.Errorf("statebolt: consistent backup: %w", err)
	}
	return CheckFile(path)
}

// RestoreBackup validates a snapshot, copies it to the target atomically, and
// validates the installed file. The target must be stopped by the operator;
// this command deliberately cannot coordinate with another running process.
func RestoreBackup(backup, target string) (err error) {
	if err := CheckFile(backup); err != nil {
		return fmt.Errorf("statebolt: backup is not usable: %w", err)
	}
	if target == "" {
		return errors.New("statebolt: restore target required")
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
