package statebolt

import (
	"path/filepath"
	"testing"
)

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
	if err := store.Close(); err != nil {
		t.Fatalf("close source: %v", err)
	}
	if err := CheckFile(backupPath); err != nil {
		t.Fatalf("check backup: %v", err)
	}
	if err := RestoreBackup(backupPath, targetPath); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := CheckFile(targetPath); err != nil {
		t.Fatalf("check restored state: %v", err)
	}
}
