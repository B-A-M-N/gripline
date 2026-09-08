package policy

// This file contains the small durable policy journal used by the executable
// runtime. It is deliberately separate from the bbolt security-state store:
// policy artifacts are deployment inputs, while bbolt remains the sole
// authority for credentials, lanes, evidence, posture, and operator actions.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

type fileStoreRecord struct {
	Manifest Manifest `json:"manifest"`
	Event    *Event   `json:"last_event,omitempty"`
}

// FileStore retains the lifecycle manifest, an append-only transition journal,
// and exact compiled policy artifacts. All writes use restricted temporary
// files and fsync/rename, so a crash cannot expose a half-written candidate.
type FileStore struct {
	mu           sync.Mutex
	dir          string
	manifestPath string
	auditPath    string
}

func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("policy: file store directory required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("policy: create lifecycle directory: %w", err)
	}
	if err := validatePolicyDir(dir); err != nil {
		return nil, fmt.Errorf("policy: lifecycle directory: %w", err)
	}
	return &FileStore{dir: dir, manifestPath: filepath.Join(dir, "manifest.json"), auditPath: filepath.Join(dir, "audit.jsonl")}, nil
}

// OpenFileStore opens an existing lifecycle directory without creating it.
// Read-only operator views use this constructor so status inspection cannot
// accidentally provision a new policy authority.
func OpenFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("policy: file store directory required")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("policy: lifecycle path is not a directory")
	}
	if err := validatePolicyDir(dir); err != nil {
		return nil, fmt.Errorf("policy: lifecycle directory: %w", err)
	}
	return &FileStore{dir: dir, manifestPath: filepath.Join(dir, "manifest.json"), auditPath: filepath.Join(dir, "audit.jsonl")}, nil
}

func validatePolicyDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("lifecycle directory must be a real directory")
	}
	if info.Mode().Perm()&0o022 != 0 && !policyDirOwnedByProcess(info) {
		return fmt.Errorf("lifecycle directory permissions %04o are writable by group/other", info.Mode().Perm())
	}
	return nil
}

func policyDirOwnedByProcess(info os.FileInfo) bool {
	if info.Mode().Perm()&0o002 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && int(stat.Gid) == os.Getgid()
}

func (s *FileStore) LoadManifest() (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Lstat(s.manifestPath); errors.Is(err, os.ErrNotExist) {
		return Manifest{}, nil
	} else if err != nil {
		return Manifest{}, err
	}
	data, err := readArtifact(s.manifestPath)
	if err != nil {
		return Manifest{}, err
	}
	var record fileStoreRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return Manifest{}, fmt.Errorf("policy: parse lifecycle manifest: %w", err)
	}
	if record.Manifest.SchemaVersion != 1 || record.Manifest.Active.ID == "" || record.Manifest.Active.Revision < 1 || record.Manifest.Active.Digest == "" {
		return Manifest{}, errors.New("policy: invalid lifecycle manifest")
	}
	return record.Manifest, nil
}

func (s *FileStore) Persist(m Manifest) error {
	return s.persist(m, nil)
}

func (s *FileStore) PersistTransition(m Manifest, event Event) error {
	return s.persist(m, &event)
}

func (s *FileStore) persist(m Manifest, event *Event) error {
	if s == nil {
		return errors.New("policy: nil file store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.SchemaVersion != 1 || m.Active.ID == "" || m.Active.Revision < 1 || m.Active.Digest == "" {
		return errors.New("policy: refusing invalid lifecycle manifest")
	}
	if _, err := os.Lstat(s.manifestPath); errors.Is(err, os.ErrNotExist) {
		// First durable manifest.
	} else if err != nil {
		return err
	} else if previous, err := readArtifact(s.manifestPath); err == nil {
		var old fileStoreRecord
		if err := json.Unmarshal(previous, &old); err != nil {
			return fmt.Errorf("policy: parse existing lifecycle manifest: %w", err)
		}
		rollback := event != nil && event.Action == "rollback" && event.Reason != ""
		if (!rollback && old.Manifest.Active.Revision > m.Active.Revision) || (old.Manifest.Active.Revision == m.Active.Revision && old.Manifest.Active.Digest != m.Active.Digest) {
			return errors.New("policy: lifecycle revision would move backwards or change at the same revision")
		}
	} else {
		return err
	}
	data, err := json.Marshal(fileStoreRecord{Manifest: m, Event: event})
	if err != nil {
		return err
	}
	if err := atomicWrite(s.manifestPath, append(data, '\n')); err != nil {
		return err
	}
	if event != nil {
		line, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if _, statErr := os.Lstat(s.auditPath); statErr == nil {
			if err := validatePolicyFile(s.auditPath); err != nil {
				return err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		f, err := os.OpenFile(s.auditPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("policy: open lifecycle audit: %w", err)
		}
		if info, statErr := f.Stat(); statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			_ = f.Close()
			if statErr != nil {
				return statErr
			}
			return errors.New("policy: lifecycle audit must be a restricted regular file")
		}
		_, writeErr := f.Write(append(line, '\n'))
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func (s *FileStore) PersistArtifact(compiled *CompiledPolicy) error {
	if s == nil || compiled == nil {
		return errors.New("policy: artifact and file store required")
	}
	digest, err := Digest(&compiled.Policy)
	if err != nil {
		return err
	}
	data, err := json.Marshal(&compiled.Policy)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(s.dir, "policy-"+strconv.Itoa(compiled.Revision)+"-"+digest+".json"), append(data, '\n'))
}

func (s *FileStore) LoadArtifact(ref PolicyRef) (*CompiledPolicy, error) {
	if s == nil || ref.ID == "" || ref.Revision < 1 || ref.Digest == "" {
		return nil, errors.New("policy: invalid artifact reference")
	}
	path := filepath.Join(s.dir, "policy-"+strconv.Itoa(ref.Revision)+"-"+ref.Digest+".json")
	compiled, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	digest, err := Digest(&compiled.Policy)
	if err != nil || compiled.ID != ref.ID || compiled.Revision != ref.Revision || digest != ref.Digest {
		return nil, errors.New("policy: stored artifact does not match manifest reference")
	}
	return compiled, nil
}

func atomicWrite(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gripline-policy-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(name)
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
	if err = os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	d, err := os.Open(dir) // #nosec G304 -- policy directory is operator-owned configuration.
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
