package awconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/awebai/aw/awid"
)

var idIssuanceFileName = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// IdentityIssuanceDir is where an identity's signer records the ID
// certificates it issued: inside that identity's own home.
func IdentityIssuanceDir(identityHome string) string {
	return filepath.Join(identityHome, "id-issuance")
}

// IDIssuanceFileStore keeps one durable file per issued certificate, named by
// its certificate ID. Callers hold the identity's transaction lock across a
// read-modify-write.
type IDIssuanceFileStore struct {
	Dir string
}

func (s IDIssuanceFileStore) path(certificateID string) (string, error) {
	m := idIssuanceFileName.FindStringSubmatch(certificateID)
	if m == nil {
		return "", fmt.Errorf("invalid certificate ID %q", certificateID)
	}
	return filepath.Join(s.Dir, m[1]+".json"), nil
}

// directory checks the store's directory: a real directory of mode 0700,
// never a symlink. With create, a missing directory is made and the identity
// home synced so the new name survives a crash.
func (s IDIssuanceFileStore) directory(create bool) (bool, error) {
	info, err := os.Lstat(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return false, nil
		}
		if err := os.Mkdir(s.Dir, 0o700); err != nil {
			return false, err
		}
		return true, syncDirectory(filepath.Dir(s.Dir))
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("issuance directory %s is not a directory", s.Dir)
	}
	if info.Mode().Perm() != 0o700 {
		return false, fmt.Errorf("issuance directory %s must have mode 0700, has %v", s.Dir, info.Mode().Perm())
	}
	return true, nil
}

func (s IDIssuanceFileStore) Entry(certificateID string) (*awid.IDIssuanceEntry, error) {
	path, err := s.path(certificateID)
	if err != nil {
		return nil, err
	}
	if exists, err := s.directory(false); err != nil || !exists {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry, err := decodeIDIssuanceEntry(data)
	if err != nil {
		return nil, fmt.Errorf("issuance entry %s: %w", path, err)
	}
	if entry.CertificateID != certificateID {
		return nil, fmt.Errorf("issuance entry %s records %s", path, entry.CertificateID)
	}
	return entry, nil
}

func (s IDIssuanceFileStore) EntryForRequest(requestID string) (*awid.IDIssuanceEntry, error) {
	if exists, err := s.directory(false); err != nil || !exists {
		return nil, err
	}
	names, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		base, ok := strings.CutSuffix(name.Name(), ".json")
		if !ok || name.IsDir() {
			continue
		}
		entry, err := s.Entry("sha256:" + base)
		if err != nil {
			return nil, err
		}
		if entry != nil && entry.Resign != nil && entry.Resign.RequestID == requestID {
			return entry, nil
		}
	}
	return nil, nil
}

// Put durably replaces the entry: the file and the directory that names it
// are both synced before Put returns.
func (s IDIssuanceFileStore) Put(entry *awid.IDIssuanceEntry) error {
	path, err := s.path(entry.CertificateID)
	if err != nil {
		return err
	}
	if _, err := s.directory(true); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return durableWriteFile(path, append(data, '\n'))
}

func decodeIDIssuanceEntry(data []byte) (*awid.IDIssuanceEntry, error) {
	var entry awid.IDIssuanceEntry
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// durableWriteFile writes a private file by temp-file-and-rename, then syncs
// the directory so the rename itself survives a crash.
func durableWriteFile(path string, data []byte) error {
	if err := atomicWriteFileMode(path, data, 0o600); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}
