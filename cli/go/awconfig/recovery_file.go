package awconfig

import (
	"errors"
	"fmt"
	"github.com/awebai/aw/awid"
	"os"
	"strings"
)

// RecoveryFile is one operation's retained state in an explicitly selected
// identity home. The operation owns its existing encoding and reconciliation
// rules; this owner supplies path admission, private writes and file errors.
type RecoveryFile struct {
	Home IdentityHome
	Name string
}

// Path admits the retained file beneath its named home, without selecting an
// actor or falling back to the process working directory.
func (record RecoveryFile) Path() (string, error) {
	if strings.TrimSpace(record.Home.Root) == "" {
		return "", fmt.Errorf("recovery file requires an explicit identity home")
	}
	return IdentityHomePath(record.Home, record.Name)
}

// Read returns the original bytes, including an os.ErrNotExist error when no
// attempt exists. Unreadable or malformed paths never mean an absent attempt.
func (record RecoveryFile) Read() ([]byte, error) {
	path, err := record.Path()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// ReadBounded retains an operation's existing byte limit while using the same
// path admission as Read. A nonpositive limit is a caller error.
func (record RecoveryFile) ReadBounded(maxBytes int64) (raw []byte, resultErr error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("recovery read requires a positive byte limit")
	}
	path, err := record.Path()
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	return awid.ReadAllBounded(file, maxBytes)
}

// Write atomically replaces the admitted file at mode 0600, creating its parent
// at 0700 when absent. It never prints or includes the record bytes in an error.
func (record RecoveryFile) Write(raw []byte) error {
	path, err := record.Path()
	if err != nil {
		return err
	}
	return atomicWriteFile(path, raw)
}

// Remove discards a reconciled attempt. Absence is idempotent; all other file
// errors are returned so the operation can preserve its recovery guidance.
func (record RecoveryFile) Remove() error {
	path, err := record.Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
