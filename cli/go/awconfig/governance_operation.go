package awconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// PendingGovernanceOperation is a protected operation aw prepared and has not
// yet seen reach a final receipt: the exact prepare body it sent, and the
// pinned origins it sent it to. A lost prepare answer is resumed from it with
// the same bytes, never re-prepared; it is removed on a final receipt. It
// holds no key and no approval.
type PendingGovernanceOperation struct {
	OperationID   string `json:"operation_id"`
	RequestOrigin string `json:"request_origin"`
	HumanOrigin   string `json:"human_origin"`
	Body          []byte `json:"body"`
}

var operationIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// pendingGovernanceOperationPath is the operation's owner-only file in aw's
// state directory.
func pendingGovernanceOperationPath(operationID string) (string, error) {
	if !operationIDPattern.MatchString(operationID) {
		return "", fmt.Errorf("invalid operation id %q", operationID)
	}
	return PathInUserState("governance", operationID+".json")
}

// SavePendingGovernanceOperation durably writes op, readable only by its owner.
func SavePendingGovernanceOperation(op *PendingGovernanceOperation) error {
	if op == nil {
		return errors.New("nil governance operation")
	}
	path, err := pendingGovernanceOperationPath(op.OperationID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(op)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data)
}

// LoadPendingGovernanceOperation returns the pending operation operationID,
// or nil when there is none.
func LoadPendingGovernanceOperation(operationID string) (*PendingGovernanceOperation, error) {
	path, err := pendingGovernanceOperationPath(operationID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var op PendingGovernanceOperation
	if err := json.Unmarshal(data, &op); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if op.OperationID != operationID {
		return nil, fmt.Errorf("%s names operation %s", filepath.Base(path), op.OperationID)
	}
	return &op, nil
}

// RemovePendingGovernanceOperation forgets operationID; an absent one is not
// an error.
func RemovePendingGovernanceOperation(operationID string) error {
	path, err := pendingGovernanceOperationPath(operationID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
