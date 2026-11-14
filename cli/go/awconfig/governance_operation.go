package awconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	// Quarantine, when set, marks an operation aw will not resume: its saved
	// body is in an approval format the service no longer serves, or was
	// prepared under another authority generation, and its outcome is not
	// settled. It keeps what aw observed for reconciliation.
	Quarantine *GovernanceQuarantine `json:"quarantine,omitempty"`
}

// GovernanceQuarantine is what aw last observed of a quarantined operation:
// its receipt's state and code, any signed bytes the receipt carried, and
// how far aw could verify them. Facts once observed are kept when a later
// read cannot be answered.
type GovernanceQuarantine struct {
	State        string `json:"state"`
	Code         string `json:"code,omitempty"`
	Signing      []byte `json:"signing,omitempty"`
	Signature    []byte `json:"signature,omitempty"`
	Verification string `json:"verification"`
	ObservedAt   string `json:"observed_at"`
	// Conflicts are every other signed result later reads carried, each
	// once, in the order observed; the original observation is kept beside
	// them.
	Conflicts []GovernanceSignedResult `json:"conflicts,omitempty"`
}

// GovernanceSignedResult is one signed result a receipt carried.
type GovernanceSignedResult struct {
	Signing   []byte `json:"signing"`
	Signature []byte `json:"signature"`
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

// ListPendingGovernanceOperations returns every pending operation aw has
// saved, in no particular order.
func ListPendingGovernanceOperations() ([]*PendingGovernanceOperation, error) {
	dir, err := PathInUserState("governance")
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ops []*PendingGovernanceOperation
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !operationIDPattern.MatchString(id) {
			continue
		}
		op, err := LoadPendingGovernanceOperation(id)
		if err != nil {
			return nil, err
		}
		if op != nil {
			ops = append(ops, op)
		}
	}
	return ops, nil
}
