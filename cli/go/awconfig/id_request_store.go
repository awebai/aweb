package awconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A requester's outstanding requests, kept in its own records: a prepared
// human's directory or an agent's identity home. Each holds the exact signed
// request until a matching response is imported, and then that exact
// response and its registration state, so a retry never needs a new key or
// a new parent signature.

const (
	// IDRequestOutstanding: exported, waiting for the parent's response.
	IDRequestOutstanding = "outstanding"
	// IDRequestImported: the verified response is installed.
	IDRequestImported = "imported"
)

// IDOutgoingRequest is one request this identity sent to a parent.
type IDOutgoingRequest struct {
	RequestID    string `json:"request_id"`
	InvitationID string `json:"invitation_id"`
	Request      string `json:"request"`
	State        string `json:"state"`
	Response     string `json:"response,omitempty"`
	// Registration is "pending" until AWID accepted the certificate, then
	// "registered"; empty for a local child, which registers nothing.
	Registration string `json:"registration,omitempty"`
	RegisteredAt string `json:"registered_at,omitempty"`
}

// IdentityRequestsDir is where an identity keeps its outgoing requests.
func IdentityRequestsDir(identityHome string) string {
	return filepath.Join(identityHome, "requests")
}

// IDRequestFileStore keeps one private file per outgoing request.
type IDRequestFileStore struct {
	Dir string
}

func (s IDRequestFileStore) path(requestID string) (string, error) {
	if !idInvitationFileName.MatchString(requestID) {
		return "", fmt.Errorf("invalid request ID %q", requestID)
	}
	return filepath.Join(s.Dir, requestID+".json"), nil
}

// Request returns the outgoing request requestID, or nil when there is none.
func (s IDRequestFileStore) Request(requestID string) (*IDOutgoingRequest, error) {
	path, err := s.path(requestID)
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
	var r IDOutgoingRequest
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&r); err != nil {
		return nil, fmt.Errorf("request %s: %w", path, err)
	}
	if r.RequestID != requestID {
		return nil, fmt.Errorf("request file %s records %s", path, r.RequestID)
	}
	return &r, nil
}

// Put durably replaces the outgoing request.
func (s IDRequestFileStore) Put(r *IDOutgoingRequest) error {
	path, err := s.path(r.RequestID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return durableWriteFile(path, append(data, '\n'))
}

// ForInvitation recovers the exact outgoing exchange after an interrupted join.
func (s IDRequestFileStore) ForInvitation(invitationID string) (*IDOutgoingRequest, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		r, err := s.Request(entry.Name()[:len(entry.Name())-5])
		if err != nil {
			return nil, err
		}
		if r.InvitationID == invitationID {
			return r, nil
		}
	}
	return nil, nil
}
