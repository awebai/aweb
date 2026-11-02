package awconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
)

var idInvitationFileName = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IdentityInvitationsDir is where an identity's issuer keeps the
// invitations it fixed, beside its issuance log. Invitations hold the
// private recipient note, so they stay in the issuer's records and are never
// exported.
func IdentityInvitationsDir(identityHome string) string {
	return filepath.Join(identityHome, "invitations")
}

// ControllerInvitationsDir is where the namespace controller of domain keeps
// the invitations the root fixed, beside its key and issuance log.
func ControllerInvitationsDir(domain string) (string, error) {
	dir, err := DefaultControllersDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, NormalizeDomain(domain)+".invitations"), nil
}

// IDInvitationFileStore keeps one private file per invitation, named by its
// invitation ID. Each invitation also holds the one request bound to it and
// that request's response, so there is no separate pending store. Callers
// hold the issuer's transaction lock across a read-modify-write.
type IDInvitationFileStore struct {
	Dir string
}

func (s IDInvitationFileStore) path(invitationID string) (string, error) {
	if !idInvitationFileName.MatchString(invitationID) {
		return "", fmt.Errorf("invalid invitation ID %q", invitationID)
	}
	return filepath.Join(s.Dir, invitationID+".json"), nil
}

func (s IDInvitationFileStore) Invitation(invitationID string) (*awid.IDInvitation, error) {
	path, err := s.path(invitationID)
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
	var inv awid.IDInvitation
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&inv); err != nil {
		return nil, fmt.Errorf("invitation %s: %w", path, err)
	}
	if inv.InvitationID != invitationID {
		return nil, fmt.Errorf("invitation file %s records %s", path, inv.InvitationID)
	}
	return &inv, nil
}

// PutInvitation durably replaces the invitation: the file and the directory
// that names it are both synced before it returns.
func (s IDInvitationFileStore) PutInvitation(inv *awid.IDInvitation) error {
	path, err := s.path(inv.InvitationID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return durableWriteFile(path, append(data, '\n'))
}

// Invitations lists every invitation, ordered by invitation ID.
func (s IDInvitationFileStore) Invitations() ([]*awid.IDInvitation, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return []*awid.IDInvitation{}, nil
	}
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, e := range entries {
		if id, ok := strings.CutSuffix(e.Name(), ".json"); ok && !e.IsDir() && idInvitationFileName.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	out := []*awid.IDInvitation{}
	for _, id := range ids {
		inv, err := s.Invitation(id)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, nil
}
