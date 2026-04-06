package awconfig

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TeamInvite is a pending team invite stored locally by the team controller.
type TeamInvite struct {
	InviteID  string `json:"invite_id" yaml:"invite_id"`
	Domain    string `json:"domain" yaml:"domain"`
	TeamName  string `json:"team_name" yaml:"team_name"`
	Ephemeral bool   `json:"ephemeral" yaml:"ephemeral"`
	Secret    string `json:"secret" yaml:"secret"`
	CreatedAt string `json:"created_at" yaml:"created_at"`
}

// TeamInviteToken is the JSON structure encoded in the invite token
// that gets shared with the invitee.
type TeamInviteToken struct {
	InviteID string `json:"i"`
	Domain   string `json:"d"`
	TeamName string `json:"t"`
	Secret   string `json:"s"`
}

func DefaultTeamInvitesDir() (string, error) {
	return PathInUserState("team-invites")
}

func teamInvitePath(inviteID string) (string, error) {
	dir, err := DefaultTeamInvitesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, strings.TrimSpace(inviteID)+".json"), nil
}

// GenerateInviteSecret generates a cryptographically random secret for invite tokens.
func GenerateInviteSecret() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate invite secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// SaveTeamInvite persists a pending invite locally.
func SaveTeamInvite(invite *TeamInvite) error {
	if invite == nil {
		return errors.New("nil invite")
	}
	path, err := teamInvitePath(invite.InviteID)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(invite, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return atomicWriteFile(path, data)
}

// LoadTeamInvite loads a pending invite by ID.
func LoadTeamInvite(inviteID string) (*TeamInvite, error) {
	path, err := teamInvitePath(inviteID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var invite TeamInvite
	if err := json.Unmarshal(data, &invite); err != nil {
		return nil, fmt.Errorf("parse invite %s: %w", path, err)
	}
	return &invite, nil
}

// DeleteTeamInvite removes a consumed invite file.
func DeleteTeamInvite(inviteID string) error {
	path, err := teamInvitePath(inviteID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// EncodeInviteToken encodes an invite into a shareable base64url token.
func EncodeInviteToken(invite *TeamInvite) (string, error) {
	tok := TeamInviteToken{
		InviteID: invite.InviteID,
		Domain:   invite.Domain,
		TeamName: invite.TeamName,
		Secret:   invite.Secret,
	}
	data, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeInviteToken decodes a shareable base64url token.
func DecodeInviteToken(token string) (*TeamInviteToken, error) {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return nil, fmt.Errorf("invalid invite token: %w", err)
	}
	var tok TeamInviteToken
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("invalid invite token payload: %w", err)
	}
	if tok.InviteID == "" || tok.Domain == "" || tok.TeamName == "" || tok.Secret == "" {
		return nil, fmt.Errorf("incomplete invite token")
	}
	return &tok, nil
}
