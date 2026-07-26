package awconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInviteTokenRoundTrip(t *testing.T) {
	invite := &TeamInvite{
		InviteID:  "inv-001",
		Domain:    "acme.com",
		TeamName:  "backend",
		Ephemeral: false,
		Secret:    "test-secret-abc",
		CreatedAt: "2026-04-06T00:00:00Z",
	}

	token, err := EncodeInviteToken(invite)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("token is empty")
	}

	decoded, err := DecodeInviteToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.InviteID != invite.InviteID {
		t.Fatalf("invite_id=%q want %q", decoded.InviteID, invite.InviteID)
	}
	if decoded.Domain != invite.Domain {
		t.Fatalf("domain=%q", decoded.Domain)
	}
	if decoded.TeamName != invite.TeamName {
		t.Fatalf("team_name=%q", decoded.TeamName)
	}
	if decoded.Secret != invite.Secret {
		t.Fatalf("secret=%q", decoded.Secret)
	}
}

func TestDecodeInviteTokenRejectsGarbage(t *testing.T) {
	if _, err := DecodeInviteToken("not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for garbage token")
	}
}

func TestDecodeInviteTokenRejectsIncomplete(t *testing.T) {
	// Valid base64 but missing fields
	if _, err := DecodeInviteToken("e30"); err == nil {
		t.Fatal("expected error for incomplete token")
	}
}

func TestSaveAndLoadTeamInvite(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	invite := &TeamInvite{
		InviteID:  "inv-002",
		Domain:    "acme.com",
		TeamName:  "backend",
		Ephemeral: true,
		Secret:    "secret-xyz",
		CreatedAt: "2026-04-06T00:00:00Z",
	}

	if err := SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadTeamInvite("inv-002")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Domain != "acme.com" {
		t.Fatalf("domain=%q", loaded.Domain)
	}
	if loaded.TeamName != "backend" {
		t.Fatalf("team_name=%q", loaded.TeamName)
	}
	if !loaded.Ephemeral {
		t.Fatal("ephemeral should be true")
	}

	if err := DeleteTeamInvite("inv-002"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTeamInvite("inv-002"); err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestListTeamInvitesByOperation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	for _, invite := range []*TeamInvite{
		{InviteID: "inv-owned-a", Domain: "acme.com", TeamName: "backend", Ephemeral: true, Secret: "secret-a", OperationID: "oas-AAAAAAAAAAAAAAAAAAAAAA", CreatedAt: "2026-04-06T00:00:00Z"},
		{InviteID: "inv-other", Domain: "acme.com", TeamName: "backend", Ephemeral: true, Secret: "secret-b", OperationID: "oas-BBBBBBBBBBBBBBBBBBBBBQ", CreatedAt: "2026-04-06T00:00:00Z"},
		{InviteID: "inv-owned-b", Domain: "acme.com", TeamName: "backend", Ephemeral: true, Secret: "secret-c", OperationID: "oas-AAAAAAAAAAAAAAAAAAAAAA", CreatedAt: "2026-04-06T00:00:01Z"},
	} {
		if err := SaveTeamInvite(invite); err != nil {
			t.Fatal(err)
		}
	}

	matches, err := ListTeamInvitesByOperation("oas-AAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 || matches[0].InviteID != "inv-owned-a" || matches[1].InviteID != "inv-owned-b" {
		t.Fatalf("matches=%+v", matches)
	}
	if matches[0].OperationID != "oas-AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("operation_id=%q", matches[0].OperationID)
	}
	if _, err := ListTeamInvitesByOperation(""); err == nil {
		t.Fatal("empty operation id should be rejected")
	}
	invalid := &TeamInvite{InviteID: "inv-invalid", Domain: "acme.com", TeamName: "backend", Ephemeral: true, Secret: "secret", OperationID: "not.valid", CreatedAt: "2026-04-06T00:00:00Z"}
	if err := SaveTeamInvite(invalid); err == nil {
		t.Fatal("invalid operation id should not be persisted")
	}
}

func TestListTeamInvitesByOperationRejectsSymlinkedGrant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	invite := &TeamInvite{InviteID: "inv-owned", Domain: "acme.com", TeamName: "backend", Ephemeral: true, Secret: "secret", OperationID: "oas-AAAAAAAAAAAAAAAAAAAAAA", CreatedAt: "2026-04-06T00:00:00Z"}
	if err := SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	path, err := teamInvitePath(invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "same-material.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := ListTeamInvitesByOperation(invite.OperationID); err == nil {
		t.Fatal("symlinked grant should be rejected")
	}
}

func TestGenerateInviteSecret(t *testing.T) {
	s1, err := GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := GenerateInviteSecret()
	if err != nil {
		t.Fatal(err)
	}
	if s1 == "" || s2 == "" {
		t.Fatal("empty secret")
	}
	if s1 == s2 {
		t.Fatal("secrets should be unique")
	}
}
