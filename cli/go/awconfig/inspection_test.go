package awconfig

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const inspectionWorkspace = `aweb_url: " https://aweb.example/api "
memberships:
  - team_id: " backend:example.com "
    alias: " alice "
    workspace_id: " workspace-1 "
    cert_path: " team-certs/backend.pem "
`

func TestWorkspaceInspectionAndCommandShareNormalizedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.yaml")
	if err := os.WriteFile(path, []byte(inspectionWorkspace), 0o600); err != nil {
		t.Fatal(err)
	}
	command, err := LoadWorktreeWorkspaceFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := InspectWorktreeWorkspaceFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inspection, command) || inspection.Memberships[0].Alias != "alice" {
		t.Fatalf("inspection and command disagree: %+v / %+v", inspection, command)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != inspectionWorkspace {
		t.Fatalf("inspection changed the file: %q, %v", body, err)
	}
}

func TestWorkspaceInspectionRetainsInvalidMembershipForDiagnosis(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.yaml")
	body := strings.Replace(inspectionWorkspace, `cert_path: " team-certs/backend.pem "`, `cert_path: ""`, 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWorktreeWorkspaceFrom(path); err == nil {
		t.Fatal("command accepted a membership with no certificate path")
	}
	inspection, err := InspectWorktreeWorkspaceFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Memberships) != 1 || inspection.Memberships[0].CertPath != "" || inspection.Memberships[0].TeamID != "backend:example.com" {
		t.Fatalf("inspection lost the invalid membership: %+v", inspection)
	}
}

func TestTeamInspectionRetainsInvalidActiveTeamWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "teams.yaml")
	body := []byte("active_team: ' missing:example.com '\nmemberships:\n  - team_id: ' backend:example.com '\n    alias: ' alice '\n    cert_path: ' team-certs/backend.pem '\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTeamStateFrom(path); err == nil {
		t.Fatal("command accepted an active team absent from memberships")
	}
	inspection, err := InspectTeamStateFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ActiveTeam != "missing:example.com" || len(inspection.Memberships) != 1 || inspection.Memberships[0].Alias != "alice" {
		t.Fatalf("inspection lost normalized diagnostic data: %+v", inspection)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, body) {
		t.Fatalf("inspection rewrote the invalid team state: %q, %v", after, err)
	}
}

func TestTeamInspectionDoesNotMigrateMissingFileFromWorkspace(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace.yaml")
	body := []byte("active_team: backend:example.com\n" + inspectionWorkspace)
	if err := os.WriteFile(workspace, body, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "teams.yaml")
	if _, err := InspectTeamStateFrom(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing inspection file = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection created teams.yaml: %v", err)
	}
	if after, err := os.ReadFile(workspace); err != nil || !bytes.Equal(after, body) {
		t.Fatalf("inspection changed migration input: %q, %v", after, err)
	}
}

func TestInspectionRejectsUnknownSchemaWithRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.yaml")
	if err := os.WriteFile(path, []byte(inspectionWorkspace+"unknown_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := InspectWorktreeWorkspaceFrom(path)
	if err == nil || !strings.Contains(err.Error(), "unknown_field") || !strings.HasSuffix(err.Error(), "Fix the YAML syntax and use only supported fields, then rerun aw doctor.") {
		t.Fatalf("unknown diagnostic input = %v", err)
	}
	if _, err := LoadWorktreeWorkspaceFrom(path); err == nil {
		t.Fatal("command accepted an unknown workspace field")
	}
}

func TestLegacyWorkspaceSentinelAndReleasedTextRemainAvailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.yaml")
	if err := os.WriteFile(path, []byte("aweb_url: https://aweb.example\nteam_id: backend:example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadWorktreeWorkspaceFrom(path)
	if !errors.Is(err, ErrLegacyWorkspaceSingleTeam) || err.Error() != LegacyWorkspaceSingleTeamError() {
		t.Fatalf("legacy shape lost its sentinel/text contract: %v", err)
	}
}
