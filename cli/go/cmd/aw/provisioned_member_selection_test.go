package main

import (
	"os"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestProvisionedSetupReuseRequiresTheSameInstalledMember(t *testing.T) {
	for _, changed := range []string{"unchanged", "other-service-team", "name", "scope", "team", "key"} {
		t.Run(changed, func(t *testing.T) {
			directory := t.TempDir()
			output, cert := writeSelfCustodyIdentityForTest(t, directory, "default:resume.example")
			home := awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(directory)}
			service := "https://service.example"
			if changed == "other-service-team" {
				service = ""
				otherTeam := "other:resume.example"
				workspacePath, err := awconfig.IdentityHomePath(home, "workspace.yaml")
				if err != nil {
					t.Fatal(err)
				}
				workspace := &awconfig.WorktreeWorkspace{AwebURL: "https://other.example", Memberships: []awconfig.WorktreeMembership{{TeamID: otherTeam, CertPath: awconfig.TeamCertificateRelativePath(otherTeam)}}}
				if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
					t.Fatal(err)
				}
			}
			if err := upsertAcceptedTeamMembershipState(teamMembershipStateUpdate{Location: teamMembershipLocation{WorkingDir: directory, IdentityHome: home.Root}, Output: output, Certificate: cert, AwebURL: service, Activation: membershipMakeActive}); err != nil {
				t.Fatal(err)
			}
			input := provisionedMemberSelection{Home: home, TeamID: cert.Team, Name: cert.Alias, Scope: awid.IdentityScopeLocal}
			switch changed {
			case "name":
				input.Name = "another"
			case "scope":
				input.Scope = awid.IdentityScopeGlobal
			case "team":
				input.TeamID = "another:resume.example"
			case "key":
				_, other, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(directory), other); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(awconfig.WorktreeSigningKeyPath(directory))
			if err != nil {
				t.Fatal(err)
			}
			accepted, err := existingProvisionedMember(input)
			if changed == "unchanged" || changed == "other-service-team" {
				if err != nil || accepted == nil || accepted.Certificate.CertificateID != cert.CertificateID || accepted.Certificate.MemberDIDKey != cert.MemberDIDKey {
					t.Fatalf("same member cannot resume: %v", err)
				}
				if accepted.AwebURL != service {
					t.Fatalf("accepted member service %q, want %q", accepted.AwebURL, service)
				}
			} else if err == nil || accepted != nil {
				t.Fatalf("changed %s selected an existing identity for setup", changed)
			}
			after, err := os.ReadFile(awconfig.WorktreeSigningKeyPath(directory))
			if err != nil || string(before) != string(after) {
				t.Fatalf("selection changed the local key: %v", err)
			}
		})
	}
}
