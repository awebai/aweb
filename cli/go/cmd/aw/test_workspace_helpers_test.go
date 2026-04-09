package main

import (
	"crypto/ed25519"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func testCommandEnv(home string) []string {
	mirrorLegacyKnownAgentsFixture(home)
	return append(os.Environ(),
		"HOME="+home,
		"AW_CONFIG_PATH=",
	)
}

func writeWorkspaceBindingForTest(t *testing.T, workingDir string, state awconfig.WorktreeWorkspace) string {
	t.Helper()
	activeMembership := state.ActiveMembership()
	if strings.TrimSpace(state.AwebURL) != "" && activeMembership != nil {
		certPath := awconfig.TeamCertificatePath(workingDir, activeMembership.TeamID)
		signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			fixture := testSelectionFixture{
				TeamID:      activeMembership.TeamID,
				Alias:       activeMembership.Alias,
				WorkspaceID: activeMembership.WorkspaceID,
				CreatedAt:   "2026-04-04T00:00:00Z",
			}
			if signingKey, err := awid.LoadSigningKey(signingKeyPath); err == nil {
				fixture.SigningKey = signingKey
			}
			writeTeamCertificateWorkspaceForTest(t, workingDir, state, &fixture)
		} else if _, err := os.Stat(signingKeyPath); os.IsNotExist(err) {
			writeTeamCertificateWorkspaceForTest(t, workingDir, state, nil)
		}
	}
	path := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := awconfig.SaveWorktreeWorkspaceTo(path, &state); err != nil {
		t.Fatalf("write workspace binding: %v", err)
	}
	return path
}

func writeContextForTest(t *testing.T, workingDir string, ctx awconfig.WorktreeContext) string {
	t.Helper()
	path := filepath.Join(workingDir, ".aw", "context")
	if err := awconfig.SaveWorktreeContextTo(path, &ctx); err != nil {
		t.Fatalf("write worktree context: %v", err)
	}
	return path
}

func writeIdentityForTest(t *testing.T, workingDir string, state awconfig.WorktreeIdentity) string {
	t.Helper()
	path := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	if err := awconfig.SaveWorktreeIdentityTo(path, &state); err != nil {
		t.Fatalf("write worktree identity: %v", err)
	}
	return path
}

func defaultWorkspaceBinding(serverURL string) awconfig.WorktreeWorkspace {
	return workspaceBinding(serverURL, "backend:demo", "alice", "workspace-1")
}

func writeDefaultWorkspaceBindingForTest(t *testing.T, workingDir, serverURL string) string {
	t.Helper()
	return writeWorkspaceBindingForTest(t, workingDir, defaultWorkspaceBinding(serverURL))
}

func workspaceBinding(serverURL, teamID, alias, workspaceID string) awconfig.WorktreeWorkspace {
	teamID = resolvedTeamIDForTest(teamID)
	return awconfig.WorktreeWorkspace{
		AwebURL:    strings.TrimSpace(serverURL),
		ActiveTeam: teamID,
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      teamID,
			Alias:       strings.TrimSpace(alias),
			WorkspaceID: strings.TrimSpace(workspaceID),
			CertPath:    awconfig.TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-04T00:00:00Z",
		}},
	}
}

func activeMembershipForTest(t *testing.T, state *awconfig.WorktreeWorkspace) *awconfig.WorktreeMembership {
	t.Helper()
	if state == nil {
		t.Fatal("workspace state is nil")
	}
	activeMembership := state.ActiveMembership()
	if activeMembership == nil {
		t.Fatal("workspace missing active membership")
	}
	return activeMembership
}

type testSelectionFixture struct {
	AwebURL     string
	TeamID      string
	Alias       string
	WorkspaceID string
	DID         string
	StableID    string
	Address     string
	Custody     string
	Lifetime    string
	SigningKey  ed25519.PrivateKey
	CreatedAt   string
}

func writeSelectionFixtureForTest(t *testing.T, workingDir string, fixture testSelectionFixture) {
	t.Helper()
	workspace := awconfig.WorktreeWorkspace{
		AwebURL:    fixture.AwebURL,
		ActiveTeam: resolvedTeamIDForTest(fixture.TeamID),
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      resolvedTeamIDForTest(fixture.TeamID),
			Alias:       fixture.Alias,
			WorkspaceID: fixture.WorkspaceID,
			CertPath:    awconfig.TeamCertificateRelativePath(resolvedTeamIDForTest(fixture.TeamID)),
			JoinedAt:    fixture.CreatedAt,
		}},
	}
	writeTeamCertificateWorkspaceForTest(t, workingDir, workspace, &fixture)
	if fixture.SigningKey != nil {
		if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), fixture.SigningKey); err != nil {
			t.Fatalf("write signing key: %v", err)
		}
	}
	writeWorkspaceBindingForTest(t, workingDir, workspace)

	if fixture.DID == "" && fixture.StableID == "" && fixture.Custody == "" && fixture.Lifetime == "" && fixture.Address == "" {
		return
	}

	createdAt := fixture.CreatedAt
	if createdAt == "" {
		createdAt = "2026-04-04T00:00:00Z"
	}
	writeIdentityForTest(t, workingDir, awconfig.WorktreeIdentity{
		DID:       fixture.DID,
		StableID:  fixture.StableID,
		Address:   fixture.Address,
		Custody:   fixture.Custody,
		Lifetime:  fixture.Lifetime,
		CreatedAt: createdAt,
	})

}

func writeTeamCertificateWorkspaceForTest(t *testing.T, workingDir string, workspace awconfig.WorktreeWorkspace, fixture *testSelectionFixture) {
	t.Helper()

	activeMembership := workspace.ActiveMembership()
	if activeMembership == nil {
		t.Fatal("workspace missing active membership")
	}

	alias := strings.TrimSpace(activeMembership.Alias)
	if alias == "" {
		alias = "alice"
	}
	teamID := resolvedTeamIDForTest(strings.TrimSpace(activeMembership.TeamID))
	teamDomain, _, err := awid.ParseTeamID(teamID)
	if err != nil {
		t.Fatalf("parse team_id %q: %v", teamID, err)
	}
	memberAddress := deriveIdentityAddress(teamDomain, alias)
	if fixture != nil && strings.TrimSpace(fixture.Address) != "" {
		memberAddress = strings.TrimSpace(fixture.Address)
	}
	lifetime := awid.LifetimePersistent
	if fixture != nil && strings.TrimSpace(fixture.Lifetime) != "" {
		lifetime = strings.TrimSpace(fixture.Lifetime)
	}

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate team keypair: %v", err)
	}

	var memberKey ed25519.PrivateKey
	memberDID := ""
	memberStableID := ""
	if fixture != nil && fixture.SigningKey != nil {
		memberKey = fixture.SigningKey
		memberDID = strings.TrimSpace(fixture.DID)
		if memberDID == "" {
			memberDID = awid.ComputeDIDKey(memberKey.Public().(ed25519.PublicKey))
		}
		memberStableID = strings.TrimSpace(fixture.StableID)
		if memberStableID == "" && lifetime == awid.LifetimePersistent {
			memberStableID = awid.ComputeStableID(memberKey.Public().(ed25519.PublicKey))
		}
	} else {
		memberPub, generatedKey, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatalf("generate member keypair: %v", err)
		}
		memberKey = generatedKey
		memberDID = awid.ComputeDIDKey(memberPub)
		if lifetime == awid.LifetimePersistent {
			memberStableID = awid.ComputeStableID(memberPub)
		}
	}

	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  memberDID,
		MemberDIDAW:   memberStableID,
		MemberAddress: memberAddress,
		Alias:         alias,
		Lifetime:      lifetime,
	})
	if err != nil {
		t.Fatalf("sign team certificate: %v", err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(workingDir, teamID, cert); err != nil {
		t.Fatalf("write team certificate: %v", err)
	}
	if fixture == nil || fixture.SigningKey == nil {
		if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), memberKey); err != nil {
			t.Fatalf("write signing key: %v", err)
		}
	}

	if fixture == nil {
		if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
			DID:       memberDID,
			StableID:  memberStableID,
			Address:   memberAddress,
			Custody:   awid.CustodySelf,
			Lifetime:  lifetime,
			CreatedAt: "2026-04-04T00:00:00Z",
		}); err != nil {
			t.Fatalf("write worktree identity: %v", err)
		}
	}
}

func resolvedTeamIDForTest(teamID string) string {
	if strings.TrimSpace(teamID) != "" {
		return strings.TrimSpace(teamID)
	}
	return "backend:demo"
}

func requireCertificateAuthForTest(t *testing.T, r *http.Request) {
	t.Helper()
	if !strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "DIDKey ") {
		t.Fatalf("auth=%q", r.Header.Get("Authorization"))
	}
	if strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) == "" {
		t.Fatal("missing X-AWID-Team-Certificate header")
	}
}

func mirrorLegacyKnownAgentsFixture(workingDir string) {
	sourcePath := filepath.Join(workingDir, "known_agents.yaml")
	if _, err := os.Stat(sourcePath); err != nil {
		return
	}
	targetPath, err := awconfig.DefaultKnownAgentsPath()
	if err != nil {
		return
	}
	if _, err := os.Stat(targetPath); err == nil {
		return
	}
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(targetPath), 0o700)
	_ = os.WriteFile(targetPath, data, 0o600)
}
