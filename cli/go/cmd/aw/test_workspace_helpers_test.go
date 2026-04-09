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
	if strings.TrimSpace(state.AwebURL) != "" && strings.TrimSpace(state.TeamAddress) != "" {
		certPath := filepath.Join(workingDir, ".aw", "team-cert.pem")
		signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			fixture := testSelectionFixture{
				TeamAddress: state.TeamAddress,
				Alias:       state.Alias,
				WorkspaceID: state.WorkspaceID,
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
	return awconfig.WorktreeWorkspace{
		AwebURL:     serverURL,
		TeamAddress: "demo/backend",
		Alias:       "alice",
		WorkspaceID: "workspace-1",
	}
}

func writeDefaultWorkspaceBindingForTest(t *testing.T, workingDir, serverURL string) string {
	t.Helper()
	return writeWorkspaceBindingForTest(t, workingDir, defaultWorkspaceBinding(serverURL))
}

type testSelectionFixture struct {
	AwebURL     string
	TeamAddress string
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
		AwebURL:     fixture.AwebURL,
		TeamAddress: resolvedTeamAddressForTest(fixture.TeamAddress),
		Alias:       fixture.Alias,
		WorkspaceID: fixture.WorkspaceID,
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

	alias := strings.TrimSpace(workspace.Alias)
	if alias == "" {
		alias = "alice"
	}
	teamAddress := resolvedTeamAddressForTest(strings.TrimSpace(workspace.TeamAddress))
	teamDomain := teamAddress
	if idx := strings.IndexByte(teamAddress, '/'); idx >= 0 {
		teamDomain = teamAddress[:idx]
	}
	memberAddress := deriveIdentityAddress(teamDomain, "", alias)
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
		Team:          teamAddress,
		MemberDIDKey:  memberDID,
		MemberDIDAW:   memberStableID,
		MemberAddress: memberAddress,
		Alias:         alias,
		Lifetime:      lifetime,
	})
	if err != nil {
		t.Fatalf("sign team certificate: %v", err)
	}
	if err := awid.SaveTeamCertificate(filepath.Join(workingDir, ".aw", "team-cert.pem"), cert); err != nil {
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

func resolvedTeamAddressForTest(teamAddress string) string {
	if strings.TrimSpace(teamAddress) != "" {
		return strings.TrimSpace(teamAddress)
	}
	return "demo/backend"
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
