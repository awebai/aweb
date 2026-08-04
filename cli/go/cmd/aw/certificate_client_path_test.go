package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func teamCertificateForClientTest(teamID, address, memberDIDKey string) *awid.TeamCertificate {
	return &awid.TeamCertificate{
		Version:       1,
		CertificateID: "cert-" + address,
		Team:          teamID,
		TeamDIDKey:    "did:key:z6MkTeam",
		MemberDIDKey:  memberDIDKey,
		MemberDIDAW:   "did:aw:member",
		MemberAddress: address,
		Alias:         "member",
		IdentityScope: awid.IdentityModeGlobal,
		IssuedAt:      "2026-04-21T00:00:00Z",
		Signature:     "sig",
	}
}

// certificateClientFixture carries the Selection resolveCertificateClient is
// handed plus the signing key's did:key. Certificates in these tests must carry
// that did:key, or NewWithCertificate rejects them for a key/certificate
// mismatch before the path resolution under test is ever reached.
type certificateClientFixture struct {
	selection    *awconfig.Selection
	memberDIDKey string
}

func newCertificateClientFixture(t *testing.T, root, teamID, certPath string) certificateClientFixture {
	t.Helper()
	workspacePath := filepath.Join(root, ".aw", "workspace.yaml")
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, &awconfig.WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "member",
			WorkspaceID: "agent-member",
			CertPath:    certPath,
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signingKeyPath := awconfig.WorktreeSigningKeyPath(root)
	if err := awid.SaveSigningKey(signingKeyPath, priv); err != nil {
		t.Fatal(err)
	}
	return certificateClientFixture{
		selection: &awconfig.Selection{
			WorkingDir:    root,
			WorkspacePath: workspacePath,
			TeamID:        teamID,
			SigningKey:    signingKeyPath,
		},
		memberDIDKey: awid.ComputeDIDKey(pub),
	}
}

func TestResolveCertificateClientRejectsCertPathEscapingIdentityHome(t *testing.T) {
	root := t.TempDir()
	teamID := "backend:aweb.ai"
	fixture := newCertificateClientFixture(t, root, teamID, "../outside/planted.pem")
	outside := filepath.Join(root, "outside", "planted.pem")
	if err := os.MkdirAll(filepath.Dir(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(outside, teamCertificateForClientTest(teamID, "aweb.ai/planted", fixture.memberDIDKey)); err != nil {
		t.Fatal(err)
	}

	_, err := resolveCertificateClient(fixture.selection, "https://app.aweb.ai/api")
	if err == nil {
		t.Fatal("expected cert_path escaping the identity home to be rejected")
	}
	if !strings.Contains(err.Error(), "escapes identity home") {
		t.Fatalf("error=%q want it to name the identity-home escape", err)
	}
}

func TestResolveCertificateClientRejectsSymlinkedTeamCertificate(t *testing.T) {
	root := t.TempDir()
	teamID := "backend:aweb.ai"
	fixture := newCertificateClientFixture(t, root, teamID, awconfig.TeamCertificateRelativePath(teamID))
	outside := filepath.Join(root, "outside", "planted.pem")
	if err := os.MkdirAll(filepath.Dir(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(outside, teamCertificateForClientTest(teamID, "aweb.ai/planted", fixture.memberDIDKey)); err != nil {
		t.Fatal(err)
	}
	certPath := awconfig.TeamCertificatePath(root, teamID)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, certPath); err != nil {
		t.Fatal(err)
	}

	_, err := resolveCertificateClient(fixture.selection, "https://app.aweb.ai/api")
	if err == nil {
		t.Fatal("expected a symlinked team certificate to be rejected")
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%q want it to name the symlink", err)
	}
}

// The stored cert_path is authoritative. Resolving from the team_id instead
// would read a different file whenever the two disagree.
func TestResolveCertificateClientReadsStoredCertPathNotTeamIDDerivedPath(t *testing.T) {
	root := t.TempDir()
	teamID := "backend:aweb.ai"
	storedRelative := "team-certs/stored.pem"
	fixture := newCertificateClientFixture(t, root, teamID, storedRelative)
	stored := filepath.Join(root, ".aw", filepath.FromSlash(storedRelative))
	if err := os.MkdirAll(filepath.Dir(stored), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(stored, teamCertificateForClientTest(teamID, "aweb.ai/stored", fixture.memberDIDKey)); err != nil {
		t.Fatal(err)
	}
	// The certificate at the team_id-derived path carries a different member
	// key, so reading it instead of the stored one surfaces as an error.
	if err := awid.SaveTeamCertificate(awconfig.TeamCertificatePath(root, teamID), teamCertificateForClientTest(teamID, "aweb.ai/derived", "did:key:z6MkOther")); err != nil {
		t.Fatal(err)
	}

	c, err := resolveCertificateClient(fixture.selection, "https://app.aweb.ai/api")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected a certificate-authenticated client")
	}
}

// A stored cert_path carrying the .aw/ prefix resolves under the identity home
// rather than beneath a second .aw segment. The value is not always ours:
// accepted membership records store the server's cert_path verbatim.
func TestResolveCertificateClientReadsStoredCertPathWithIdentityHomePrefix(t *testing.T) {
	root := t.TempDir()
	teamID := "backend:aweb.ai"
	fixture := newCertificateClientFixture(t, root, teamID, ".aw/"+awconfig.TeamCertificateRelativePath(teamID))
	if err := awid.SaveTeamCertificate(awconfig.TeamCertificatePath(root, teamID), teamCertificateForClientTest(teamID, "aweb.ai/stored", fixture.memberDIDKey)); err != nil {
		t.Fatal(err)
	}

	c, err := resolveCertificateClient(fixture.selection, "https://app.aweb.ai/api")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected a certificate-authenticated client")
	}
}
