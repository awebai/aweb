package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// certificateListingFunc lets a test decide what the registry's certificate
// listing returns when cleanup reads it back, so a truncated listing and an
// empty one can each be driven through the real cleanup path.
type certificateListingFunc func(w http.ResponseWriter, r *http.Request, certificateID, teamID, memberDIDKey, alias string, revoked bool)

type localProvisionCleanupFixture struct {
	bin               string
	instanceDir       string
	cleanupArgs       []string
	registryURL       string
	env               []string
	targetHome        string
	certificateRevoke func() bool
}

// setupProvisionedLocalMember runs the real provision-local path against a fake
// registry so the cleanup under test starts from a genuine completed record,
// then hands the listing behaviour over to listing.
func setupProvisionedLocalMember(t *testing.T, listing certificateListingFunc) localProvisionCleanupFixture {
	t.Helper()

	var stateMu sync.Mutex
	var registeredCert *awid.TeamCertificate
	var certificateRevoked bool
	var authorityDID, controllerDID string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates":
			var request struct {
				Certificate string `json:"certificate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			decoded, err := awid.DecodeTeamCertificateHeader(request.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			registeredCert = decoded
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/members/oas-worker":
			if registeredCert == nil {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": registeredCert.Team, "certificate_id": registeredCert.CertificateID,
				"member_did_key": registeredCert.MemberDIDKey, "alias": registeredCert.Alias,
				"identity_scope": registeredCert.IdentityScope, "issued_at": registeredCert.IssuedAt,
			})
		case registeredCert != nil && r.Method == http.MethodGet &&
			r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates/"+registeredCert.CertificateID:
			encoded, err := awid.EncodeTeamCertificateHeader(registeredCert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"certificate_id": registeredCert.CertificateID, "team_id": registeredCert.Team,
				"member_did_key": registeredCert.MemberDIDKey, "alias": registeredCert.Alias,
				"identity_scope": registeredCert.IdentityScope, "issued_at": registeredCert.IssuedAt,
				"certificate": encoded,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates":
			if registeredCert == nil {
				http.NotFound(w, r)
				return
			}
			listing(w, r, registeredCert.CertificateID, registeredCert.Team,
				registeredCert.MemberDIDKey, registeredCert.Alias, certificateRevoked)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates/revoke":
			auth := strings.Fields(r.Header.Get("Authorization"))
			if len(auth) < 2 || auth[0] != "DIDKey" || auth[1] != controllerDID {
				t.Fatalf("certificate revoke auth=%q want controller %q", r.Header.Get("Authorization"), controllerDID)
			}
			certificateRevoked = true
			_ = json.NewEncoder(w).Encode(map[string]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.test", "alias": "oas-worker", "agent_id": "agent-provisioned",
				"workspace_id": "workspace-provisioned", "repo_id": "", "team_did_key": "did:key:z6MkiTeam",
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-provisioned", "backend:acme.test", "oas-worker")
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/workspaces/workspace-provisioned":
			encodedCert := r.Header.Get("X-AWID-Team-Certificate")
			authorityCert, err := awid.DecodeTeamCertificateHeader(encodedCert)
			if err != nil || authorityCert.Alias != "provisioner" || authorityCert.MemberDIDKey != authorityDID {
				t.Fatalf("workspace cleanup did not use declared authority: cert=%+v err=%v", authorityCert, err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workspace_id": "workspace-provisioned"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	rawRoot := t.TempDir()
	root, err := filepath.EvalSymlinks(rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	t.Setenv("HOME", root)

	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, root, "acme.test", "backend", controllerKey)
	stateMu.Lock()
	controllerDID = awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	stateMu.Unlock()

	authorityDir := filepath.Join(root, "authority")
	instanceDir := filepath.Join(root, "instance")
	targetHome := filepath.Join(root, "external-principal")
	for _, path := range []string{authorityDir, instanceDir} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, authorityKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stateMu.Lock()
	authorityDID = awid.ComputeDIDKey(authorityKey.Public().(ed25519.PublicKey))
	stateMu.Unlock()
	authorityStableID := awid.ComputeStableID(authorityKey.Public().(ed25519.PublicKey))
	writeSelectionFixtureForTest(t, authorityDir, testSelectionFixture{
		AwebURL: server.URL, TeamID: "backend:acme.test", Alias: "provisioner", WorkspaceID: "workspace-provisioner",
		DID: authorityDID, StableID: authorityStableID, Address: "acme.test/provisioner", Custody: awid.CustodySelf,
		Lifetime: awid.LifetimePersistent, RegistryURL: server.URL, SigningKey: authorityKey,
	})
	_, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeSelectionFixtureForTest(t, instanceDir, testSelectionFixture{
		AwebURL: server.URL, TeamID: "backend:acme.test", Alias: "shadow", WorkspaceID: "workspace-shadow",
		DID: awid.ComputeDIDKey(shadowKey.Public().(ed25519.PublicKey)), StableID: awid.ComputeStableID(shadowKey.Public().(ed25519.PublicKey)),
		Address: "acme.test/shadow", Custody: awid.CustodySelf, Lifetime: awid.LifetimePersistent, RegistryURL: server.URL, SigningKey: shadowKey,
	})

	env := append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	sharedArgs := []string{
		"--operation-id", "oas-AAAAAAAAAAAAAAAAAAAAAA", "--team-id", "backend:acme.test", "--name", "oas-worker",
		"--authority-identity-home", filepath.Join(authorityDir, ".aw"), "--target-identity-home", targetHome,
		"--authority-address", "acme.test/provisioner", "--authority-stable-id", authorityStableID,
		"--controller-did", awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey)), "--json",
	}

	provision := exec.CommandContext(ctx, bin, append([]string{"id", "team", "provision-local"}, sharedArgs...)...)
	provision.Env = env
	provision.Dir = instanceDir
	if output, err := provision.CombinedOutput(); err != nil {
		t.Fatalf("provision-local failed: %v\n%s", err, output)
	}

	return localProvisionCleanupFixture{
		bin:         bin,
		instanceDir: instanceDir,
		cleanupArgs: append([]string{"id", "team", "cleanup-local-provision"}, sharedArgs...),
		registryURL: server.URL,
		env:         env,
		targetHome:  targetHome,
		certificateRevoke: func() bool {
			stateMu.Lock()
			defer stateMu.Unlock()
			return certificateRevoked
		},
	}
}

func (f localProvisionCleanupFixture) runCleanup(t *testing.T) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cleanup := exec.CommandContext(ctx, f.bin, f.cleanupArgs...)
	cleanup.Env = f.env
	cleanup.Dir = f.instanceDir
	return cleanup.CombinedOutput()
}

func (f localProvisionCleanupFixture) recordedCertificateState(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(localProvisionTargetRecordPath(f.targetHome))
	if err != nil {
		t.Fatalf("read target record: %v", err)
	}
	var record localProvisionTargetRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("decode target record: %v", err)
	}
	if record.Cleanup == nil {
		return ""
	}
	return record.Cleanup.Certificate
}

// The certificate cleanup has to revoke belongs to the team it is cleaning, so a
// listing that stops at its first page hides it behind the members already there.
func TestCleanupLocalProvisionRevokesCertificateBeyondTheFirstPage(t *testing.T) {
	fixture := setupProvisionedLocalMember(t, func(
		w http.ResponseWriter, r *http.Request, certificateID, teamID, memberDIDKey, alias string, revoked bool,
	) {
		// Fifty older members fill the first page; the provisioned certificate is
		// the newest and so sorts last, exactly as the registry orders by issue
		// time ascending. The page size is capped here whatever the client asks
		// for, so this fixture keeps forcing a second page.
		const firstPage = 50
		revokedAt := ""
		if revoked {
			revokedAt = "2026-07-29T01:00:00Z"
		}
		target := map[string]any{
			"certificate_id": certificateID, "team_id": teamID, "member_did_key": memberDIDKey,
			"alias": alias, "identity_scope": "global", "issued_at": "2026-07-29T00:00:00Z",
			"revoked_at": revokedAt,
		}
		if r.URL.Query().Get("cursor") == "" {
			items := make([]map[string]any, 0, firstPage)
			for index := 0; index < firstPage; index++ {
				items = append(items, map[string]any{
					"certificate_id": "cert-filler-" + strconv.Itoa(index),
					"team_id":        teamID,
					"member_did_key": "did:key:z6MkFiller" + strconv.Itoa(index),
					"alias":          "filler-" + strconv.Itoa(index),
					"identity_scope": "global",
					"issued_at":      "2026-04-06T00:00:00Z",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"certificates": items, "has_more": true, "next_cursor": "page-2",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{target}, "has_more": false,
		})
	})

	output, err := fixture.runCleanup(t)
	if err != nil {
		t.Fatalf("cleanup failed: %v\n%s", err, output)
	}
	if !fixture.certificateRevoke() {
		t.Fatal("the provisioned certificate sits on the second page and was never revoked; cleanup read only the first")
	}
	if got := fixture.recordedCertificateState(t); got != "revoked" {
		t.Fatalf("recorded certificate state=%q want revoked", got)
	}
}

// A cleanup that cannot find the certificate has not established that it was
// revoked, and must not record that it was.
func TestCleanupLocalProvisionDoesNotRecordRevokedWhenCertificateIsNotFound(t *testing.T) {
	fixture := setupProvisionedLocalMember(t, func(
		w http.ResponseWriter, r *http.Request, certificateID, teamID, memberDIDKey, alias string, revoked bool,
	) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"certificates": []map[string]any{}, "has_more": false,
		})
	})

	output, err := fixture.runCleanup(t)
	if err == nil {
		t.Fatalf("cleanup reported success without finding the certificate to revoke:\n%s", output)
	}
	if fixture.certificateRevoke() {
		t.Fatal("no certificate was found, so nothing should have been revoked")
	}
	if got := fixture.recordedCertificateState(t); got == "revoked" {
		t.Fatal("the certificate was never found or revoked, and the record says it was revoked")
	}
}
