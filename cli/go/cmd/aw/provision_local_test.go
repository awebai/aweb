package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestProvisionLocalCommandUsesDeclaredAuthorityAndExternalTarget(t *testing.T) {
	var registeredCert *awid.TeamCertificate
	var connectWorkspacePath string
	var registerCalls, connectCalls int
	var workspaceDeleted, certificateRevoked bool
	var workspaceDeleteCalls int
	var authorityDID, controllerDID string
	var stateMu sync.Mutex
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		defer stateMu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates":
			registerCalls++
			var request struct {
				Certificate string `json:"certificate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			var err error
			registeredCert, err = awid.DecodeTeamCertificateHeader(request.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			// Commit the certificate, then lose the response. The next real command
			// must reconcile by alias + target key instead of signing a duplicate.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
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
		case registeredCert != nil && r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates/"+registeredCert.CertificateID:
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
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			connectWorkspacePath, _ = request["workspace_path"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.test", "alias": "oas-worker", "agent_id": "agent-provisioned",
				"workspace_id": "workspace-provisioned", "repo_id": "", "team_did_key": "did:key:z6MkiTeam",
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-provisioned", "backend:acme.test", "oas-worker")
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/workspaces/workspace-provisioned":
			workspaceDeleteCalls++
			encodedCert := r.Header.Get("X-AWID-Team-Certificate")
			authorityCert, err := awid.DecodeTeamCertificateHeader(encodedCert)
			if err != nil || authorityCert.Alias != "provisioner" || authorityCert.MemberDIDKey != authorityDID {
				t.Fatalf("workspace cleanup did not use declared authority: cert=%+v err=%v", authorityCert, err)
			}
			if workspaceDeleted {
				// The server's real refusal for this case, not a bare 404. It is
				// reached only inside `deleted_at is not None`, so it establishes that
				// the row IS deleted and that the bound identity is NOT - which is why
				// it refuses. A bare http.NotFound would let the client treat an
				// unidentifiable 404 as this one.
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"detail": map[string]any{
						"code":                  "workspace_already_deleted",
						"workspace_id":          "workspace-provisioned",
						"identity_scope":        "local",
						"recommended_next_step": "The workspace is deleted; its identity is not.",
					},
				})
				return
			}
			workspaceDeleted = true
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		case registeredCert != nil && r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates":
			revokedAt := ""
			if certificateRevoked {
				revokedAt = "2026-07-26T00:00:00Z"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]any{{
				"certificate_id": registeredCert.CertificateID, "team_id": registeredCert.Team,
				"member_did_key": registeredCert.MemberDIDKey, "alias": registeredCert.Alias,
				"identity_scope": registeredCert.IdentityScope, "issued_at": registeredCert.IssuedAt,
				"revoked_at": revokedAt,
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.test/teams/backend/certificates/revoke":
			auth := strings.Fields(r.Header.Get("Authorization"))
			if len(auth) < 2 || auth[0] != "DIDKey" || auth[1] != controllerDID {
				t.Fatalf("certificate revoke auth=%q want controller %q", r.Header.Get("Authorization"), controllerDID)
			}
			certificateRevoked = true
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	snapshot := func() (*awid.TeamCertificate, string, int, int, bool, bool, int) {
		stateMu.Lock()
		defer stateMu.Unlock()
		return registeredCert, connectWorkspacePath, registerCalls, connectCalls, workspaceDeleted, certificateRevoked, workspaceDeleteCalls
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
	controllerDID = awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))

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
	authorityDID = awid.ComputeDIDKey(authorityKey.Public().(ed25519.PublicKey))
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

	run := exec.CommandContext(ctx, bin, "id", "team", "provision-local",
		"--operation-id", "oas-AAAAAAAAAAAAAAAAAAAAAA", "--team-id", "backend:acme.test", "--name", "oas-worker",
		"--authority-identity-home", filepath.Join(authorityDir, ".aw"), "--target-identity-home", targetHome,
		"--authority-address", "acme.test/provisioner", "--authority-stable-id", authorityStableID,
		"--controller-did", controllerDID, "--json")
	run.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	run.Dir = instanceDir
	output, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("first provision-local should lose its committed registry response:\n%s", output)
	}
	registered, _, registeredCalls, _, _, _, _ := snapshot()
	if registeredCalls != 1 || registered == nil {
		t.Fatalf("register_calls=%d cert=%+v", registeredCalls, registered)
	}
	if matches, err := awconfig.ListTeamInvitesByOperation("oas-AAAAAAAAAAAAAAAAAAAAAA"); err != nil || len(matches) != 1 {
		t.Fatalf("response-loss grant matches=%+v err=%v", matches, err)
	}

	recover := exec.CommandContext(ctx, bin, "id", "team", "provision-local",
		"--operation-id", "oas-AAAAAAAAAAAAAAAAAAAAAA", "--team-id", "backend:acme.test", "--name", "oas-worker",
		"--authority-identity-home", filepath.Join(authorityDir, ".aw"), "--target-identity-home", targetHome,
		"--authority-address", "acme.test/provisioner", "--authority-stable-id", authorityStableID,
		"--controller-did", controllerDID, "--json")
	recover.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	recover.Dir = instanceDir
	output, err = recover.CombinedOutput()
	if err != nil {
		t.Fatalf("provision-local reconciliation failed: %v\n%s", err, output)
	}
	var got localProvisionOutput
	if err := json.Unmarshal(extractJSON(t, output), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, output)
	}
	if got.Status != "provisioned" || got.OperationID != "oas-AAAAAAAAAAAAAAAAAAAAAA" || got.CertificateID == "" || got.WorkspaceID != "workspace-provisioned" || got.AgentID != "agent-provisioned" {
		t.Fatalf("output=%+v", got)
	}
	principalKey, err := awid.LoadSigningKey(filepath.Join(targetHome, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalKey.Public().(ed25519.PublicKey))
	registered, connectedPath, _, _, _, _, _ := snapshot()
	if registered.MemberDIDKey != principalDID || registered.MemberDIDKey == awid.ComputeDIDKey(shadowKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("registered did=%q principal=%q", registered.MemberDIDKey, principalDID)
	}
	if connectedPath != instanceDir {
		t.Fatalf("connect workspace_path=%q want %q", connectedPath, instanceDir)
	}
	if matches, err := awconfig.ListTeamInvitesByOperation("oas-AAAAAAAAAAAAAAAAAAAAAA"); err != nil || len(matches) != 0 {
		t.Fatalf("terminal grants=%+v err=%v", matches, err)
	}

	// A lost command response is reconciled from the operation-specific target;
	// it must not mint another certificate or create another workspace.
	retry := exec.CommandContext(ctx, bin, "id", "team", "provision-local",
		"--operation-id", "oas-AAAAAAAAAAAAAAAAAAAAAA", "--team-id", "backend:acme.test", "--name", "oas-worker",
		"--authority-identity-home", filepath.Join(authorityDir, ".aw"), "--target-identity-home", targetHome,
		"--authority-address", "acme.test/provisioner", "--authority-stable-id", authorityStableID,
		"--controller-did", controllerDID, "--json")
	retry.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	retry.Dir = instanceDir
	retryOutput, err := retry.CombinedOutput()
	if err != nil {
		t.Fatalf("provision-local response-loss retry failed: %v\n%s", err, retryOutput)
	}
	var retried localProvisionOutput
	if err := json.Unmarshal(extractJSON(t, retryOutput), &retried); err != nil {
		t.Fatal(err)
	}
	_, _, registeredCalls, connectedCalls, _, _, _ := snapshot()
	if retried.CertificateID != got.CertificateID || retried.WorkspaceID != got.WorkspaceID || registeredCalls != 1 || connectedCalls != 1 {
		t.Fatalf("retry=%+v register_calls=%d connect_calls=%d", retried, registeredCalls, connectedCalls)
	}

	// A complete-looking target record is not authority if its nested resource
	// tuple contradicts the operation that owns it.
	targetRecordPath := localProvisionTargetRecordPath(targetHome)
	originalRecord, err := os.ReadFile(targetRecordPath)
	if err != nil {
		t.Fatal(err)
	}
	var contradictoryRecord localProvisionTargetRecord
	if err := json.Unmarshal(originalRecord, &contradictoryRecord); err != nil {
		t.Fatal(err)
	}
	contradictoryRecord.Result.OperationID = "oas-BBBBBBBBBBBBBBBBBBBBBQ"
	contradictoryJSON, err := json.Marshal(contradictoryRecord)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetRecordPath, append(contradictoryJSON, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	contradictory := exec.CommandContext(ctx, bin, "id", "team", "cleanup-local-provision",
		"--operation-id", "oas-AAAAAAAAAAAAAAAAAAAAAA", "--team-id", "backend:acme.test", "--name", "oas-worker",
		"--authority-identity-home", filepath.Join(authorityDir, ".aw"), "--target-identity-home", targetHome,
		"--authority-address", "acme.test/provisioner", "--authority-stable-id", authorityStableID,
		"--controller-did", controllerDID, "--json")
	contradictory.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	contradictory.Dir = instanceDir
	contradictoryOutput, contradictoryErr := contradictory.CombinedOutput()
	if contradictoryErr == nil || !strings.Contains(string(contradictoryOutput), "nested resource tuple contradicts") {
		t.Fatalf("contradictory nested resource attribution: err=%v\n%s", contradictoryErr, contradictoryOutput)
	}
	if err := os.WriteFile(targetRecordPath, originalRecord, 0o600); err != nil {
		t.Fatal(err)
	}

	// Local-path threat label: accident/confused-deputy only. A forged instance
	// receipt for another operation cannot target this throwaway principal unless
	// the operation-specific execution record corroborates it. The authorized
	// half immediately below proves the delete route is live rather than inert.
	forgedArgs := []string{"id", "team", "cleanup-local-provision",
		"--operation-id", "oas-BBBBBBBBBBBBBBBBBBBBBQ", "--team-id", "backend:acme.test", "--name", "oas-worker",
		"--authority-identity-home", filepath.Join(authorityDir, ".aw"), "--target-identity-home", targetHome,
		"--authority-address", "acme.test/provisioner", "--authority-stable-id", authorityStableID,
		"--controller-did", controllerDID, "--json"}
	forged := exec.CommandContext(ctx, bin, forgedArgs...)
	forged.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	forged.Dir = instanceDir
	forgedOutput, forgedErr := forged.CombinedOutput()
	if forgedErr == nil || !strings.Contains(string(forgedOutput), "target record contradicts the requested operation") {
		t.Fatalf("forged cleanup attribution: err=%v\n%s", forgedErr, forgedOutput)
	}
	_, _, _, _, workspaceWasDeleted, certificateWasRevoked, _ := snapshot()
	if workspaceWasDeleted || certificateWasRevoked {
		t.Fatal("forged operation reached destructive cleanup")
	}

	cleanupArgs := []string{"id", "team", "cleanup-local-provision",
		"--operation-id", "oas-AAAAAAAAAAAAAAAAAAAAAA", "--team-id", "backend:acme.test", "--name", "oas-worker",
		"--authority-identity-home", filepath.Join(authorityDir, ".aw"), "--target-identity-home", targetHome,
		"--authority-address", "acme.test/provisioner", "--authority-stable-id", authorityStableID,
		"--controller-did", controllerDID, "--json"}
	cleanup := exec.CommandContext(ctx, bin, cleanupArgs...)
	cleanup.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	cleanup.Dir = instanceDir
	cleanupOutput, cleanupErr := cleanup.CombinedOutput()
	if cleanupErr == nil {
		t.Fatalf("first cleanup should lose the committed workspace-delete response:\n%s", cleanupOutput)
	}
	_, _, _, _, workspaceWasDeleted, certificateWasRevoked, _ = snapshot()
	if !workspaceWasDeleted || certificateWasRevoked {
		t.Fatalf("workspace_deleted=%v certificate_revoked=%v", workspaceWasDeleted, certificateWasRevoked)
	}

	cleanupRetry := exec.CommandContext(ctx, bin, cleanupArgs...)
	cleanupRetry.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	cleanupRetry.Dir = instanceDir
	cleanupOutput, cleanupErr = cleanupRetry.CombinedOutput()
	if cleanupErr == nil {
		t.Fatalf("second cleanup should lose the committed certificate-revoke response:\n%s", cleanupOutput)
	}
	_, _, _, _, _, certificateWasRevoked, _ = snapshot()
	if !certificateWasRevoked {
		t.Fatal("certificate revoke did not commit before response loss")
	}

	cleanupFinal := exec.CommandContext(ctx, bin, cleanupArgs...)
	cleanupFinal.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+server.URL)
	cleanupFinal.Dir = instanceDir
	cleanupOutput, cleanupErr = cleanupFinal.CombinedOutput()
	if cleanupErr != nil {
		t.Fatalf("cleanup reconciliation failed: %v\n%s", cleanupErr, cleanupOutput)
	}
	var cleaned map[string]any
	if err := json.Unmarshal(extractJSON(t, cleanupOutput), &cleaned); err != nil {
		t.Fatal(err)
	}
	// The reconciliation run re-deletes and is refused with "already deleted". That
	// refusal establishes the workspace IS gone and the identity is NOT cleaned, so
	// the tuple must say both. It used to say identity "soft-deleted" here on the
	// strength of a hardcoded literal - the value the OAS retire flow verifies
	// against, which is why an unobserved field in this tuple is not a log-line bug.
	if cleaned["status"] != "complete" || cleaned["workspace"] != "soft-deleted" || cleaned["certificate"] != "revoked" || cleaned["credentials"] != "physically-absent" {
		t.Fatalf("cleanup=%v", cleaned)
	}
	if cleaned["identity"] != "not-deleted" {
		t.Fatalf("the server refused because the identity was still bound; tuple says identity=%v\ncleanup=%v", cleaned["identity"], cleaned)
	}
	_, _, _, _, _, certificateWasRevoked, deleteCalls := snapshot()
	if deleteCalls != 2 || !certificateWasRevoked {
		t.Fatalf("workspace_delete_calls=%d certificate_revoked=%v", deleteCalls, certificateWasRevoked)
	}
	entries, err := os.ReadDir(targetHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "provision-operation.json" {
		t.Fatalf("retained target entries=%v", entries)
	}
}

func TestProvisionedCertificateIdentityUsesExplicitHomeForEncryption(t *testing.T) {
	root := t.TempDir()
	workingDir := filepath.Join(root, "instance")
	identityHome := filepath.Join(root, "principal")
	if err := os.MkdirAll(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(identityHome, "signing.key"), principalKey); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team: "backend:acme.test", MemberDIDKey: awid.ComputeDIDKey(principalKey.Public().(ed25519.PublicKey)),
		Alias: "provisioned", Lifetime: awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	certPath, err := saveAcceptedTeamCertificate(workingDir, identityHome, "backend:acme.test", cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamStateToIdentityHome(identityHome, &awconfig.TeamState{
		ActiveTeam:  "backend:acme.test",
		Memberships: []awconfig.TeamMembership{{TeamID: "backend:acme.test", Alias: "provisioned", CertPath: certPath, RegistryURL: "https://registry.test"}},
	}); err != nil {
		t.Fatal(err)
	}

	identity, err := resolveIdentityForEncryptionKeyForDir(workingDir, explicitEncryptionKeyIdentityHome(identityHome))
	if err != nil {
		t.Fatal(err)
	}
	if identity.SigningKeyPath != filepath.Join(identityHome, "signing.key") || !identity.ExternalIdentityHome {
		t.Fatalf("identity=%+v", identity)
	}
}

func TestLocalProvisionEnrollmentUsesExplicitIdentityHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	workingDir := filepath.Join(root, "instance")
	identityHome := filepath.Join(root, "principal")
	if err := os.MkdirAll(filepath.Join(workingDir, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, ".gitignore"), []byte(".aw/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, workingDir, "https://example.com/repo.git")

	_, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowKeyPath := filepath.Join(workingDir, ".aw", "signing.key")
	if err := awid.SaveSigningKey(shadowKeyPath, shadowKey); err != nil {
		t.Fatal(err)
	}
	shadowBefore, err := os.ReadFile(shadowKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := resolveTeamMemberEnrollment(context.Background(), teamMemberEnrollmentResolveOptions{
		WorkingDir:     workingDir,
		IdentityHome:   identityHome,
		TeamDomain:     "acme.test",
		Name:           "provisioned",
		Scope:          awid.IdentityModeLocal,
		AllowLocalMint: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	principalKey, err := awid.LoadSigningKey(filepath.Join(identityHome, "signing.key"))
	if err != nil {
		t.Fatalf("load explicit principal key: %v", err)
	}
	principalDID := awid.ComputeDIDKey(principalKey.Public().(ed25519.PublicKey))
	if plan.MemberDIDKey != principalDID {
		t.Fatalf("member_did_key=%q want explicit principal %q", plan.MemberDIDKey, principalDID)
	}
	if plan.MemberDIDKey == awid.ComputeDIDKey(shadowKey.Public().(ed25519.PublicKey)) {
		t.Fatal("local provision selected the cwd shadow key")
	}
	shadowAfter, err := os.ReadFile(shadowKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shadowBefore, shadowAfter) {
		t.Fatal("local provision mutated the cwd shadow key")
	}
}
