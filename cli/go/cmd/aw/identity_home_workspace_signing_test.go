package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestExternalIdentityHomeWorkspaceAndSigningLifecycle(t *testing.T) {
	const (
		teamID      = "backend:alice.aweb.ai"
		workspaceID = "principal-workspace"
		origin      = "https://github.com/acme/repo.git"
	)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	principalPub, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	principalStableID := awid.ComputeStableID(principalPub)
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	type signedClaim struct {
		authorization string
		timestamp     string
		body          []byte
	}
	claimRequests := make(chan signedClaim, 1)
	certificateRequests := make(chan map[string]any, 1)
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/alice.aweb.ai/teams/backend/certificates" {
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		certificateRequests <- body
		w.WriteHeader(http.StatusCreated)
	}))
	var serverURL string
	server := newLocalHTTPServerWithURL(t, func(baseURL string) http.Handler {
		serverURL = baseURL
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"onboarding_url": baseURL,
					"aweb_url":       baseURL,
					"registry_url":   "http://127.0.0.1:1",
					"version":        "1.7.0",
				})
			case r.Method == http.MethodPost && r.URL.Path == "/api/v1/claim-human":
				body, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				claimRequests <- signedClaim{
					authorization: strings.TrimSpace(r.Header.Get("Authorization")),
					timestamp:     strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp")),
					body:          body,
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "verification_sent", "email": "alice@example.com"})
			case r.Method == http.MethodGet && r.URL.Path == "/v1/workspaces/team":
				requireCertificateAuthForTest(t, r)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"workspaces": []map[string]any{{
						"workspace_id":   workspaceID,
						"alias":          "alice",
						"role":           "developer",
						"status":         "active",
						"workspace_path": os.TempDir(),
					}},
					"has_more": false,
				})
			case r.Method == http.MethodGet && r.URL.Path == "/v1/workspaces":
				_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []any{}, "has_more": false})
			case r.Method == http.MethodGet && r.URL.Path == "/v1/reservations":
				_ = json.NewEncoder(w).Encode(map[string]any{"reservations": []any{}})
			case r.Method == http.MethodGet && r.URL.Path == "/v1/status":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"workspace":           map[string]any{"workspace_count": 1},
					"agents":              []any{},
					"claims":              []any{},
					"conflicts":           []any{},
					"escalations_pending": 0,
					"timestamp":           "2026-07-25T00:00:00Z",
				})
			case r.Method == http.MethodGet && r.URL.Path == "/v1/roles/active":
				requireCertificateAuthForTest(t, r)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"team_roles_id": "roles-1",
					"roles": map[string]any{
						"developer": map[string]any{"title": "Developer"},
					},
				})
			case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
				requireCertificateAuthForTest(t, r)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"team_id":      teamID,
					"alias":        "charlie",
					"agent_id":     "child-agent",
					"workspace_id": "child-workspace",
					"repo_id":      "repo-1",
					"team_did_key": "did:key:z6MkTeam",
					"role":         "developer",
				})
			case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/heartbeat":
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
				writePublishEncryptionKeyResponseForTest(t, w, "child-agent", teamID, "charlie")
			default:
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
		})
	})

	tmp := t.TempDir()
	canonicalTmp, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(canonicalTmp, "aw")
	instance := filepath.Join(canonicalTmp, "repo")
	principalDir := filepath.Join(canonicalTmp, "principal")
	identityHome := filepath.Join(principalDir, ".aw")
	if err := os.MkdirAll(instance, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, instance, origin)
	buildAwBinary(t, ctx, bin)

	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(principalDir), principalKey); err != nil {
		t.Fatal(err)
	}
	binding := workspaceBinding(serverURL, teamID, "alice", workspaceID)
	binding.HumanName = "Alice"
	binding.AgentType = "agent"
	binding.WorkspacePath = instance
	binding.CanonicalOrigin = origin
	writeWorkspaceBindingForTest(t, principalDir, binding)
	writeTeamKeyForTest(t, tmp, "alice.aweb.ai", "backend", teamKey)
	if _, err := os.Lstat(filepath.Join(identityHome, "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("claim-human fallback fixture unexpectedly has identity.yaml: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("disposable instance is not empty: %v", err)
	}

	run := func(args ...string) []byte {
		t.Helper()
		fullArgs := append([]string{"--identity-home", identityHome}, args...)
		command := exec.CommandContext(ctx, bin, fullArgs...)
		command.Env = testCommandEnv(tmp)
		command.Dir = instance
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("aw %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	assertInstanceStateAbsent := func(step string) {
		t.Helper()
		if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
			t.Fatalf("%s created principal state in disposable instance: %v", step, err)
		}
	}
	seedLocalShadow := func() map[string]struct{} {
		t.Helper()
		shadow := workspaceBinding(server.URL, teamID, "mallory", "shadow-workspace")
		if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(instance, ".aw", "workspace.yaml"), &shadow); err != nil {
			t.Fatal(err)
		}
		if err := awconfig.SaveTeamState(instance, &awconfig.TeamState{
			ActiveTeam: teamID,
			Memberships: []awconfig.TeamMembership{{
				TeamID:   teamID,
				Alias:    "mallory",
				CertPath: awconfig.TeamCertificateRelativePath(teamID),
			}},
		}); err != nil {
			t.Fatal(err)
		}
		return fileDigestsForTest(t, filepath.Join(instance, ".aw"))
	}
	removeLocalShadow := func(step string, before map[string]struct{}) {
		t.Helper()
		if after := fileDigestsForTest(t, filepath.Join(instance, ".aw")); !reflect.DeepEqual(after, before) {
			t.Fatalf("%s allowed local shadow state to influence or mutate the external principal flow", step)
		}
		if err := os.RemoveAll(filepath.Join(instance, ".aw")); err != nil {
			t.Fatal(err)
		}
	}

	assertExternalClaim := func(email, wantUsername string) {
		t.Helper()
		claimOut := run("claim-human", "--email", email, "--mock-url", server.URL, "--json")
		var claimOutput map[string]any
		if err := json.Unmarshal(extractJSON(t, claimOut), &claimOutput); err != nil {
			t.Fatal(err)
		}
		if claimOutput["username"] != wantUsername || claimOutput["status"] != "verification_sent" {
			t.Fatalf("claim-human output=%v", claimOutput)
		}
		var claim signedClaim
		select {
		case claim = <-claimRequests:
		case <-time.After(5 * time.Second):
			t.Fatal("claim-human did not send the externally signed request")
		}
		var claimBody map[string]any
		if err := json.Unmarshal(claim.body, &claimBody); err != nil {
			t.Fatal(err)
		}
		parts := strings.Fields(claim.authorization)
		if claimBody["username"] != wantUsername || claimBody["did_key"] != principalDID || len(parts) != 3 || parts[1] != principalDID {
			t.Fatalf("claim-human did not use external principal state: body=%v auth=%q", claimBody, claim.authorization)
		}
		if !verifyCloudDIDPayload(t, principalPub, http.MethodPost, "/api/v1/claim-human", claim.timestamp, claim.body, parts[2]) {
			t.Fatal("claim-human signature did not verify with external principal key")
		}
	}

	assertExternalClaim("alice@example.com", "alice")
	assertInstanceStateAbsent("identity-less claim-human")

	statusShadow := seedLocalShadow()
	statusOut := run("workspace", "status", "--json")
	var status workspaceStatusOutput
	if err := json.Unmarshal(extractJSON(t, statusOut), &status); err != nil {
		t.Fatal(err)
	}
	if status.SelectedTeam != teamID || status.Workspace.WorkspaceID != workspaceID || status.Workspace.Alias != "alice" || len(status.Memberships) != 1 || !status.Memberships[0].Active {
		t.Fatalf("workspace status omitted external principal state: %+v", status)
	}
	removeLocalShadow("workspace status", statusShadow)
	assertInstanceStateAbsent("workspace status")

	writeIdentityForTest(t, principalDir, awconfig.WorktreeIdentity{
		DID:            principalDID,
		StableID:       principalStableID,
		Address:        "external.aweb.ai/principal-name",
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryURL:    registryServer.URL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-07-25T00:00:00Z",
	})
	writeStandaloneSelfCustodyIdentity(t, instance, "shadow.aweb.ai/shadow", principalDID, principalStableID, registryServer.URL, principalKey)
	identityShadow := fileDigestsForTest(t, filepath.Join(instance, ".aw"))
	assertExternalClaim("principal@example.com", "external")
	removeLocalShadow("identity-present claim-human", identityShadow)
	assertInstanceStateAbsent("identity-present claim-human")

	requestOut := run("id", "team", "request", "--team", teamID, "--name", "alice", "--json")
	var request teamRequestOutput
	if err := json.Unmarshal(extractJSON(t, requestOut), &request); err != nil {
		t.Fatal(err)
	}
	if request.DIDKey != principalDID || request.DIDAW != principalStableID || request.Address != "external.aweb.ai/principal-name" || !strings.Contains(request.Command, "--global") {
		t.Fatalf("team request omitted external principal identity: %+v", request)
	}
	assertInstanceStateAbsent("team request")

	addShadow := seedLocalShadow()
	addOut := run("workspace", "add-worktree", "developer", "--name", "charlie", "--json")
	var added workspaceAddWorktreeOutput
	if err := json.Unmarshal(extractJSON(t, addOut), &added); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(canonicalTmp, "repo-charlie")
	if added.Alias != "charlie" || added.Role != "developer" || added.WorktreePath != child {
		t.Fatalf("add-worktree output=%+v", added)
	}
	var registered map[string]any
	select {
	case registered = <-certificateRequests:
	case <-time.After(5 * time.Second):
		t.Fatal("add-worktree did not register the child certificate")
	}
	if registered["alias"] != "charlie" || registered["identity_scope"] != awid.IdentityModeLocal {
		t.Fatalf("add-worktree certificate request=%v", registered)
	}
	childWorkspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(child, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	childMembership := childWorkspace.Membership(teamID)
	if childMembership == nil || childMembership.WorkspaceID != "child-workspace" || childMembership.Alias != "charlie" {
		t.Fatalf("child workspace did not materialize external source membership: %+v", childWorkspace)
	}
	removeLocalShadow("workspace add-worktree", addShadow)
	assertInstanceStateAbsent("workspace add-worktree")
}
