package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
)

const (
	hostedRemovalTestTeam = "default:alice.aweb.ai"
	hostedRemovalTestW    = "11111111-2222-3333-4444-555555555555"
	hostedRemovalTestA    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	hostedRemovalTestC    = "cert-hosted-removal"
	hostedRemovalTestOp   = "99999999-8888-7777-6666-555555555555"
)

type hostedRemovalHTTPFixture struct {
	t *testing.T

	mu                       sync.Mutex
	calls                    []string
	prepareStatus            int
	commitStatus             int
	commitOutcome            string
	getStatus                string
	preparedWorkspace        string
	preparedAgent            string
	deleteWorkspace          string
	recoveryPath             string
	prepareWorkspaceOverride string
}

func newHostedRemovalHTTPFixture(t *testing.T) (*hostedRemovalHTTPFixture, *httptest.Server) {
	t.Helper()
	fixture := &hostedRemovalHTTPFixture{t: t, prepareStatus: http.StatusOK, commitStatus: http.StatusOK, commitOutcome: "revoked", getStatus: "prepared"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/workspaces":
			fixture.calls = append(fixture.calls, "workspace-list")
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []map[string]any{{
				"workspace_id": hostedRemovalTestW, "agent_id": hostedRemovalTestA,
				"alias": "retiree", "agent_identity_scope": "local",
			}}, "has_more": false})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/agents/removals/prepare"):
			fixture.calls = append(fixture.calls, "prepare")
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode prepare: %v", err)
			}
			fixture.preparedWorkspace = body["workspace_id"]
			fixture.preparedAgent = body["agent_id"]
			if fixture.prepareStatus != http.StatusOK {
				w.WriteHeader(fixture.prepareStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "prepare_unavailable"}})
				return
			}
			responseWorkspace := hostedRemovalTestW
			if fixture.prepareWorkspaceOverride != "" {
				responseWorkspace = fixture.prepareWorkspaceOverride
			}
			_ = json.NewEncoder(w).Encode(hostedRemovalOperation{
				OperationID: hostedRemovalTestOp, Status: "prepared", TeamID: "server-team-id",
				CanonicalTeamID: hostedRemovalTestTeam, WorkspaceID: responseWorkspace,
				AgentID: hostedRemovalTestA, CertificateID: hostedRemovalTestC,
				Alias: "retiree", IdentityScope: "local",
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/agents/removals/"+hostedRemovalTestOp):
			fixture.calls = append(fixture.calls, "get")
			_ = json.NewEncoder(w).Encode(hostedRemovalOperation{
				OperationID: hostedRemovalTestOp, Status: fixture.getStatus, TeamID: "server-team-id",
				CanonicalTeamID: hostedRemovalTestTeam, WorkspaceID: hostedRemovalTestW,
				AgentID: hostedRemovalTestA, CertificateID: hostedRemovalTestC,
				Alias: "retiree", IdentityScope: "local",
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/workspaces/"):
			fixture.calls = append(fixture.calls, "delete")
			if fixture.recoveryPath != "" {
				if _, err := os.Stat(fixture.recoveryPath); err != nil {
					t.Fatalf("coordination release happened before durable recovery: %v", err)
				}
			}
			fixture.deleteWorkspace = strings.TrimPrefix(r.URL.Path, "/v1/workspaces/")
			claims := 2
			_ = json.NewEncoder(w).Encode(aweb.DeleteWorkspaceResponse{
				WorkspaceID: hostedRemovalTestW, Alias: "retiree", DeletedAt: "2026-08-18T00:00:00Z",
				IdentityDeleted: true, ClaimsReleased: &claims,
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/agents/removals/"+hostedRemovalTestOp+"/commit"):
			fixture.calls = append(fixture.calls, "commit")
			if fixture.commitStatus != http.StatusOK {
				w.WriteHeader(fixture.commitStatus)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "registry_revoke_pending"}})
				return
			}
			_ = json.NewEncoder(w).Encode(hostedRemovalOperation{
				OperationID: hostedRemovalTestOp, Status: "committed", TeamID: "server-team-id",
				CanonicalTeamID: hostedRemovalTestTeam, WorkspaceID: hostedRemovalTestW,
				AgentID: hostedRemovalTestA, CertificateID: hostedRemovalTestC,
				Alias: "retiree", IdentityScope: "local", RegistryRevokeOutcome: fixture.commitOutcome,
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(server.Close)
	return fixture, server
}

func (f *hostedRemovalHTTPFixture) order() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func configureHostedRemovalTest(t *testing.T, serverURL string) string {
	t.Helper()
	workingDir := t.TempDir()
	teamRemoveAwebURL = serverURL
	teamRemoveAPIKey = "owner-admin-secret-that-must-not-be-persisted"
	t.Cleanup(func() {
		teamRemoveAwebURL = ""
		teamRemoveAPIKey = ""
	})
	return workingDir
}

func TestHostedRemovalRecoveryModesDoNotAcceptAliasInput(t *testing.T) {
	teamHumanRemoveResumeOperation = hostedRemovalTestOp
	t.Cleanup(func() {
		teamHumanRemoveResumeOperation = ""
		teamHumanRemoveAbortOperation = ""
		teamHumanRemoveListPending = false
	})
	if err := validateTeamRemoveAgentArgs(nil, []string{"alice.aweb.ai/retiree"}); err == nil {
		t.Fatal("resume accepted alias input")
	}
	if err := validateTeamRemoveAgentArgs(nil, nil); err != nil {
		t.Fatalf("resume without alias refused: %v", err)
	}
	teamHumanRemoveAbortOperation = "another-operation"
	if err := validateTeamRemoveAgentArgs(nil, nil); err == nil {
		t.Fatal("mutually exclusive recovery modes were accepted")
	}
}

func TestHostedLocalRemovalPreparesAndPersistsBeforeExactReleaseThenCommits(t *testing.T) {
	fixture, server := newHostedRemovalHTTPFixture(t)
	workingDir := configureHostedRemovalTest(t, server.URL)
	client, err := aweb.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fixture.recoveryPath, _ = hostedRemovalRecoveryPath(workingDir, hostedRemovalTestOp)
	scope := "local"
	out, err := runHostedLocalRemoval(context.Background(), client, workingDir, hostedRemovalTestTeam, "alice.aweb.ai/retiree", aweb.WorkspaceInfo{
		WorkspaceID: hostedRemovalTestW, AgentID: hostedRemovalTestA, Alias: "retiree", AgentIdentityScope: &scope,
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if out.Status != retirementRetired || out.CertificateID != hostedRemovalTestC {
		t.Fatalf("output=%+v", out)
	}
	if got := strings.Join(fixture.order(), ","); got != "prepare,delete,commit" {
		t.Fatalf("order=%s", got)
	}
	if fixture.preparedWorkspace != hostedRemovalTestW || fixture.preparedAgent != hostedRemovalTestA || fixture.deleteWorkspace != hostedRemovalTestW {
		t.Fatalf("prepare/delete did not bind exact W/A: %+v", fixture)
	}
	path, _ := hostedRemovalRecoveryPath(workingDir, hostedRemovalTestOp)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("terminal recovery file remains: %v", err)
	}
}

func TestHostedLocalRemovalPrepareFailureLeavesCoordinationUntouched(t *testing.T) {
	fixture, server := newHostedRemovalHTTPFixture(t)
	fixture.prepareStatus = http.StatusNotFound
	workingDir := configureHostedRemovalTest(t, server.URL)
	client, _ := aweb.New(server.URL)
	_, err := runHostedLocalRemoval(context.Background(), client, workingDir, hostedRemovalTestTeam, "alice.aweb.ai/retiree", aweb.WorkspaceInfo{
		WorkspaceID: hostedRemovalTestW, AgentID: hostedRemovalTestA, Alias: "retiree",
	})
	if err == nil || !strings.Contains(err.Error(), "before coordination release") {
		t.Fatalf("error=%v", err)
	}
	if got := strings.Join(fixture.order(), ","); got != "prepare" {
		t.Fatalf("prepare failure wrote another store: %s", got)
	}
	entries, readErr := os.ReadDir(filepath.Join(workingDir, ".aw", hostedRemovalRecoveryDir))
	if readErr == nil && len(entries) != 0 {
		t.Fatalf("prepare failure persisted recovery: %v", entries)
	}
}

func TestHostedLocalRemovalMismatchedPrepareResponseRefusesBeforeRelease(t *testing.T) {
	fixture, server := newHostedRemovalHTTPFixture(t)
	fixture.prepareWorkspaceOverride = "22222222-3333-4444-5555-666666666666"
	workingDir := configureHostedRemovalTest(t, server.URL)
	client, _ := aweb.New(server.URL)
	_, err := runHostedLocalRemoval(context.Background(), client, workingDir, hostedRemovalTestTeam, "alice.aweb.ai/retiree", aweb.WorkspaceInfo{
		WorkspaceID: hostedRemovalTestW, AgentID: hostedRemovalTestA, Alias: "retiree",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match requested workspace") {
		t.Fatalf("error=%v", err)
	}
	if got := strings.Join(fixture.order(), ","); got != "prepare" {
		t.Fatalf("mismatched prepare wrote another store: %s", got)
	}
}

func TestTeamRemoveAgentBinaryUsesHostedPrepareBeforeExactRelease(t *testing.T) {
	t.Parallel()
	fixture, server := newHostedRemovalHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	publicKey, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(publicKey)
	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, server.URL, hostedRemovalTestTeam, "operator", did, signingKey)
	run := exec.CommandContext(ctx, bin, "team", "remove-agent", "alice.aweb.ai/retiree",
		"--team-id", hostedRemovalTestTeam, "--aweb-url", server.URL,
		"--api-key", "owner-admin-test-key", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("remove-agent failed: %v\n%s", err, output)
	}
	if got := strings.Join(fixture.order(), ","); got != "workspace-list,prepare,delete,commit" {
		t.Fatalf("binary call order=%s\n%s", got, output)
	}
	var result teamRemoveAgentOutput
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode output: %v\n%s", err, output)
	}
	if result.Status != retirementRetired || result.WorkspaceID != hostedRemovalTestW || result.CertificateID != hostedRemovalTestC || result.OperationID != hostedRemovalTestOp || result.RecoveryPath != "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestResumeHostedRemovalRefusesTerminalAbortedAndUnknownBeforeDelete(t *testing.T) {
	for _, status := range []string{"aborted", "queued_for_operator"} {
		t.Run(status, func(t *testing.T) {
			fixture, server := newHostedRemovalHTTPFixture(t)
			fixture.getStatus = status
			workingDir := configureHostedRemovalTest(t, server.URL)
			client, _ := aweb.New(server.URL)
			_, err := resumeHostedRemoval(context.Background(), client, workingDir, hostedRemovalTestTeam, hostedRemovalTestOp)
			if err == nil || !strings.Contains(err.Error(), "refusing to release coordination state") {
				t.Fatalf("status=%s error=%v", status, err)
			}
			if got := strings.Join(fixture.order(), ","); got != "get" {
				t.Fatalf("status %s caused a destructive call: %s", status, got)
			}
		})
	}
}

func TestHostedLocalRemovalCommitFailureKeepsCredentialFreeRecoveryAndResumeConverges(t *testing.T) {
	fixture, server := newHostedRemovalHTTPFixture(t)
	fixture.commitStatus = http.StatusServiceUnavailable
	workingDir := configureHostedRemovalTest(t, server.URL)
	client, _ := aweb.New(server.URL)
	out, err := runHostedLocalRemoval(context.Background(), client, workingDir, hostedRemovalTestTeam, "alice.aweb.ai/retiree", aweb.WorkspaceInfo{
		WorkspaceID: hostedRemovalTestW, AgentID: hostedRemovalTestA, Alias: "retiree",
	})
	if err == nil || out.Status != retirementIncomplete {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	path, _ := hostedRemovalRecoveryPath(workingDir, hostedRemovalTestOp)
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read recovery: %v", readErr)
	}
	text := string(body)
	for _, forbidden := range []string{teamRemoveAPIKey, "signing_key", "private_key", "grant", "controller_key"} {
		if forbidden != "" && strings.Contains(text, forbidden) {
			t.Fatalf("recovery contains credential marker %q: %s", forbidden, text)
		}
	}
	fixture.mu.Lock()
	fixture.commitStatus = http.StatusOK
	fixture.mu.Unlock()
	// Simulate lost local state. Recovery uses the owner/admin operation read and
	// exact W/A; it never searches deleted history by alias.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove local recovery before lost-state resume: %v", err)
	}
	operation, resumeErr := resumeHostedRemoval(context.Background(), client, workingDir, hostedRemovalTestTeam, hostedRemovalTestOp)
	if resumeErr != nil || operation.Status != "committed" {
		t.Fatalf("resume=%+v err=%v", operation, resumeErr)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("recovery file remains after resume: %v", err)
	}
	if !strings.Contains(strings.Join(fixture.order(), ","), "get,delete,commit") {
		t.Fatalf("resume did not use exact operation and workspace: %v", fixture.order())
	}
}

func TestHostedLocalRemovalRefusesUnprovenNotFoundOutcome(t *testing.T) {
	fixture, server := newHostedRemovalHTTPFixture(t)
	fixture.commitOutcome = "not_found"
	workingDir := configureHostedRemovalTest(t, server.URL)
	client, _ := aweb.New(server.URL)
	out, err := runHostedLocalRemoval(context.Background(), client, workingDir, hostedRemovalTestTeam, "alice.aweb.ai/retiree", aweb.WorkspaceInfo{
		WorkspaceID: hostedRemovalTestW, AgentID: hostedRemovalTestA, Alias: "retiree",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown registry outcome") {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if out.Status != retirementIncomplete {
		t.Fatalf("status=%s", out.Status)
	}
	path, _ := hostedRemovalRecoveryPath(workingDir, hostedRemovalTestOp)
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("unproven outcome did not retain recovery: %v", statErr)
	}
}
