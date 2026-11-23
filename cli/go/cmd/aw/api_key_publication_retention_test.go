package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestAPIKeyProvisioningPublicationFailureKeepsConnectedCredential(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv(initAPIKeyEnvVar, "")
	t.Chdir(root)
	const teamID = "default:publication.aweb.ai"
	teamPublic, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	connectCalls, publicationCalls := 0, 0
	server := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
		if serveAPIKeyCreationTeamRead(w, r, teamID) {
			return
		}
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var request struct {
				DID string `json:"did"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			certificate, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, Alias: "retained", MemberDIDKey: request.DID, IdentityScope: awid.IdentityModeLocal})
			if err != nil {
				t.Error(err)
				return
			}
			header, err := awid.EncodeTeamCertificateHeader(certificate)
			if err != nil {
				t.Error(err)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"server_url": origin, "team_cert": header, "alias": "retained", "team_id": teamID, "workspace_id": "member-workspace", "did": request.DID, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "aw_sk_member_fixture"}); err != nil {
				t.Error(err)
			}
		case "/v1/connect":
			connectCalls++
			requireCertificateAuthForTest(t, r)
			if err := json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "alias": "retained", "agent_id": "retained", "workspace_id": "member-workspace", "team_did_key": awid.ComputeDIDKey(teamPublic)}); err != nil {
				t.Error(err)
			}
		case "/v1/agents/me/encryption-key":
			publicationCalls++
			http.Error(w, "publication unavailable", http.StatusServiceUnavailable)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	defer server.Close()
	teamHumanExtendAPIKey = "aw_sk_setup_fixture"
	initAwebURL = server.URL
	failure := runTeamHumanExtend(nil, []string{"retained"})
	if failure == nil || connectCalls != 1 || publicationCalls == 0 {
		t.Fatalf("did not reach admitted publication failure: connect=%d publish=%d err=%v", connectCalls, publicationCalls, failure)
	}
	directory := filepath.Join(root, "agents", "instances", "retained")
	if _, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(directory)); err != nil {
		t.Fatalf("publication failure discarded the connected member key: %v", err)
	}
	state, err := awconfig.LoadEncryptionKeyStateFrom(awconfig.WorktreeEncryptionStatePath(directory))
	if err != nil || state.ActiveRecord() == nil {
		t.Fatalf("publication failure discarded its encryption-key recovery: %v", err)
	}
	keyPath, pathErr := resolveIdentityStoredPath(directory, awconfig.WorktreeIdentityHome(directory), state.ActiveRecord().PrivateKeyPath)
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if info, err := os.Stat(keyPath); err != nil || info.Size() == 0 {
		t.Fatalf("publication failure discarded the retained encryption private key: %v", err)
	}
	binding, err := awconfig.LoadWorktreeWorkspaceFrom(awconfig.WorktreeWorkspacePath(directory))
	if err != nil || binding.APIKey != "aw_sk_member_fixture" {
		t.Fatalf("publication failure discarded the received workspace credential: binding=%v err=%v", binding != nil, err)
	}
	if _, err := os.Stat(apiKeyPartialInitPath(awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(directory)})); !os.IsNotExist(err) {
		t.Fatalf("connected member still offers identity-creation replay: %v", err)
	}
	if !strings.Contains(failure.Error(), "id encryption-key setup") || strings.Contains(failure.Error(), "rerun the same command") || !retainUnfinishedProvisioningIdentity(failure) {
		t.Fatalf("connected publication failure lost its precise recovery: %v", failure)
	}
}
