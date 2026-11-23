package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedInvitePersistsOnlyAnExplicitRegistrySelection(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "discovered"
		if explicit {
			name = "env-selected"
		}
		t.Run(name, func(t *testing.T) {
			const teamID = "backend:selection.example.test"
			const discovered = "https://discovered-registry.example.test"
			pub, key, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			teamKey := awid.ComputeDIDKey(pub)
			var requestedHost atomic.Value
			statusServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/teams/backend/certificates/") || !strings.HasSuffix(r.URL.Path, "/status") {
					t.Errorf("unexpected registry request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				requestedHost.Store(r.Host)
				_ = json.NewEncoder(w).Encode(awid.TeamCertificateStatus{TeamID: teamID, TeamDIDKey: teamKey, Status: "active"})
			}))
			t.Cleanup(statusServer.Close)
			transport := statusServer.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.ServerName = "127.0.0.1"
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, statusServer.Listener.Addr().String())
			}
			t.Cleanup(transport.CloseIdleConnections)
			wantURL, wantHost := "", strings.TrimPrefix(discovered, "https://")
			if explicit {
				wantURL = statusServer.URL
				wantHost = strings.TrimPrefix(statusServer.URL, "https://")
			}
			t.Setenv("AWID_REGISTRY_URL", wantURL)
			registry := newAWIDRegistryClient(&http.Client{Transport: transport}, staticTXTResolver{
				"_awid.selection.example.test": {idCreateDNSRecordValue(teamKey, discovered)},
			})
			if err := registry.Resolver.TrustRegistryOrigin(discovered); err != nil {
				t.Fatal(err)
			}
			issuer := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/spawn/invite-preview":
					writeLegacyHostedPreviewForTest(t, w, r, teamID, origin)
				case "/api/v1/spawn/accept-invite":
					var request awid.SpawnAcceptInviteRequest
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Error(err)
						return
					}
					cert, err := awid.SignTeamCertificate(key, awid.TeamCertificateFields{
						Team: teamID, MemberDIDKey: request.DID, Alias: "child", IdentityScope: awid.IdentityModeLocal,
					})
					if err != nil {
						t.Error(err)
						return
					}
					encoded, err := awid.EncodeTeamCertificateHeader(cert)
					if err != nil {
						t.Error(err)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"team_id": "hosted-team", "team_slug": "backend", "namespace": "selection.example.test",
						"identity_id": "hosted-child", "alias": "child", "server_url": origin, "did": request.DID,
						"identity_scope": awid.IdentityModeLocal, "custody": "self", "team_cert": encoded,
					})
				default:
					t.Errorf("unexpected issuer request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			})
			t.Cleanup(issuer.Close)
			root := t.TempDir()
			identityHome := filepath.Join(root, ".aw")
			accepted, err := acceptAndStoreTeamInvite(teamInviteStoreRequest{
				Acceptance: teamInviteAcceptanceRequest{
					WorkingDir: root,
					Token:      "aw_inv_registry_selection",
					Options: teamAcceptInviteOptions{
						Name: "child", Scope: awid.IdentityModeLocal, AwebURL: issuer.URL, Registry: registry,
					},
				},
				Store: teamInviteStoreOptions{
					IdentityHome: explicitEncryptionKeyIdentityHome(identityHome),
					Activation:   membershipMakeActive,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if accepted.Output.TeamKey.State != awid.TeamKeyConfirmed {
				t.Errorf("team key evidence = %+v, want confirmed", accepted.Output.TeamKey)
			}
			if got := requestedHost.Load(); got != wantHost {
				t.Errorf("registry request host = %v, want %s", got, wantHost)
			}
			stored, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
			if err != nil {
				t.Fatal(err)
			}
			membership := stored.Membership(teamID)
			if membership == nil || membership.RegistryURL != wantURL {
				t.Fatalf("persisted membership = %+v, want registry %q", membership, wantURL)
			}
		})
	}
}

func TestWorkspaceAddWorktreeChecksTheSelectedMembershipRegistry(t *testing.T) {
	const teamID = "backend:example.test"
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamKey := awid.ComputeDIDKey(pub)
	var selectedReads, fallbackReads atomic.Int32
	selected := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selectedReads.Add(1)
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/v1/namespaces/example.test/teams/backend/certificates/") || !strings.HasSuffix(r.URL.Path, "/status") {
			t.Errorf("unexpected selected registry request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(awid.TeamCertificateStatus{TeamID: teamID, TeamDIDKey: teamKey, Status: "active"})
	}))
	defer selected.Close()
	fallback := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackReads.Add(1)
		servePendingPrivateTeamRead(w, r, teamID)
	}))
	defer fallback.Close()
	server := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
		if serveAPIKeyCreationTeamRead(w, r, teamID) {
			return
		}
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "roles", "roles": map[string]any{"developer": map[string]any{"title": "Developer"}},
			})
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "name_prefix": "child"})
		case "/api/v1/workspaces/init":
			var request apiKeyBootstrapRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				return
			}
			cert, err := awid.SignTeamCertificate(key, awid.TeamCertificateFields{
				Team: teamID, MemberDIDKey: request.DID, Alias: request.Alias, IdentityScope: awid.IdentityModeLocal,
			})
			if err != nil {
				t.Error(err)
				return
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Error(err)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": teamID, "workspace_id": "child-workspace", "server_url": origin,
				"alias": request.Alias, "did": request.DID, "team_cert": encoded,
				"team_did_key": teamKey, "custody": awid.CustodySelf, "identity_scope": awid.IdentityModeLocal,
				"api_key": "aw_sk_child",
			})
		case "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": teamID, "alias": "child", "workspace_id": "child-workspace",
				"agent_id": "child-agent", "team_did_key": teamKey, "role": "developer",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "child-agent", teamID, "child")
		default:
			t.Errorf("unexpected service request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	defer server.Close()
	for _, tc := range []struct {
		name         string
		envOrigin    string
		wantState    awid.TeamKeyConfirmation
		wantRequests int32
		isolated     bool
	}{
		{"stored-private-registry", fallback.URL, awid.TeamKeyUnconfirmed, 0, false},
		{"isolated-membership-selection", fallback.URL, awid.TeamKeyConfirmed, 1, true},
		{"operator-selected-registry", selected.URL, awid.TeamKeyConfirmed, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selectedReads.Store(0)
			fallbackReads.Store(0)
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			repo := filepath.Join(root, "repo")
			if err := os.MkdirAll(repo, 0o755); err != nil {
				t.Fatal(err)
			}
			initGitRepoWithOriginAndCommit(t, repo, "https://github.com/example/project.git")
			binding := workspaceBinding(server.URL, teamID, "parent", "parent-workspace")
			binding.APIKey = "aw_sk_parent"
			writeTeamCertificateWorkspaceForTest(t, repo, binding, &testSelectionFixture{IdentityScope: awid.IdentityModeLocal})
			writeWorkspaceBindingForTest(t, repo, binding)
			state, err := awconfig.LoadTeamState(repo)
			if err != nil {
				t.Fatal(err)
			}
			state.Membership(teamID).RegistryURL = selected.URL
			if err := awconfig.SaveTeamState(repo, state); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			bin := filepath.Join(root, "aw")
			buildAwBinary(t, ctx, bin)
			command := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer")
			command.Dir = repo
			command.Env = append(testCommandEnv(root), "AWID_REGISTRY_URL="+tc.envOrigin,
				"APP_ENV=production", "AWEB_FEDERATION_TEST=")
			if tc.isolated {
				command.Env = append(command.Env, "APP_ENV=development", "AWEB_FEDERATION_TEST=1")
			}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("add-worktree: %v\n%s", err, output)
			}
			if selectedReads.Load() != tc.wantRequests || fallbackReads.Load() != 0 {
				t.Errorf("registry requests: selected %d, fallback %d; want %d and 0\n%s",
					selectedReads.Load(), fallbackReads.Load(), tc.wantRequests, output)
			}
			child, err := awconfig.LoadTeamState(filepath.Join(root, "repo-child"))
			if err != nil {
				t.Fatal(err)
			}
			membership := child.Membership(teamID)
			if membership == nil || membership.RegistryURL != selected.URL || membership.TeamKey == nil || membership.TeamKey.State != tc.wantState {
				t.Fatalf("child membership = %+v, want %s at %s\n%s", membership, tc.wantState, selected.URL, output)
			}
		})
	}
}
