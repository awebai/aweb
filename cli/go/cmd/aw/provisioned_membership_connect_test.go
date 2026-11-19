package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestProvisionedMembershipConnectsBeforePublishingItsKey(t *testing.T) {
	for _, scenario := range []string{"ready", "connect unavailable", "publish unavailable", "normal connect publish unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("APP_ENV", "development")
			target := t.TempDir()
			output, cert := writeSelfCustodyIdentityForTest(t, target, "default:provision.example")
			connected := false
			connectCalls, publishCalls := 0, 0
			server := newLocalHTTPServerWithURL(t, func(base string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/api/v1/discovery":
						if err := json.NewEncoder(w).Encode(map[string]any{"aweb_url": base, "registry_url": base, "version": "1.7.0"}); err != nil {
							t.Error(err)
						}
					case "/v1/connect", "/api/v1/connect":
						connectCalls++
						if scenario == "connect unavailable" {
							http.Error(w, "connect unavailable", 503)
							return
						}
						connected = true
						if err := json.NewEncoder(w).Encode(map[string]any{"team_id": cert.Team, "alias": cert.Alias, "agent_id": "target", "workspace_id": "workspace-target", "team_did_key": cert.TeamDIDKey}); err != nil {
							t.Error(err)
						}
					case "/v1/agents/me/encryption-key", "/api/v1/agents/me/encryption-key":
						publishCalls++
						if !connected {
							http.Error(w, "Agent not connected", 403)
							return
						}
						if strings.HasSuffix(scenario, "publish unavailable") {
							http.Error(w, "publication unavailable", 503)
							return
						}
						writePublishEncryptionKeyResponseForTest(t, w, "target", cert.Team, cert.Alias)
					default:
						http.NotFound(w, r)
					}
				})
			})
			defer server.Close()
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			var err error
			if scenario == "normal connect publish unavailable" {
				result, connectErr := initCertificateConnectWithOptions(target, server.URL, certificateConnectOptions{IdentityHome: awconfig.WorktreeIdentityHome(target)})
				err = connectErr
				if err == nil && result.Status != "connected" {
					t.Fatalf("normal connect status=%s", result.Status)
				}
			} else {
				err = recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: target, Output: output, Certificate: cert, RegistryURL: server.URL, AwebURL: server.URL, IdentityHome: explicitEncryptionKeyIdentityHome(awconfig.WorktreeIdentityHome(target)), Activation: membershipMakeActive, Binding: membershipWriteWorkspaceBinding})
			}
			switch scenario {
			case "ready":
				if err != nil || connectCalls != 1 || publishCalls == 0 {
					t.Fatalf("not admitted before publish: connect=%d publish=%d err=%v", connectCalls, publishCalls, err)
				}
				if _, err := os.Stat(filepath.Join(target, ".aw", "context")); err != nil {
					t.Fatalf("default admission did not create context: %v", err)
				}
				state, err := awconfig.LoadEncryptionKeyStateFrom(awconfig.WorktreeEncryptionStatePath(target))
				if err != nil || state.ActiveRecord() == nil || state.ActiveRecord().PublishedAt == "" {
					t.Fatalf("successful provisioning has no publication receipt: %v", err)
				}
			case "connect unavailable":
				expected := workspaceConnectCommandForIdentityHome(server.URL, awconfig.WorktreeIdentityHome(target))
				if err == nil || !strings.Contains(err.Error(), "NOT published") || !strings.Contains(err.Error(), expected) || publishCalls != 0 {
					t.Fatalf("connect failure reported success or lost recovery: connect=%d publish=%d err=%v", connectCalls, publishCalls, err)
				}
			case "normal connect publish unavailable":
				if err != nil || connectCalls != 1 || publishCalls == 0 {
					t.Fatalf("released best-effort behavior changed: %v", err)
				}
			case "publish unavailable":
				if err == nil || !strings.Contains(err.Error(), "not confirmed") || !strings.Contains(err.Error(), "encryption-key setup") || !connected {
					t.Fatalf("publication uncertainty reported success: connect=%d publish=%d err=%v", connectCalls, publishCalls, err)
				}
			}
			if err != nil && !retainUnfinishedProvisioningIdentity(err) {
				t.Fatal("roster cleanup would discard the admitted member's home", err)
			}
			if _, err := os.Stat(filepath.Join(target, ".aw", "signing.key")); err != nil {
				t.Fatal("failure discarded admitted identity", err)
			}
			if _, err := os.Stat(awconfig.TeamCertificatePath(target, cert.Team)); err != nil {
				t.Fatal("failure discarded accepted certificate", err)
			}
		})
	}
}

func TestConnectRejectsUnknownPublicationPolicyBeforeTransport(t *testing.T) {
	_, err := initCertificateConnectWithOptions(t.TempDir(), "http://127.0.0.1:1", certificateConnectOptions{EncryptionPublication: encryptionPublicationPolicy(255)})
	if err == nil || !strings.Contains(err.Error(), "publication policy is unknown") {
		t.Fatalf("unknown policy reached admission: %v", err)
	}
}
