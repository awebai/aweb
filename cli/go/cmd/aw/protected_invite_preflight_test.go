package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Invite workflow fixtures explicitly model an upgraded legacy registry. The
// controller read is signed with their saved team key; these fixtures test the
// workflow after that read, while native AWID tests cover registry authority.
func serveExplicitLegacyInviteTeam(t *testing.T, w http.ResponseWriter, r *http.Request, teamID string) bool {
	t.Helper()
	name, domain, ok := strings.Cut(teamID, ":")
	if !ok || r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/"+domain+"/teams/"+name {
		return false
	}
	credential := strings.Fields(r.Header.Get("Authorization"))
	if len(credential) == 0 {
		// Unsigned reachability/creation probes keep the fixture's own reply.
		return false
	}
	if len(credential) != 3 || credential[0] != "DIDKey" {
		t.Fatalf("expected signed controller read, got %q", r.Header.Get("Authorization"))
	}
	if _, err := awid.ExtractPublicKey(credential[1]); err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"team_id": teamID, "team_did_key": credential[1],
		"protection": map[string]any{"mode": "legacy"},
	})
	return true
}

func TestLocalInviteProtectionRefusesBeforeMintOrInviteConsumption(t *testing.T) {
	for _, mode := range []string{"protected", "missing"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("AWEB_IDENTITY_HOME", "")
			_, key, _ := awid.GenerateKeypair()
			_, service, _ := awid.GenerateKeypair()
			writes := 0
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/v1/namespaces/example.test/teams/team" {
					fields := map[string]any{"team_id": "team:example.test", "team_did_key": awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))}
					if mode == "protected" {
						fields["protection"] = map[string]any{"mode": "protected", "service_id": "test-service", "service_did_key": awid.ComputeDIDKey(service.Public().(ed25519.PublicKey)), "history_id": "11111111-1111-4111-8111-111111111111", "generation": 1}
					}
					json.NewEncoder(w).Encode(fields)
					return
				}
				if r.Method != "GET" {
					writes++
				}
				http.NotFound(w, r)
			}))
			t.Setenv("AWID_REGISTRY_URL", server.URL)
			if err := awconfig.SaveTeamKey("example.test", "team", key); err != nil {
				t.Fatal(err)
			}
			invite := &awconfig.TeamInvite{InviteID: "fixture-protected-invite", Domain: "example.test", TeamName: "team", Secret: "synthetic-invite-secret", RegistryURL: server.URL, IdentityScope: "local"}
			if err := awconfig.SaveTeamInvite(invite); err != nil {
				t.Fatal(err)
			}
			token, err := awconfig.EncodeInviteToken(invite)
			if err != nil {
				t.Fatal(err)
			}
			work := t.TempDir()
			identity := filepath.Join(work, ".aw")
			_, err = acceptTeamInviteWithDetails(work, token, teamAcceptInviteOptions{Scope: "local", Name: "new-member", IdentityHome: identity})
			expected := "protected_admission_required"
			if mode == "missing" {
				expected = "protected_state_unavailable"
			}
			if errorCodeOf(err) != expected {
				t.Fatalf("%s: %v", expected, err)
			}
			if writes != 0 {
				t.Fatalf("%d writes before refusal", writes)
			}
			if _, err = os.Stat(filepath.Join(identity, "signing.key")); !os.IsNotExist(err) {
				t.Fatalf("minted key or unexpected state: %v", err)
			}
			if current, err := awconfig.LoadTeamInvite(invite.InviteID); err != nil || current == nil {
				t.Fatalf("consumed invite: %v", err)
			}
		})
	}
}
