package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedInviteRefusalReleasesAttemptButInterruptionRetainsIt(t *testing.T) {
	for _, scenario := range []string{"local condition mismatch", "server condition mismatch", "accept unavailable", "registry unavailable", "legacy local condition mismatch", "legacy unknown submission", "uncoded name refusal", "uncoded expired refusal", "uncoded consumed refusal"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("APP_ENV", "development")
			v := loadWhoVectors(t)
			wd := t.TempDir()
			home := filepath.Join(wd, ".aw")
			actor := v.Keys["global_agent"]
			seed, _ := hex.DecodeString(actor.SeedHex)
			key := ed25519.NewKeyFromSeed(seed)
			writeIdentityForTest(t, wd, awconfig.WorktreeIdentity{DID: actor.DIDKey, StableID: actor.DIDAW, Custody: "self", IdentityScope: "global", RegistryStatus: "registered", CreatedAt: "2026-10-26T00:00:00Z"})
			if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveInstalledIDChain(home, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["global-agent"].Signed}}); err != nil {
				t.Fatal(err)
			}
			original := map[string][]byte{}
			for _, name := range []string{"identity.yaml", "signing.key", "id-chain.json"} {
				raw, err := os.ReadFile(filepath.Join(home, name))
				if err != nil {
					t.Fatal(err)
				}
				original[name] = raw
			}
			registryUnavailable := scenario == "registry unavailable"
			teamPublic, teamKey, keyErr := awid.GenerateKeypair()
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			var receivedMember atomic.Pointer[awid.TeamCertificate]
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if cert := receivedMember.Load(); cert != nil && strings.HasSuffix(r.URL.Path, "/certificates/"+cert.CertificateID+"/status") {
					if err := json.NewEncoder(w).Encode(awid.TeamCertificateStatus{TeamID: cert.Team, TeamDIDKey: awid.ComputeDIDKey(teamPublic), Status: "active"}); err != nil {
						t.Error(err)
					}
					return
				}
				if r.URL.Path != "/v1/id-certificates/status" {
					t.Errorf("unexpected registry path: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				if registryUnavailable {
					http.Error(w, "outage", 503)
					return
				}
				json.NewEncoder(w).Encode(v.Statuses["normal"])
			}))
			defer registry.Close()
			registryURL := strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
			t.Setenv("AWID_REGISTRY_URL", registryURL)
			serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, registryURL))
			previews, accepts := 0, 0
			refuseRetry := false
			var origin string

			service := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/spawn/invite-preview":
					previews++
					var req map[string]any
					json.NewDecoder(r.Body).Decode(&req)
					human := v.Keys["alice"].DIDAW
					if (scenario == "local condition mismatch" || scenario == "legacy local condition mismatch") && req["token"] == "aw_inv_first" {
						human = v.Keys["bob"].DIDAW
					}
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "identity_scope": "unknown", "server_url": origin, "status": "active", "for_human": human, "id_tree": map[string]any{"v": 1, "issuer_id": v.Keys["bob_agent"].DIDKey, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
				case "/api/v1/spawn/accept-invite":
					accepts++
					if strings.HasPrefix(scenario, "uncoded ") && accepts == 1 {
						status, detail := 409, "Name already taken in this team"
						if scenario == "uncoded expired refusal" {
							status, detail = 410, "Invite token expired or revoked"
						}
						if scenario == "uncoded consumed refusal" {
							detail = "Invite token use limit reached"
						}
						w.WriteHeader(status)
						json.NewEncoder(w).Encode(map[string]any{"detail": detail})
						return
					}
					if ((scenario == "server condition mismatch" || scenario == "legacy unknown submission") && accepts == 1) || refuseRetry {
						w.WriteHeader(409)
						json.NewEncoder(w).Encode(map[string]any{"detail": "condition refused before membership", "reason": "human_condition_mismatch"})
						return
					}
					if scenario == "accept unavailable" && accepts == 1 {
						http.Error(w, "lost upstream outcome", 503)
						return
					}
					var req awid.SpawnAcceptInviteRequest
					decoder := json.NewDecoder(r.Body)
					decoder.UseNumber()
					decoder.Decode(&req)
					if req.DID != actor.DIDKey || req.StableID != actor.DIDAW || req.IDTree != nil || req.IDChain == nil {
						t.Error("registered identity binding changed")
						http.Error(w, "bad binding", 422)
						return
					}
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:example.com", MemberDIDKey: req.DID, MemberDIDAW: req.StableID, Alias: "child", IdentityScope: "global"})
					if err != nil {
						t.Error(err)
						return
					}
					receivedMember.Store(cert)
					encoded, _ := awid.EncodeTeamCertificateHeader(cert)
					json.NewEncoder(w).Encode(map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "cloud-child", "alias": "child", "server_url": origin, "did": req.DID, "stable_id": req.StableID, "identity_scope": "global", "custody": "self", "created": true, "team_cert": encoded, "id_chain": req.IDChain, "registration_request": nil})
				default:
					t.Errorf("unexpected service path: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer service.Close()
			origin = service.URL
			t.Setenv("AWEB_URL", origin)
			opts := teamAcceptInviteOptions{IdentityHome: home, Name: "child", Scope: "global", NoAddress: true}
			if strings.HasPrefix(scenario, "legacy ") {
				material := workspaceTeamIdentityMaterial{SigningKey: key, DIDKey: actor.DIDKey, StableID: actor.DIDAW, IdentityScope: "global"}
				state, err := prepareHostedInviteCreation(context.Background(), nil, "aw_inv_first", origin, "child", "", true, material, false, false, "", "")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := state.prepareRequest(home, material); err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				var saved map[string]json.RawMessage
				if err := json.Unmarshal(raw, &saved); err != nil {
					t.Fatal(err)
				}
				delete(saved, "accept_attempted")
				raw, err = json.Marshal(saved)
				if err != nil {
					t.Fatal(err)
				}
				if err := awid.AtomicWriteFile(filepath.Join(home, hostedInviteRecoveryFile), raw); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "legacy local condition mismatch" {
				accepted, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{
					WorkingDir: wd,
					Token:      "aw_inv_second",
					Options:    opts,
				})
				if err != nil || accepted == nil {
					t.Fatalf("retained refused home cannot try correct invite directly: %+v %v", accepted, err)
				}
				for name, before := range original {
					after, err := os.ReadFile(filepath.Join(home, name))
					if err != nil || string(before) != string(after) {
						t.Fatalf("released legacy attempt changed %s: %v", name, err)
					}
				}
				if _, err := os.Stat(filepath.Join(home, hostedInviteRecoveryFile)); !os.IsNotExist(err) {
					t.Fatalf("success retained old recovery: %v", err)
				}
				if accepts != 1 {
					t.Fatalf("old refused invitation was submitted: %d", accepts)
				}
				return
			}
			_, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{
				WorkingDir: wd,
				Token:      "aw_inv_first",
				Options:    opts,
			})
			if err == nil {
				t.Fatal("first attempt must refuse or be interrupted")
			}
			definitive := scenario == "local condition mismatch" || scenario == "server condition mismatch" || scenario == "legacy local condition mismatch"
			if (scenario == "local condition mismatch" || scenario == "legacy local condition mismatch") && !strings.Contains(err.Error(), "human_mismatch") {
				t.Fatalf("wrong refusal: %v", err)
			}
			recoveryPath := filepath.Join(home, hostedInviteRecoveryFile)
			if strings.HasPrefix(scenario, "uncoded ") {
				for _, text := range []string{recoveryPath, "init-invite.json", "fetch-cert", "If it is not"} {
					if !strings.Contains(err.Error(), text) {
						t.Fatalf("retained first refusal has no recovery exit %q: %v", text, err)
					}
				}
			}
			if definitive {
				if _, err := os.Stat(recoveryPath); !os.IsNotExist(err) {
					t.Fatalf("definitive refusal retained pending attempt: %v", err)
				}
			} else if state, err := loadHostedInviteCreation(recoveryPath); err != nil || state == nil {
				t.Fatalf("interrupted attempt lost recovery: %v", err)
			}
			for name, before := range original {
				after, err := os.ReadFile(filepath.Join(home, name))
				if err != nil || string(before) != string(after) {
					t.Fatalf("refusal changed %s: %v", name, err)
				}
			}
			_, beforeCertErr := os.Stat(filepath.Join(home, "team-certs"))
			if !os.IsNotExist(beforeCertErr) {
				t.Fatalf("refusal installed membership: %v", beforeCertErr)
			}
			nextToken := "aw_inv_second"
			if !definitive {
				oldPreviews, oldAccepts := previews, accepts
				if _, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{
					WorkingDir: wd,
					Token:      nextToken,
					Options:    opts,
				}); err == nil || !strings.Contains(err.Error(), "retry changed") {
					t.Fatalf("interrupted operation changed invite: %v", err)
				}
				if previews != oldPreviews || accepts != oldAccepts {
					t.Fatal("changed invite reached service")
				}
				nextToken = "aw_inv_first"
			}
			if scenario == "accept unavailable" {
				refuseRetry = true
				if _, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{
					WorkingDir: wd,
					Token:      "aw_inv_first",
					Options:    opts,
				}); err == nil {
					t.Fatal("expected explicit refusal after ambiguous acceptance")
				}
				if state, err := loadHostedInviteCreation(recoveryPath); err != nil || state == nil {
					t.Fatalf("later refusal erased an earlier uncertain outcome: %v", err)
				}
				refuseRetry = false
			}
			registryUnavailable = false
			accepted, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{
				WorkingDir: wd,
				Token:      nextToken,
				Options:    opts,
			})
			if err != nil || accepted == nil || accepted.Certificate.MemberDIDAW != actor.DIDAW {
				t.Fatalf("correct invite/resume failed: %+v %v", accepted, err)
			}
			for _, name := range []string{"signing.key", "id-chain.json"} {
				after, err := os.ReadFile(filepath.Join(home, name))
				if err != nil || string(original[name]) != string(after) {
					t.Fatalf("success changed %s: %v", name, err)
				}
			}
			if _, err := os.Stat(recoveryPath); !os.IsNotExist(err) {
				t.Fatalf("success retained recovery: %v", err)
			}
		})
	}
}
