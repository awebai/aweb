package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedInviteCodedRefusalRetry(t *testing.T) {
	for _, tc := range []struct {
		reason                    string
		status                    int
		release, earlierUncertain bool
	}{
		{"invite_invalid", 401, true, false}, {"invite_expired", 410, true, false},
		{"invite_revoked", 410, true, false}, {"invite_exhausted", 409, true, false},
		{"alias_taken", 409, true, false}, {"alias_taken", 409, false, true},
		{"alias_taken", 503, false, false}, {"invite_invalid", 409, false, false},
		{"invite_expired", 401, false, false}, {"invite_revoked", 409, false, false},
		{"invite_exhausted", 410, false, false}, {"alias_taken", 403, false, false},
		{"accepted_identity_mismatch", 409, false, false}, {"accepted_team_removed", 410, false, false},
		{"accepted_identity_removed", 410, false, false}, {"creation_invitation_consumed", 409, false, false},
		{"unknown", 409, false, false}, {"", 409, false, false},
	} {
		t.Run(fmt.Sprintf("%s/%d/uncertain=%t", tc.reason, tc.status, tc.earlierUncertain), func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("APP_ENV", "development")
			wd := t.TempDir()
			home := filepath.Join(wd, ".aw")
			_, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			detail := map[string]string{"invite_invalid": "Invalid invite token", "invite_expired": "Invite token expired or revoked", "invite_revoked": "Invite token expired or revoked", "invite_exhausted": "Invite token use limit reached", "alias_taken": "Alias already taken in this team"}[tc.reason]
			if detail == "" {
				detail = "refused"
			}
			attempts := 0
			var firstKey, origin string
			service := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/spawn/invite-preview":
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": nil})
				case "/api/v1/spawn/accept-invite":
					attempts++
					var req awid.SpawnAcceptInviteRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						return
					}
					if firstKey == "" {
						firstKey = req.DID
					}
					if req.DID != firstKey {
						t.Error("retry replaced the child key")
					}
					if tc.earlierUncertain && attempts == 1 {
						http.Error(w, "unknown upstream outcome", 503)
						return
					}
					refusedAttempt := 1
					if tc.earlierUncertain {
						refusedAttempt = 2
					}
					if attempts == refusedAttempt {
						w.WriteHeader(tc.status)
						json.NewEncoder(w).Encode(map[string]any{"detail": detail, "reason": tc.reason})
						return
					}
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:example.com", MemberDIDKey: req.DID, Alias: req.Alias, IdentityScope: "local"})
					if err != nil {
						t.Error(err)
						return
					}
					encoded, _ := awid.EncodeTeamCertificateHeader(cert)
					json.NewEncoder(w).Encode(map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "cloud-child", "alias": req.Alias, "server_url": origin, "did": req.DID, "identity_scope": "local", "custody": "self", "created": true, "team_cert": encoded, "id_chain": nil, "registration_request": nil})
				default:
					t.Errorf("unexpected path: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer service.Close()
			origin = service.URL
			t.Setenv("AWEB_URL", origin)
			opts := teamAcceptInviteOptions{IdentityHome: home, Name: "taken", Scope: "local"}
			_, err = acceptHostedTeamInviteWithDetails(wd, "aw_inv_first", opts)
			if err == nil {
				t.Fatal("first submission must fail")
			}
			if tc.earlierUncertain {
				_, err = acceptHostedTeamInviteWithDetails(wd, "aw_inv_first", opts)
				if err == nil {
					t.Fatal("second submission must refuse")
				}
			}
			if code := awid.RefusalCode(err); code != tc.reason {
				t.Fatalf("reason lost: %q", code)
			}
			if tc.reason == "alias_taken" && tc.status == 409 {
				if strings.Contains(err.Error(), "Your invite is still valid.") != tc.release {
					t.Fatalf("incorrect invitation-valid advice: %v", err)
				}
				if got := errorEnvelope(err, err.Error()).Error; got.Code != "alias_conflict" || got.Reason != tc.reason || got.Detail != "Alias already taken in this team" {
					t.Fatalf("name conflict lost structured fields: %+v", got)
				}
			}
			if !tc.release && tc.status >= 400 && tc.status < 500 {
				for _, text := range []string{"earlier attempt may have succeeded", filepath.Join(home, hostedInviteRecoveryFile), "fetch-cert", "Check with the hosting service"} {
					if !strings.Contains(err.Error(), text) {
						t.Fatalf("retained refusal lacks %q: %v", text, err)
					}
				}
			}
			keyPath := filepath.Join(home, "signing.key")
			beforeKey, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			recoveryPath := filepath.Join(home, hostedInviteRecoveryFile)
			_, statErr := os.Stat(recoveryPath)
			if tc.release != os.IsNotExist(statErr) {
				t.Fatalf("wrong recovery retention: %v", statErr)
			}
			if err := statHostedAcceptPendingMarker(hostedAcceptPendingMarkerPath(wd, home), keyPath); err != nil {
				t.Fatalf("fresh key provenance lost: %v", err)
			}
			nextToken := "aw_inv_first"
			if tc.release {
				opts.Name = "available"
				if tc.reason != "alias_taken" {
					nextToken = "aw_inv_second"
				}
			} else {
				beforeAttempts := attempts
				changed := opts
				changed.Name = "available"
				if _, err := acceptHostedTeamInviteWithDetails(wd, "aw_inv_second", changed); err == nil || !strings.Contains(err.Error(), "retry changed") {
					t.Fatalf("uncertain selection changed: %v", err)
				}
				if attempts != beforeAttempts {
					t.Fatal("changed selection reached the service")
				}
			}
			accepted, err := acceptHostedTeamInviteWithDetails(wd, nextToken, opts)
			if err != nil || accepted == nil || accepted.Certificate.MemberDIDKey != firstKey {
				t.Fatalf("retry failed: %+v %v", accepted, err)
			}
			afterKey, err := os.ReadFile(keyPath)
			if err != nil || string(afterKey) != string(beforeKey) {
				t.Fatal("retry changed signing key")
			}
			for _, path := range []string{recoveryPath, hostedAcceptPendingMarkerPath(wd, home)} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("success retained pending state: %s %v", path, err)
				}
			}
		})
	}
}

func TestPendingHostedCertificateFetchIsNarrow(t *testing.T) {
	oldTeam, oldDomain, oldID := teamFetchCertTeam, teamFetchCertNamespace, teamFetchCertID
	t.Cleanup(func() { teamFetchCertTeam, teamFetchCertNamespace, teamFetchCertID = oldTeam, oldDomain, oldID })
	home := awconfig.IdentityHome{Root: t.TempDir(), Source: awconfig.IdentityHomeFlag}
	pub, key, _ := awid.GenerateKeypair()
	if err := awid.SaveSigningKey(filepath.Join(home.Root, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	tree, err := newHostedIDTreeRecovery(hostedIdentityContext{})
	if err != nil {
		t.Fatal(err)
	}
	state := &hostedInviteCreation{Tree: tree, TokenHash: "original", DIDKey: awid.ComputeDIDKey(pub), Scope: "local", TeamID: "backend:example.com"}
	if err := state.save(filepath.Join(home.Root, hostedInviteRecoveryFile)); err != nil {
		t.Fatal(err)
	}
	teamFetchCertTeam, teamFetchCertNamespace, teamFetchCertID = "backend", "example.com", "certificate-from-service"
	ok, err := pendingHostedExchangeTarget(teamFetchCertCmd, home)
	if err != nil || !ok {
		t.Fatalf("reconciliation cannot use pending home: %v", err)
	}
	teamFetchCertTeam = "another"
	if ok, err := pendingHostedExchangeTarget(teamFetchCertCmd, home); err != nil || ok {
		t.Fatal("pending fetch escaped original team")
	}
	teamFetchCertTeam = "backend"
	_, otherKey, _ := awid.GenerateKeypair()
	if err := awid.SaveSigningKey(filepath.Join(home.Root, "signing.key"), otherKey); err != nil {
		t.Fatal(err)
	}
	if ok, err := pendingHostedExchangeTarget(teamFetchCertCmd, home); err != nil || ok {
		t.Fatal("pending fetch used a replaced key")
	}
	if ok, err := pendingHostedExchangeTarget(mailInboxCmd, home); err != nil || ok {
		t.Fatal("pending home became an acting identity")
	}
}
