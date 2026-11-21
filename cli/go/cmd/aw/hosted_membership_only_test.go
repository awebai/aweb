package main

import (
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

func TestHostedExistingGlobalPinnedInviteDoesNotCreateParentage(t *testing.T) {
	for _, issuer := range []string{"registered", "local"} {
		for _, scenario := range []string{"ordinary", "lost response retry", "condition retry", "unsolicited parentage", "unrecorded creation"} {
			t.Run(issuer+"/"+scenario, func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				v := loadWhoVectors(t)
				pub, key, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				did, stable := awid.ComputeDIDKey(pub), awid.ComputeStableID(pub)
				wd := t.TempDir()
				root := filepath.Join(wd, ".aw")
				writeIdentityForTest(t, wd, awconfig.WorktreeIdentity{DID: did, StableID: stable, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryStatus: "registered"})
				if err := awid.SaveSigningKey(filepath.Join(root, "signing.key"), key); err != nil {
					t.Fatal(err)
				}
				_, teamKey, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:example.com", MemberDIDKey: did, MemberDIDAW: stable, Alias: "child", IdentityScope: "global"})
				if err != nil {
					t.Fatal(err)
				}
				header, err := awid.EncodeTeamCertificateHeader(cert)
				if err != nil {
					t.Fatal(err)
				}
				var teamStatusReads atomic.Int32
				registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if serveHostedInviteCertificateStatus(t, w, r, cert) {
						teamStatusReads.Add(1)
						return
					}
					t.Errorf("unexpected registry call %s %s", r.Method, r.URL.RequestURI())
					http.Error(w, "membership must not register or resolve parentage", http.StatusInternalServerError)
				}))
				defer registry.Close()
				t.Setenv("AWID_REGISTRY_URL", registry.URL)
				previews, accepts := 0, 0
				service := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/api/v1/spawn/invite-preview":
						previews++
						parent, mode := v.Keys["global_agent"].DIDAW, "host_managed"
						if issuer == "local" {
							parent, mode = v.Keys["coordinator"].DIDKey, "self_custodial"
						}
						var required any
						if scenario == "condition retry" {
							required = v.Keys["alice"].DIDAW
						}
						_ = json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "identity_scope": "unknown", "server_url": origin, "status": "active", "for_human": required, "id_tree": map[string]any{"v": 1, "issuer_id": parent, "domain": "example.com", "child_kind": "agent", "mode": mode}})
					case "/api/v1/spawn/accept-invite":
						accepts++
						var req awid.SpawnAcceptInviteRequest
						if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
							t.Error(err)
						}
						if req.IDTree != nil || req.IDChain != nil || req.DID != did || req.StableID != stable {
							t.Error("existing chainless identity acquired an issuer creation request")
							http.Error(w, "unexpected parentage", 422)
							return
						}
						if scenario == "lost response retry" && accepts == 1 {
							http.Error(w, "outcome unavailable", 503)
							return
						}
						response := map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "child", "name": "child", "server_url": origin, "did": did, "stable_id": stable, "custody": "self", "identity_scope": "global", "created": true, "team_cert": header}
						if scenario == "unsolicited parentage" {
							response["registration_request"] = map[string]any{}
						}
						_ = json.NewEncoder(w).Encode(response)
					default:
						http.NotFound(w, r)
					}
				})
				opts := teamAcceptInviteOptions{Name: "child", Scope: "global", NoAddress: true, AwebURL: service.URL}
				if scenario == "unrecorded creation" {
					tree, err := newHostedIDTreeRecovery(hostedIdentityContext{})
					if err != nil {
						t.Fatal(err)
					}
					attempted := true
					notMinted := false
					state := &hostedInviteCreation{MintedKey: &notMinted, Tree: tree, IssuerCreationStarted: true, AcceptAttempted: &attempted, TokenHash: strings.TrimPrefix(hostedTeamInviteRecordID("aw_inv_existing"), "hosted-"), AwebURL: service.URL, Alias: "child", Scope: "global", NoAddress: true, DIDKey: did, StableID: stable, InviteID: "11111111-1111-4111-8111-111111111111", TeamID: "backend:example.com"}
					if err := state.save(filepath.Join(root, hostedInviteRecoveryFile)); err != nil {
						t.Fatal(err)
					}
				}
				join := func() error {
					_, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{WorkingDir: wd, Token: "aw_inv_existing", Options: opts})
					return err
				}
				err = join()
				if scenario == "lost response retry" || scenario == "condition retry" {
					if err == nil {
						t.Fatal("expected initial refusal or interruption")
					}
					raw, readErr := os.ReadFile(filepath.Join(root, hostedInviteRecoveryFile))
					var retained map[string]any
					if readErr != nil || json.Unmarshal(raw, &retained) != nil || retained["minted_key"] != false {
						t.Fatalf("key provenance not retained: %v", readErr)
					}
					err = join()
				}
				if scenario == "condition retry" {
					if awid.IDCertificateErrorCode(err) != "human_required" || accepts != 0 || !strings.Contains(err.Error(), "own creator") {
						t.Fatalf("conditioned chainless join: accepts=%d err=%v", accepts, err)
					}
				} else if scenario == "unrecorded creation" {
					if err == nil || !strings.Contains(err.Error(), "reconcile") || accepts != 0 {
						t.Fatalf("unrecorded creation was reissued or silently downgraded: %v", err)
					}
				} else if scenario == "unsolicited parentage" {
					if err == nil {
						t.Fatal("membership-only response requested registration")
					}
				} else if err != nil {
					t.Fatal(err)
				}
				wantPreviews := 1
				if scenario == "unrecorded creation" {
					wantPreviews = 0
				}
				var wantStatusReads int32
				if scenario == "ordinary" || scenario == "lost response retry" {
					wantStatusReads = 1
				}
				if reads := teamStatusReads.Load(); previews != wantPreviews || reads != wantStatusReads {
					t.Fatalf("previews=%d, want %d; team certificate status reads=%d, want %d", previews, wantPreviews, reads, wantStatusReads)
				}
				if _, err := os.Stat(filepath.Join(root, "id-chain.json")); !os.IsNotExist(err) {
					t.Fatalf("membership changed parentage: %v", err)
				}
			})
		}
	}
}
