package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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

func TestHostedInviteResumesStable58CreationSelection(t *testing.T) {
	for _, installed := range []bool{false, true} {
		for _, savedResponse := range []bool{false, true} {
			t.Run(fmt.Sprintf("installed=%t/response=%t", installed, savedResponse), func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				v := loadWhoVectors(t)
				seed, _ := hex.DecodeString(v.Keys["seat"].SeedHex)
				key := ed25519.NewKeyFromSeed(seed)
				did := v.Keys["seat"].DIDKey
				bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed, v.Certificates["seat"].Signed}}
				_, teamKey, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:example.com", MemberDIDKey: did, Alias: "child", IdentityScope: "local"})
				if err != nil {
					t.Fatal(err)
				}
				header, err := awid.EncodeTeamCertificateHeader(cert)
				if err != nil {
					t.Fatal(err)
				}
				var teamStatusReads atomic.Int32
				status := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case serveHostedInviteCertificateStatus(t, w, r, cert):
						teamStatusReads.Add(1)
					case r.Method == http.MethodPost && r.URL.RequestURI() == "/v1/id-certificates/status":
						if err := json.NewEncoder(w).Encode(v.Statuses["normal"]); err != nil {
							t.Error(err)
						}
					default:
						t.Errorf("unexpected registry call %s %s", r.Method, r.URL.RequestURI())
						http.Error(w, "local child must not register", http.StatusInternalServerError)
					}
				}))
				defer status.Close()
				transport := status.Client().Transport.(*http.Transport).Clone()
				transport.TLSClientConfig.ServerName = "127.0.0.1"
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, status.Listener.Addr().String())
				}
				resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "https://registry.example.test")}}
				t.Setenv("AWID_REGISTRY_URL", "https://registry.example.test")
				registry := awid.NewAWIDRegistryClient(&http.Client{Transport: transport}, resolver)
				accepts := 0
				mode := "host_managed"
				if installed {
					mode = "self_custodial"
				}
				const requestID = "22222222-2222-4222-8222-222222222222"
				var response map[string]any
				service := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/api/v1/spawn/accept-invite" {
						t.Errorf("stable resume repeated preview or changed operation: %s", r.URL.Path)
						http.Error(w, "unexpected request", 500)
						return
					}
					accepts++
					var req awid.SpawnAcceptInviteRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
					}
					if req.IDTree == nil || req.IDTree.RequestID != requestID || req.IDTree.Mode != mode || req.IDTree.Parent["id"] != v.Keys["coordinator"].DIDKey || req.IDChain != nil || (req.IDTree.IDChain != nil) != installed {
						t.Error("upgrade replaced the stable issuer-creation request with membership-only")
						http.Error(w, "original creation request required", 422)
						return
					}
					_ = json.NewEncoder(w).Encode(response)
				})
				response = map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "child", "alias": "child", "server_url": service.URL, "did": did, "custody": "self", "identity_scope": "local", "created": true, "team_cert": header, "id_chain": bundle, "registration_request": nil}
				wd := t.TempDir()
				root := filepath.Join(wd, ".aw")
				if err := awid.SaveSigningKey(filepath.Join(root, "signing.key"), key); err != nil {
					t.Fatal(err)
				}
				if installed {
					if err := awconfig.SaveInstalledIDChain(root, bundle); err != nil {
						t.Fatal(err)
					}
				}
				// Exact fields from npm aw 1.36.58, source a3223c1d32b8,
				// cmd/aw/hosted_invite_creation.go:28-43. No post-release fields.
				tree := map[string]any{"mode": mode, "request_id": requestID, "domain": "example.com", "parent": map[string]any{"kind": "identity", "id": v.Keys["coordinator"].DIDKey}}
				if installed {
					tree["native_chain_header"], _ = awid.EncodeIDChainHeader(bundle)
				}
				legacy := map[string]any{"token_hash": strings.TrimPrefix(hostedTeamInviteRecordID("aw_inv_stable"), "hosted-"), "aweb_url": service.URL, "alias": "child", "address": "", "scope": "local", "no_address": false, "did_key": did, "stable_id": "", "invite_id": "11111111-1111-4111-8111-111111111111", "team_id": "backend:example.com", "id_tree": tree, "request_ready": true}
				if savedResponse {
					raw, _ := json.Marshal(response)
					legacy["response_json"] = string(raw)
					retained := &hostedIDTreeRecovery{}
					if err := retained.retainResponse(awid.IDTreeCreationResponse{FieldsPresent: true, IDChain: awid.ReceivedIDChain(bundle)}); err != nil {
						t.Fatal(err)
					}
					tree["response_fields_present"], tree["response_json"] = true, retained.ResponseJSON
				}
				raw, _ := json.Marshal(legacy)
				if err := os.WriteFile(filepath.Join(root, hostedInviteRecoveryFile), raw, 0600); err != nil {
					t.Fatal(err)
				}
				got, err := acceptHostedTeamInviteWithDetails(teamInviteAcceptanceRequest{WorkingDir: wd, Token: "aw_inv_stable", Options: teamAcceptInviteOptions{Name: "child", Scope: "local", AwebURL: service.URL, Registry: registry, TXTResolver: resolver}})
				if err != nil || got == nil || got.Output.Responsibility.Outcome != "nearest_human" {
					t.Fatalf("stable interrupted creation did not finish: %+v %v", got, err)
				}
				wantAccepts := 1
				if savedResponse {
					wantAccepts = 0
				}
				if reads := teamStatusReads.Load(); accepts != wantAccepts || reads != 1 {
					t.Fatalf("resume: accepts=%d, want %d; team certificate status reads=%d, want 1", accepts, wantAccepts, reads)
				}
			})
		}
	}
}

// Both hosted invite fixtures issue a certificate in backend:example.com.
func serveHostedInviteCertificateStatus(t *testing.T, w http.ResponseWriter, r *http.Request, cert *awid.TeamCertificate) bool {
	t.Helper()
	path := "/v1/namespaces/example.com/teams/backend/certificates/" + cert.CertificateID + "/status"
	if r.Method != http.MethodGet || r.URL.RequestURI() != path {
		return false
	}
	if err := json.NewEncoder(w).Encode(awid.TeamCertificateStatus{
		TeamID: cert.Team, TeamDIDKey: cert.TeamDIDKey, Status: "active",
	}); err != nil {
		t.Error(err)
	}
	return true
}
