package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

func TestHostedInviteRequiresPinnedPreviewBeforeAccept(t *testing.T) {
	for _, tc := range []struct {
		name, mode, kind string
		status           int
	}{
		{"no preview", "host_managed", "agent", 404},
		{"metadata omitted", "host_managed", "agent", 200},
		{"bad mode", "human_key", "agent", 200},
		{"bad child kind", "host_managed", "human", 200},
		{"native signature missing", "self_custodial", "agent", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			previews, accepts := 0, 0
			var origin string
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/spawn/invite-preview":
					previews++
					if r.Header.Get("Authorization") != "" {
						t.Error("preview sent principal credentials")
					}
					if tc.status != 200 {
						w.WriteHeader(tc.status)
						return
					}
					response := map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": map[string]any{"v": 1, "issuer_id": "did:aw:issuer", "domain": "example.com", "child_kind": tc.kind, "mode": tc.mode}}
					if tc.name == "metadata omitted" {
						delete(response, "id_tree")
					}
					json.NewEncoder(w).Encode(response)
				case "/api/v1/spawn/accept-invite":
					accepts++
					http.Error(w, "must refuse before accept", 500)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			origin = server.URL
			t.Setenv("AWEB_URL", origin)
			_, err := acceptHostedTeamInviteWithDetails(dir, "aw_inv_preview_fixture", teamAcceptInviteOptions{Name: "child", Scope: "local"})
			if tc.status == 404 && errorEnvelope(err, err.Error()).Error.Code != "unknown_or_invalid" {
				t.Fatal("accept lost the preview refusal code")
			}
			if err == nil || previews != 1 || accepts != 0 {
				t.Fatalf("err=%v previews=%d accepts=%d", err, previews, accepts)
			}
			if tc.mode == "self_custodial" {
				key, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(dir)}, "signing.key")
				if err != nil {
					t.Fatal(err)
				}
				assertPathExists(t, key)
				assertPathExists(t, filepath.Join(dir, ".aw", "hosted-invite-creation.json"))
			}
		})
	}
}

func TestHostedInviteLocalChainVerifiesAndResumesWithoutSecondAccept(t *testing.T) {
	v := loadWhoVectors(t)
	seed, _ := hex.DecodeString(v.Keys["root_agent"].SeedHex)
	issuerKey := ed25519.NewKeyFromSeed(seed)
	issuer := v.Keys["root_agent"].DIDKey
	for _, scenario := range []string{"valid", "outage resume", "native issued later", "wrong parent", "bogus signature"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			var available atomic.Bool
			available.Store(scenario != "outage resume")
			var statusReads, writes atomic.Int32
			statusServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/id-certificates/status" {
					writes.Add(1)
					http.Error(w, "no local publication", 500)
					return
				}
				statusReads.Add(1)
				if !available.Load() {
					http.Error(w, "temporary evidence outage", 503)
					return
				}
				json.NewEncoder(w).Encode(v.Statuses["normal"])
			}))
			defer statusServer.Close()
			transport := statusServer.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.ServerName = "127.0.0.1"
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, statusServer.Listener.Addr().String())
			}
			resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "https://registry.example.test")}}
			registry := awid.NewAWIDRegistryClient(&http.Client{Transport: transport}, resolver)
			previews, accepts := 0, 0
			var origin string
			var originalUUID, originalDID string
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/spawn/invite-preview":
					previews++
					mode := "host_managed"
					if scenario == "native issued later" {
						mode = "self_custodial"
					}
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:example.com", "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": map[string]any{"v": 1, "issuer_id": issuer, "domain": "example.com", "child_kind": "agent", "mode": mode}})
				case "/api/v1/spawn/accept-invite":
					accepts++
					body, _ := io.ReadAll(r.Body)
					var req awid.SpawnAcceptInviteRequest
					if err := json.Unmarshal(body, &req); err != nil {
						t.Fatal(err)
					}
					expectedMode := "host_managed"
					if scenario == "native issued later" {
						expectedMode = "self_custodial"
					}
					if req.IDTree == nil || req.IDTree.Mode != expectedMode || req.IDTree.Parent["id"] != issuer || req.IDTree.Domain != "example.com" || !hostedIdentityTeamUUID.MatchString(req.IDTree.RequestID) {
						t.Errorf("accept lost pinned selection: %+v", req.IDTree)
						http.Error(w, "missing selection", 422)
						return
					}
					originalUUID, originalDID = req.IDTree.RequestID, req.DID
					auth := strings.Fields(r.Header.Get("Authorization"))
					if len(auth) != 3 || !verifyCloudDIDPayload(t, mustExtractPublicKey(t, req.DID), r.Method, r.URL.Path, r.Header.Get("X-AWEB-Timestamp"), body, auth[2]) {
						t.Error("id_tree is not in the child's signed body")
					}
					parent := issuer
					if scenario == "wrong parent" {
						parent = v.Keys["alice"].DIDKey
					}
					certificate := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": req.DID, "domain": "example.com", "parent": map[string]any{"kind": "identity", "id": parent}, "kind": "agent", "issuer_key": issuer, "issued_at": "2026-10-30T00:00:00Z"}
					payload, err := awid.IDCertificateSigningBytes(certificate)
					if err != nil {
						t.Fatal(err)
					}
					signature := ed25519.Sign(issuerKey, payload)
					if scenario == "bogus signature" {
						signature[0] ^= 1
					}
					child := map[string]any{"certificate": certificate, "signature": base64.RawURLEncoding.EncodeToString(signature)}
					bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["root-agent"].Signed, child}}
					_, teamKey, _ := awid.GenerateKeypair()
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:example.com", MemberDIDKey: req.DID, Alias: "child", IdentityScope: "local"})
					if err != nil {
						t.Fatal(err)
					}
					encoded, err := awid.EncodeTeamCertificateHeader(cert)
					if err != nil {
						t.Fatal(err)
					}
					json.NewEncoder(w).Encode(map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "cloud-child", "alias": "child", "server_url": origin, "did": req.DID, "identity_scope": "local", "custody": "self", "created": true, "team_cert": encoded, "id_chain": bundle, "registration_request": nil})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			origin = server.URL
			opts := teamAcceptInviteOptions{Name: "child", Scope: "local", AwebURL: origin, Registry: registry, TXTResolver: resolver}
			accepted, err := acceptHostedTeamInviteWithDetails(dir, "aw_inv_typed_local", opts)
			if scenario == "native issued later" {
				if err == nil || accepts != 0 {
					t.Fatal("native issuer absence did not pend before membership")
				}
				pending, loadErr := loadHostedInviteCreation(filepath.Join(dir, ".aw", hostedInviteRecoveryFile))
				if loadErr != nil {
					t.Fatal(loadErr)
				}
				invitationID, _ := awid.GenerateUUID4()
				parentOpts := idParentOptions{WorkingDir: dir, IdentityHome: filepath.Join(dir, ".aw"), Domain: "example.com"}
				if _, _, err := executeIDParentRequest(parentOpts, invitationID, v.Keys["alice"].DIDKey, false); err == nil {
					t.Fatal("pending child requested a different parent")
				}
				requested, raw, requestErr := executeIDParentRequest(parentOpts, invitationID, issuer, false)
				if requestErr != nil || requested.ID != pending.DIDKey || requested.Kind != "agent" {
					t.Fatalf("pending key cannot use the existing parent exchange: %+v %v", requested, requestErr)
				}
				if _, err := awid.ParseIDCertificateRequest(raw); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(dir, ".aw", "identity.yaml")); !os.IsNotExist(err) {
					t.Fatal("pending exchange fabricated identity or membership")
				}
				c := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": pending.DIDKey, "domain": "example.com", "parent": map[string]any{"kind": "identity", "id": issuer}, "kind": "agent", "issuer_key": issuer, "issued_at": "2026-10-30T00:00:00Z"}
				bytesToSign, signErr := awid.IDCertificateSigningBytes(c)
				if signErr != nil {
					t.Fatal(signErr)
				}
				signed := map[string]any{"certificate": c, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, bytesToSign))}
				chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["root-agent"].Signed, signed}}
				if err := awconfig.SaveInstalledIDChain(filepath.Join(dir, ".aw"), chain); err != nil {
					t.Fatal(err)
				}
				accepted, err = acceptHostedTeamInviteWithDetails(dir, "aw_inv_typed_local", opts)
			}
			if scenario == "outage resume" {
				if err == nil {
					t.Fatal("outage installed a chain")
				}
				recovery, loadErr := loadHostedInviteCreation(filepath.Join(dir, ".aw", hostedInviteRecoveryFile))
				if loadErr != nil || recovery == nil || recovery.Tree.RequestID != originalUUID || recovery.DIDKey != originalDID || recovery.ResponseJSON == "" {
					t.Fatalf("lost original response: %+v %v", recovery, loadErr)
				}
				installed, _ := awconfig.LoadInstalledIDChain(filepath.Join(dir, ".aw"))
				if installed != nil {
					t.Fatal("outage installed ancestry")
				}
				changed := opts
				changed.Name = "different"
				if _, changeErr := acceptHostedTeamInviteWithDetails(dir, "aw_inv_typed_local", changed); changeErr == nil {
					t.Fatal("resume accepted a changed selection")
				}
				if _, changeErr := acceptHostedTeamInviteWithDetails(dir, "aw_inv_other_token", opts); changeErr == nil {
					t.Fatal("resume accepted another invite")
				}
				available.Store(true)
				accepted, err = acceptHostedTeamInviteWithDetails(dir, "aw_inv_typed_local", opts)
			}
			installed, loadErr := awconfig.LoadInstalledIDChain(filepath.Join(dir, ".aw"))
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if scenario == "wrong parent" || scenario == "bogus signature" {
				if err == nil || installed != nil {
					t.Fatalf("invalid response installed: %+v %v", installed, err)
				}
			} else if err != nil || installed == nil || accepted.Output.Responsibility.Outcome != "no_human" || accepted.Output.IDRegistration != "not_required" {
				t.Fatalf("accepted=%+v installed=%+v err=%v", accepted, installed, err)
			}
			if accepts != 1 || previews != 1 || writes.Load() != 0 {
				t.Fatalf("previews=%d accepts=%d registry writes=%d", previews, accepts, writes.Load())
			}
		})
	}
}

func TestHostedInviteGlobalRegistrationRetainsPerChildInvitation(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing-same-parent=%t", reuse), func(t *testing.T) {
			v := loadWhoVectors(t)
			subject := v.Keys["bob"]
			seed, _ := hex.DecodeString(subject.SeedHex)
			key := ed25519.NewKeyFromSeed(seed)
			issuer := v.Keys["global_agent"]
			seed, _ = hex.DecodeString(issuer.SeedHex)
			issuerKey := ed25519.NewKeyFromSeed(seed)
			certificate := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": subject.DIDAW, "domain": "example.com", "kind": "agent", "parent": map[string]any{"kind": "identity", "id": issuer.DIDAW}, "issuer_key": issuer.DIDKey, "issued_at": "2026-10-30T00:00:00Z"}
			payload, err := awid.IDCertificateSigningBytes(certificate)
			if err != nil {
				t.Fatal(err)
			}
			signed := map[string]any{"certificate": certificate, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, payload))}
			bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["registered-root-agent"].Signed, signed}}

			childCertID, _ := awid.IDCertificateID(certificate)
			status := v.Statuses["registered-root-agent-rotated"]
			status["observed_at"] = "2026-10-30T00:01:00.000000Z"
			rows := status["identities"].([]any)
			var childRow map[string]any
			for _, raw := range v.Statuses["normal"]["identities"].([]any) {
				row := raw.(map[string]any)
				if row["id"] == subject.DIDAW {
					childRow = row
				}
			}
			childRow["current_certificate_id"] = childCertID
			childRow["certificates"] = []any{map[string]any{"signed": signed, "registered_at": "2026-10-30T00:00:01.000000Z", "superseded_at": nil, "issuer_key_seq": 1}}
			status["missing"] = []any{subject.DIDAW}
			var registered atomic.Bool
			registered.Store(reuse)
			var writes atomic.Int32
			var originalBody []byte
			const spawnID = "11111111-1111-4111-8111-111111111111"
			const childInvitation = "22222222-2222-4222-8222-222222222222"
			registryServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/id-certificates/status":
					if registered.Load() {
						status["identities"] = append(rows, childRow)
						status["missing"] = []any{}
					}
					json.NewEncoder(w).Encode(status)
				case "/v1/id-certificates/register":
					body, _ := io.ReadAll(r.Body)
					var request map[string]any
					json.Unmarshal(body, &request)
					if request["invitation_id"] != childInvitation {
						t.Error("spawn invitation replaced per-child registration invitation")
					}
					if writes.Add(1) == 1 {
						originalBody = body
						http.Error(w, "registry outage", 503)
						return
					}
					if !bytes.Equal(originalBody, body) {
						t.Error("registry resume changed exact registration")
					}
					registered.Store(true)
					io.WriteString(w, `{}`)
				default:
					t.Errorf("unexpected registry path %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer registryServer.Close()
			transport := registryServer.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.ServerName = "127.0.0.1"
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, registryServer.Listener.Addr().String())
			}
			resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root_rotated"].DIDKey, "https://registry.example.test")}}
			registry := awid.NewAWIDRegistryClient(&http.Client{Transport: transport}, resolver)
			dir := t.TempDir()
			writeIdentityForTest(t, dir, awconfig.WorktreeIdentity{DID: subject.DIDKey, StableID: subject.DIDAW, Custody: "self", IdentityScope: "global", RegistryStatus: "registered", CreatedAt: "2026-10-26T00:00:00Z"})
			if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(dir), key); err != nil {
				t.Fatal(err)
			}
			if reuse {
				if err := awconfig.SaveInstalledIDChain(filepath.Join(dir, ".aw"), bundle); err != nil {
					t.Fatal(err)
				}
			}
			previews, accepts := 0, 0
			var origin, requestID string
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/spawn/invite-preview":
					previews++
					json.NewEncoder(w).Encode(map[string]any{"invite_id": spawnID, "canonical_team_id": "backend:example.com", "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": map[string]any{"v": 1, "issuer_id": issuer.DIDAW, "domain": "example.com", "child_kind": "agent", "mode": "host_managed"}})
				case "/api/v1/spawn/accept-invite":
					accepts++
					var req awid.SpawnAcceptInviteRequest
					json.NewDecoder(r.Body).Decode(&req)
					if req.IDTree == nil {
						t.Fatal("missing pinned request")
					}
					requestID = req.IDTree.RequestID
					_, teamKey, _ := awid.GenerateKeypair()
					cert, _ := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:example.com", MemberDIDKey: req.DID, MemberDIDAW: req.StableID, Alias: "child", IdentityScope: "global"})
					encoded, _ := awid.EncodeTeamCertificateHeader(cert)
					var registration any = map[string]any{"expected_head": nil, "invitation_id": childInvitation}
					if reuse {
						registration = nil
						if req.IDTree.IDChain == nil {
							t.Fatal("same-parent global membership did not present its existing chain")
						}
					}
					json.NewEncoder(w).Encode(map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "cloud-child", "alias": "child", "server_url": origin, "did": req.DID, "stable_id": req.StableID, "identity_scope": "global", "custody": "self", "created": true, "team_cert": encoded, "id_chain": bundle, "registration_request": registration})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			origin = server.URL
			opts := teamAcceptInviteOptions{Name: "child", Scope: "global", NoAddress: true, AwebURL: origin, Registry: registry, TXTResolver: resolver}
			firstAccepted, err := acceptHostedTeamInviteWithDetails(dir, "aw_inv_typed_global", opts)
			if reuse {
				if err != nil || firstAccepted.Output.IDRegistration != "registered" || accepts != 1 || previews != 1 || writes.Load() != 0 {
					t.Fatalf("existing global was reissued: accepted=%+v err=%v accepts=%d previews=%d registrations=%d", firstAccepted, err, accepts, previews, writes.Load())
				}
				return
			}
			if err == nil || writes.Load() != 1 {
				t.Fatalf("expected registration outage: %v writes=%d", err, writes.Load())
			}
			recovery, err := loadHostedInviteCreation(filepath.Join(dir, ".aw", hostedInviteRecoveryFile))
			if err != nil || recovery.InviteID != spawnID || recovery.Tree.RequestID != requestID || recovery.DIDKey != subject.DIDKey {
				t.Fatalf("lost selected operation: %+v %v", recovery, err)
			}
			installed, _ := awconfig.LoadInstalledIDChain(filepath.Join(dir, ".aw"))
			if installed != nil {
				t.Fatal("failed registration installed chain")
			}
			accepted, err := acceptHostedTeamInviteWithDetails(dir, "aw_inv_typed_global", opts)
			if err != nil || accepted.Output.IDRegistration != "registered" || accepted.Output.Responsibility.Outcome != "no_human" {
				t.Fatalf("resume: %+v %v", accepted, err)
			}
			if accepts != 1 || previews != 1 || writes.Load() != 2 {
				t.Fatalf("resume repeated Cloud creation: accepts=%d previews=%d registrations=%d", accepts, previews, writes.Load())
			}
		})
	}

}

// Existing untyped-invite scenarios now explicitly supply the required preview;
// they still test legacy ancestry and their original membership behavior.
func writeLegacyHostedPreviewForTest(t *testing.T, w http.ResponseWriter, r *http.Request, teamID, origin string) {
	t.Helper()
	if r.Method != "POST" || r.Header.Get("Authorization") != "" {
		t.Fatal("preview must be a possession-only POST")
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Token == "" {
		t.Fatal("preview omitted token")
	}
	_, embedded, err := decodeJoinToken(body.Token)
	if err != nil {
		t.Fatal(err)
	}
	if embedded != "" {
		origin = embedded
	}
	json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": teamID, "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": nil})
}

func TestHostedInviteIssuePresentsSelectedAgentChain(t *testing.T) {
	v := loadWhoVectors(t)
	seed, _ := hex.DecodeString(v.Keys["root_agent"].SeedHex)
	key := ed25519.NewKeyFromSeed(seed)
	const team = "default:hosted.aweb.ai"
	for _, wrongIssuer := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrong-issuer=%t", wrongIssuer), func(t *testing.T) {
			principal, decoy := t.TempDir(), t.TempDir()
			calls := 0
			var origin string
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/discovery":
					json.NewEncoder(w).Encode(map[string]string{"aweb_url": origin, "registry_url": origin})
				case "/api/v1/spawn/create-invite":
					calls++
					var request awid.SpawnCreateInviteRequest
					body, _ := io.ReadAll(r.Body)
					decoder := json.NewDecoder(bytes.NewReader(body))
					decoder.UseNumber()
					if err := decoder.Decode(&request); err != nil {
						t.Fatal(err)
					}
					expected := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["root-agent"].Signed}}
					want, _ := awid.EncodeIDChainHeader(expected)
					got, err := awid.EncodeIDChainHeader(request.IDChain)
					if err != nil || got != want {
						t.Fatal("issue did not send the selected installed agent bundle")
					}
					cert := requireCertificateAuthForTest(t, r)
					if cert.MemberDIDKey != v.Keys["root_agent"].DIDKey {
						t.Fatal("issue used another selected identity")
					}
					issuer := v.Keys["root_agent"].DIDKey
					if wrongIssuer {
						issuer = v.Keys["coordinator"].DIDKey
					}
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "token": "aw_inv_signed_fixture", "expires_at": "2026-11-06T12:00:00Z", "id_tree": map[string]any{"v": 1, "issuer_id": issuer, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			origin = server.URL
			writeSelectionFixtureForTest(t, principal, testSelectionFixture{AwebURL: origin, RegistryURL: origin, TeamID: team, Alias: "issuer", DID: v.Keys["root_agent"].DIDKey, Custody: "self", IdentityScope: "local", SigningKey: key})
			chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["root-agent"].Signed}}
			if err := awconfig.SaveInstalledIDChain(filepath.Join(principal, ".aw"), chain); err != nil {
				t.Fatal(err)
			}
			created, err := createHostedTeamInvite(decoy, filepath.Join(principal, ".aw"), team, true)
			if (err != nil) != wrongIssuer || calls != 1 || (!wrongIssuer && created.Token == "") {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
			if !wrongIssuer && created.ExpiresAt != "2026-11-06T12:00:00Z" {
				t.Fatalf("hosted invite expiry not returned: %q", created.ExpiresAt)
			}
		})
	}
}
