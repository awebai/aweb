package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestHostedPersonRetainedResponseDoesNotRepeatConstructorPOST(t *testing.T) {
	v := loadWhoVectors(t)
	const teamID = "11111111-1111-4111-8111-111111111111"
	var origin string
	calls := 0
	var response hostedIdentityResponse
	var expectedID, expectedRequest string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cliIdentityCreatePath || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer fixture-person-token" {
			t.Error("wrong person constructor request")
			http.Error(w, "refused", 401)
			return
		}
		calls++
		var request struct {
			DID    string                     `json:"did"`
			IDTree awid.IDTreeCreationRequest `json:"id_tree"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.DID != expectedID || request.IDTree.RequestID != expectedRequest || request.IDTree.Parent["id"] != v.Keys["alice"].DIDAW {
			t.Error("request differs from retained operation")
		}
		if calls > 1 {
			http.Error(w, "constructor must not be posted after a durable result", 409)
			return
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	origin = server.URL
	root := t.TempDir()
	path := filepath.Join(root, "hosted-identity-create.json")
	association := hostedIdentityContext{Issuer: origin, AccountID: "account", Org: "org", TeamID: teamID, Name: "child", InboundMode: "team_and_contacts", RegistryURL: "http://127.0.0.1:1", Domain: "example.com", ParentKind: "identity", ParentID: v.Keys["alice"].DIDAW}
	material, err := prepareHostedIdentity(root, path, association)
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadHostedIdentityRecovery(path)
	if err != nil {
		t.Fatal(err)
	}
	expectedID, expectedRequest = material.DIDKey, state.IDTree.RequestID
	seed, _ := hex.DecodeString(v.Keys["alice"].SeedHex)
	parentKey := ed25519.NewKeyFromSeed(seed)
	child := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": material.StableID, "domain": "example.com", "parent": state.IDTree.Parent, "kind": "agent", "issuer_key": v.Keys["alice"].DIDKey, "issued_at": "2026-10-30T00:00:00Z"}
	payload, err := awid.IDCertificateSigningBytes(child)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]any{"certificate": child, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(parentKey, payload))}
	_, teamKey, _ := awid.GenerateKeypair()
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "agents:hosted.aweb.ai", MemberDIDKey: material.DIDKey, MemberDIDAW: material.StableID, MemberAddress: "hosted.aweb.ai/child", Alias: "child", IdentityScope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	header, err := awid.EncodeTeamCertificateHeader(cert)
	if err != nil {
		t.Fatal(err)
	}
	response = hostedIdentityResponse{IDTreeCreationResponse: awid.IDTreeCreationResponse{FieldsPresent: true, IDChain: awid.ReceivedIDChain{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, signed}}, RegistrationRequest: &awid.IDTreeRegistrationRequest{}}, TeamID: teamID, CanonicalTeamID: "agents:hosted.aweb.ai", IdentityID: "child", AgentID: "child", Name: "child", DID: material.DIDKey, StableID: material.StableID, IdentityScope: "global", Custody: "self", Namespace: "hosted.aweb.ai", Address: "hosted.aweb.ai/child", InboundMode: "team_and_contacts", TeamCert: header, Created: true}
	request := map[string]any{"did": material.DIDKey, "id_tree": state.IDTree.request(nil)}
	var first, second hostedIdentityResponse
	if err := readHostedCreationResponse("", &first, func() error {
		return postCLIAuthJSON(context.Background(), origin, cliIdentityCreatePath, "fixture-person-token", request, &first)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := validateHostedIdentityResponse(first, association, material); err != nil {
		t.Fatal(err)
	}
	if err := state.IDTree.retainResponse(first.IDTreeCreationResponse); err != nil {
		t.Fatal(err)
	}
	state.ResponseJSON, err = canonicalHostedCreationResponse(first, first.IDTreeCreationResponse)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveHostedIdentityRecovery(path, state); err != nil {
		t.Fatal(err)
	}
	// Model restart while the child's registry operation remains pending.
	restored, err := loadHostedIdentityRecovery(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := readHostedCreationResponse(restored.ResponseJSON, &second, func() error {
		return postCLIAuthJSON(context.Background(), origin, cliIdentityCreatePath, "fixture-person-token", request, &second)
	}); err != nil {
		t.Fatalf("registry-only resume contacted Cloud: %v", err)
	}
	if calls != 1 || !reflect.DeepEqual(first, second) || restored.IDTree.RequestID != expectedRequest {
		t.Fatal("resume replaced or reissued the durable human-child membership result")
	}
	changed := association
	changed.ParentID = v.Keys["bob"].DIDAW
	if _, err := prepareHostedIdentity(root, path, changed); err == nil {
		t.Fatal("retained membership allowed a different selected human")
	}
}

func TestHostedRetainedResponsePreservesAttributionProtocol(t *testing.T) {
	for _, constructor := range []string{"person", "api-key"} {
		for _, tc := range []struct {
			name string
			raw  string
		}{
			{"legacy omission", `{"team_id":"membership"}`},
			{"explicit null", `{"team_id":"membership","id_chain":null,"registration_request":null}`},
			{"issued", `{"team_id":"membership","id_chain":{"v":1,"type":"aweb.id-chain","certificates":[]},"registration_request":{"expected_head":null,"invitation_id":null}}`},
		} {
			t.Run(constructor+"/"+tc.name, func(t *testing.T) {
				var first, second any
				var tree *awid.IDTreeCreationResponse
				if constructor == "person" {
					response := &hostedIdentityResponse{}
					first, second, tree = response, &hostedIdentityResponse{}, &response.IDTreeCreationResponse
				} else {
					response := &apiKeyBootstrapResponse{}
					first, second, tree = response, &apiKeyBootstrapResponse{}, &response.IDTreeCreationResponse
				}
				if err := json.Unmarshal([]byte(tc.raw), first); err != nil {
					t.Fatal(err)
				}
				retained, err := canonicalHostedCreationResponse(first, *tree)
				if err != nil {
					t.Fatal(err)
				}
				if err := readHostedCreationResponse(retained, second, func() error {
					t.Fatal("retained response repeated the constructor POST")
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(first, second) {
					t.Fatalf("resume changed membership or attribution: %s", retained)
				}
				if tree.IDChain != nil {
					if _, ok := tree.IDChain["v"].(json.Number); !ok {
						t.Fatal("chain integer token was changed")
					}
				}
			})
		}
	}
}
