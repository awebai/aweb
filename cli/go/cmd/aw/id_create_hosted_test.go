package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestHostedIdentityCreateRetainsKeyAcrossLostResponse(t *testing.T) {
	for _, mode := range []string{"team_and_contacts", "contacts_only"} {
		t.Run(mode, func(t *testing.T) { testHostedIdentityCreateRetainsKeyAcrossLostResponse(t, mode) })
	}
}
func testHostedIdentityCreateRetainsKeyAcrossLostResponse(t *testing.T, mode string) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	host, wd, principal := t.TempDir(), t.TempDir(), t.TempDir()
	principal, resolveErr := filepath.EvalSymlinks(principal)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	_, controller, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const serviceTeam = "786a02e4-6a72-44f1-a722-bef232c49a97"
	const canonicalTeam = "machine:chosen.example"
	var originalDID string
	registerCalls, createCalls, readCalls := 0, 0, 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/cli") && r.Header.Get("Authorization") != "Bearer test-access" {
			t.Error("hosted operation substituted another authority")
		}
		switch {
		case r.URL.Path == "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]any{"id": "account-1", "handle": "alice"}})
		case r.URL.Path == "/v1/did":
			registerCalls++
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			did, _ := body["new_did_key"].(string)
			if originalDID == "" {
				originalDID = did
			} else if did != originalDID {
				t.Error("retry replaced original signing identity")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && (strings.HasSuffix(r.URL.Path, "/full") || strings.HasSuffix(r.URL.Path, "/key")):
			pub, _ := awid.ExtractPublicKey(originalDID)
			_ = json.NewEncoder(w).Encode(map[string]any{"did_aw": awid.ComputeStableID(pub), "current_did_key": originalDID, "created_at": "2026-10-22T00:00:00Z", "updated_at": "2026-10-22T00:00:00Z"})
		case r.URL.Path == "/api/v1/cli/identities":
			createCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if body["org"] != "chosen" || body["team_id"] != serviceTeam || body["name"] != "steward" || body["inbound_mode"] != mode || body["did"] != originalDID {
				t.Error("creation lost explicit authority/key binding")
			}
			if _, ok := body["role"]; ok {
				t.Error("creation supplied role override")
			}
			proof, ok := body["proof"].(map[string]any)
			if !ok {
				t.Error("missing proof")
				w.WriteHeader(400)
				return
			}
			payload := map[string]any{"operation": "cli_global_identity_create.v1", "aud": server.URL, "method": "POST", "path": "/api/v1/cli/identities", "org": "chosen", "team_id": serviceTeam, "name": "steward", "did": originalDID, "inbound_mode": mode, "timestamp": proof["timestamp"]}
			canonical, _ := awid.CanonicalJSONValue(payload)
			pub, _ := awid.ExtractPublicKey(originalDID)
			sig, _ := base64.RawStdEncoding.DecodeString(proof["signature"].(string))
			if !ed25519.Verify(pub, []byte(canonical), sig) {
				t.Error("creation signature did not bind exact intent")
			}
			payload["org"] = "other"
			canonical, _ = awid.CanonicalJSONValue(payload)
			if ed25519.Verify(pub, []byte(canonical), sig) {
				t.Error("organization substitution verified")
			}
			if createCalls == 1 {
				http.Error(w, "lost reply after commit", 500)
				return
			}
			stable := awid.ComputeStableID(pub)
			cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: canonicalTeam, MemberDIDKey: originalDID, MemberDIDAW: stable, MemberAddress: "chosen.example/steward", Alias: "steward", IdentityScope: "global"})
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			encoded, _ := awid.EncodeTeamCertificateHeader(cert)
			responseDID := originalDID
			if createCalls == 2 {
				responseDID = awid.ComputeDIDKey(controller.Public().(ed25519.PublicKey))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": serviceTeam, "canonical_team_id": canonicalTeam, "identity_id": "identity-1", "agent_id": "agent-1", "name": "steward", "did": responseDID, "stable_id": stable, "identity_scope": "global", "custody": "self", "namespace": "chosen.example", "address": "chosen.example/steward", "inbound_mode": mode, "team_cert": encoded, "created": false})
		case strings.HasSuffix(r.URL.Path, "/encryption-key") && strings.HasPrefix(r.URL.Path, "/v1/did/"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.URL.Path == "/v1/agents/me/inbound-mode":
			requireCertificateAuthForTest(t, r)
			readCalls++
			actual := mode
			if readCalls == 1 {
				actual = "open"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "agent-1", "team_id": serviceTeam, "alias": "steward", "identity_scope": "global", "inbound_mode": actual, "configurable": true})
		case r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", canonicalTeam, "steward")
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	cfg := cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", ClientID: cliAuthClientID, Scope: "cli.workspace_team cli.org_create", AccessToken: "test-access", RefreshToken: "test-refresh", ExpiresAt: time.Now().Add(time.Hour)}
	data, _ := json.Marshal(cfg)
	dir := filepath.Join(host, ".config", "aw")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(org string) ([]byte, []byte, error) {
		cmd := exec.CommandContext(ctx, bin, "--identity-home", principal, "id", "create", "--org", org, "--team-id", serviceTeam, "--name", "steward", "--inbound-mode", strings.ReplaceAll(mode, "_", "-"), "--registry", server.URL, "--json")
		cmd.Dir = wd
		cmd.Env = append(os.Environ(), "HOME="+host, "AW_NO_UPDATE_CHECK=1", "AWEB_API_KEY=", "AWEB_IDENTITY_HOME=", "AW_IDENTITY_HOME=", "AWID_REGISTRY_URL=")
		var out, diagnostic bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostic
		err := cmd.Run()
		return out.Bytes(), diagnostic.Bytes(), err
	}
	_, diagnostic, err := run("chosen")
	if err == nil || createCalls != 1 {
		t.Fatalf("first attempt did not reach lost response: %v; %s", err, diagnostic)
	}
	if _, err := os.Stat(filepath.Join(principal, "identity.yaml")); !os.IsNotExist(err) {
		t.Error("installed identity before validated success")
	}
	if _, err := os.Stat(filepath.Join(principal, "hosted-identity-create.json")); err != nil {
		t.Error("interrupted creation lost its recovery material")
	}
	registrationsBefore := registerCalls
	_, _, err = run("other")
	if err == nil || createCalls != 1 || registerCalls != registrationsBefore {
		t.Error("changed association reached remote creation")
	}
	_, _, err = run("chosen")
	if err == nil {
		t.Error("accepted a response for another identity")
	}
	if _, err := os.Stat(filepath.Join(principal, "identity.yaml")); !os.IsNotExist(err) {
		t.Error("installed mismatched server identity")
	}
	_, _, err = run("chosen")
	if err == nil || readCalls != 1 {
		t.Error("accepted downgraded effective inbound mode without readback")
	}
	out, diagnostic, err := run("chosen")
	if err != nil {
		t.Fatalf("same-key retry: %v; %s", err, diagnostic)
	}
	var result map[string]any
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	if result["address"] != "chosen.example/steward" || result["did_key"] != originalDID || result["team_id"] != canonicalTeam || result["service_team_id"] != serviceTeam || result["status"] != "reused" || result["inbound_mode"] != mode {
		t.Error("creation output lost identity/team binding")
	}
	if _, err := os.Stat(filepath.Join(principal, "signing.key")); err != nil {
		t.Error("validated identity key was not installed")
	}
	if _, err := os.Stat(filepath.Join(principal, "hosted-identity-create.json")); !os.IsNotExist(err) {
		t.Error("completed creation retained recovery seed material")
	}
	if data, err := os.ReadFile(filepath.Join(principal, "hosted-identity-create.json.lock")); err != nil || len(data) != 0 {
		t.Error("reusable recovery lock must remain empty")
	}
	if _, err := os.Stat(filepath.Join(wd, ".aw")); !os.IsNotExist(err) {
		t.Error("creation changed invoking workspace")
	}
}

func TestHostedIdentityRejectsMismatchedServerBinding(t *testing.T) {
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, controller, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	material := workspaceTeamIdentityMaterial{PublicKey: pub, SigningKey: key, DIDKey: awid.ComputeDIDKey(pub), StableID: awid.ComputeStableID(pub), IdentityScope: "global", Alias: "steward"}
	association := hostedIdentityContext{TeamID: "786a02e4-6a72-44f1-a722-bef232c49a97", Name: "steward", InboundMode: "contacts_only"}
	cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: "machine:chosen.example", MemberDIDKey: material.DIDKey, MemberDIDAW: material.StableID, MemberAddress: "chosen.example/steward", Alias: "steward", IdentityScope: "global"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := awid.EncodeTeamCertificateHeader(cert)
	original := hostedIdentityResponse{TeamID: association.TeamID, CanonicalTeamID: cert.Team, IdentityID: "identity-1", AgentID: "agent-1", Name: "steward", DID: material.DIDKey, StableID: material.StableID, IdentityScope: "global", Custody: "self", Namespace: "chosen.example", Address: cert.MemberAddress, InboundMode: "contacts_only", TeamCert: encoded}
	if _, err := validateHostedIdentityResponse(original, association, material); err != nil {
		t.Fatalf("valid neighboring response refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*hostedIdentityResponse)
	}{
		{"team", func(r *hostedIdentityResponse) { r.TeamID = "another-team" }},
		{"key", func(r *hostedIdentityResponse) { r.DID = awid.ComputeDIDKey(controller.Public().(ed25519.PublicKey)) }},
		{"continuity", func(r *hostedIdentityResponse) { r.StableID = "did:aw:another" }},
		{"scope", func(r *hostedIdentityResponse) { r.IdentityScope = "local" }},
		{"custody", func(r *hostedIdentityResponse) { r.Custody = "custodial" }},
		{"namespace", func(r *hostedIdentityResponse) { r.Namespace = "other.example" }},
		{"address", func(r *hostedIdentityResponse) { r.Address = "chosen.example/other" }},
		{"mode", func(r *hostedIdentityResponse) { r.InboundMode = "team_and_contacts" }},
		{"api-key", func(r *hostedIdentityResponse) { r.APIKey = "unexpected-test-only" }},
		{"certificate", func(r *hostedIdentityResponse) {
			other := *cert
			other.Signature = "invalid"
			r.TeamCert, _ = awid.EncodeTeamCertificateHeader(&other)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := original
			tc.mutate(&response)
			if _, err := validateHostedIdentityResponse(response, association, material); err == nil {
				t.Error("installed mismatched server binding")
			}
		})
	}
}

func TestHostedIdentityRecoveryPreservesOriginalAssociation(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "hosted-identity-create.json")
	association := hostedIdentityContext{Issuer: "https://host.example", AccountID: "account-1", Org: "chosen", TeamID: "team", Name: "steward", InboundMode: "contacts_only", RegistryURL: "https://registry.example"}
	first, err := prepareHostedIdentity(root, path, association)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Error("recovery material is not private")
	}
	next, err := prepareHostedIdentity(root, path, association)
	if err != nil {
		t.Fatal(err)
	}
	if next.DIDKey != first.DIDKey || !next.SigningKey.Equal(first.SigningKey) {
		t.Error("same-operation retry replaced signing material")
	}
	for _, changed := range []hostedIdentityContext{
		{Issuer: "other"}, {AccountID: "other"}, {Org: "other"}, {TeamID: "other"}, {Name: "other"}, {InboundMode: "open"}, {RegistryURL: "other"},
	} {
		replacement := association
		if changed.Issuer != "" {
			replacement.Issuer = changed.Issuer
		}
		if changed.AccountID != "" {
			replacement.AccountID = changed.AccountID
		}
		if changed.Org != "" {
			replacement.Org = changed.Org
		}
		if changed.TeamID != "" {
			replacement.TeamID = changed.TeamID
		}
		if changed.Name != "" {
			replacement.Name = changed.Name
		}
		if changed.InboundMode != "" {
			replacement.InboundMode = changed.InboundMode
		}
		if changed.RegistryURL != "" {
			replacement.RegistryURL = changed.RegistryURL
		}
		if _, err := prepareHostedIdentity(root, path, replacement); err == nil {
			t.Error("reused key for a different creation association")
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Error("refusal changed original recovery material")
		}
	}
}
