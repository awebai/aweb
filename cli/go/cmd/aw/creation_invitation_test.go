package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestAPIKeyCreationInvitationFixesParentAndIntentBeforeRequest(t *testing.T) {
	v := adoptionVectors(t)
	for _, scenario := range []string{"person", "legacy", "null", "missing-id", "wrong-name", "wrong-scope", "invalid-parent", "retry-changed-parent"} {
		t.Run(scenario, func(t *testing.T) {
			invitation := map[string]any{"id": "11111111-1111-4111-8111-111111111111", "parent": map[string]any{"kind": "identity", "id": v.Keys["alice"].DIDAW}, "domain": "example.com", "name": "terminal", "identity_scope": "local"}
			body := map[string]any{"team_id": "22222222-2222-4222-8222-222222222222", "canonical_team_id": "agents:other.example", "creation_invitation": invitation}
			switch scenario {
			case "legacy":
				delete(body, "creation_invitation")
			case "null":
				body["creation_invitation"] = nil
			case "missing-id":
				delete(invitation, "id")
			case "wrong-name":
				invitation["name"] = "other"
			case "wrong-scope":
				invitation["identity_scope"] = "global"
			case "invalid-parent":
				invitation["parent"] = map[string]any{"kind": "identity", "id": "did:aw:invalid"}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(body) }))
			defer server.Close()
			selected, err := readAPIKeyCreationTeam(t.Context(), server.URL, "fixture")
			if scenario == "null" || scenario == "missing-id" || scenario == "invalid-parent" {
				if err == nil {
					t.Fatal("malformed invitation accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			req := apiKeyInitRequest{CanonicalTeamID: selected.CanonicalTeamID, SelectedTeamID: selected.TeamID, CreationInvitation: selected.CreationInvitation, Name: "terminal", Alias: "terminal", WorkingDir: t.TempDir(), APIKey: "fixture", AwebURL: server.URL, RegistryURL: "https://registry.example.test"}
			tree, err := newAPIKeyCreationRecovery(req)
			if scenario == "wrong-name" || scenario == "wrong-scope" {
				if err == nil {
					t.Fatal("changed invitation intent accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			request := tree.request(nil)
			if request == nil {
				t.Fatal("missing request")
			}
			if scenario == "legacy" {
				if request.Parent["kind"] != "namespace" || request.Domain != "other.example" || request.InvitationID != "" {
					t.Fatal(request)
				}
				return
			}
			if request.Parent["id"] != v.Keys["alice"].DIDAW || request.Domain != "example.com" || request.InvitationID != invitation["id"] {
				t.Fatalf("lost invitation: %+v", request)
			}
			if scenario == "retry-changed-parent" {
				req.IdentityHome = filepath.Join(req.WorkingDir, ".aw")
				registry := awid.NewAWIDRegistryClient(nil, nil)
				registry.DefaultRegistryURL = req.RegistryURL
				first, err := prepareAPIKeyBootstrapIdentity(req, req.Name, registry)
				if err != nil {
					t.Fatal(err)
				}
				selected.CreationInvitation.Parent["id"] = v.Keys["bob"].DIDAW
				if _, err := prepareAPIKeyBootstrapIdentity(req, req.Name, registry); err == nil {
					t.Fatal("retry changed parent")
				}
				state, err := loadAPIKeyPartialInit(apiKeyPartialInitPath(req.WorkingDir, req.IdentityHome))
				if err != nil {
					t.Fatal(err)
				}
				if state.DIDKey != first.DIDKey || state.IDTree.Parent["id"] != v.Keys["alice"].DIDAW {
					t.Fatal("retry replaced saved key or parent")
				}
			}
		})
	}
}

func TestHostedInvitePreviewConsumesPersonInvitationAndRetainsItOnRetry(t *testing.T) {
	v := adoptionVectors(t)
	for _, scope := range []string{"local", "global"} {
		t.Run(scope, func(t *testing.T) {
			previewReads := 0
			var origin string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/spawn/invite-preview" {
					http.NotFound(w, r)
					return
				}
				previewReads++
				json.NewEncoder(w).Encode(map[string]any{"invite_id": "22222222-2222-4222-8222-222222222222", "id_tree": nil, "canonical_team_id": "agents:other.example", "identity_scope": scope, "server_url": origin, "status": "active", "creation_invitation": map[string]any{"id": "11111111-1111-4111-8111-111111111111", "parent": map[string]any{"kind": "identity", "id": v.Keys["alice"].DIDAW}, "domain": "example.com", "name": "terminal", "identity_scope": scope}})
			}))
			defer server.Close()
			origin = server.URL
			material := workspaceTeamIdentityMaterial{DIDKey: v.Keys["root_agent"].DIDKey, IdentityScope: scope, StableID: v.Keys["global_agent"].DIDAW}
			state, err := prepareHostedInviteCreation(t.Context(), nil, "aw_inv_test", server.URL, "terminal", "other.example/different-address", false, material)
			if err != nil {
				t.Fatal(err)
			}
			request, err := state.prepareRequest(t.TempDir(), material)
			if err != nil {
				t.Fatal(err)
			}
			if request == nil || request.InvitationID != "11111111-1111-4111-8111-111111111111" || request.Parent["id"] != v.Keys["alice"].DIDAW || request.Domain != "example.com" {
				t.Fatalf("lost person selection: %+v", request)
			}
			retry, err := prepareHostedInviteCreation(t.Context(), state, "aw_inv_test", server.URL, "terminal", "other.example/different-address", false, material)
			if err != nil || retry != state || previewReads != 1 {
				t.Fatalf("retry: %v reads=%d", err, previewReads)
			}
		})
	}
}

func TestAPIKeyInitSendsAndRetainsInvitationBoundRequest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	v := adoptionVectors(t)
	posts := 0
	parent := v.Keys["alice"].DIDAW
	var origin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/teams/current":
			json.NewEncoder(w).Encode(map[string]any{"team_id": "22222222-2222-4222-8222-222222222222", "canonical_team_id": "agents:other.example", "creation_invitation": map[string]any{"id": "11111111-1111-4111-8111-111111111111", "parent": map[string]any{"kind": "identity", "id": parent}, "domain": "example.com", "name": "terminal", "identity_scope": "local"}})
		case "/api/v1/workspaces/init":
			posts++
			var req apiKeyBootstrapRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
			}
			if req.IDTree == nil || req.IDTree.Parent["id"] != v.Keys["alice"].DIDAW || req.IDTree.Domain != "example.com" || req.IDTree.InvitationID != "11111111-1111-4111-8111-111111111111" || req.Alias != "terminal" {
				t.Errorf("wrong creation request: %+v", req)
			}
			http.Error(w, "temporary", 503)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	origin = server.URL
	req := apiKeyInitRequest{WorkingDir: t.TempDir(), AwebURL: origin, RegistryURL: "https://registry.example.test", APIKey: "fixture", Alias: "terminal"}
	if _, err := runAPIKeyBootstrapInit(req); err == nil {
		t.Fatal("creation failure hidden")
	}
	if posts != 1 {
		t.Fatalf("posts=%d", posts)
	}
	state, err := loadAPIKeyPartialInit(apiKeyPartialInitPath(req.WorkingDir))
	if err != nil || state == nil {
		t.Fatalf("recovery: %v", err)
	}
	key, requestID := state.DIDKey, state.IDTree.RequestID
	parent = v.Keys["bob"].DIDAW
	if _, err := runAPIKeyBootstrapInit(req); err == nil {
		t.Fatal("changed invitation accepted on retry")
	}
	if posts != 1 {
		t.Fatal("changed parent reached creation")
	}
	state, err = loadAPIKeyPartialInit(apiKeyPartialInitPath(req.WorkingDir))
	if err != nil {
		t.Fatal(err)
	}
	if state.DIDKey != key || state.IDTree.RequestID != requestID || state.IDTree.Parent["id"] != v.Keys["alice"].DIDAW {
		t.Fatal("retry changed original key or request")
	}
}
