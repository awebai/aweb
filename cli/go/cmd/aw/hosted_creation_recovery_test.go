package main

import (
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostedCreationRetainsRequestIDWithOriginalKey(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "hosted-identity-create.json")
	association := hostedIdentityContext{Issuer: "https://service.test", AccountID: "account", Org: "org", TeamID: "agents:example.test", Name: "child", InboundMode: "team_and_contacts", RegistryURL: "http://127.0.0.1:1", Domain: "example.test", ParentKind: "identity", ParentID: "did:aw:selected-parent"}
	first, err := prepareHostedIdentity(root, path, association)
	if err != nil {
		t.Fatal(err)
	}
	requestID := func() string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var saved struct {
			IDTree struct {
				RequestID string `json:"request_id"`
			} `json:"id_tree"`
		}
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		if saved.IDTree.RequestID == "" {
			t.Fatal("creation request ID was not persisted with the key")
		}
		return saved.IDTree.RequestID
	}
	original := requestID()
	second, err := prepareHostedIdentity(root, path, association)
	if err != nil {
		t.Fatal(err)
	}
	if original != requestID() || first.DIDKey != second.DIDKey || !first.SigningKey.Equal(second.SigningKey) {
		t.Fatal("retry changed the request or child key")
	}
	changed := association
	changed.ParentID = "did:aw:different-parent"
	if _, err := prepareHostedIdentity(root, path, changed); err == nil {
		t.Fatal("changed creation operation reused the recovery key")
	}
	if original != requestID() {
		t.Fatal("refused operation changed original request")
	}
}

func TestHostedCreationFreezesReturnedRegistrationArguments(t *testing.T) {
	tree := &hostedIDTreeRecovery{}
	chain := awid.ReceivedIDChain{"v": json.Number("1"), "type": "aweb.id-chain", "certificates": []any{}}
	response := awid.IDTreeCreationResponse{IDChain: chain, RegistrationRequest: &awid.IDTreeRegistrationRequest{}}
	if err := tree.retainResponse(response); err != nil {
		t.Fatal(err)
	}
	original := tree.ResponseJSON
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	var restored hostedIDTreeRecovery
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if err := restored.retainResponse(response); err != nil || restored.ResponseJSON != original {
		t.Fatalf("retry changed original response: %v", err)
	}
	head := "different-head"
	response.RegistrationRequest = &awid.IDTreeRegistrationRequest{ExpectedHead: &head}
	if err := restored.retainResponse(response); err == nil {
		t.Fatal("changed registry operation reused recovery")
	}
	if restored.ResponseJSON != original {
		t.Fatal("refusal replaced original certificate arguments")
	}
	if err := (&hostedIDTreeRecovery{}).retainResponse(awid.IDTreeCreationResponse{RegistrationRequest: &awid.IDTreeRegistrationRequest{}}); err == nil {
		t.Fatal("accepted registration without a certificate")
	}
}

func TestHostedCreationOmissionCannotDowngradeAnExplicitNull(t *testing.T) {
	for _, tt := range []struct {
		name, kind, raw string
		ok              bool
	}{
		{"legacy-api-key", "namespace", `{}`, true},
		{"explicit-api-key-null", "namespace", `{"id_chain":null,"registration_request":null}`, false},
		{"partial-new-protocol", "namespace", `{"registration_request":null}`, false},
		{"person-no-fallback", "identity", `{}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			response, err := awid.DecodeIDTreeCreationResponse([]byte(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			tree := &hostedIDTreeRecovery{Domain: "example.test", Parent: map[string]any{"kind": tt.kind, "id": "selected"}}
			verdict, err := finishHostedIDTree(t.Context(), tree, response, workspaceTeamIdentityMaterial{}, t.TempDir(), nil, nil)
			if (err == nil) != tt.ok || verdict != nil {
				t.Fatalf("unexpected attribution %+v / %v", verdict, err)
			}
		})
	}
	tree := &hostedIDTreeRecovery{}
	explicit, _ := awid.DecodeIDTreeCreationResponse([]byte(`{"id_chain":null,"registration_request":null}`))
	omitted, _ := awid.DecodeIDTreeCreationResponse([]byte(`{}`))
	if err := tree.retainResponse(explicit); err != nil {
		t.Fatal(err)
	}
	if err := tree.retainResponse(omitted); err == nil {
		t.Fatal("retry dropped the advertised protocol to bypass incomplete attribution")
	}
}

func TestAPIKeyLocalCreationRetainsKeyRequestAndSelectedTeam(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := apiKeyInitRequest{WorkingDir: root, IdentityHome: filepath.Join(root, ".aw"), AwebURL: "http://127.0.0.1:1", APIKey: "fixture-only", Alias: "child", SelectedTeamID: "11111111-1111-4111-8111-111111111111", CanonicalTeamID: "agents:example.test"}
	first, err := prepareAPIKeyBootstrapIdentity(req, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadAPIKeyPartialInit(apiKeyPartialInitPath(root, req.IdentityHome))
	if err != nil || state == nil || state.IDTree == nil {
		t.Fatalf("local creation lacks durable recovery: %v", err)
	}
	id := state.IDTree.RequestID
	second, err := prepareAPIKeyBootstrapIdentity(req, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.DIDKey != second.DIDKey || id == "" {
		t.Fatal("local retry replaced original key/request")
	}
	changed := req
	changed.CanonicalTeamID = "agents:other.test"
	if _, err := prepareAPIKeyBootstrapIdentity(changed, "", nil); err == nil {
		t.Fatal("changed team/parent reused the original operation")
	}
	after, err := loadAPIKeyPartialInit(apiKeyPartialInitPath(root, req.IdentityHome))
	if err != nil {
		t.Fatal(err)
	}
	if after.IDTree.RequestID != id || after.DIDKey != first.DIDKey {
		t.Fatal("refused change replaced original operation")
	}
}

func TestAPIKeyCreationCannotReplaceAnActiveOperationsRecovery(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, ".aw")
	lock, err := awconfig.TryLockExclusive(apiKeyPartialInitPath(root, home) + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{WorkingDir: root, IdentityHome: home, AwebURL: "http://127.0.0.1:1", APIKey: "fixture-only", Alias: "child"})
	if err == nil || !strings.Contains(err.Error(), "creation already in progress") {
		t.Fatalf("concurrent creation reached another effect: %v", err)
	}
}
