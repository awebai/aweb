package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Continue the provisioning path with its newly registered key/address, before
// any parent certificate or membership exists. All exchange/signing is product code.
func TestTeamAdminGlobalAgentGetsRegisteredCreatorsChain(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("APP_ENV", "development")
	v := loadWhoVectors(t)
	root, child := t.TempDir(), t.TempDir()
	actor, target := v.Keys["global_agent"], v.Keys["bob"]
	status := v.Statuses["normal"]
	var targetRow map[string]any
	for _, raw := range status["identities"].([]any) {
		row := raw.(map[string]any)
		if row["id"] == target.DIDAW {
			targetRow = row
			row["certificates"] = []any{}
			row["current_certificate_id"] = nil
		}
	}
	idWrites, teamWrites := 0, 0
	var signed map[string]any
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/id-certificates/status":
			json.NewEncoder(w).Encode(status)
		case r.URL.Path == "/v1/did/register":
			json.NewEncoder(w).Encode(map[string]any{"did_aw": target.DIDAW, "did_key": target.DIDKey})
		case r.URL.Path == "/v1/id-certificates/register":
			var body map[string]any
			dec := json.NewDecoder(r.Body)
			dec.UseNumber()
			dec.Decode(&body)
			signed = body["certificate"].(map[string]any)
			certificate := signed["certificate"].(map[string]any)
			if certificate["parent"].(map[string]any)["id"] != actor.DIDAW || certificate["id"] != target.DIDAW {
				t.Error("wrong creator or child")
			}
			idWrites++
			certID, _ := awid.IDCertificateID(certificate)
			targetRow["current_certificate_id"] = certID
			targetRow["certificates"] = []any{map[string]any{"signed": signed, "registered_at": certificate["issued_at"], "superseded_at": nil, "issuer_key_seq": 1}}
			json.NewEncoder(w).Encode(map[string]any{"registered_at": time.Now().UTC().Format(time.RFC3339Nano)})
		case strings.HasSuffix(r.URL.Path, "/addresses/child"):
			json.NewEncoder(w).Encode(map[string]any{"domain": "example.com", "name": "child", "did_aw": target.DIDAW, "current_did_key": target.DIDKey})
		case strings.HasSuffix(r.URL.Path, "/teams/backend/certificates"):
			if idWrites != 1 {
				t.Error("membership before creator registration")
			}
			teamWrites++
			json.NewEncoder(w).Encode(map[string]any{"status": "registered"})
		default:
			t.Errorf("unexpected registry %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer registry.Close()
	origin := strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
	t.Setenv("AWID_REGISTRY_URL", origin)
	serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, origin))
	_, teamKey, _ := awid.GenerateKeypair()
	if err := awconfig.SaveTeamKey("example.com", "backend", teamKey); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(actor.SeedHex)
	actorKey := ed25519.NewKeyFromSeed(seed)
	workspace := workspaceBinding("http://127.0.0.1:1", "backend:example.com", "creator", "workspace-parent")
	writeTeamCertificateWorkspaceForTest(t, root, workspace, &testSelectionFixture{SigningKey: actorKey, IdentityScope: "global"})
	writeWorkspaceBindingForTest(t, root, workspace)
	for _, entry := range []struct {
		dir         string
		did, stable string
		key         ed25519.PrivateKey
	}{{root, actor.DIDKey, actor.DIDAW, actorKey}, {child, target.DIDKey, target.DIDAW, nil}} {
		key := entry.key
		if key == nil {
			seed, _ := hex.DecodeString(target.SeedHex)
			key = ed25519.NewKeyFromSeed(seed)
		}
		if err := awid.SaveSigningKey(filepath.Join(entry.dir, ".aw", "signing.key"), key); err != nil {
			t.Fatal(err)
		}
		address := "example.com/creator"
		if entry.dir == child {
			address = "example.com/child"
		}
		writeIdentityForTest(t, entry.dir, awconfig.WorktreeIdentity{DID: entry.did, StableID: entry.stable, Custody: "self", IdentityScope: "global", RegistryURL: origin, RegistryStatus: "registered", Address: address, CreatedAt: "2026-10-26T00:00:00Z"})
	}
	if err := awconfig.SaveInstalledIDChain(filepath.Join(root, ".aw"), map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["global-agent"].Signed}}); err != nil {
		t.Fatal(err)
	}
	accepted, err := createAndAcceptTeamInviteForEmptyAgent(root, child, "child", true)
	if err != nil {
		t.Fatalf("global creator provisioning: %v", err)
	}
	if idWrites != 1 || teamWrites != 1 || accepted.Output.Responsibility == nil || accepted.Output.Responsibility.Outcome != "nearest_human" {
		t.Fatalf("writes %d/%d result %+v", idWrites, teamWrites, accepted.Output)
	}
	verdict, err := executeWho(context.Background(), whoOptions{WorkingDir: child})
	if err != nil || verdict.HumanID == nil || *verdict.HumanID != v.Keys["alice"].DIDAW {
		t.Fatalf("ancestry %+v %v", verdict, err)
	}
}
