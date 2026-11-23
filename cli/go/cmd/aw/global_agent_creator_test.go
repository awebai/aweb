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
	for _, sample := range []struct {
		name                 string
		chained, mintFailure bool
	}{
		{"registered creator", true, false},
		{"chainless unchanged", false, false},
		{"prepared global identity survives mint failure", false, true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			chained := sample.chained
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
			rows := []any{}
			for _, raw := range status["identities"].([]any) {
				if raw.(map[string]any)["id"] != target.DIDAW {
					rows = append(rows, raw)
				}
			}
			status["identities"] = rows
			status["missing"] = []any{target.DIDAW}
			idWrites, teamWrites, creatorKeyReads := 0, 0, 0
			var signed map[string]any
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/id-certificates/status":
					status["observed_at"] = time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")
					json.NewEncoder(w).Encode(status)
				case strings.HasSuffix(r.URL.Path, "/encryption-key"):
					writeRegistryEncryptionKeyAssertionForTest(t, w, r)
				case r.URL.Path == "/v1/did/"+actor.DIDAW+"/key":
					creatorKeyReads++
					// A chainless registered creator needs a current,
					// explicitly not-enrolled key response of its own.
					json.NewEncoder(w).Encode(map[string]any{"did_aw": actor.DIDAW, "current_did_key": actor.DIDKey, "id_tree": map[string]any{"enrolled": chained}})
				case r.URL.Path == "/v1/did/"+target.DIDAW+"/key":
					tree := map[string]any{"enrolled": idWrites > 0}
					if idWrites > 0 {
						tree["domain"] = "example.com"
					}
					json.NewEncoder(w).Encode(map[string]any{"did_aw": target.DIDAW, "current_did_key": target.DIDKey, "id_tree": tree})
				case r.URL.Path == "/v1/did":
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
					targetRow["certificates"] = []any{map[string]any{"signed": signed, "registered_at": time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"), "superseded_at": nil, "issuer_key_seq": 1}}
					status["identities"] = append(rows, targetRow)
					status["missing"] = []any{}
					json.NewEncoder(w).Encode(map[string]any{"registered_at": time.Now().UTC().Format("2006-01-02T15:04:05.000000Z")})
				case strings.HasSuffix(r.URL.Path, "/addresses/child"):
					json.NewEncoder(w).Encode(map[string]any{"domain": "example.com", "name": "child", "did_aw": target.DIDAW, "current_did_key": target.DIDKey})
				case strings.HasSuffix(r.URL.Path, "/teams/backend/certificates"):
					if chained && idWrites != 1 {
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
			if !sample.mintFailure {
				if err := awconfig.SaveTeamKey("example.com", "backend", teamKey); err != nil {
					t.Fatal(err)
				}
			}
			seed, _ := hex.DecodeString(actor.SeedHex)
			actorKey := ed25519.NewKeyFromSeed(seed)
			connectCalls, publishCalls, mintCalls := 0, 0, 0
			service := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if sample.mintFailure && r.URL.Path == "/api/v1/spawn/create-invite" {
					mintCalls++
					http.Error(w, "invite service unavailable", http.StatusServiceUnavailable)
					return
				}
				if r.URL.Path == "/v1/connect" {
					connectCalls++
					cert, err := awid.DecodeTeamCertificateHeader(r.Header.Get(awid.HeaderTeamCertificate))
					if err != nil {
						t.Error(err)
						http.Error(w, "invalid membership", http.StatusUnauthorized)
						return
					}
					if cert.MemberDIDKey != target.DIDKey || cert.Team != "backend:example.com" || cert.Alias != "child" {
						t.Error("connect did not use the newly issued member certificate")
					}
					if err := json.NewEncoder(w).Encode(map[string]any{"team_id": cert.Team, "alias": cert.Alias, "agent_id": "child", "workspace_id": "workspace-child", "team_did_key": cert.TeamDIDKey}); err != nil {
						t.Error(err)
					}
					return
				}
				if strings.HasSuffix(r.URL.Path, "/encryption-key") {
					publishCalls++
					if connectCalls != 1 {
						t.Error("encryption publication preceded normal member admission")
					}
					writePublishEncryptionKeyResponseForTest(t, w, "child", "backend:example.com", "child")
					return
				}
				t.Errorf("unexpected service call %s", r.URL.Path)
				http.NotFound(w, r)
			}))
			defer service.Close()
			workspace := workspaceBinding(service.URL, "backend:example.com", "creator", "workspace-parent")
			writeTeamCertificateWorkspaceForTest(t, root, workspace, &testSelectionFixture{SigningKey: actorKey, IdentityScope: "global"})
			if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), actorKey); err != nil {
				t.Fatal(err)
			}
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
			if chained {
				if err := awconfig.SaveInstalledIDChain(filepath.Join(root, ".aw"), map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["global-agent"].Signed}}); err != nil {
					t.Fatal(err)
				}
			}
			accepted, err := createProvisionedTeamMember(teamMemberCreation{SourceDir: root, HomeDir: child, Name: "child", Scope: awid.IdentityScopeGlobal})
			if sample.mintFailure {
				if mintCalls != 1 {
					t.Fatalf("mint-failure control did not reach its endpoint: calls=%d err=%v", mintCalls, err)
				}
				if err == nil || !retainUnfinishedProvisioningIdentity(err) {
					t.Fatalf("mint refusal could discard the prepared global identity: %v", err)
				}
				if teamWrites != 0 || idWrites != 0 {
					t.Fatal("mint-failure control unexpectedly submitted a membership or child chain")
				}
				return
			}
			if err != nil {
				t.Fatalf("global creator provisioning (%d ID writes/%d membership writes): %v", idWrites, teamWrites, err)
			}
			if connectCalls != 1 || publishCalls == 0 {
				t.Fatalf("provisioning completed without connect/publication: %d/%d", connectCalls, publishCalls)
			}
			if !chained && creatorKeyReads != 1 {
				t.Fatalf("chainless creator key reads=%d; want one authoritative absence check", creatorKeyReads)
			}
			wantIDWrites := 0
			if chained {
				wantIDWrites = 1
			}
			if idWrites != wantIDWrites || teamWrites != 1 {
				t.Fatalf("writes %d/%d result %+v", idWrites, teamWrites, accepted.Output)
			}
			verdict, err := executeWho(context.Background(), whoOptions{WorkingDir: child})
			if !chained {
				if err != nil || verdict.Outcome != "unknown" {
					t.Fatalf("chainless changed: %+v %v", verdict, err)
				}
				return
			}
			if err != nil || verdict.HumanID == nil || *verdict.HumanID != v.Keys["alice"].DIDAW {
				t.Fatalf("ancestry %+v %v", verdict, err)
			}

		})
	}
}
