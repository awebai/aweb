package main

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// The hosted boundary is HTTP; the child's proof, parent approval, import and
// chain verification run the production exchange, with no substituted signer.
func TestHostedRosterRunsNativeChildExchange(t *testing.T) {
	for _, scenario := range []string{"three children", "cert-only worktree", "cert-only revoked parent", "revoked parent", "different preview parent"} {
		t.Run(scenario, func(t *testing.T) {
			resetTeamHumanCreateGlobals(t)
			v := loadWhoVectors(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AW_CONFIG_PATH", "")
			root := t.TempDir()
			t.Chdir(root)
			t.Setenv("AWEB_IDENTITY_HOME", "")
			t.Setenv("AWEB_API_KEY", "")
			t.Setenv("APP_ENV", "development")
			seed, _ := hex.DecodeString(v.Keys["coordinator"].SeedHex)
			parentKey := ed25519.NewKeyFromSeed(seed)
			parent := v.Keys["coordinator"].DIDKey
			if err := awid.SaveSigningKey(filepath.Join(root, ".aw", "signing.key"), parentKey); err != nil {
				t.Fatal(err)
			}
			if err := awconfig.SaveInstalledIDChain(filepath.Join(root, ".aw"), map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}); err != nil {
				t.Fatal(err)
			}
			status := v.Statuses["normal"]
			worktree := strings.HasPrefix(scenario, "cert-only")
			if scenario == "revoked parent" || scenario == "cert-only revoked parent" {
				status = v.Statuses["alice-revoked-now"]
			}
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/id-certificates/status" {
					t.Errorf("unexpected registry call %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				json.NewEncoder(w).Encode(status)
			}))
			defer registry.Close()
			registryURL := strings.Replace(registry.URL, "127.0.0.1", "registry.example.com", 1)
			t.Setenv("AWID_REGISTRY_URL", registryURL)
			serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, registryURL))
			const team = "backend:example.com"
			_, teamKey, _ := awid.GenerateKeypair()
			previews, accepts := 0, 0
			var origin string
			service := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/discovery", "/v1/discovery":
					json.NewEncoder(w).Encode(map[string]string{"aweb_url": origin, "registry_url": registryURL})
				case "/v1/roles/active", "/api/v1/roles/active":
					json.NewEncoder(w).Encode(map[string]any{"roles": map[string]any{"developer": map[string]any{"description": "Develop"}}})
				case "/v1/workspaces/team":
					json.NewEncoder(w).Encode(map[string]any{"workspaces": []any{}})
				case "/v1/agents", "/api/v1/agents":
					json.NewEncoder(w).Encode(awid.ListAgentsResponse{})
				case "/api/v1/spawn/create-invite":
					cert := requireCertificateAuthForTest(t, r)
					if cert.MemberDIDKey != parent {
						t.Error("invite did not use the parent identity")
					}
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "token": "aw_inv_native_roster", "id_tree": map[string]any{"v": 1, "issuer_id": parent, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
				case "/api/v1/spawn/invite-preview":
					previews++
					pinned := parent
					if scenario == "different preview parent" {
						pinned = v.Keys["alice"].DIDKey
					}
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": team, "identity_scope": "unknown", "server_url": origin, "status": "active", "id_tree": map[string]any{"v": 1, "issuer_id": pinned, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
				case "/api/v1/spawn/accept-invite":
					accepts++
					var req awid.SpawnAcceptInviteRequest
					dec := json.NewDecoder(r.Body)
					dec.UseNumber()
					if err := dec.Decode(&req); err != nil {
						t.Error(err)
						http.Error(w, "bad request", 400)
						return
					}
					if req.IDTree == nil || req.IDTree.IDChain == nil || req.IDTree.Parent["id"] != parent || req.IDTree.Mode != "self_custodial" {
						t.Error("hosted accept did not carry the parent-issued child chain")
						http.Error(w, "missing chain", 422)
						return
					}
					chain := req.IDTree.IDChain
					certs := chain["certificates"].([]any)
					leaf := certs[len(certs)-1].(map[string]any)["certificate"].(map[string]any)
					if leaf["id"] != req.DID || leaf["kind"] != "agent" || leaf["parent"].(map[string]any)["id"] != parent {
						t.Error("child binding changed")
					}
					childHome := filepath.Join(root, "agents", "instances", req.Alias, ".aw")
					if worktree {
						childHome = filepath.Join(root+"-child", ".aw")
					}
					pending, err := loadHostedInviteCreation(filepath.Join(childHome, hostedInviteRecoveryFile))
					if err != nil || pending == nil || pending.DIDKey != req.DID || pending.Tree.RequestID != req.IDTree.RequestID {
						t.Error("original child request/key not retained through exchange")
					}
					cert, _ := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: team, MemberDIDKey: req.DID, Alias: req.Alias, IdentityScope: "local"})
					encoded, _ := awid.EncodeTeamCertificateHeader(cert)
					json.NewEncoder(w).Encode(map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "cloud-" + req.Alias, "alias": req.Alias, "server_url": origin, "did": req.DID, "identity_scope": "local", "custody": "self", "created": true, "team_cert": encoded, "id_chain": chain, "registration_request": nil})
				case "/v1/connect":
					json.NewEncoder(w).Encode(map[string]any{"workspace_id": "workspace-child", "agent_id": "cloud-child", "alias": "child", "team_id": team, "role": "developer", "server_url": origin})
				case "/v1/agents/me/encryption-key", "/api/v1/agents/me/encryption-key":
					writePublishEncryptionKeyResponseForTest(t, w, "cloud-child", team, "child")
				default:
					t.Errorf("unexpected service request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer service.Close()
			origin = service.URL
			t.Setenv("AWEB_URL", origin)
			workspace := workspaceBinding(origin, team, "coordinator", "workspace-parent")
			writeTeamCertificateWorkspaceForTest(t, root, workspace, &testSelectionFixture{SigningKey: parentKey, IdentityScope: "local"})
			writeWorkspaceBindingForTest(t, root, workspace)
			if worktree {
				// Normal local constructor state has a key, certificate and
				// chain, with no global identity file and no stored API key.
				if err := exec.Command("git", "init", root).Run(); err != nil {
					t.Fatal(err)
				}
				specs := []string{"config", "user.email", "fixture@example.test"}
				if err := exec.Command("git", append([]string{"-C", root}, specs...)...).Run(); err != nil {
					t.Fatal(err)
				}
				if err := exec.Command("git", "-C", root, "config", "user.name", "Fixture").Run(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".aw/\nagents/\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := exec.Command("git", "-C", root, "add", ".gitignore").Run(); err != nil {
					t.Fatal(err)
				}
				if err := exec.Command("git", "-C", root, "commit", "-m", "fixture").Run(); err != nil {
					t.Fatal(err)
				}
				oldAlias := workspaceAddAlias
				workspaceAddAlias = "child"
				t.Cleanup(func() { workspaceAddAlias = oldAlias })
				err := runWorkspaceAddWorktree(nil, []string{"developer"})
				if scenario == "cert-only revoked parent" {
					if err == nil || accepts != 0 {
						t.Fatalf("revoked parent accepted: err=%v accepts=%d", err, accepts)
					}
					assertHostedPendingChildKey(t, filepath.Join(root+"-child", ".aw"))
					return
				}
				if err != nil {
					t.Fatalf("cert-only hosted worktree failed: %v", err)
				}
				if accepts != 1 || previews != 1 {
					t.Fatalf("accepts=%d previews=%d", accepts, previews)
				}
				return
			}
			specs := []teamAgentSpec{{Raw: "alice", Name: "alice", Scope: "local"}, {Raw: "bob", Name: "bob", Scope: "local"}, {Raw: "charlie", Name: "charlie", Scope: "local"}}
			err := runTeamHumanCreateRosterAdd(specs)
			if scenario != "three children" {
				if err == nil || accepts != 0 {
					t.Fatalf("unsafe parent accepted: err=%v accepts=%d", err, accepts)
				}
				home := filepath.Join(root, "agents", "instances", "alice", ".aw")
				assertHostedPendingChildKey(t, home)
				return
			}
			if err != nil {
				invitations, _ := (awconfig.IDInvitationFileStore{Dir: awconfig.IdentityInvitationsDir(filepath.Join(root, ".aw"))}).Invitations()
				for _, inv := range invitations {
					if inv.Request != nil {
						t.Logf("parent request state %s", inv.Request.State)
					}
				}
				t.Fatalf("normal hosted roster failed: %v", err)
			}
			if accepts != 3 || previews != 3 {
				t.Fatalf("accepts=%d previews=%d; each child must use its first preview/key", accepts, previews)
			}
			for _, spec := range specs {
				home := filepath.Join(root, "agents", "instances", spec.Name)
				chain, err := awconfig.LoadInstalledIDChain(filepath.Join(home, ".aw"))
				if err != nil || chain == nil {
					t.Fatalf("%s has no child chain: %v", spec.Name, err)
				}
				key, _ := awid.LoadSigningKey(filepath.Join(home, ".aw", "signing.key"))
				verdict, err := executeWho(context.Background(), whoOptions{WorkingDir: home})
				if err != nil || verdict.Outcome != "nearest_human" || verdict.HumanID == nil || *verdict.HumanID != v.Keys["alice"].DIDAW {
					t.Fatalf("%s ancestry=%+v err=%v", spec.Name, verdict, err)
				}
				if verdict.ID != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) {
					t.Fatal("issued identity differs from child key")
				}
			}
		})
	}
}

func assertHostedPendingChildKey(t *testing.T, home string) {
	t.Helper()
	pending, err := loadHostedInviteCreation(filepath.Join(home, hostedInviteRecoveryFile))
	if err != nil || pending == nil {
		t.Fatalf("pending child was rolled back before exchange: %v", err)
	}
	key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil || awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != pending.DIDKey {
		t.Fatal("pending child key was lost")
	}
}

// Use the ordinary net resolver for the frozen domain's TXT. Production still
// parses the DNS record and verifies the full chain/status evidence.
func serveRosterTXT(t *testing.T, record string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old; conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			if n < 16 {
				continue
			}
			end := 12
			var labels []string
			for end < n && packet[end] != 0 {
				size := int(packet[end])
				end++
				if end+size >= n {
					break
				}
				labels = append(labels, string(packet[end:end+size]))
				end += size
			}
			if end+5 > n {
				continue
			}
			end++
			typ := binary.BigEndian.Uint16(packet[end : end+2])
			end += 4
			answer := append([]byte(nil), packet[:end]...)
			answer[2], answer[3] = 0x81, 0x80
			binary.BigEndian.PutUint16(answer[6:8], 0)
			binary.BigEndian.PutUint16(answer[8:10], 0)
			binary.BigEndian.PutUint16(answer[10:12], 0)

			if typ == 16 && strings.Join(labels, ".") == "_awid.example.com" {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				data := append([]byte{byte(len(record))}, []byte(record)...)
				answer = append(answer, 0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, byte(len(data)>>8), byte(len(data)))
				answer = append(answer, data...)
			} else if typ == 1 && strings.Join(labels, ".") == "registry.example.com" {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			}
			conn.WriteTo(answer, addr)
		}
	}()
}
