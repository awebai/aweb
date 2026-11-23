package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// The hosted boundary is HTTP; the child's proof, parent approval, import and
// chain verification run the production exchange, with no substituted signer.
func TestHostedRosterRunsNativeChildExchange(t *testing.T) {
	for _, scenario := range []string{
		"three children",
		"three children workspace key add",
		"three children workspace key extend",
		"workspace key wrong team",
		"three children discovered creator",
		"join-from stored key",
		"implicit init workspace key refuses external home",
		"cert-only worktree",
		"cert-only revoked parent",
		"revoked parent",
		"different preview parent",
		"join-from workspace",
		"join-from identity home",
		"join-from revoked parent",
		"further-team external home",
		"further-team cross-machine recipe",
		"further-team retry",
		"further-team api-base alias",
		"further-team cleanup warning",
		"further-team consumption failure",
		"further-team own chain",
		"further-team parent source",
		"further-team other human fresh",
		"further-team independent init",
		"further-team independent init stdin",
		"further-team independent init file",
		"further-team own chain retry",
		"further-team explicit condition echo",
		"further-team explicit condition missing echo",
		"global provision chained actor",
		"join-from retry preview",
		"join-from retry accept",
		"join-from retry connect",
		"join-from retry connect without saved key",
		"further-team parent source retry",
		"further-team add parent retry",
		"further-team parent signed retry",
		"further-team parent two children",
		"further-team parent host managed",
	} {
		t.Run(scenario, func(t *testing.T) {
			resetTeamHumanCreateGlobals(t)
			v := loadWhoVectors(t)
			t.Setenv("HOME", t.TempDir())
			t.Setenv("AW_CONFIG_PATH", "")
			var warningLog *os.File
			if scenario == "further-team cleanup warning" || strings.Contains(scenario, "workspace key") {
				var err error
				warningLog, err = os.CreateTemp(t.TempDir(), "stderr")
				if err != nil {
					t.Fatal(err)
				}
				oldStderr := os.Stderr
				os.Stderr = warningLog
				t.Cleanup(func() {
					os.Stderr = oldStderr
					warningLog.Close()
				})
			}
			deployment := t.TempDir()
			root := deployment
			if scenario == "three children discovered creator" {
				root = filepath.Join(deployment, "agents", "instances", "creator")
				if err := os.MkdirAll(root, 0700); err != nil {
					t.Fatal(err)
				}
			}
			rosterRoot := root
			if scenario == "three children discovered creator" {
				rosterRoot = deployment
			}
			joinFrom := strings.HasPrefix(scenario, "join-from") || scenario == "implicit init workspace key refuses external home"
			furtherTeam := strings.HasPrefix(scenario, "further-team")
			childDir := root + "-child"
			if joinFrom || furtherTeam {
				childDir = t.TempDir()
			}
			recipientHome := filepath.Join(childDir, ".aw")
			if furtherTeam && !strings.HasPrefix(scenario, "further-team independent init") {
				recipientHome = t.TempDir()
			}
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
			var revoked atomic.Bool
			teamPublic, teamKey, keyErr := awid.GenerateKeypair()
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			var receivedMember atomic.Pointer[awid.TeamCertificate]
			var failedAfterSignature atomic.Bool
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if cert := receivedMember.Load(); cert != nil && strings.HasSuffix(r.URL.Path, "/certificates/"+cert.CertificateID+"/status") {
					if err := json.NewEncoder(w).Encode(awid.TeamCertificateStatus{TeamID: cert.Team, TeamDIDKey: awid.ComputeDIDKey(teamPublic), Status: "active"}); err != nil {
						t.Error(err)
					}
					return
				}
				if scenario == "further-team parent signed retry" {
					entries, _ := filepath.Glob(filepath.Join(awconfig.IdentityIssuanceDir(filepath.Join(root, ".aw")), "*.json"))
					if len(entries) > 0 && failedAfterSignature.CompareAndSwap(false, true) {
						http.Error(w, "import unavailable after parent signed", 503)
						return
					}
				}
				if r.URL.Path != "/v1/id-certificates/status" {
					t.Errorf("unexpected registry call %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				current := status
				if revoked.Load() {
					current = v.Statuses["alice-revoked-now"]
				}
				json.NewEncoder(w).Encode(current)
			}))
			defer registry.Close()
			registryURL := strings.Replace(registry.URL, "127.0.0.1", "registry.example", 1)
			t.Setenv("AWID_REGISTRY_URL", registryURL)
			serveRosterTXT(t, idCreateDNSRecordValue(v.Keys["root"].DIDKey, registryURL))
			const team = "backend:example.com"
			previews, accepts, creates, connects := 0, 0, 0, 0
			var origin string
			service := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/teams/current":
					canonical := team
					if scenario == "workspace key wrong team" {
						canonical = "other:example.com"
					}
					json.NewEncoder(w).Encode(map[string]any{"team_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": canonical, "api_key_kind": "workspace"})
				case "/api/v1/discovery", "/v1/discovery":
					json.NewEncoder(w).Encode(map[string]string{"aweb_url": origin, "registry_url": registryURL})
				case "/v1/roles/active", "/api/v1/roles/active":
					json.NewEncoder(w).Encode(map[string]any{"roles": map[string]any{"developer": map[string]any{"description": "Develop"}}})
				case "/v1/workspaces/team":
					json.NewEncoder(w).Encode(map[string]any{"workspaces": []any{}})
				case "/v1/agents", "/api/v1/agents":
					json.NewEncoder(w).Encode(awid.ListAgentsResponse{})
				case "/api/v1/spawn/create-invite":
					creates++
					cert := requireCertificateAuthForTest(t, r)
					if cert.MemberDIDKey != parent {
						t.Error("invite did not use the parent identity")
					}
					var echoedHuman any
					if scenario == "further-team explicit condition echo" {
						echoedHuman = v.Keys["alice"].DIDAW
					}
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "token": "aw_inv_native_roster", "for_human": echoedHuman, "id_tree": map[string]any{"v": 1, "issuer_id": parent, "domain": "example.com", "child_kind": "agent", "mode": "self_custodial"}})
				case "/api/v1/spawn/invite-preview":
					previews++
					if scenario == "join-from retry preview" && previews == 1 {
						http.Error(w, "preview unavailable", 503)
						return
					}
					// Revoke after issuance, before completion must recheck it.
					if strings.Contains(scenario, "revoked parent") {
						revoked.Store(true)
					}
					pinned := parent
					if scenario == "different preview parent" {
						pinned = v.Keys["alice"].DIDKey
					}
					var requiredHuman any
					if scenario == "further-team other human fresh" {
						requiredHuman = v.Keys["bob"].DIDAW
					}
					if scenario == "further-team explicit condition echo" {
						requiredHuman = v.Keys["alice"].DIDAW
					}
					mode := "self_custodial"
					if scenario == "further-team parent host managed" {
						mode = "host_managed"
					}
					json.NewEncoder(w).Encode(map[string]any{"invite_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": team, "identity_scope": "unknown", "server_url": origin, "status": "active", "for_human": requiredHuman, "id_tree": map[string]any{"v": 1, "issuer_id": pinned, "domain": "example.com", "child_kind": "agent", "mode": mode}})
				case "/api/v1/spawn/accept-invite":
					accepts++
					if scenario == "further-team parent two children" && accepts <= 2 {
						http.Error(w, "pending", 503)
						return
					}
					if (scenario == "further-team retry" || scenario == "further-team own chain retry" || scenario == "join-from retry accept" || scenario == "further-team parent source retry") && accepts == 1 {
						http.Error(w, "retryable service failure", http.StatusServiceUnavailable)
						return
					}
					var req awid.SpawnAcceptInviteRequest
					dec := json.NewDecoder(r.Body)
					dec.UseNumber()
					if err := dec.Decode(&req); err != nil {
						t.Error(err)
						http.Error(w, "bad request", 400)
						return
					}
					independent := strings.HasPrefix(scenario, "further-team own chain") || strings.HasPrefix(scenario, "further-team parent") || scenario == "further-team add parent retry" || strings.HasPrefix(scenario, "further-team independent init")
					if !independent && (req.IDTree == nil || req.IDTree.IDChain == nil || req.IDTree.Parent["id"] != parent || req.IDTree.Mode != "self_custodial") {
						t.Error("hosted accept did not carry the parent-issued child chain")
						http.Error(w, "missing chain", 422)
						return
					}
					var chain map[string]any
					requestID := ""
					if independent {
						if req.IDTree != nil || req.IDChain == nil {
							t.Error("independent creator used invite parentage")
							http.Error(w, "missing own chain", 422)
							return
						}
						chain = *req.IDChain
					} else {
						chain = req.IDTree.IDChain
						requestID = req.IDTree.RequestID
					}
					certs := chain["certificates"].([]any)
					leaf := certs[len(certs)-1].(map[string]any)["certificate"].(map[string]any)
					if leaf["id"] != req.DID || leaf["kind"] != "agent" || (!strings.HasPrefix(scenario, "further-team own chain") && leaf["parent"].(map[string]any)["id"] != parent) {
						t.Error("child binding changed")
					}
					childHome := filepath.Join(rosterRoot, "agents", "instances", req.Alias, ".aw")
					if worktree || joinFrom {
						childHome = filepath.Join(childDir, ".aw")
					}
					if furtherTeam {
						childHome = recipientHome
					}
					pending, err := loadHostedInviteCreation(filepath.Join(childHome, hostedInviteRecoveryFile))
					if err != nil || pending == nil || pending.DIDKey != req.DID || (!independent && pending.Tree.RequestID != requestID) {
						t.Error("original child request/key not retained through exchange")
					}
					if scenario == "further-team consumption failure" {
						// The exchange has finished; make consumption recording fail even
						// when tests run as root, without substituting filesystem calls.
						dir, err := awconfig.DefaultTeamInvitesDir()
						if err != nil {
							t.Error(err)
							return
						}
						path := filepath.Join(dir, hostedTeamInviteRecordID("aw_inv_native_roster")+".json")
						if err := os.Remove(path); err != nil {
							t.Error(err)
							return
						}
						if err := os.Mkdir(path, 0700); err != nil {
							t.Error(err)
							return
						}
						if err := os.WriteFile(filepath.Join(path, "held"), []byte("keep directory nonempty"), 0600); err != nil {
							t.Error(err)
							return
						}
					}
					cert, _ := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: team, MemberDIDKey: req.DID, Alias: req.Alias, IdentityScope: "local"})
					receivedMember.Store(cert)
					encoded, _ := awid.EncodeTeamCertificateHeader(cert)
					json.NewEncoder(w).Encode(map[string]any{"team_id": "cloud-team", "team_slug": "backend", "namespace": "example.com", "identity_id": "cloud-" + req.Alias, "alias": req.Alias, "server_url": origin, "did": req.DID, "identity_scope": "local", "custody": "self", "created": true, "team_cert": encoded, "id_chain": chain, "registration_request": nil})
				case "/v1/connect":
					connects++
					if strings.HasPrefix(scenario, "join-from retry connect") && connects == 1 {
						http.Error(w, "connect unavailable", 503)
						return
					}
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
			if strings.Contains(scenario, "workspace key") || scenario == "join-from stored key" {
				workspace.APIKey = "aw_sk_stored"
			}
			if strings.Contains(scenario, "workspace key") {
				t.Setenv("AWEB_API_KEY", "aw_sk_selected_agent")
			}
			if scenario == "further-team api-base alias" {
				workspace.AwebURL = origin + "/api"
			}
			writeTeamCertificateWorkspaceForTest(t, root, workspace, &testSelectionFixture{SigningKey: parentKey, IdentityScope: "local"})
			writeWorkspaceBindingForTest(t, root, workspace)
			if scenario == "workspace key wrong team" {
				err := runTeamHumanAddWithOptions(authTestCmd(&bytes.Buffer{}), nil, teamHumanAddRunOptions{Specs: []teamAgentSpec{{Raw: "child:local", Name: "child", Scope: "local"}}})
				want := "This workspace belongs to backend:example.com, not other:example.com. " + creationA5
				if err == nil || err.Error() != want || accepts != 0 || previews != 0 {
					t.Fatalf("wrong-team authority: %v previews=%d accepts=%d", err, previews, accepts)
				}
				if _, err := os.Stat(filepath.Join(root, "agents")); !os.IsNotExist(err) {
					t.Fatalf("wrong-team wrote child state: %v", err)
				}
				return
			}
			assertNotice := func() {
				if strings.Contains(scenario, "workspace key") {
					raw, err := os.ReadFile(warningLog.Name())
					if err != nil {
						t.Fatal(err)
					}
					if strings.Count(string(raw), creationWorkspaceNotice+"\n") != 1 {
						t.Fatalf("notice must occur once: %q", raw)
					}
				}
			}
			if scenario == "global provision chained actor" {
				_, err := createProvisionedTeamMember(teamMemberCreation{SourceDir: root, HomeDir: childDir, Name: "child", Scope: awid.IdentityScopeGlobal})
				if err == nil || !strings.Contains(err.Error(), "aw id team add-member") || !strings.Contains(err.Error(), "parent") {
					t.Fatalf("global creation should refuse before effects: %v", err)
				}
				if _, err := os.Stat(filepath.Join(childDir, ".aw")); !os.IsNotExist(err) {
					t.Fatalf("global child written before refusal: %v", err)
				}
				if creates != 0 || accepts != 0 {
					t.Fatalf("hosted effects before refusal: %d/%d", creates, accepts)
				}
				return
			}
			if furtherTeam {
				oldJSON, oldAlias, oldLocal, oldGlobal, oldHome := jsonFlag, teamAcceptAlias, teamAcceptLocal, teamAcceptGlobal, activeIdentityHome
				t.Cleanup(func() {
					jsonFlag, teamAcceptAlias, teamAcceptLocal, teamAcceptGlobal, activeIdentityHome = oldJSON, oldAlias, oldLocal, oldGlobal, oldHome
				})
				jsonFlag = true
				issueCmd := authTestCmd(&bytes.Buffer{})
				if strings.HasPrefix(scenario, "further-team explicit condition") {
					issueCmd.Flags().String("for-human", "", "")
					issueCmd.Flags().Set("for-human", v.Keys["alice"].DIDAW)
				}
				issueErr := runTeamInvite(issueCmd, nil)
				if scenario == "further-team explicit condition missing echo" {
					if issueErr == nil || !strings.Contains(issueErr.Error(), "did not retain --for-human") || accepts != 0 {
						t.Fatalf("old service silently dropped condition: %v", issueErr)
					}
					return
				}
				if issueErr != nil {
					t.Fatal(issueErr)
				}
				const token = "aw_inv_native_roster"
				digest := sha256.Sum256([]byte(token))
				recordID := "hosted-" + hex.EncodeToString(digest[:])
				if strings.HasPrefix(scenario, "further-team own chain") {
					seed, _ := hex.DecodeString(v.Keys["seat"].SeedHex)
					if err := awid.SaveSigningKey(filepath.Join(recipientHome, "signing.key"), ed25519.NewKeyFromSeed(seed)); err != nil {
						t.Fatal(err)
					}
					if err := awconfig.SaveInstalledIDChain(recipientHome, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed, v.Certificates["seat"].Signed}}); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "further-team cross-machine recipe" || strings.HasPrefix(scenario, "further-team parent") || scenario == "further-team add parent retry" {
					if err := awconfig.DeleteTeamInvite(recordID); err != nil {
						t.Fatal(err)
					}
				}
				activeIdentityHome = awconfig.IdentityHome{Root: recipientHome, Source: awconfig.IdentityHomeFlag}
				if strings.HasPrefix(scenario, "further-team independent init") {
					oldInvite, oldParent, oldName := initInvite, initParent, initName
					t.Cleanup(func() { initInvite, initParent, initName = oldInvite, oldParent, oldName })
					initInvite, initParent, initName = token, root, "child"
					if scenario != "further-team independent init" {
						initInvite = ""
					}
					activeIdentityHome = awconfig.IdentityHome{}
					t.Setenv("AWEB_URL", origin)
				}
				teamAcceptAlias, teamAcceptLocal, teamAcceptGlobal = "child", true, false
				acceptCalls := 0
				accept := func() error {
					acceptCalls++
					var result error
					withTestWorkingDir(t, childDir, func() {
						cmd := authTestCmd(&bytes.Buffer{})
						fromStdin := !strings.HasPrefix(scenario, "further-team independent init") || strings.HasSuffix(scenario, " stdin")
						cmd.Flags().Bool("token-stdin", fromStdin, "")
						tokenFile := ""
						if scenario == "further-team independent init file" {
							tokenFile = filepath.Join(childDir, "private-invite.token")
							if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0600); err != nil {
								t.Fatal(err)
							}
						}
						cmd.Flags().String("token-file", tokenFile, "")
						if scenario == "further-team parent source" || (scenario == "further-team parent source retry" && acceptCalls == 1) || scenario == "further-team parent signed retry" || scenario == "further-team parent two children" || scenario == "further-team parent host managed" || (scenario == "further-team add parent retry" && acceptCalls > 1) {
							cmd.Flags().String("parent", root, "")
						}
						cmd.SetIn(strings.NewReader(token + "\n"))
						if strings.HasPrefix(scenario, "further-team independent init") {
							result = runInit(cmd, nil)
						} else {
							result = runTeamAcceptInvite(cmd, nil)
						}
					})
					return result
				}
				var firstErr error
				if scenario != "further-team cross-machine recipe" {
					firstErr = accept()
				}
				if scenario == "further-team parent two children" {
					if firstErr == nil {
						t.Fatal("first child interruption missing")
					}
					firstHome := recipientHome
					recipientHome = t.TempDir()
					activeIdentityHome.Root = recipientHome
					if err := accept(); err == nil {
						t.Fatal("second child interruption missing")
					}
					first, _ := loadHostedInviteCreation(filepath.Join(firstHome, hostedInviteRecoveryFile))
					second, _ := loadHostedInviteCreation(filepath.Join(recipientHome, hostedInviteRecoveryFile))
					if first == nil || second == nil || first.DIDKey == second.DIDKey {
						t.Fatal("multi-use invitation conflated child homes")
					}
					if err := accept(); err != nil {
						t.Fatalf("second child resume: %v", err)
					}
					recipientHome = firstHome
					activeIdentityHome.Root = firstHome
					firstErr = accept()
				}
				if scenario == "further-team parent source retry" || scenario == "further-team add parent retry" || scenario == "further-team parent signed retry" {
					if firstErr == nil {
						t.Fatal("interruption missing")
					}
					t.Logf("initial interruption: %v", firstErr)
					firstErr = accept()
					entries, err := filepath.Glob(filepath.Join(awconfig.IdentityIssuanceDir(filepath.Join(root, ".aw")), "*.json"))
					if err != nil || len(entries) != 1 {
						t.Fatalf("retry caused multiple parent issuances: %v %v", entries, err)
					}
				}
				if scenario == "further-team other human fresh" {
					if firstErr == nil || !strings.Contains(firstErr.Error(), "human_mismatch") || accepts != 0 {
						t.Fatalf("wrong-human fresh child reached membership: accepts=%d err=%v", accepts, firstErr)
					}
					if _, err := os.Stat(filepath.Join(recipientHome, "teams.yaml")); !os.IsNotExist(err) {
						t.Fatalf("refusal installed membership: %v", err)
					}
					if _, err := awconfig.LoadTeamInvite(recordID); err != nil {
						t.Fatalf("refusal consumed invite: %v", err)
					}
					return
				}
				if scenario == "further-team cross-machine recipe" {
					bin := filepath.Join(t.TempDir(), "aw")
					buildAwBinary(t, context.Background(), bin)
					initial := exec.Command(bin, "--identity-home", recipientHome, "id", "team", "accept-invite", "--token-stdin", "--name", "child", "--local", "--json")
					initial.Dir = childDir
					initial.Env = append(testCommandEnv(os.Getenv("HOME")), "AW_NO_UPDATE_CHECK=1")
					initial.Stdin = strings.NewReader(token + "\n")
					out, err := initial.Output()
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 1 || accepts != 0 {
						t.Fatalf("pending accept exit=%v submissions=%d stdout=%s", err, accepts, out)
					}
					var refusal cliErrorEnvelope
					if err := json.Unmarshal(out, &refusal); err != nil || refusal.Error.Code != "native_agent_signature_pending" {
						t.Fatalf("pending accept did not report its CLI code: %v\n%s", err, out)
					}
					assertHostedPendingChildKey(t, recipientHome)
					if _, err := os.Stat(filepath.Join(recipientHome, "teams.yaml")); !os.IsNotExist(err) {
						t.Fatalf("pending accept installed membership: %v", err)
					}
					pending, err := loadHostedInviteCreation(filepath.Join(recipientHome, hostedInviteRecoveryFile))
					if err != nil {
						t.Fatal(err)
					}
					grantPath := filepath.Join(recipientHome, "grant.yaml")
					if err := os.WriteFile(grantPath, []byte("not a pending agent home"), 0600); err != nil {
						t.Fatal(err)
					}
					allowed, policyErr := pendingHostedExchangeTarget(idParentRequestCmd, activeIdentityHome)
					if err := os.Remove(grantPath); err != nil {
						t.Fatal(err)
					}
					if policyErr != nil || allowed {
						t.Fatalf("pending bypass covered a grant home: allowed=%v err=%v", allowed, policyErr)
					}
					issuerOpts := idChildOptions{WorkingDir: root, IdentityHome: filepath.Join(root, ".aw"), Now: time.Now}
					invitation, err := executeIDChildInvite(context.Background(), issuerOpts, "agent", pending.DIDKey, 7*24*time.Hour)
					if err != nil {
						t.Fatal(err)
					}
					// Run the printed child request through the actual binary and
					// its root identity-home checks, before any teams.yaml exists.
					invitationJSON, _ := json.Marshal(invitation)
					if err := os.WriteFile(filepath.Join(childDir, "id-invitation.json"), invitationJSON, 0600); err != nil {
						t.Fatal(err)
					}
					blocked := exec.Command(bin, "--identity-home", recipientHome, "mail", "inbox")
					blocked.Dir, blocked.Env = childDir, testCommandEnv(os.Getenv("HOME"))
					if out, err := blocked.CombinedOutput(); err == nil || !strings.Contains(string(out), "teams.yaml") {
						t.Fatalf("pending home became a general acting principal: %v\n%s", err, out)
					}
					inherited := exec.Command(bin, "id", "parent", "request", "--domain", "example.com", "--parent", parent, "--invitation-id", invitation.InvitationID)
					inherited.Dir = childDir
					inherited.Env = append(testCommandEnv(os.Getenv("HOME")), "AWEB_IDENTITY_HOME="+recipientHome)
					if out, err := inherited.CombinedOutput(); err == nil || !strings.Contains(string(out), "teams.yaml") {
						t.Fatalf("inherited pending home bypassed principal validation: %v\n%s", err, out)
					}
					var printed string
					for _, line := range strings.Split(refusal.Error.Message, "\n") {
						if strings.Contains(line, " id parent request ") {
							printed = strings.TrimSpace(line)
							break
						}
					}
					if printed == "" {
						t.Fatal("no printed request")
					}
					command := exec.Command("sh", "-c", printed)
					command.Dir = childDir
					command.Env = append(testCommandEnv(os.Getenv("HOME")), "PATH="+filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
					if out, err := command.CombinedOutput(); err != nil {
						t.Fatalf("printed request failed: %v\n%s", err, out)
					}
					raw, err := os.ReadFile(filepath.Join(childDir, "id-request.json"))
					if err != nil {
						t.Fatal(err)
					}
					received, err := executeIDChildReceive(context.Background(), issuerOpts, raw)
					if err != nil {
						t.Fatal(err)
					}
					response, err := executeIDChildApprove(context.Background(), issuerOpts, received.RequestID)
					if err != nil {
						t.Fatal(err)
					}
					_, err = executeIDParentImport(context.Background(), idParentOptions{WorkingDir: childDir, IdentityHome: recipientHome, RegistryURL: registryURL}, response)
					if err != nil {
						t.Fatal(err)
					}
					firstErr = accept()
				} else if scenario == "further-team retry" || scenario == "further-team own chain retry" {
					if firstErr == nil {
						t.Fatal("expected service failure")
					}
					assertHostedPendingChildKey(t, recipientHome)
					if _, err := awconfig.LoadTeamInvite(recordID); err != nil {
						t.Fatalf("failed attempt lost link: %v", err)
					}
					firstErr = accept()
				}
				if scenario == "further-team consumption failure" {
					if firstErr == nil || !strings.Contains(firstErr.Error(), "membership was issued, but recording consumed invite") {
						t.Fatalf("consumption failure was hidden: %v", firstErr)
					}
					if _, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(recipientHome, team); err != nil {
						t.Fatalf("issued certificate was lost: %v", err)
					}
					return
				}
				if firstErr != nil {
					t.Fatalf("further-team accept: %v", firstErr)
				}
				for _, file := range []string{"identity.yaml", "signing.key", "teams.yaml", "id-chain.json"} {
					if _, err := os.Stat(filepath.Join(recipientHome, file)); err != nil {
						t.Fatalf("selected home missing %s: %v", file, err)
					}
				}
				if _, err := os.Stat(filepath.Join(childDir, ".aw", "signing.key")); recipientHome != filepath.Join(childDir, ".aw") && !os.IsNotExist(err) {
					t.Fatalf("identity escaped selected home: %v", err)
				}
				if _, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(recipientHome, team); err != nil {
					t.Fatalf("selected home certificate missing: %v", err)
				}
				state, err := awconfig.LoadTeamStateFromIdentityHome(recipientHome)
				if err != nil || state.Membership(team) == nil {
					t.Fatalf("selected membership: %v", err)
				}
				verdict, err := executeWho(context.Background(), whoOptions{WorkingDir: childDir})
				if err != nil || verdict.Outcome != "nearest_human" {
					t.Fatalf("selected home ancestry=%+v err=%v", verdict, err)
				}
				switch {
				case strings.HasPrefix(scenario, "further-team parent"), scenario == "further-team add parent retry":
					parentID, _, err := loadTeamInviteParentRecord(token, recipientHome)
					if err != nil {
						t.Fatal(err)
					}
					requireConsumedInviteRecord(t, parentID)
					if _, err := awconfig.LoadTeamInvite(recordID); !os.IsNotExist(err) {
						t.Fatalf("independent parent created a replacement issuer link: %v", err)
					}
				case scenario != "further-team cross-machine recipe":
					requireConsumedInviteRecord(t, recordID)
				}
				return
			}
			if joinFrom {
				oldFrom, oldTeam, oldName, oldGlobal, oldJSON := initJoinFrom, initJoinTeam, initName, initGlobal, jsonFlag
				t.Cleanup(func() {
					initJoinFrom, initJoinTeam, initName, initGlobal, jsonFlag = oldFrom, oldTeam, oldName, oldGlobal, oldJSON
				})
				initJoinFrom, initJoinTeam, initName, initGlobal, jsonFlag = root, team, "child", false, true
				if scenario == "join-from identity home" {
					initJoinFrom = filepath.Join(root, ".aw")
				}
				var joinErr error
				withTestWorkingDir(t, childDir, func() {
					var out bytes.Buffer
					if scenario == "implicit init workspace key refuses external home" {
						oldHome := activeIdentityHome
						activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(root, ".aw"), Source: awconfig.IdentityHomeFlag}
						defer func() { activeIdentityHome = oldHome }()
						initJoinFrom = ""
						initJoinTeam = ""
						joinErr = runInit(authTestCmd(&out), nil)

					} else {
						joinErr = runInitJoinFrom(authTestCmd(&out))
					}
				})
				if scenario == "implicit init workspace key refuses external home" {
					if joinErr == nil || !strings.Contains(joinErr.Error(), "only supported for --workspace-team or explicit fresh --join-from") {
						t.Fatalf("implicit external creation did not refuse: %v", joinErr)
					}
					if creates != 0 || accepts != 0 {
						t.Fatalf("refused implicit init created or accepted an invite: %d/%d", creates, accepts)
					}
					if _, err := os.Stat(filepath.Join(childDir, ".aw")); !os.IsNotExist(err) {
						t.Fatalf("implicit external creation wrote child state: %v", err)
					}
					return
				}
				if strings.HasPrefix(scenario, "join-from retry") {
					if joinErr == nil {
						t.Fatal("first attempt unexpectedly succeeded")
					}
					if strings.Contains(joinErr.Error(), "aw_inv_native_roster") {
						t.Fatal("error leaked bearer token")
					}
					info, err := os.Stat(filepath.Join(childDir, ".aw", initInviteRecoveryFile))
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatalf("private init recovery: %v %v", info, err)
					}
					home := filepath.Join(childDir, ".aw")
					keyBefore, err := os.ReadFile(filepath.Join(home, "signing.key"))
					if err != nil {
						t.Fatal(err)
					}
					if scenario == "join-from retry connect without saved key" {
						// Simulate death after membership persistence but before
						// the final key-binding save in the outer init command.
						path := filepath.Join(home, initInviteRecoveryFile)
						state, err := loadInitInviteRecovery(path)
						if err != nil || state == nil {
							t.Fatalf("missing init selection: %v", err)
						}
						state.DIDKey = ""
						if err := state.save(path); err != nil {
							t.Fatal(err)
						}
						if _, err := awconfig.LoadTeamCertificateForTeam(childDir, team); err != nil {
							t.Fatalf("missing persisted membership: %v", err)
						}
					}
					withTestWorkingDir(t, childDir, func() {
						initName = "different-child"
						if err := runInitJoinFrom(authTestCmd(&bytes.Buffer{})); err == nil {
							t.Fatal("changed selection resumed the original spawn")
						}
						initName = "child"
						joinErr = runInitJoinFrom(authTestCmd(&bytes.Buffer{}))
					})
					if joinErr != nil {
						t.Fatalf("same-directory retry: %v", joinErr)
					}
					keyAfter, err := os.ReadFile(filepath.Join(home, "signing.key"))
					if err != nil || !bytes.Equal(keyBefore, keyAfter) {
						t.Fatal("retry replaced child key")
					}
					if _, err := os.Stat(filepath.Join(home, initInviteRecoveryFile)); !os.IsNotExist(err) {
						t.Fatalf("success retained bearer record: %v", err)
					}
					if creates != 1 {
						t.Fatalf("minted %d invitations instead of resuming", creates)
					}
				}
				if scenario == "join-from revoked parent" {
					if joinErr == nil || accepts != 0 {
						t.Fatalf("revoked source accepted: err=%v accepts=%d", joinErr, accepts)
					}
					assertHostedPendingChildKey(t, filepath.Join(childDir, ".aw"))
					if !strings.Contains(joinErr.Error(), "child key and request retained") || strings.Contains(joinErr.Error(), "id parent request") {
						t.Fatalf("failed provisioning printed the manual invite recipe: %v", joinErr)
					}
					return
				}
				if joinErr != nil {
					t.Fatalf("hosted join-from failed: %v", joinErr)
				}
				assertNotice()
				wantAccepts, wantPreviews := 1, 1
				if scenario == "join-from retry accept" {
					wantAccepts = 2
				}
				if scenario == "join-from retry preview" {
					wantPreviews = 2
				}
				if accepts != wantAccepts || previews != wantPreviews {
					t.Fatalf("accepts=%d previews=%d", accepts, previews)
				}
				chain, err := awconfig.LoadInstalledIDChain(filepath.Join(childDir, ".aw"))
				if err != nil || chain == nil {
					t.Fatalf("child chain missing: %v", err)
				}
				certificates := chain.Bundle["certificates"].([]any)
				leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
				if leaf["parent"].(map[string]any)["id"] != parent {
					t.Fatalf("child parent is not source: %+v", leaf)
				}
				verdict, err := executeWho(context.Background(), whoOptions{WorkingDir: childDir})
				if err != nil || verdict.Outcome != "nearest_human" || verdict.HumanID == nil || *verdict.HumanID != v.Keys["alice"].DIDAW {
					t.Fatalf("join-from ancestry=%+v err=%v", verdict, err)
				}
				return
			}
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
			var err error
			if scenario == "three children discovered creator" {
				log, logErr := os.CreateTemp(t.TempDir(), "stderr")
				if logErr != nil {
					t.Fatal(logErr)
				}
				old := os.Stderr
				os.Stderr = log
				withTestWorkingDir(t, deployment, func() {
					err = runTeamHumanExtend(authTestCmd(&bytes.Buffer{}), []string{"alice:local", "bob:local", "charlie:local"})
				})
				os.Stderr = old
				log.Close()
				raw, readErr := os.ReadFile(log.Name())
				if readErr != nil || !strings.Contains(string(raw), "Using agent workspace "+root+" as the creator.\n") {
					t.Fatalf("missing creator: %q %v", raw, readErr)
				}
			} else if scenario == "three children workspace key add" {
				err = runTeamHumanAddWithOptions(authTestCmd(&bytes.Buffer{}), nil, teamHumanAddRunOptions{Specs: specs})
			} else if scenario == "three children workspace key extend" {
				teamHumanExtendAPIKey = "aw_sk_selected_agent"
				err = runTeamHumanExtend(authTestCmd(&bytes.Buffer{}), []string{"alice:local", "bob:local", "charlie:local"})
			} else {
				err = runTeamHumanCreateRosterAdd(specs)
			}
			if !strings.HasPrefix(scenario, "three children") {
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
			assertNotice()
			if accepts != 3 || previews != 3 {
				t.Fatalf("accepts=%d previews=%d; each child must use its first preview/key", accepts, previews)
			}
			for _, spec := range specs {
				home := filepath.Join(rosterRoot, "agents", "instances", spec.Name)
				chain, err := awconfig.LoadInstalledIDChain(filepath.Join(home, ".aw"))
				if err != nil || chain == nil {
					t.Fatalf("%s has no child chain: %v", spec.Name, err)
				}
				certificates := chain.Bundle["certificates"].([]any)
				leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
				if leaf["parent"].(map[string]any)["id"] != parent {
					t.Fatalf("wrong creator: %+v", leaf)
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
			} else if typ == 1 && (strings.Join(labels, ".") == "registry.example" || strings.Join(labels, ".") == "registry.test") {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			}
			conn.WriteTo(answer, addr)
		}
	}()
}
