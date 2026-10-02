package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const siblingRequestID = "12345678-1234-4234-8234-123456789abc"

func runSiblingBinary(ctx context.Context, bin, cwd, home, principal, source string, args ...string) (string, string, error) {
	env := append(testCommandEnv(home), "AW_NO_UPDATE_CHECK=1", "AWEB_URL=", "AWID_REGISTRY_URL=", "AW_TRACE=1", awconfig.IdentityHomeEnv+"=")
	if source == "flag" {
		args = append([]string{"--identity-home", principal}, args...)
	} else if source == "environment" {
		env = append(env, awconfig.IdentityHomeEnv+"="+principal)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir, cmd.Env = cwd, env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestHostedSiblingCreateBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, source := range []string{"cwd", "flag", "environment"} {
		for _, shadow := range []bool{false, true} {
			if source == "cwd" && shadow {
				continue
			}
			t.Run(fmt.Sprintf("%s/shadow=%t", source, shadow), func(t *testing.T) {
				dir := t.TempDir()
				cwd := filepath.Join(dir, "cwd")
				os.MkdirAll(cwd, 0700)
				principalRoot := filepath.Join(dir, "principal")
				if source == "cwd" {
					principalRoot = cwd
				}
				pub, key, _ := awid.GenerateKeypair()
				var calls atomic.Int32
				var seenID string
				var expectedSource string
				secret := "aw_inv_sibling_secret"
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := calls.Add(1)
					if r.Method != "POST" || r.URL.Path != "/api/v1/teams/sibling" {
						t.Errorf("unexpected request %s %s", r.Method, r.URL)
						http.NotFound(w, r)
						return
					}
					body, _ := io.ReadAll(r.Body)
					assertLockPrincipalRequest(t, r, body, "native", "runtime:aweb.test", pub)
					var req map[string]string
					json.Unmarshal(body, &req)
					if req["name"] != "sibling" || req["display_name"] != "Sibling Team" || req["source_team_id"] != expectedSource {
						t.Errorf("request=%s", body)
					}
					if expectedSource == "" {
						if _, ok := req["source_team_id"]; ok {
							t.Error("source_team_id should be omitted")
						}
					}
					if n == 1 {
						seenID = req["request_id"]
						if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(seenID) {
							t.Errorf("not UUID4: %q", seenID)
						}
					} else if req["request_id"] != seenID {
						t.Errorf("replay id=%q want %q", req["request_id"], seenID)
					}
					status := 201
					if n > 1 {
						status = 200
					}
					w.WriteHeader(status)
					json.NewEncoder(w).Encode(map[string]any{"team_id": "sibling-server-id", "canonical_team_id": "sibling:aweb.test", "namespace": "aweb.test", "org_handle": "example", "reused": n > 1, "token": secret, "invite_id": "invite-id", "token_prefix": "aw_inv_", "expires_at": "2099-01-01T00:00:00Z", "max_uses": 1, "server_url": "https://service.example/api"})
				}))
				defer server.Close()
				writeMessagingPrincipalForTest(t, principalRoot, server.URL+"/api", "alice", awid.ComputeDIDKey(pub), key)
				if shadow {
					writeTestConfig(t, cwd, "http://127.0.0.1:1")
				}
				beforePrincipal := fileDigestsForTest(t, principalRoot)
				beforeCWD := fileDigestsForTest(t, cwd)
				base := []string{"id", "team", "create", "--name", " Sibling ", "--display-name", "Sibling Team"}
				if source == "flag" && shadow {
					base = append(base, "--namespace", "aweb.test")
				}
				if source == "environment" && shadow {
					_, controller, err := awid.GenerateKeypair()
					if err != nil {
						t.Fatal(err)
					}
					writeControllerKeyForTest(t, dir, "aweb.test", controller)
					base = append(base, "--namespace", "aweb.test", "--hosted")
				}
				out, trace, err := runSiblingBinary(ctx, bin, cwd, dir, filepath.Join(principalRoot, ".aw"), source, append(base, "--json")...)
				if err != nil {
					t.Fatalf("create: %v\n%s\n%s", err, out, trace)
				}
				var result map[string]any
				if err = json.Unmarshal([]byte(out), &result); err != nil {
					t.Fatal(err)
				}
				if result["team_id"] != "sibling:aweb.test" || result["service_team_id"] != "sibling-server-id" || result["token"] != secret || result["canonical_team_id"] != "sibling:aweb.test" || result["request_id"] != seenID || result["reused"] != false {
					t.Fatalf("output=%s", out)
				}
				if strings.Contains(trace, secret) {
					t.Fatal("trace leaked invite token")
				}
				expectedSource = "runtime:aweb.test"
				replay := append(base, "--hosted", "--team", expectedSource, "--request-id", seenID)
				out, trace, err = runSiblingBinary(ctx, bin, cwd, dir, filepath.Join(principalRoot, ".aw"), source, replay...)
				if err != nil || strings.Contains(out+trace, secret) || !strings.Contains(out, seenID) || !strings.Contains(out, "sibling:aweb.test") {
					t.Fatalf("safe text replay: %v\n%s\n%s", err, out, trace)
				}
				out, trace, err = runSiblingBinary(ctx, bin, cwd, dir, filepath.Join(principalRoot, ".aw"), source, append(replay, "--show-token")...)
				if err != nil || !strings.Contains(out, secret) || strings.Contains(trace, secret) {
					t.Fatalf("explicit token output: %v\n%s\n%s", err, out, trace)
				}
				if calls.Load() != 3 {
					t.Fatalf("requests=%d", calls.Load())
				}
				if !reflect.DeepEqual(beforePrincipal, fileDigestsForTest(t, principalRoot)) || !reflect.DeepEqual(beforeCWD, fileDigestsForTest(t, cwd)) {
					t.Error("create modified local identity/workspace state")
				}
			})
		}
	}
}

func TestHostedSiblingCreateErrorsBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		status int
		code   string
	}{
		{401, "team_key_required"}, {403, "team_member_required"}, {403, "sibling_team_forbidden"}, {403, "source_team_mismatch"}, {403, "sibling_team_replay_forbidden"}, {404, "source_team_not_found"}, {409, "source_team_not_org_owned"}, {409, "source_team_not_hosted"}, {409, "sibling_team_request_mismatch"}, {409, "sibling_team_invite_closed"}, {409, "sibling_team_replay_expired"}, {409, "sibling_team_name_taken"}, {402, "team_limit_reached"}, {429, "rate_limited"}, {503, "rate_limit_unavailable"}, {422, "validation_error"}, {422, "invalid_request_id"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			dir := t.TempDir()
			principal := filepath.Join(dir, "principal")
			pub, key, _ := awid.GenerateKeypair()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				assertLockPrincipalRequest(t, r, body, "native", "runtime:aweb.test", pub)
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(tc.status)
				json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": tc.code, "message": "Server explanation", "limit": 3, "current": 3}})
			}))
			defer server.Close()
			writeMessagingPrincipalForTest(t, principal, server.URL, "alice", awid.ComputeDIDKey(pub), key)
			out, trace, err := runSiblingBinary(ctx, bin, dir, dir, filepath.Join(principal, ".aw"), "flag", "id", "team", "create", "--name", "sibling", "--request-id", siblingRequestID, "--json")
			if err == nil || !strings.Contains(out+trace, tc.code) || !strings.Contains(out+trace, "Server explanation") || !strings.Contains(out+trace, siblingRequestID) {
				t.Fatalf("error not surfaced: %v\n%s\n%s", err, out, trace)
			}
			if calls.Load() != 1 {
				t.Errorf("requests=%d; mutation must not retry", calls.Load())
			}
		})
	}
}

func TestHostedSiblingCreateRefusalsBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, kind := range []string{"grant", "wrong-team", "missing-key", "missing-teams", "namespace-mismatch", "registry", "bad-request-id", "corrupt-controller"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			cwd := filepath.Join(dir, "cwd")
			os.MkdirAll(cwd, 0700)
			principal := filepath.Join(dir, "principal")
			pub, key, _ := awid.GenerateKeypair()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "unexpected network", 500) }))
			defer server.Close()
			writeMessagingPrincipalForTest(t, cwd, server.URL, "shadow", awid.ComputeDIDKey(pub), key)
			writeMessagingPrincipalForTest(t, principal, server.URL, "alice", awid.ComputeDIDKey(pub), key)
			args := []string{"id", "team", "create", "--name", "sibling", "--json"}
			switch kind {
			case "grant":
				principal = filepath.Join(dir, "grant")
				writeGrantHomeForTest(t, filepath.Join(principal, ".aw"), server.URL)
			case "wrong-team":
				args = append(args, "--team", "wrong:aweb.test")
			case "missing-key":
				os.Remove(filepath.Join(principal, ".aw", "signing.key"))
			case "missing-teams":
				os.Remove(filepath.Join(principal, ".aw", "teams.yaml"))
			case "namespace-mismatch":
				args = append(args, "--namespace", "wrong.test")
			case "registry":
				args = append(args, "--registry", server.URL)
			case "bad-request-id":
				args = append(args, "--request-id", "not-a-uuid")
			case "corrupt-controller":
				writeControllerKeyForTest(t, dir, "aweb.test", key)
				// A corrupt controller is not permission to switch authorities.
				controllerPath := filepath.Join(dir, ".awid", "controllers", "aweb.test.key")
				if err := os.WriteFile(controllerPath, []byte("broken key"), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--namespace", "aweb.test")
			}
			out, trace, err := runSiblingBinary(ctx, bin, cwd, dir, filepath.Join(principal, ".aw"), "flag", args...)
			if err == nil {
				t.Fatalf("refusal succeeded: %s %s", out, trace)
			}
			if strings.Contains(trace, "unknown flag") || strings.Contains(trace, "does not support --identity-home") {
				t.Fatalf("refusal did not reach identity/scope checks: %s", trace)
			}
			if kind == "grant" && !strings.Contains(trace, "team_key_required") {
				t.Fatalf("grant refusal unclear: %s", trace)
			}
			if calls.Load() != 0 {
				t.Errorf("refusal made %d requests", calls.Load())
			}
		})
	}
}

func TestHostedSiblingInviteAcceptsIntoFreshExternalHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	source := filepath.Join(dir, "source")
	cwd := filepath.Join(dir, "instance")
	os.MkdirAll(cwd, 0700)
	pub, key, _ := awid.GenerateKeypair()
	teamPub, teamKey, _ := awid.GenerateKeypair()
	teamID := "sibling:aweb.test"
	var token string
	var creates, accepts, connects atomic.Int32
	server := newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/teams/sibling":
			creates.Add(1)
			body, _ := io.ReadAll(r.Body)
			assertLockPrincipalRequest(t, r, body, "native", "runtime:aweb.test", pub)
			token = hostedJoinTokenForTest(t, "aw_inv_sibling_accept", serverURL)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"team_id": "new-server-id", "canonical_team_id": teamID, "namespace": "aweb.test", "token": token, "server_url": serverURL + "/api", "invite_id": "invite-sibling", "max_uses": 1})
		case "/api/v1/connect":
			connects.Add(1)
			cert := requireCertificateAuthForTest(t, r)
			if cert.Team != teamID || cert.MemberDIDKey == awid.ComputeDIDKey(pub) {
				t.Error("connect used source identity")
			}
			json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "alias": "bob", "agent_id": "agent-bob", "workspace_id": "workspace-bob", "repo_id": "", "team_did_key": awid.ComputeDIDKey(teamPub)})
		case "/api/v1/instructions/active":
			json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Fixture instructions."}})
		case "/api/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-bob", teamID, "bob")
		case "/api/v1/discovery":
			json.NewEncoder(w).Encode(map[string]any{"onboarding_url": serverURL, "aweb_url": serverURL + "/api", "registry_url": serverURL})
		case "/api/v1/spawn/accept-invite":
			accepts.Add(1)
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			json.Unmarshal(body, &req)
			if req["token"] != token {
				t.Error("invite not forwarded unchanged")
			}
			did, _ := req["did"].(string)
			parts := strings.Fields(r.Header.Get("Authorization"))
			if did == awid.ComputeDIDKey(pub) || len(parts) != 3 || !verifyCloudDIDPayload(t, mustExtractPublicKey(t, did), "POST", r.URL.Path, r.Header.Get("X-AWEB-Timestamp"), body, parts[2]) {
				t.Error("accept did not use a fresh identity's proof")
			}
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: did, Alias: "bob", IdentityScope: awid.IdentityModeLocal})
			if err != nil {
				t.Error(err)
				http.Error(w, "cert", 500)
				return
			}
			encoded, _ := awid.EncodeTeamCertificateHeader(cert)
			json.NewEncoder(w).Encode(map[string]any{"team_id": "new-server-id", "team_slug": "sibling", "namespace": "aweb.test", "namespace_slug": "example", "identity_id": "agent-bob", "alias": "bob", "server_url": serverURL + "/api", "did": did, "custody": "self", "identity_scope": "local", "access_mode": "open", "created": true, "team_cert": encoded})
		default:
			t.Errorf("unexpected request: %s %s (no implicit connect)", r.Method, r.URL)
			http.NotFound(w, r)
		}
	})
	writeMessagingPrincipalForTest(t, source, server.URL+"/api", "alice", awid.ComputeDIDKey(pub), key)
	before := fileDigestsForTest(t, source)
	out, trace, err := runSiblingBinary(ctx, bin, cwd, dir, filepath.Join(source, ".aw"), "flag", "id", "team", "create", "--name", "sibling", "--json")
	if err != nil {
		t.Fatalf("create: %v %s %s", err, out, trace)
	}
	var created map[string]any
	json.Unmarshal([]byte(out), &created)
	fresh := filepath.Join(dir, "fresh", ".aw")
	accept := exec.CommandContext(ctx, bin, "--identity-home", fresh, "id", "team", "accept-invite", created["token"].(string), "--name", "bob", "--local", "--json")
	accept.Dir = cwd
	accept.Env = append(testCommandEnv(dir), "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWID_REGISTRY_URL=", "AW_NO_UPDATE_CHECK=1", "AW_TRACE=")
	accepted, err := accept.CombinedOutput()
	if err != nil {
		t.Fatalf("accept: %v\n%s", err, accepted)
	}
	var result map[string]any
	json.Unmarshal(extractJSON(t, accepted), &result)
	if result["team_id"] != teamID || result["alias"] != "bob" {
		t.Fatalf("accept output=%s", accepted)
	}
	cert, err := awid.LoadTeamCertificate(filepath.Join(fresh, awconfig.TeamCertificateRelativePath(teamID)))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Team != teamID || cert.IdentityScope != awid.IdentityModeLocal || cert.MemberDIDKey == awid.ComputeDIDKey(pub) {
		t.Fatalf("wrong fresh membership: %+v", cert)
	}
	if creates.Load() != 1 || accepts.Load() != 1 {
		t.Errorf("create/accept=%d/%d", creates.Load(), accepts.Load())
	}
	if !reflect.DeepEqual(before, fileDigestsForTest(t, source)) {
		t.Error("caller identity changed")
	}
	if _, err := os.Stat(filepath.Join(cwd, ".aw")); !os.IsNotExist(err) {
		t.Errorf("instance cwd enrolled: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fresh, "workspace.yaml")); !os.IsNotExist(err) {
		t.Errorf("accept implicitly connected: %v", err)
	}
	if connects.Load() != 0 {
		t.Error("create/accept implicitly connected")
	}
	connect := exec.CommandContext(ctx, bin, "init")
	connect.Dir = filepath.Dir(fresh)
	connect.Env = accept.Env
	connected, err := connect.CombinedOutput()
	if err != nil {
		t.Fatalf("explicit init: %v\n%s", err, connected)
	}
	if connects.Load() != 1 {
		t.Errorf("explicit connect calls=%d", connects.Load())
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(fresh, "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if workspace.AwebURL != server.URL+"/api" || workspace.Membership(teamID) == nil {
		t.Fatalf("wrong new workspace: %+v", workspace)
	}
	if !reflect.DeepEqual(before, fileDigestsForTest(t, source)) {
		t.Error("fresh home init changed caller identity")
	}
}

func TestHostedSiblingAmbiguousFailureDoesNotRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	principal := filepath.Join(dir, "principal")
	pub, key, _ := awid.GenerateKeypair()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		assertLockPrincipalRequest(t, r, body, "native", "runtime:aweb.test", pub)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		connection.Close()
	}))
	defer server.Close()
	writeMessagingPrincipalForTest(t, principal, server.URL, "alice", awid.ComputeDIDKey(pub), key)
	out, trace, err := runSiblingBinary(ctx, bin, dir, dir, filepath.Join(principal, ".aw"), "flag", "id", "team", "create", "--name", "sibling", "--request-id", siblingRequestID, "--json")
	if err == nil || !strings.Contains(out+trace, siblingRequestID) || !strings.Contains(out+trace, "replay") {
		t.Fatalf("no replay guidance: %v %s %s", err, out, trace)
	}
	if calls.Load() != 1 {
		t.Errorf("ambiguous POST retried: %d calls", calls.Load())
	}
}
