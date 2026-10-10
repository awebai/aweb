package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// Real CLI boundary; the loopback service models the documented no-repo,
// original-team-key contract. It is not the hosted implementation or an incident replay.
func TestAPIKeyGlobalRecoveryCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, scenario := range []string{"http_failure", "http_body_only", "http_header_only", "http_malformed", "http_missing_id", "http_untrusted_id", "http_conflicting_id", "http_duplicate_json_id", "http_case_variant_id", "http_unicode_fold_id", "http_repeated_header", "http_unauthorized", "http_not_found", "committed_response_loss"} {
		t.Run(scenario, func(t *testing.T) {
			teamPub, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			const provisioningKey = "aw_sk_disposable_original_team_authority"
			const requestID = "11111111-2222-4333-8444-555555555555"
			const team = "staff:example.test"
			var mu sync.Mutex
			var did, pub string
			calls, issued, registered := 0, 0, 0
			server := newLocalHTTPServerHandlerWithURL(t, func(base string, w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case r.Method == "POST" && r.URL.Path == "/v1/did":
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						return
					}
					key, _ := body["new_did_key"].(string)
					if registered > 0 && key != did {
						t.Error("registry saw remint")
					}
					registered++
					if registered > 1 {
						http.Error(w, `{"detail":"already registered"}`, 409)
						return
					}
					did = key
					json.NewEncoder(w).Encode(map[string]any{"registered": true})
				case strings.HasPrefix(r.URL.Path, "/v1/did/") && (strings.HasSuffix(r.URL.Path, "/full") || strings.HasSuffix(r.URL.Path, "/key")):
					suffix := "/key"
					if strings.HasSuffix(r.URL.Path, "/full") {
						suffix = "/full"
					}
					json.NewEncoder(w).Encode(map[string]any{"did_aw": strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), suffix), "current_did_key": did, "created_at": "2026-04-18T00:00:00Z", "updated_at": "2026-04-18T00:00:00Z"})
				case r.Method == "POST" && r.URL.Path == "/api/v1/workspaces/init":
					calls++
					if r.Header.Get("Authorization") != "Bearer "+provisioningKey {
						t.Error("not original team authority")
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
						return
					}
					if body["did"] != did || body["name"] != "alice" || body["identity_scope"] != "global" || body["custody"] != "self" {
						t.Errorf("unexpected identity request: %v", body)
					}
					for _, field := range []string{"repo", "repo_id", "team_id", "namespace", "address"} {
						if _, ok := body[field]; ok {
							t.Errorf("unexpected input %s", field)
						}
					}
					currentPub, _ := body["public_key"].(string)
					if pub != "" && currentPub != pub {
						t.Error("hosted saw replacement key")
					}
					pub = currentPub
					if strings.HasPrefix(scenario, "http_") {
						headerID, bodyID, status := requestID, requestID, 500
						switch scenario {
						case "http_body_only":
							headerID = ""
						case "http_header_only":
							bodyID = ""
						case "http_malformed":
							headerID = ""
						case "http_missing_id":
							headerID = ""
							bodyID = ""
						case "http_untrusted_id":
							headerID = provisioningKey
							bodyID = provisioningKey
						case "http_conflicting_id":
							bodyID = "22222222-2222-4333-8444-555555555555"
						case "http_unauthorized":
							status = 401
						case "http_not_found":
							status = 404
						}
						if scenario == "http_duplicate_json_id" || scenario == "http_case_variant_id" || scenario == "http_unicode_fold_id" {
							headerID = ""
						}
						w.Header().Set("X-Request-ID", headerID)
						if scenario == "http_repeated_header" {
							w.Header().Add("X-Request-ID", "22222222-2222-4333-8444-555555555555")
						}
						w.WriteHeader(status)
						if scenario == "http_duplicate_json_id" || scenario == "http_case_variant_id" || scenario == "http_unicode_fold_id" {
							field := "request_id"
							if scenario == "http_case_variant_id" || scenario == "http_unicode_fold_id" {
								field = "REQUEST_ID"
							}
							if scenario == "http_unicode_fold_id" {
								field = "reque\u017ft_id"
							}
							fmt.Fprintf(w, `{"error":{"code":"INTERNAL_ERROR","request_id":%q,%+q:"22222222-2222-4333-8444-555555555555"}}`, requestID, field)
							return
						}
						if scenario == "http_malformed" {
							fmt.Fprint(w, "<html>"+provisioningKey)
							return
						}
						fmt.Fprintf(w, `{"error":{"code":"INTERNAL_ERROR","request_id":%q,"message":%q}}`, bodyID, "sensitive arbitrary server detail "+provisioningKey)
						return
					}
					// Commit identity/address selection and a credential BEFORE losing response.
					// Subsequent calls reuse the bound identity but model another credential issue.
					issued++
					if calls == 1 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						conn.Close()
						return
					}
					raw, err := base64.StdEncoding.DecodeString(pub)
					if err != nil {
						t.Error(err)
						return
					}
					stable := awid.ComputeStableID(ed25519.PublicKey(raw))
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: team, MemberDIDKey: did, MemberDIDAW: stable, MemberAddress: "example.test/alice", Alias: "alice", IdentityScope: awid.IdentityModeGlobal})
					if err != nil {
						t.Error(err)
						return
					}
					encoded, err := awid.EncodeTeamCertificateHeader(cert)
					if err != nil {
						t.Error(err)
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"server_url": base, "team_cert": encoded, "alias": "alice", "team_id": team, "workspace_id": "ws-1", "did": did, "stable_id": stable, "identity_scope": "global", "custody": "self", "api_key": fmt.Sprintf("disposable-workspace-credential-%d", issued)})
				case r.URL.Path == "/v1/connect":
					requireCertificateAuthForTest(t, r)
					json.NewEncoder(w).Encode(map[string]any{"team_id": team, "alias": "alice", "agent_id": "agent-1", "workspace_id": "ws-1", "repo_id": "", "team_did_key": awid.ComputeDIDKey(teamPub)})
				case r.URL.Path == "/v1/agents/heartbeat":
					w.WriteHeader(200)
				case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
					writeRegistryEncryptionKeyAssertionForTest(t, w, r)
				case r.URL.Path == "/v1/agents/me/encryption-key":
					writePublishEncryptionKeyResponseForTest(t, w, "agent-1", team, "alice")
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected", 404)
				}
			})
			target := t.TempDir()
			home := t.TempDir()
			run := func(key string) (string, string, int) {
				t.Helper()
				evidence := t.TempDir()
				if err := os.Chmod(evidence, 0700); err != nil {
					t.Fatal(err)
				}
				// Exactly the documented capture recipe: independent stdout/stderr/status,
				// exclusive owned directory, no environment or invocation logging.
				script := nativeBootstrapCaptureExample(t)
				cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script, "capture", bin, "init", "--global", "--name", "alice", "--aweb-url", server.URL, "--awid-registry", server.URL, "--do-not-touch-agents-md", "--json")
				cmd.Dir = target
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "USER=fixture", "AW_NO_UPDATE_CHECK=1", "AWEB_API_KEY=" + key, "CAPTURE_DIR=" + evidence}
				err := cmd.Run()
				code := 0
				if err != nil {
					if ee, ok := err.(*exec.ExitError); ok {
						code = ee.ExitCode()
					} else {
						t.Fatal(err)
					}
				}
				contents := func(name string) string {
					b, err := os.ReadFile(filepath.Join(evidence, name))
					if err != nil {
						t.Fatal(err)
					}
					info, err := os.Stat(filepath.Join(evidence, name))
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatalf("capture mode %s", name)
					}
					return string(b)
				}
				stdout, stderr, exit := contents("stdout"), contents("stderr"), contents("exit")
				if exit != fmt.Sprintf("%d\n", code) {
					t.Fatal("native exit lost")
				}
				return stdout, stderr, code
			}
			stdout, stderr, code := run(provisioningKey)
			if code == 0 || stdout != "" || stderr == "" {
				t.Fatalf("expected captured failure, code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			partial, err := os.ReadFile(apiKeyPartialInitPath(target))
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(scenario, "http_") {
				expectedID, expectedCode, status := requestID, "INTERNAL_ERROR", 500
				switch scenario {
				case "http_malformed":
					expectedID = "unknown"
					expectedCode = "unknown"
				case "http_missing_id", "http_untrusted_id", "http_conflicting_id", "http_repeated_header":
					expectedID = "unknown"
				case "http_duplicate_json_id", "http_case_variant_id", "http_unicode_fold_id":
					expectedID = "unknown"
					expectedCode = "unknown"
				case "http_unauthorized":
					status = 401
				case "http_not_found":
					status = 404
				}
				for _, want := range []string{"category=hosted_http_failure", fmt.Sprintf("status=%d", status), "request_id=" + expectedID, "error_code=" + expectedCode} {
					if !strings.Contains(stderr, want) {
						t.Errorf("missing safe diagnostic %q in %q", want, stderr)
					}
				}
				if strings.Contains(stderr, provisioningKey) || strings.Contains(stderr, "sensitive arbitrary") {
					t.Error("hosted body exposed in diagnostic")
				}
			} else {
				mu.Lock()
				beforeCalls, beforeIssued := calls, issued
				mu.Unlock()
				if beforeCalls != 1 || beforeIssued != 1 {
					t.Fatalf("lost response auto-retried: %d/%d", beforeCalls, beforeIssued)
				}
				if !strings.Contains(stderr, "rerun the same command in this directory; do not delete .aw/partial-init.yaml") {
					t.Fatalf("missing resumable failure guidance: %s", stderr)
				}
				// Wrong original authority must refuse locally without altering the partial.
				_, _, changedCode := run("aw_sk_different_fixture_key")
				after, err := os.ReadFile(apiKeyPartialInitPath(target))
				if err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				unchanged := calls == beforeCalls
				mu.Unlock()
				if changedCode == 0 || !unchanged || string(after) != string(partial) {
					t.Fatal("changed context did not refuse intact before hosted call")
				}
				stdout, stderr, code = run(provisioningKey)
				if code != 0 {
					t.Fatalf("same identity continuation failed: %s", stderr)
				}
				var result map[string]any
				if err := json.Unmarshal([]byte(stdout), &result); err != nil {
					t.Fatal(err)
				}
				raw, _ := base64.StdEncoding.DecodeString(pub)
				if result["status"] != "connected" || result["team_id"] != team || result["address"] != "example.test/alice" || result["stable_id"] != awid.ComputeStableID(ed25519.PublicKey(raw)) || result["identity_scope"] != "global" || result["aweb_url"] != server.URL {
					t.Fatalf("returned outputs: %v", result)
				}
				key, err := awid.LoadSigningKey(filepath.Join(target, ".aw", "signing.key"))
				if err != nil {
					t.Fatal(err)
				}
				if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != did {
					t.Fatal("persisted replacement identity")
				}
				if _, err := os.Stat(apiKeyPartialInitPath(target)); !os.IsNotExist(err) {
					t.Fatal("success left partial")
				}
				mu.Lock()
				finalCalls, finalIssued := calls, issued
				mu.Unlock()
				if finalCalls != 2 || finalIssued != 2 {
					t.Fatalf("repeat effects not accounted: %d/%d", finalCalls, finalIssued)
				}
			}
		})
	}
}

func nativeBootstrapCaptureExample(t *testing.T) string {
	t.Helper()
	doc, err := os.ReadFile("../../../../docs/hosted-global-bootstrap.md")
	if err != nil {
		t.Fatal(err)
	}
	section := strings.Split(string(doc), "<!-- native-capture-example -->")
	if len(section) != 2 {
		t.Fatal("capture example missing or duplicated")
	}
	codeBlocks := strings.SplitN(section[1], "```sh\n", 2)
	if len(codeBlocks) != 2 {
		t.Fatal("capture script missing")
	}
	return strings.SplitN(codeBlocks[1], "```", 2)[0]
}

func TestNativeBootstrapCaptureExample(t *testing.T) {
	script := nativeBootstrapCaptureExample(t)
	for _, unavailable := range []bool{false, true} {
		t.Run(fmt.Sprintf("unavailable_%t", unavailable), func(t *testing.T) {
			dir := t.TempDir()
			capture := filepath.Join(dir, "capture")
			if !unavailable {
				if err := os.Mkdir(capture, 0700); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(dir, "dispatched")
			cmd := exec.Command("/bin/sh", "-c", script, "capture", "/bin/sh", "-c", `printf '{malformed json'; printf 'PRIVATE_FIXTURE_ERROR' >&2; : > "$1"; exit 7`, "child", marker)
			cmd.Env = []string{"CAPTURE_DIR=" + capture}
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("expected native failure or capture refusal")
			}
			if strings.Contains(string(out), "PRIVATE_FIXTURE_ERROR") || strings.Contains(string(out), "malformed json") {
				t.Fatal("raw evidence escaped private files")
			}
			if unavailable {
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("dispatched without capture")
				}
				return
			}
			for name, want := range map[string]string{"stdout": "{malformed json", "stderr": "PRIVATE_FIXTURE_ERROR", "exit": "7\n"} {
				path := filepath.Join(capture, name)
				b, err := os.ReadFile(path)
				if err != nil || string(b) != want {
					t.Fatalf("lost %s", name)
				}
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatalf("unsafe %s", name)
				}
			}
		})
	}
}
