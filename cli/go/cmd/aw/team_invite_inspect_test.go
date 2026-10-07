package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTeamInviteInspectCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	const inner = "aw_inv_" + "synthetic-inspection-secret-0123456789"
	var calls, uses, redirected atomic.Int32
	var mode atomic.Value
	mode.Store("active")
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
	}))
	defer other.Close()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/api/v1/spawn/accept-invite" {
			uses.Add(1)
			http.Error(w, "unexpected redemption", 400)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/api/v1/spawn/invite-preview" || r.URL.RawQuery != "" {
			t.Error("wrong preview method/path or token in query")
		}
		for _, header := range []string{"Authorization", "Cookie", "X-Aweb-Signature", "X-Aweb-DID", "X-API-Key"} {
			if r.Header.Get(header) != "" {
				t.Errorf("unexpected principal credential header %s", header)
			}
		}
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil || len(request) != 1 || request["token"] != inner {
			t.Error("preview did not send exactly the inner token")
		}
		selected := mode.Load().(string)
		status := map[string]int{"unknown": 404, "rate": 429, "unavailable": 503, "redirect": 307, "bad_request": 422}[selected]
		w.Header().Set("X-Reflected-Secret", inner)
		if status != 0 {
			w.Header().Set("Location", other.URL+"/?token="+inner)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"detail":"` + inner + `"}`))
			return
		}
		result := map[string]any{"canonical_team_id": "backend:example.test", "identity_scope": "local", "server_url": server.URL + "/api", "expires_at": "2030-01-01T00:00:00Z", "status": "active", "token": inner}
		switch selected {
		case "expired", "exhausted", "revoked":
			result["status"] = selected
		case "nullable":
			result["expires_at"] = nil
			result["identity_scope"] = "global"
		case "mismatch":
			result["server_url"] = other.URL
		case "echo":
			result["canonical_team_id"] = strings.TrimPrefix(inner, "aw_inv_") + ":example.test"
		case "bad_scope":
			result["identity_scope"] = inner
		case "bad_status":
			result["status"] = inner
		case "bad_expiry":
			result["expires_at"] = inner
		case "malformed":
			_, _ = w.Write([]byte(`{"canonical_team_id":` + inner))
			return
		case "oversized":
			_, _ = w.Write([]byte(strings.Repeat(inner, 4096)))
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	token := inspectEnvelopeFixture(1, inner, server.URL+"/api")
	home := t.TempDir()
	wd := t.TempDir()
	// Invalid local principal files must not be loaded for inspection.
	for _, root := range []string{home, wd} {
		if err := os.MkdirAll(filepath.Join(root, ".aw"), 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"identity.yaml", "workspace.yaml", "signing.key"} {
			if err := os.WriteFile(filepath.Join(root, ".aw", name), []byte("invalid-principal-fixture"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	beforeHome, beforeWD := snapshotJoinFiles(t, home), snapshotJoinFiles(t, wd)
	run := func(input string, extraEnv []string, extraArgs ...string) (map[string]any, string, int) {
		t.Helper()
		args := append([]string{"team", "invite", "inspect", "--json", "--trace"}, extraArgs...)
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = wd
		cmd.Env = append(testCommandEnv(home), "AWEB_IDENTITY_HOME=", "AWEB_API_KEY=synthetic-key-must-not-send", "AWEB_URL="+other.URL, "AW_NO_UPDATE_CHECK=1", "AW_TRACE=1")
		cmd.Env = append(cmd.Env, extraEnv...)
		cmd.Stdin = strings.NewReader(input)
		var out, diagnostic bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostic
		err := cmd.Run()
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		combined := out.String() + diagnostic.String()
		if candidate := strings.TrimSpace(input); len(candidate) > 20 && strings.Contains(combined, candidate) {
			t.Fatal("stdin token echoed in output")
		}
		for _, secret := range []string{token, inner, strings.TrimPrefix(inner, "aw_inv_"), "synthetic-key-must-not-send"} {
			if strings.Contains(combined, secret) {
				t.Fatal("secret in stdout/stderr/trace")
			}
		}
		result := map[string]any{}
		if out.Len() > 0 && json.Unmarshal(out.Bytes(), &result) != nil {
			t.Fatal("stdout is not one JSON result")
		}
		return result, diagnostic.String(), code
	}
	for _, tc := range []struct{ mode, code string }{
		{"active", ""}, {"nullable", ""}, {"expired", "expired"}, {"exhausted", "exhausted"}, {"revoked", "revoked"},
		{"unknown", "unknown_or_invalid"}, {"rate", "server_unreachable"}, {"unavailable", "server_unreachable"},
		{"redirect", "server_unreachable"}, {"bad_request", "server_unreachable"}, {"mismatch", "server_mismatch"},
		{"echo", "server_unreachable"}, {"bad_scope", "server_unreachable"}, {"bad_status", "server_unreachable"},
		{"bad_expiry", "server_unreachable"}, {"malformed", "server_unreachable"}, {"oversized", "server_unreachable"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			mode.Store(tc.mode)
			before := calls.Load()
			result, _, exit := run(token+"\n", nil, "--token-stdin")
			if calls.Load() != before+1 || uses.Load() != 0 || redirected.Load() != 0 {
				t.Fatal("inspect redeemed, retried, or followed a response URL")
			}
			if tc.code == "" {
				if exit != 0 || result["status"] != "active" || result["kind"] != "hosted" || len(result) != 6 {
					t.Fatalf("bad successful inspection: exit=%d result=%v", exit, result)
				}
				if tc.mode == "nullable" && (result["expires_at"] != nil || result["identity_scope"] != "global") {
					t.Fatal("nullable expiry/global scope not preserved")
				}
			} else {
				failure, ok := result["error"].(map[string]any)
				if exit != 1 || !ok || failure["code"] != tc.code {
					t.Fatalf("bad error: exit=%d result=%v", exit, result)
				}
				if tc.mode == "expired" || tc.mode == "exhausted" || tc.mode == "revoked" {
					if inspected, ok := result["invite"].(map[string]any); !ok || inspected["status"] != tc.mode {
						t.Fatal("inactive metadata missing")
					}
				} else if result["invite"] != nil {
					t.Fatal("untrusted metadata returned with failure")
				}
			}
		})
	}
	before := calls.Load()
	controllerBytes, _ := json.Marshal(map[string]string{"i": "fixture", "d": "example.test", "t": "Backend", "s": inner, "a": server.URL})
	controller := base64.RawURLEncoding.EncodeToString(controllerBytes)
	result, _, code := run(controller, nil)
	if code != 0 || result["kind"] != "controller" || result["identity_scope"] != "unknown" || result["status"] != "unverified" || result["canonical_team_id"] != "backend:example.test" || len(result) != 5 {
		t.Fatalf("bad controller metadata: %v", result)
	}
	for _, tc := range []struct {
		input, code string
		exit        int
	}{
		{"garbage", "malformed_token", 1}, {"", "malformed_token", 2},
		{inspectEnvelopeFixture(2, inner, server.URL), "unsupported_version", 1},
	} {
		result, _, code := run(tc.input, nil)
		failure, ok := result["error"].(map[string]any)
		if code != tc.exit || !ok || failure["code"] != tc.code {
			t.Fatalf("wrong local error: %v exit=%d", result, code)
		}
	}
	if _, _, code := run("", nil, token); code != 2 {
		t.Fatal("argv token was not refused")
	}
	// Both policy paths refuse before token parsing or HTTP dispatch, preserving
	// principal files and the ordinary directory. No exception is added.
	external, _ := filepath.EvalSymlinks(t.TempDir())
	if err := os.WriteFile(filepath.Join(external, "identity.yaml"), []byte("invalid-principal-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	externalBefore := snapshotJoinFiles(t, external)
	for _, ambient := range []bool{false, true} {
		var env, args []string
		if ambient {
			env = []string{"AWEB_IDENTITY_HOME=" + external}
		} else {
			args = []string{"--identity-home", external}
		}
		_, diagnostic, code := run(token, env, args...)
		if code != 2 || !strings.Contains(diagnostic, "not yet identity-home-aware") {
			t.Fatalf("external identity policy not enforced: exit=%d diagnostic=%s", code, diagnostic)
		}
	}
	if calls.Load() != before || !reflect.DeepEqual(externalBefore, snapshotJoinFiles(t, external)) || !reflect.DeepEqual(beforeHome, snapshotJoinFiles(t, home)) || !reflect.DeepEqual(beforeWD, snapshotJoinFiles(t, wd)) {
		t.Fatal("local inspection/refusal performed network access or changed identity/workspace files")
	}
	server.Close()
	result, _, code = run(token, nil)
	if code != 1 || result["error"].(map[string]any)["code"] != "server_unreachable" {
		t.Fatal("transport failure did not produce safe typed error")
	}
}
