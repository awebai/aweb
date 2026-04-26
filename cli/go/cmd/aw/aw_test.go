package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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

func newLocalHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()

	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// aw probes for aweb by calling GET /v1/agents/heartbeat on candidate bases.
		// Return any non-404 to indicate "endpoint exists" without side effects.
		// Only intercept GET; POST is the actual heartbeat and should reach the inner handler.
		if r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat") {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
	srv := &httptest.Server{
		Listener: l,
		Config:   &http.Server{Handler: wrapped},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// extractJSON finds the first JSON object in mixed output (e.g. from
// CombinedOutput where stderr warnings precede stdout JSON).
func extractJSON(t *testing.T, out []byte) []byte {
	t.Helper()
	idx := bytes.IndexByte(out, '{')
	if idx < 0 {
		t.Fatalf("no JSON object in output:\n%s", string(out))
	}
	return out[idx:]
}

func stableIDFromDidForTest(t *testing.T, did string) string {
	t.Helper()
	pub, err := awid.ExtractPublicKey(did)
	if err != nil {
		t.Fatalf("ExtractPublicKey(%q): %v", did, err)
	}
	return awid.ComputeStableID(pub)
}

func TestAwTopLevelHelpGroupsCommandsByArchitecture(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	helpCmd := exec.CommandContext(ctx, bin, "--help")
	helpCmd.Dir = tmp
	out, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("top-level help failed: %v\n%s", err, string(out))
	}

	text := string(out)
	for _, want := range []string{
		"Workspace Setup",
		"Identity",
		"Messaging & Network",
		"Coordination & Runtime",
		"Utility",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("top-level help missing group %q:\n%s", want, text)
		}
	}

	identityIdx := strings.Index(text, "Identity")
	networkIdx := strings.Index(text, "Messaging & Network")
	coordinationIdx := strings.Index(text, "Coordination & Runtime")
	workspaceIdx := strings.Index(text, "Workspace Setup")
	if workspaceIdx < 0 || identityIdx < 0 || networkIdx < 0 || coordinationIdx < 0 {
		t.Fatalf("missing expected group boundaries:\n%s", text)
	}

	claimHumanIdx := strings.Index(text, "claim-human")
	if claimHumanIdx < workspaceIdx || claimHumanIdx > identityIdx {
		t.Fatalf("expected claim-human in Workspace Setup group:\n%s", text)
	}

	mcpIdx := strings.Index(text, "mcp-config")
	if mcpIdx < identityIdx || mcpIdx > networkIdx {
		t.Fatalf("expected mcp-config in Identity group:\n%s", text)
	}

	whoamiIdx := strings.Index(text, "whoami")
	if whoamiIdx < identityIdx || whoamiIdx > networkIdx {
		t.Fatalf("expected whoami in Identity group:\n%s", text)
	}

	runIdx := strings.Index(text, "run")
	if runIdx < coordinationIdx {
		t.Fatalf("expected run in Coordination & Runtime group:\n%s", text)
	}
	if strings.Contains(text, "\n  spawn") || strings.Contains(text, "\nspawn") {
		t.Fatalf("spawn should not appear in top-level help:\n%s", text)
	}
}

func TestAwWhoAmIIsCanonicalCommandName(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	helpCmd := exec.CommandContext(ctx, bin, "whoami", "--help")
	helpCmd.Dir = tmp
	out, err := helpCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("whoami help failed: %v\n%s", err, string(out))
	}

	text := string(out)
	if !strings.Contains(text, "Usage:\n  aw whoami [flags]") {
		t.Fatalf("expected canonical whoami usage:\n%s", text)
	}
	if !strings.Contains(text, "Aliases:\n  whoami, introspect") {
		t.Fatalf("expected introspect alias in help:\n%s", text)
	}
}

func TestAwWhoamiJSONUsesActiveCertMemberAddress(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     server.URL,
		TeamID:      "backend:aweb.ai",
		Alias:       "amy",
		WorkspaceID: "workspace-amy",
		DID:         did,
		StableID:    stableID,
		Address:     "aweb.ai/amy",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  key,
		CreatedAt:   "2026-04-21T00:00:00Z",
	})
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Address:   "juan.aweb.ai/amy",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-21T00:00:00Z",
	})

	run := exec.CommandContext(ctx, bin, "whoami", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("whoami failed: %v\n%s", err, string(out))
	}
	var got struct {
		Address string `json:"address"`
		Domain  string `json:"domain"`
	}
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("parse whoami json: %v\n%s", err, string(out))
	}
	if got.Address != "aweb.ai/amy" || got.Domain != "aweb.ai" {
		t.Fatalf("whoami address/domain=%q/%q want aweb.ai/amy/aweb.ai", got.Address, got.Domain)
	}
}

func TestAwInitRejectsProjectOverrideFlag(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init", "--project", "demo")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected aw init --project to fail, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), `unknown flag: --project`) {
		t.Fatalf("expected unknown flag error for aw init --project:\n%s", string(out))
	}
}

func TestAwLockRenew(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/reservations/renew":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			requireCertificateAuthForTest(t, r)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["resource_key"] != "my-lock" {
				t.Fatalf("resource_key=%v", payload["resource_key"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "renewed",
				"resource_key": "my-lock",
				"expires_at":   "2026-02-04T11:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "lock", "renew", "--resource-key", "my-lock", "--ttl-seconds", "3600", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["resource_key"] != "my-lock" {
		t.Fatalf("resource_key=%v", got["resource_key"])
	}
	if got["status"] != "renewed" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestAwLockRevoke(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/reservations/revoke":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			requireCertificateAuthForTest(t, r)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload["prefix"] != "test-" {
				t.Fatalf("prefix=%v", payload["prefix"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"revoked_count": 2,
				"revoked_keys":  []string{"test-lock-1", "test-lock-2"},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "lock", "revoke", "--prefix", "test-", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["revoked_count"] != float64(2) {
		t.Fatalf("revoked_count=%v", got["revoked_count"])
	}
}

func TestAwChatSendAndLeavePositionalArgs(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "sess-1",
				"message_id":        "msg-1",
				"participants":      []map[string]any{},
				"sse_url":           "/v1/chat/sessions/sess-1/stream",
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "backend:demo", "eve", "workspace-1"))

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["session_id"] != "sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}

	// Verify the API request used the positional alias and message
	aliases, ok := gotReq["to_aliases"].([]any)
	if !ok || len(aliases) != 1 || aliases[0] != "bob" {
		t.Fatalf("to_aliases=%v", gotReq["to_aliases"])
	}
	if gotReq["message"] != "hello there" {
		t.Fatalf("message=%v", gotReq["message"])
	}
	if gotReq["leaving"] != true {
		t.Fatalf("leaving=%v", gotReq["leaving"])
	}
}

func TestAwChatSendAndWaitMissingArgs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	// No positional args at all
	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got: %s", string(out))
	}
	if !strings.Contains(string(out), "accepts 2 arg(s)") {
		t.Fatalf("expected args error, got: %s", string(out))
	}
}

func TestAwChatSendAndWaitExtraArgsRejected(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "chat", "send-and-wait", "bob", "hello", "extra-arg")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for extra args, got: %s", string(out))
	}
	if !strings.Contains(string(out), "accepts 2 arg(s)") {
		t.Fatalf("expected args error, got: %s", string(out))
	}
}

func TestAwChatSendAndLeavePositionalArgsOrder(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
				t.Fatalf("decode: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"session_id":        "sess-1",
				"message_id":        "msg-1",
				"participants":      []map[string]any{},
				"sse_url":           "/v1/chat/sessions/sess-1/stream",
				"targets_connected": []string{},
				"targets_left":      []string{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "backend:demo", "eve", "workspace-1"))

	run := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "bob", "hello there", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["session_id"] != "sess-1" {
		t.Fatalf("session_id=%v", got["session_id"])
	}

	aliases, ok := gotReq["to_aliases"].([]any)
	if !ok || len(aliases) != 1 || aliases[0] != "bob" {
		t.Fatalf("to_aliases=%v", gotReq["to_aliases"])
	}
	if gotReq["message"] != "hello there" {
		t.Fatalf("message=%v", gotReq["message"])
	}
	if gotReq["leaving"] != true {
		t.Fatalf("leaving=%v", gotReq["leaving"])
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "version")
	run.Env = append(os.Environ(), "AWEB_URL=")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if !strings.HasPrefix(string(out), "aw ") {
		t.Fatalf("unexpected version output: %s", string(out))
	}
}

func TestAwContactsList(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{
					{
						"contact_id":      "ct-1",
						"contact_address": "alice@example.com",
						"label":           "Alice",
						"created_at":      "2026-02-08T10:00:00Z",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "list", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	contacts, ok := got["contacts"].([]any)
	if !ok || len(contacts) != 1 {
		t.Fatalf("contacts=%v", got["contacts"])
	}
	first := contacts[0].(map[string]any)
	if first["contact_address"] != "alice@example.com" {
		t.Fatalf("contact_address=%v", first["contact_address"])
	}
}

func TestAwContactsAdd(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contact_id":      "ct-1",
				"contact_address": gotBody["contact_address"],
				"label":           gotBody["label"],
				"created_at":      "2026-02-08T10:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "add", "bob@example.com", "--label", "Bob", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["contact_id"] != "ct-1" {
		t.Fatalf("contact_id=%v", got["contact_id"])
	}
	if got["contact_address"] != "bob@example.com" {
		t.Fatalf("contact_address=%v", got["contact_address"])
	}
	if gotBody["contact_address"] != "bob@example.com" {
		t.Fatalf("req contact_address=%v", gotBody["contact_address"])
	}
	if gotBody["label"] != "Bob" {
		t.Fatalf("req label=%v", gotBody["label"])
	}
}

func TestAwContactsRemove(t *testing.T) {
	t.Parallel()

	var deletePath string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/contacts" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{
					{"contact_id": "ct-1", "contact_address": "alice@example.com", "created_at": "2026-02-08T10:00:00Z"},
					{"contact_id": "ct-2", "contact_address": "bob@example.com", "created_at": "2026-02-08T11:00:00Z"},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/contacts/") && r.Method == http.MethodDelete:
			deletePath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s method=%s", r.URL.Path, r.Method)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "bob@example.com", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["deleted"] != true {
		t.Fatalf("deleted=%v", got["deleted"])
	}
	if deletePath != "/v1/contacts/ct-2" {
		t.Fatalf("delete path=%s (expected /v1/contacts/ct-2)", deletePath)
	}
}

func TestAwContactsRemoveNotFound(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/contacts":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"contacts": []map[string]any{},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "contacts", "remove", "nobody@example.com")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got: %s", string(out))
	}
	if !strings.Contains(string(out), "contact not found") {
		t.Fatalf("expected 'contact not found' error, got: %s", string(out))
	}
}

// TestAwIntrospectVerificationRequired was removed: the email verification
// flow was part of the old API-key architecture. In the team architecture,
// aw whoami reads local state and there is no server-side email gate.

func TestAwMailSendAliasUsesTeamScopedTarget(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			gotPath = r.URL.Path
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-03-17T12:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "alice",
		"--body", "hello",
		"--json",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("expected /v1/messages, got %s", gotPath)
	}
	if gotBody["to_alias"] != "alice" {
		t.Fatalf("to_alias=%v", gotBody["to_alias"])
	}
}

func TestAwMailSendToDIDUsesIdentityAuth(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	recipientDID := "did:aw:recipient-123"

	var gotBody map[string]any
	var gotAuth string
	var gotTeamCert string
	var gotStableID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			gotAuth = r.Header.Get("Authorization")
			gotTeamCert = r.Header.Get("X-AWID-Team-Certificate")
			gotStableID = r.Header.Get("X-AWEB-DID-AW")
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	address := "myco/agent"

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     server.URL,
		TeamID:      "backend:myco",
		Alias:       "agent",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    stableID,
		Address:     address,
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  priv,
	})

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-did", recipientDID,
		"--body", "hello from identity",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Verify the request carries identity fields.
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if gotBody["to_did"] != nil {
		t.Fatalf("to_did=%v, want absent without current recipient binding", gotBody["to_did"])
	}
	if gotBody["to_stable_id"] != recipientDID {
		t.Fatalf("to_stable_id=%v, want %s", gotBody["to_stable_id"], recipientDID)
	}
	if gotTeamCert != "" {
		t.Fatalf("expected identity auth without team certificate, got %q", gotTeamCert)
	}
	if gotStableID != stableID {
		t.Fatalf("X-AWEB-DID-AW=%q want %q", gotStableID, stableID)
	}
	if !strings.HasPrefix(gotAuth, "DIDKey ") {
		t.Fatalf("Authorization=%q", gotAuth)
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing or empty")
	}
	msgID, ok := gotBody["message_id"].(string)
	if !ok || msgID == "" {
		t.Fatal("message_id missing or empty")
	}

	_ = msgID
}

func TestAwMailSendToAddressUsesIdentityAuth(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Address not found"}`))
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	address := "acme/bot"

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     server.URL,
		TeamID:      "backend:acme",
		Alias:       "bot",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    stableIDFromDidForTest(t, did),
		Address:     address,
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		SigningKey:  priv,
	})
	writeKnownAgentPinForTest(t, tmp, "test.local/monitor", registryServer.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-address", "test.local/monitor",
		"--body", "hello from address",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Verify local signing still works when the derived team domain is present.
	if gotBody["from_did"] != did {
		t.Fatalf("from_did=%v, want %s", gotBody["from_did"], did)
	}
	if gotBody["to_address"] != "test.local/monitor" {
		t.Fatalf("to_address=%v", gotBody["to_address"])
	}
	sig, ok := gotBody["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("signature missing")
	}

	// Verify from_did and signature are present — message-level signing
	// allows recipients to verify the sender independently.
	if gotBody["from_did"] == nil || gotBody["from_did"] == "" {
		t.Fatal("from_did missing")
	}
}

func TestAwMessagingUsesIdentityRegistryURLForRecipientBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	recipientPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)
	recipientStableID := awid.ComputeStableID(recipientPub)

	var registryHits atomic.Int64
	var signedAddressHits atomic.Int64
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryHits.Add(1)
		switch r.URL.Path {
		case "/v1/namespaces/example.invalid/addresses/randy":
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "DIDKey "+did+" ") {
				t.Fatalf("address lookup Authorization=%q, want DIDKey auth for sender", auth)
			}
			if strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp")) == "" {
				t.Fatal("address lookup missing X-AWEB-Timestamp")
			}
			signedAddressHits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"address_id":      "addr-randy",
				"domain":          "example.invalid",
				"name":            "randy",
				"did_aw":          recipientStableID,
				"current_did_key": recipientDID,
				"reachability":    "direct",
				"created_at":      "2026-04-25T00:00:00Z",
			})
		case "/v1/did/" + recipientStableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did_aw":          recipientStableID,
				"current_did_key": recipientDID,
			})
		default:
			t.Fatalf("unexpected registry path=%s", r.URL.Path)
		}
	}))

	var mailBody map[string]any
	var chatBody map[string]any
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&mailBody); err != nil {
				t.Fatalf("decode mail body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "mail-1",
				"status":       "delivered",
				"delivered_at": "2026-04-25T00:00:00Z",
			})
		case "/v1/chat/sessions":
			if err := json.NewDecoder(r.Body).Decode(&chatBody); err != nil {
				t.Fatalf("decode chat body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{
				SessionID: "session-1",
				MessageID: "chat-1",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected api path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     apiServer.URL,
		TeamID:      "aweb:aweb.ai",
		Alias:       "amy",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    stableID,
		Address:     "aweb.ai/amy",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  priv,
	})
	// aako-pattern workspace: the active team certificate supplies the
	// messaging address, while the persistent identity carries the registry URL.
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:         did,
		StableID:    stableID,
		Address:     "juan.aweb.ai/amy",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		CreatedAt:   "2026-04-25T00:00:00Z",
	})

	env := withoutEnvForTest(testCommandEnv(tmp), "AWID_REGISTRY_URL")
	runMail := exec.CommandContext(ctx, bin, "mail", "send", "--to-address", "example.invalid/randy", "--body", "mail repro")
	runMail.Env = env
	runMail.Dir = tmp
	if out, err := runMail.CombinedOutput(); err != nil {
		t.Fatalf("mail failed: %v\n%s", err, string(out))
	}

	runChat := exec.CommandContext(ctx, bin, "chat", "send-and-leave", "example.invalid/randy", "chat repro")
	runChat.Env = env
	runChat.Dir = tmp
	if out, err := runChat.CombinedOutput(); err != nil {
		t.Fatalf("chat failed: %v\n%s", err, string(out))
	}

	if registryHits.Load() == 0 {
		t.Fatal("identity registry_url was not used for messaging recipient resolution")
	}
	if signedAddressHits.Load() != 2 {
		t.Fatalf("signed address lookups=%d, want 2", signedAddressHits.Load())
	}
	requireSignedPayloadBindingForTest(t, mailBody["signed_payload"], "mail", recipientDID, recipientStableID, "aweb.ai/amy")
	requireSignedPayloadBindingForTest(t, chatBody["signed_payload"], "chat", recipientDID, recipientStableID, "")
}

func TestAwMessagingUsesKnownAgentPinWhenRegistryAddressMissing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	recipientDID := "did:key:z6MkpfXL8ijUSkuwevHQhYJaUwoD46EekWmdRc6jX7p5bmEm"
	recipientStableID := "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn"
	recipientAddress := "example.invalid/randy"

	var registryHits atomic.Int64
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Address not found"}`))
	}))

	var mailBody map[string]any
	var chatBody map[string]any
	var mailTeamCert string
	var chatTeamCert string
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			mailTeamCert = r.Header.Get("X-AWID-Team-Certificate")
			if err := json.NewDecoder(r.Body).Decode(&mailBody); err != nil {
				t.Fatalf("decode mail body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "mail-1",
				"status":       "delivered",
				"delivered_at": "2026-04-26T00:00:00Z",
			})
		case "/v1/chat/sessions":
			chatTeamCert = r.Header.Get("X-AWID-Team-Certificate")
			if err := json.NewDecoder(r.Body).Decode(&chatBody); err != nil {
				t.Fatalf("decode chat body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{
				SessionID: "session-1",
				MessageID: "chat-1",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected api path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     apiServer.URL,
		TeamID:      "aweb:aweb.ai",
		Alias:       "amy",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    stableID,
		Address:     "aweb.ai/amy",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  priv,
	})
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:         did,
		StableID:    stableID,
		Address:     "juan.aweb.ai/amy",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		CreatedAt:   "2026-04-26T00:00:00Z",
	})
	pins := awid.NewPinStore()
	pins.Pins[recipientStableID] = &awid.Pin{
		Address:  recipientAddress,
		StableID: recipientStableID,
		DIDKey:   recipientDID,
		Server:   registryServer.URL,
	}
	pins.Addresses[recipientAddress] = recipientStableID
	if err := pins.Save(filepath.Join(tmp, ".config", "aw", "known_agents.yaml")); err != nil {
		t.Fatalf("write known_agents: %v", err)
	}

	env := withoutEnvForTest(testCommandEnv(tmp), "AWID_REGISTRY_URL")
	runMail := exec.CommandContext(ctx, bin, "mail", "send", "--to-address", recipientAddress, "--body", "mail repro")
	runMail.Env = env
	runMail.Dir = tmp
	if out, err := runMail.CombinedOutput(); err != nil {
		t.Fatalf("mail failed: %v\n%s", err, string(out))
	}

	runChat := exec.CommandContext(ctx, bin, "chat", "send-and-leave", recipientAddress, "chat repro")
	runChat.Env = env
	runChat.Dir = tmp
	if out, err := runChat.CombinedOutput(); err != nil {
		t.Fatalf("chat failed: %v\n%s", err, string(out))
	}

	if registryHits.Load() == 0 {
		t.Fatal("registry was not attempted before known-agent fallback")
	}
	if mailTeamCert != "" {
		t.Fatalf("mail --to-address should use identity auth, got cert header")
	}
	if chatTeamCert == "" {
		t.Fatal("chat send-and-leave should use certificate auth")
	}
	requireSignedPayloadBindingForTest(t, mailBody["signed_payload"], "mail", recipientDID, recipientStableID, "aweb.ai/amy")
	requireSignedPayloadBindingForTest(t, chatBody["signed_payload"], "chat", recipientDID, recipientStableID, "")
}

func TestAwChatSendFailsClosedWhenRecipientBindingCannotResolve(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	recipientAddress := "example.invalid/randy"

	var registryHits atomic.Int64
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryHits.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"Address not found"}`))
	}))

	var chatPosts atomic.Int64
	apiServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			chatPosts.Add(1)
			http.Error(w, "unexpected chat send", http.StatusInternalServerError)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected api path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     apiServer.URL,
		TeamID:      "aweb:aweb.ai",
		Alias:       "amy",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    stableID,
		Address:     "aweb.ai/amy",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  priv,
	})
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:         did,
		StableID:    stableID,
		Address:     "juan.aweb.ai/amy",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		CreatedAt:   "2026-04-26T00:00:00Z",
	})

	env := withoutEnvForTest(testCommandEnv(tmp), "AWID_REGISTRY_URL")
	runChat := exec.CommandContext(ctx, bin, "chat", "send-and-leave", recipientAddress, "chat repro")
	runChat.Env = env
	runChat.Dir = tmp
	out, err := runChat.CombinedOutput()
	if err == nil {
		t.Fatalf("expected chat to fail closed when recipient binding cannot resolve:\n%s", string(out))
	}
	if !strings.Contains(string(out), `resolve recipient "example.invalid/randy" for signed chat`) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if registryHits.Load() == 0 {
		t.Fatal("registry was not attempted before failing closed")
	}
	if chatPosts.Load() != 0 {
		t.Fatalf("chat posts=%d, want 0", chatPosts.Load())
	}
}

func requireSignedPayloadBindingForTest(t *testing.T, raw any, messageType, recipientDID, recipientStableID, senderAddress string) {
	t.Helper()
	signedPayload, ok := raw.(string)
	if !ok || signedPayload == "" {
		t.Fatalf("%s signed_payload missing", messageType)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(signedPayload), &payload); err != nil {
		t.Fatalf("decode %s signed_payload: %v", messageType, err)
	}
	if got := strings.TrimSpace(payload["to_did"].(string)); got != recipientDID {
		t.Fatalf("%s signed_payload to_did=%q, want %s", messageType, got, recipientDID)
	}
	if got := strings.TrimSpace(payload["to_stable_id"].(string)); got != recipientStableID {
		t.Fatalf("%s signed_payload to_stable_id=%q, want %s", messageType, got, recipientStableID)
	}
	if senderAddress != "" {
		if got := strings.TrimSpace(payload["from"].(string)); got != senderAddress {
			t.Fatalf("%s signed_payload from=%q, want %s", messageType, got, senderAddress)
		}
	}
}

func TestAwMailSendToDIDLogsStableIDForStandaloneIdentityWithoutAddress(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-standalone-1",
				"status":       "delivered",
				"delivered_at": "2026-02-22T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-04T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-did", "did:aw:monitor",
		"--body", "hello from standalone",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	logDir := filepath.Join(tmp, ".config", "aw", "logs")
	logName := commLogNameForSelection(&awconfig.Selection{StableID: stableID, DID: did})
	entries, err := readCommLog(commLogPath(logDir, logName), 0)
	if err != nil {
		t.Fatalf("readCommLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(entries))
	}
	if entries[0].From != stableID {
		t.Fatalf("from=%q, want stable id %q", entries[0].From, stableID)
	}
}

func TestAwMailSendRejectsMultipleRecipientFlags(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, "http://127.0.0.1:1")

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "alice",
		"--to-did", "did:aw:alice",
		"--body", "hello",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got:\n%s", string(out))
	}
}

func TestAwMailInboxLogsStableIDWhenAddressMissing(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:    "msg-1",
						FromAlias:    "monitor",
						FromAddress:  "",
						FromStableID: "did:aw:monitor",
						Subject:      "status",
						Body:         "done",
						CreatedAt:    "2026-04-10T00:00:00Z",
					},
				},
			})
		case "/v1/messages/msg-1/ack":
			_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: "msg-1"})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:     server.URL,
		TeamID:      "backend:acme",
		Alias:       "bot",
		WorkspaceID: "workspace-1",
		DID:         did,
		StableID:    stableID,
		Address:     "acme.com/bot",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  priv,
	})

	run := exec.CommandContext(ctx, bin, "mail", "inbox")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	entries, err := readInteractionLog(interactionLogPath(tmp), 0)
	if err != nil {
		t.Fatalf("readInteractionLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want 1", len(entries))
	}
	if got := entries[0].From; got != "did:aw:monitor" {
		t.Fatalf("interaction from=%q want did:aw:monitor", got)
	}

	recap := formatInteractionRecap(entries, 10)
	if !strings.Contains(recap, "from did:aw:monitor (mail)") {
		t.Fatalf("interaction recap lost sender identity:\n%s", recap)
	}
}

func TestAwResetLocal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	// Create .aw/context and .aw/workspace.yaml.
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ctxPath := filepath.Join(awDir, "context")
	if err := os.WriteFile(ctxPath, []byte("default_account: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workspacePath := filepath.Join(awDir, "workspace.yaml")
	if err := os.WriteFile(workspacePath, []byte("server_url: https://app.aweb.ai\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "reset")
	run.Dir = tmp
	run.Env = os.Environ()
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw reset failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Removed") {
		t.Fatalf("expected 'Removed' message, got: %s", string(out))
	}
	if _, err := os.Stat(ctxPath); !os.IsNotExist(err) {
		t.Fatal(".aw/context still exists after reset")
	}
	if _, err := os.Stat(workspacePath); !os.IsNotExist(err) {
		t.Fatal(".aw/workspace.yaml still exists after reset")
	}
	if _, err := os.Stat(awDir); !os.IsNotExist(err) {
		t.Fatal(".aw directory still exists after reset (should be cleaned up when empty)")
	}
}

func TestAwMailSendWritesCommLog(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-log-1",
				"status":       "delivered",
				"delivered_at": "2026-02-26T12:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")

	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "eve",
		"--body", "hello from log test",
		"--subject", "log test",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	// Communication logs now live in the per-user state dir under ~/.config/aw/logs.
	logMatches, err := filepath.Glob(filepath.Join(tmp, ".config", "aw", "logs", "*.jsonl"))
	if err != nil {
		t.Fatalf("glob log files: %v", err)
	}
	if len(logMatches) != 1 {
		t.Fatalf("expected one log file, got %v", logMatches)
	}
	logData, err := os.ReadFile(logMatches[0])
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}

	var entry CommLogEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(logData))), &entry); err != nil {
		t.Fatalf("invalid log entry: %v\ndata: %s", err, string(logData))
	}
	if entry.Dir != "send" {
		t.Fatalf("dir=%q, want send", entry.Dir)
	}
	if entry.Channel != "mail" {
		t.Fatalf("channel=%q, want mail", entry.Channel)
	}
	if entry.MessageID != "msg-log-1" {
		t.Fatalf("message_id=%q, want msg-log-1", entry.MessageID)
	}
	if entry.Body != "hello from log test" {
		t.Fatalf("body=%q", entry.Body)
	}
	if entry.Subject != "log test" {
		t.Fatalf("subject=%q", entry.Subject)
	}
}

func TestDefaultAwebURL(t *testing.T) {
	t.Parallel()
	if DefaultAwebURL != "https://app.aweb.ai" {
		t.Fatalf("DefaultAwebURL=%q, want https://app.aweb.ai", DefaultAwebURL)
	}
}

func TestResolveBaseURLForInitFallsBackToDefault(t *testing.T) {
	// Cannot use t.Parallel() — needs env and cwd control.

	tmp := t.TempDir()

	origCfg := os.Getenv("AW_CONFIG_PATH")
	origURL := os.Getenv("AWEB_URL")
	origWd, _ := os.Getwd()
	os.Setenv("AW_CONFIG_PATH", "")
	os.Setenv("AWEB_URL", "")
	os.Chdir(tmp)
	defer func() {
		os.Setenv("AW_CONFIG_PATH", origCfg)
		os.Setenv("AWEB_URL", origURL)
		os.Chdir(origWd)
	}()

	// resolveBaseURLForInit should fall back to the default URL.
	// If the server is reachable, we get a URL back; if not, the error
	// should mention app.aweb.ai. Either way, the default was used.
	baseURL, serverName, err := resolveBaseURLForInit("", "")
	if err != nil {
		if !strings.Contains(err.Error(), "app.aweb.ai") {
			t.Fatalf("expected error to reference default URL app.aweb.ai, got: %v", err)
		}
		return
	}
	if !strings.Contains(baseURL, "app.aweb.ai") {
		t.Fatalf("expected baseURL to contain app.aweb.ai, got %q", baseURL)
	}
	if !strings.Contains(serverName, "app.aweb.ai") {
		t.Fatalf("expected serverName to contain app.aweb.ai, got %q", serverName)
	}
}

func TestMCPConfigRequiresChannelForCertificateAuth(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	writeWorkspaceBindingForTest(t, tmp, workspaceBinding("https://app.aweb.ai", "backend:demo", "alice", "workspace-1"))

	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "mcp-config")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected mcp-config to fail without --channel, got:\n%s", string(out))
	}
	if !strings.Contains(string(out), "use `aw mcp-config --channel`") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}
