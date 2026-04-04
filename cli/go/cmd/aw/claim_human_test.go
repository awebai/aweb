package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

func TestAwClaimHuman(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	var gotAuth string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/claim-human":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			gotAuth = r.Header.Get("Authorization")
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "verification_sent",
				"message":      "Check your inbox",
				"email":        "alice@example.com",
				"org_id":       "org-1",
				"org_slug":     "myteam",
				"project_id":   "proj-1",
				"project_slug": "default",
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

	// JSON output.
	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if gotAuth != "Bearer aw_sk_test" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if gotBody["email"] != "alice@example.com" {
		t.Fatalf("email=%v", gotBody["email"])
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["status"] != "verification_sent" {
		t.Fatalf("status=%v", resp["status"])
	}
	if resp["org_slug"] != "myteam" {
		t.Fatalf("org_slug=%v", resp["org_slug"])
	}
	if resp["email"] != "alice@example.com" {
		t.Fatalf("email=%v", resp["email"])
	}
}

func TestAwClaimHumanNormalizesAPIServerURL(t *testing.T) {
	t.Parallel()

	var seenClaim bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/claim-human":
			seenClaim = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":   "verification_sent",
				"message":  "Check your inbox",
				"email":    "alice@example.com",
				"org_id":   "org-1",
				"org_slug": "myteam",
			})
		case "/api/v1/namespaces":
			// resolveCloudClient should not probe or list namespaces here; fail loudly if it does.
			t.Fatalf("unexpected namespace request: %s", r.URL.Path)
		case "/api/v1/claim-human/":
			t.Fatalf("unexpected claim-human path with trailing slash: %s", r.URL.Path)
		case "/api/api/v1/claim-human":
			t.Fatalf("claim-human doubled /api prefix: %s", r.URL.Path)
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

	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL: server.URL + "/api",
		APIKey:    "aw_sk_test",
	})

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if !seenClaim {
		t.Fatalf("expected claim-human request to hit cloud root path")
	}

	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["status"] != "verification_sent" {
		t.Fatalf("status=%v", resp["status"])
	}
}

func TestAwClaimHumanTextOutput(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/claim-human":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":   "verification_sent",
				"message":  "Check your inbox",
				"email":    "alice@example.com",
				"org_id":   "org-1",
				"org_slug": "myteam",
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

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	output := strings.TrimSpace(string(out))
	want := "Verification email sent to alice@example.com. Check your inbox to complete the claim."
	if output != want {
		t.Fatalf("output=%q, want %q", output, want)
	}
}

func TestAwClaimHumanAttachedStatus(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/claim-human":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":   "attached",
				"message":  "Human attached",
				"email":    "alice@example.com",
				"org_slug": "myteam",
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

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	output := strings.TrimSpace(string(out))
	want := "Human account attached to myteam. Dashboard access is now available."
	if output != want {
		t.Fatalf("output=%q, want %q", output, want)
	}
}

func TestAwClaimHumanAlreadyAttachedStatus(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/claim-human":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":   "already_attached",
				"message":  "Already attached",
				"org_slug": "myteam",
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

	run := exec.CommandContext(ctx, bin, "claim-human", "--email", "alice@example.com")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	output := strings.TrimSpace(string(out))
	want := "Human account is already attached to myteam."
	if output != want {
		t.Fatalf("output=%q, want %q", output, want)
	}
}

func TestAwClaimHumanMissingEmail(t *testing.T) {
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
	run := exec.CommandContext(ctx, bin, "claim-human")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--email") {
		t.Fatalf("expected '--email' in error output:\n%s", string(out))
	}
}
