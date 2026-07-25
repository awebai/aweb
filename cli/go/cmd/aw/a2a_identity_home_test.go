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

func TestExternalIdentityHomeSplitsStaticA2ACredentialsFromInstanceTaskTokens(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principal := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	if err := os.MkdirAll(filepath.Join(instance, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(principal, 0o700); err != nil {
		t.Fatal(err)
	}
	// Put a task entry first so removing the static-entry discriminator makes
	// this regression fail instead of accidentally selecting the static entry.
	principalYAML := "credentials:\n  - host: gateway.example\n    task_id: task-1\n    task_token: principal-task-must-not-win\n  - host: gateway.example\n    api_key: principal-static\n    caller_id: principal\n"
	instanceYAML := "credentials:\n  - host: gateway.example\n    task_id: task-1\n    task_token: instance-task\n"
	if err := os.WriteFile(filepath.Join(principal, "a2a-credentials.yaml"), []byte(principalYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(instance, ".aw", "a2a-credentials.yaml"), []byte(instanceYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(awconfig.IdentityHomeEnv, principal)
	credential := loadA2ACredentialBestEffortForDir(instance, "https://gateway.example/card", "https://gateway.example/rpc")
	if credential.APIKey != "principal-static" || credential.CallerID != "principal" || credential.TaskToken != "" {
		t.Fatalf("static credential=%#v", credential)
	}
	token := loadA2ATaskTokenBestEffortForDir(instance, "https://gateway.example/card", "https://gateway.example/rpc", "task-1")
	if token != "instance-task" {
		t.Fatalf("task token=%q want instance-task", token)
	}
	principalAfter, err := os.ReadFile(filepath.Join(principal, "a2a-credentials.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	instanceAfter, err := os.ReadFile(filepath.Join(instance, ".aw", "a2a-credentials.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(principalAfter), "instance-task") {
		t.Fatal("instance task token entered principal credential file")
	}
	if strings.Contains(string(instanceAfter), "principal-static") {
		t.Fatal("principal static credential entered instance task file")
	}
}

func TestExternalIdentityHomeA2AStatusMergesPrincipalStaticAndInstanceTaskCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principal := filepath.Join(root, "principal")
	instance := filepath.Join(root, "instance")
	if err := os.MkdirAll(principal, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(instance, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/card":
			_ = json.NewEncoder(w).Encode(testA2ACard("http://" + r.Host + "/rpc"))
		case "/rpc":
			if got := r.Header.Get("X-A2A-API-Key"); got != "principal-static" {
				t.Fatalf("X-A2A-API-Key=%q", got)
			}
			if got := r.Header.Get("X-A2A-Caller-ID"); got != "principal" {
				t.Fatalf("X-A2A-Caller-ID=%q", got)
			}
			if got := r.Header.Get("X-A2A-Task-Token"); got != "instance-task" {
				t.Fatalf("X-A2A-Task-Token=%q", got)
			}
			var req struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req.ID,
				"result": map[string]any{"id": "task-1", "status": map[string]any{"state": "TASK_STATE_COMPLETED"}},
			})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	principalYAML := "credentials:\n  - host: " + strings.TrimPrefix(server.URL, "http://") + "\n    task_id: task-1\n    task_token: wrong-principal-task\n  - host: " + strings.TrimPrefix(server.URL, "http://") + "\n    api_key: principal-static\n    caller_id: principal\n"
	instanceYAML := "credentials:\n  - host: " + strings.TrimPrefix(server.URL, "http://") + "\n    task_id: task-1\n    task_token: instance-task\n"
	if err := os.WriteFile(filepath.Join(principal, "a2a-credentials.yaml"), []byte(principalYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(instance, ".aw", "a2a-credentials.yaml"), []byte(instanceYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, bin, "--identity-home", principal, "--json", "a2a", "status", server.URL+"/card", "task-1")
	cmd.Dir = instance
	cmd.Env = testCommandEnv(instance)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("status failed: %v\n%s", err, out)
	}
}
