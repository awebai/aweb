package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	principalYAML := "credentials:\n  - host: gateway.example\n    api_key: principal-static\n    caller_id: principal\n  - host: gateway.example\n    task_id: task-1\n    task_token: principal-task-must-not-win\n"
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
	credential.TaskToken = token
	if credential.APIKey != "principal-static" || credential.TaskToken != "instance-task" {
		t.Fatalf("merged credential=%#v", credential)
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
