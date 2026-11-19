package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awconfig"
)

func TestA2ACredentialReadRefusesMalformedFileWithoutExposingItsContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a2a-credentials.yaml")
	original := []byte("credentials: [private-key-value: [")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readA2ACredentials(path)
	if err == nil || !strings.Contains(err.Error(), "Repair its YAML and retry") || strings.Contains(err.Error(), "private-key-value") {
		t.Fatalf("error=%v", err)
	}
	err = saveA2ATaskTokenInDirectory(a2aTokenSave{Directory: dir, RPCURL: "https://gateway.example/rpc", TaskID: "task", Token: "token"})
	if err == nil {
		t.Fatal("save accepted a malformed credential file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatalf("malformed credential file changed: %q", after)
	}
	if _, err := readA2ACredentials(filepath.Join(dir, "absent")); err != nil {
		t.Fatalf("absent optional file: %v", err)
	}
	if _, err := readA2ACredentials(dir); err == nil {
		t.Fatal("directory read failure treated as absent")
	}
}

func TestA2AConcurrentTokenSavesRetainEveryDeliveredTask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a2a-credentials.yaml")
	if err := os.WriteFile(path, []byte("credentials:\n  - host: gateway.example\n    api_key: static-credential\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const sends = 16
	start := make(chan struct{})
	failures := make(chan error, sends)
	var wg sync.WaitGroup
	for i := range sends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			failures <- saveA2ATaskTokenInDirectory(a2aTokenSave{Directory: dir, RPCURL: "https://gateway.example/rpc", TaskID: fmt.Sprintf("task-%d", i), Token: fmt.Sprintf("token-%d", i)})
		}()
	}
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	file, err := readA2ACredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Credentials) != sends+1 || file.Credentials[0].APIKey != "static-credential" {
		t.Fatalf("credentials=%#v", file.Credentials)
	}
	for i := range sends {
		found := false
		for _, entry := range file.Credentials {
			if entry.TaskID == fmt.Sprintf("task-%d", i) && entry.TaskToken == fmt.Sprintf("token-%d", i) {
				found = true
			}
		}
		if !found {
			t.Fatalf("lost task %d", i)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode())
	}
}

func TestA2ASendReturnsDeliveredTaskWhenTokenFileBecomesMalformed(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv(awconfig.IdentityHomeEnv, "")
	previousHome := activeIdentityHome
	activeIdentityHome = awconfig.IdentityHome{}
	t.Cleanup(func() { activeIdentityHome = previousHome })
	if err := os.Mkdir(".aw", 0o700); err != nil {
		t.Fatal(err)
	}
	original := "credentials: ["
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/card":
			if err := json.NewEncoder(w).Encode(testA2ACard("http://" + r.Host + "/rpc")); err != nil {
				t.Error(err)
			}
		case "/rpc":
			var req struct {
				ID     string `json:"id"`
				Method string `json:"method"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			if req.Method != "SendMessage" {
				t.Errorf("method=%s", req.Method)
				return
			}
			if err := os.WriteFile(filepath.Join(dir, ".aw", "a2a-credentials.yaml"), []byte(original), 0o600); err != nil {
				t.Error(err)
				return
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{"task": map[string]any{"id": "delivered-task", "status": map[string]any{"state": "TASK_STATE_WORKING"}, "metadata": map[string]any{"task_bearer_token": "delivered-token"}}}}); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("path=%s", r.URL.Path)
		}
	}))
	result, err := runA2ASend(context.Background(), a2aSendInput{CardURL: server.URL + "/card", Text: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Task.ID != "delivered-task" || result.Task.Metadata["task_bearer_token"] != "delivered-token" || result.TokenSaveError == nil {
		t.Fatalf("result=%#v", result)
	}
	after, err := os.ReadFile(filepath.Join(dir, ".aw", "a2a-credentials.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != original {
		t.Fatalf("damaged file overwritten: %s", after)
	}
}

func TestA2ARegistryFallbackDoesNotAcquireOperatorTrust(t *testing.T) {
	var requests atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if err := json.NewEncoder(w).Encode(map[string]any{"address": "acme.com/help", "a2a": map[string]string{"status": "active", "verification": "awid_publication_available", "card_url": "https://gateway.example/card", "card_digest": "digest"}}); err != nil {
			t.Error(err)
		}
	}))
	input := a2aCardVerification{CardURL: "https://gateway.example/card", Digest: "digest", Address: "acme.com/help", RegistryURL: server.URL}
	refused := verifyA2ACardWithAWID(context.Background(), input)
	if refused.Code != "awid_lookup_failed" || requests.Load() != 0 {
		t.Fatalf("stored URL reached without operator authority: result=%#v requests=%d", refused, requests.Load())
	}
	input.ExplicitRegistryURL = server.URL
	accepted := verifyA2ACardWithAWID(context.Background(), input)
	if accepted.Status != a2a.VerificationAWIDVerified || requests.Load() != 1 {
		t.Fatalf("operator URL failed: result=%#v requests=%d", accepted, requests.Load())
	}
}
