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

func TestAwUseBindsDirectoryWithoutRepo(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	resolvedTmp, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/workspaces/attach":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if req["attachment_type"] != "local_dir" {
				t.Fatalf("attachment_type=%v", req["attachment_type"])
			}
			if req["workspace_path"] != resolvedTmp {
				t.Fatalf("workspace_path=%v, want %q", req["workspace_path"], resolvedTmp)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":    "11111111-1111-1111-1111-111111111111",
				"project_id":      "22222222-2222-2222-2222-222222222222",
				"project_slug":    "demo",
				"alias":           "coordinator",
				"human_name":      "Coordinator",
				"attachment_type": "local_dir",
				"created":         true,
			})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    identity_id: 11111111-1111-1111-1111-111111111111
    identity_handle: coordinator
    namespace_slug: demo
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "use", "acct")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	text := string(out)
	for _, want := range []string{
		"Using identity coordinator",
		"Account:    acct",
		"Server:     local",
		"Project:    demo",
		"Context:    attached local directory",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}

	ctxState, err := awconfig.LoadWorktreeContextFrom(filepath.Join(tmp, ".aw", "context"))
	if err != nil {
		t.Fatalf("load context: %v", err)
	}
	if ctxState.DefaultAccount != "acct" {
		t.Fatalf("default_account=%q", ctxState.DefaultAccount)
	}
}
