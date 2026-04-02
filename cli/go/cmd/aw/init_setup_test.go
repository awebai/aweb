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
)

func TestAwInitInjectDocsAndSetupHooks(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "reviewer", "roles": []string{}})
		case "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_instructions_id":        "instructions-1",
				"active_project_instructions_id": "instructions-1",
				"project_id":                     "proj-1",
				"version":                        1,
				"updated_at":                     "2026-03-10T10:00:00Z",
				"document": map[string]any{
					"body_md": "## Shared Rules\n\nUse `aw`.\n",
					"format":  "markdown",
				},
			})
		case "/api/v1/create-project":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "default",
				"namespace_slug": "myteam",
				"namespace":      "myteam.aweb.ai",
				"identity_id":    "identity-1",
				"alias":          "reviewer",
				"address":        "myteam.aweb.ai/reviewer",
				"api_key":        "aw_sk_headless_test",
				"did":            "did:key:z6MkTest",
				"stable_id":      "stable-1",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"created":        true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")

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

	run := exec.CommandContext(ctx, bin, "project", "create",
		"--project", "myteam",
		"--alias", "reviewer",
		"--inject-docs",
		"--setup-hooks",
		"--write-context=false",
		"--print-exports=false",
	)
	run.Env = append(os.Environ(),
		"AWEB_URL="+server.URL,
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_API_KEY=",
		"AWEB_ALIAS=",
	)
	run.Dir = tmp
	run.Stdin = strings.NewReader("")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"Created AGENTS.md with aw project instructions",
		"settings.json with notification hook",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}

	agentsData, err := os.ReadFile(filepath.Join(tmp, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(agentsData), awDocsMarkerStart) || !strings.Contains(string(agentsData), "## Shared Rules") {
		t.Fatalf("AGENTS.md missing injected docs:\n%s", string(agentsData))
	}

	settingsData, err := os.ReadFile(filepath.Join(tmp, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(settingsData), `"command": "aw notify"`) {
		t.Fatalf("settings missing aw notify hook:\n%s", string(settingsData))
	}
}
