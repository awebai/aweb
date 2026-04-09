package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAwInstructionsShowDisplaysActiveInstructions(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id":        "instructions-1",
				"active_team_instructions_id": "instructions-1",
				"team_id":                     "backend:proj-1",
				"version":                     4,
				"updated_at":                  "2026-03-10T10:00:00Z",
				"document": map[string]any{
					"body_md": "## Shared Rules\n\nUse `aw`.\n",
					"format":  "markdown",
				},
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
	buildAwBinary(t, ctx, bin)

	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "instructions", "show")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"Team Instructions v4 (active)",
		"ID: instructions-1",
		"## Shared Rules",
		"Use `aw`.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("instructions show output missing %q:\n%s", want, text)
		}
	}
}

func TestAwInstructionsShowByIDMarksActiveVersion(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id":        "instructions-2",
				"active_team_instructions_id": "instructions-2",
				"team_id":                     "backend:proj-1",
				"version":                     2,
				"updated_at":                  "2026-03-11T10:00:00Z",
				"document": map[string]any{
					"body_md": "## Active Body\n",
					"format":  "markdown",
				},
			})
		case "/v1/instructions/instructions-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id": "instructions-2",
				"team_id":              "backend:proj-1",
				"version":              2,
				"updated_at":           "2026-03-11T10:00:00Z",
				"document": map[string]any{
					"body_md": "## Active Body\n",
					"format":  "markdown",
				},
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
	buildAwBinary(t, ctx, bin)

	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "instructions", "show", "instructions-2")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"Team Instructions v2 (active)",
		"ID: instructions-2",
		"## Active Body",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("instructions show-by-id output missing %q:\n%s", want, text)
		}
	}
}

func TestAwInstructionsSetCreatesAndActivatesNewVersion(t *testing.T) {
	t.Parallel()

	var createBody map[string]any
	var activatedPath string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id":        "instructions-1",
				"active_team_instructions_id": "instructions-1",
				"team_id":                     "backend:proj-1",
				"version":                     1,
				"updated_at":                  "2026-03-10T10:00:00Z",
				"document": map[string]any{
					"body_md": "Old body",
					"format":  "markdown",
				},
			})
		case "/v1/instructions":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id": "instructions-2",
				"team_id":              "backend:proj-1",
				"version":              2,
				"created":              true,
			})
		case "/v1/instructions/instructions-2/activate":
			activatedPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activated":                   true,
				"active_team_instructions_id": "instructions-2",
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
	buildAwBinary(t, ctx, bin)

	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "instructions", "set", "--body-file", "-")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	run.Stdin = strings.NewReader("## Shared Rules\n\nUse `aw`.\n")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if activatedPath != "/v1/instructions/instructions-2/activate" {
		t.Fatalf("activate path=%q", activatedPath)
	}

	document, ok := createBody["document"].(map[string]any)
	if !ok {
		t.Fatalf("document=%#v", createBody["document"])
	}
	if createBody["base_team_instructions_id"] != "instructions-1" {
		t.Fatalf("base_team_instructions_id=%v", createBody["base_team_instructions_id"])
	}
	if document["body_md"] != "## Shared Rules\n\nUse `aw`." {
		t.Fatalf("body_md=%q", document["body_md"])
	}
	if document["format"] != "markdown" {
		t.Fatalf("format=%v", document["format"])
	}

	text := string(out)
	if !strings.Contains(text, "Activated team instructions v2 (instructions-2)") {
		t.Fatalf("unexpected output:\n%s", text)
	}
}

func TestAwInstructionsHistoryListsVersions(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/instructions/history":
			if got := r.URL.Query().Get("limit"); got != "5" {
				t.Fatalf("limit=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_versions": []map[string]any{
					{
						"team_instructions_id": "instructions-2",
						"version":              2,
						"created_at":           "2026-03-11T10:00:00Z",
						"created_by_alias":     "ivy",
						"is_active":            true,
					},
					{
						"team_instructions_id": "instructions-1",
						"version":              1,
						"created_at":           "2026-03-10T10:00:00Z",
						"created_by_alias":     "ivy",
						"is_active":            false,
					},
				},
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
	buildAwBinary(t, ctx, bin)

	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "instructions", "history", "--limit", "5")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"v2\tactive\t2026-03-11T10:00:00Z\tinstructions-2\tivy",
		"v1\tinactive\t2026-03-10T10:00:00Z\tinstructions-1\tivy",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("instructions history output missing %q:\n%s", want, text)
		}
	}
}

func writeTestConfig(t *testing.T, workingDir, serverURL string) {
	t.Helper()
	writeDefaultWorkspaceBindingForTest(t, workingDir, serverURL)
}
