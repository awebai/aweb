package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func snapshotJoinFiles(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	result := map[string][32]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		result[rel] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTeamJoinHarnessCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	var admissionCalls, connectCalls, docsCalls atomic.Int32
	var docsFailure, connectFailure atomic.Bool
	server := newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"onboarding_url": serverURL, "aweb_url": serverURL, "registry_url": serverURL})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/certificates"):
			admissionCalls.Add(1)
			w.WriteHeader(http.StatusCreated)
		case r.Method == "POST" && r.URL.Path == "/v1/connect":
			connectCalls.Add(1)
			if connectFailure.Load() {
				http.Error(w, "connection unavailable", 403)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:acme.com", "alias": "bob", "agent_id": "agent-bob", "workspace_id": "workspace-bob", "team_did_key": "did:key:z6MkiTeam"})
		case r.Method == "GET" && r.URL.Path == "/v1/instructions/active":
			docsCalls.Add(1)
			if docsFailure.Load() {
				http.Error(w, "instructions unavailable", 503)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"document": map[string]any{"body_md": "Use aw mail inbox and aw chat pending."}})
		case r.Method == "PUT" && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-bob", "backend:acme.com", "bob")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	})
	for _, harness := range []string{"", "claude", "codex", "pi", "missing-claude", "failed-claude", "failed-pi", "failed-docs", "failed-connect"} {
		t.Run(harness, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			docsFailure.Store(false)
			defer docsFailure.Store(false)
			defer connectFailure.Store(false)
			wd := filepath.Join(home, "work")
			toolDir := filepath.Join(home, "bin")
			configDir := filepath.Join(home, "harness-config")
			for _, d := range []string{wd, toolDir, configDir} {
				if err := os.MkdirAll(d, 0700); err != nil {
					t.Fatal(err)
				}
			}
			_, key, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			writeTeamKeyForTest(t, home, "acme.com", "backend", key)
			id, err := awid.GenerateUUID4()
			if err != nil {
				t.Fatal(err)
			}
			secret, err := awconfig.GenerateInviteSecret()
			if err != nil {
				t.Fatal(err)
			}
			invite := &awconfig.TeamInvite{InviteID: id, Domain: "acme.com", TeamName: "backend", Secret: secret, RegistryURL: server.URL, AwebURL: server.URL, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
			writeTeamInviteForTest(t, home, invite)
			token, err := awconfig.EncodeInviteToken(invite)
			if err != nil {
				t.Fatal(err)
			}
			writeTool := func(name, body string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(toolDir, name), []byte("#!/bin/sh\n"+body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			claudeScript := "printf '%s\\n' installer-chatter\n: > \"$HOME/harness-config/claude-$2\"\n"
			piScript := "if [ \"$1\" = list ]; then\n if [ -f \"$HOME/harness-config/pi-installed\" ]; then printf '%s\\n' npm:@awebai/pi; fi\nelse\n : > \"$HOME/harness-config/pi-installed\"\nfi\n"
			if harness != "missing-claude" {
				writeTool("claude", claudeScript)
			}
			writeTool("pi", piScript)
			actual := harness
			if harness == "missing-claude" {
				actual = "claude"
			}
			if harness == "failed-claude" {
				actual = "claude"
				writeTool("claude", "printf '%s\\n' installer-failed >&2\nexit 7\n")
			}
			if harness == "failed-connect" {
				actual = "claude"
				connectFailure.Store(true)
			}
			if harness == "failed-pi" {
				actual = "pi"
				writeTool("pi", "printf '%s\\n' installer-failed >&2\nexit 7\n")
			}
			if harness == "failed-docs" {
				actual = "codex"
				docsFailure.Store(true)
				defer docsFailure.Store(false)
			}
			run := func(extraEnv []string, args ...string) (map[string]any, string, error) {
				t.Helper()
				command := exec.CommandContext(ctx, bin, args...)
				command.Dir = wd
				command.Env = append(testCommandEnv(home), "PATH="+toolDir, "AWEB_IDENTITY_HOME=", "AWEB_URL=", "AWID_REGISTRY_URL=", "AW_NO_UPDATE_CHECK=1", "AW_TRACE=")
				command.Env = append(command.Env, extraEnv...)
				var stdout, stderr bytes.Buffer
				command.Stdout = &stdout
				command.Stderr = &stderr
				err := command.Run()
				if strings.Contains(stdout.String()+stderr.String(), token) || strings.Contains(stdout.String()+stderr.String(), secret) {
					t.Fatal("secret in output")
				}
				result := map[string]any{}
				if stdout.Len() > 0 {
					if e := json.Unmarshal(stdout.Bytes(), &result); e != nil {
						t.Fatalf("stdout is not one JSON result: %v: %s; stderr=%s", e, stdout.String(), stderr.String())
					}
				}
				return result, stderr.String(), err
			}
			admissions, connections := admissionCalls.Load(), connectCalls.Load()
			args := []string{"team", "join", token, "--name", "bob", "--json"}
			if actual != "" {
				args = append(args, "--harness", actual)
			}
			result, diagnostic, err := run(nil, args...)
			wantFailure := strings.HasPrefix(harness, "missing-") || strings.HasPrefix(harness, "failed-")
			if (err != nil) != wantFailure {
				t.Fatalf("join err=%v result=%v stderr=%s", err, result, diagnostic)
			}
			if harness == "failed-connect" {
				setup, _ := result["harness_setup"].(map[string]any)
				if result["connected"] != false || result["status"] != "accepted" || setup["status"] != "not_started" || !strings.Contains(diagnostic, "workspace connect") || !strings.Contains(diagnostic, "--setup-only") {
					t.Fatalf("connection partial result: %v %s", result, diagnostic)
				}
				before := snapshotJoinFiles(t, wd)
				_, retryDiagnostic, retryErr := run(nil, "team", "join", "--setup-only", "--harness", actual, "--json")
				if retryErr == nil || !strings.Contains(retryDiagnostic, "connected workspace") || !reflect.DeepEqual(before, snapshotJoinFiles(t, wd)) {
					t.Fatalf("unconnected retry wrote files or unclear refusal: %v %s", retryErr, retryDiagnostic)
				}
				connectFailure.Store(false)
				_, diagnostic, err = run(nil, "workspace", "connect", "--service", server.URL, "--json")
				if err != nil {
					t.Fatalf("connect continuation: %v %s", err, diagnostic)
				}
				retried, diagnostic, err := run(nil, "team", "join", "--setup-only", "--harness", actual, "--json")
				if err != nil || retried["status"] != "prepared" || admissionCalls.Load() != admissions+1 || connectCalls.Load() != connections+2 {
					t.Fatalf("connection+setup continuation: %v %v %s", err, retried, diagnostic)
				}
				return
			}
			if result["connected"] != true {
				t.Fatalf("membership connection not reported: %v %s", result, diagnostic)
			}
			if admissionCalls.Load() != admissions+1 || connectCalls.Load() != connections+1 {
				t.Fatal("join did not admit/connect exactly once")
			}
			if actual == "" {
				if _, ok := result["harness_setup"]; ok {
					t.Fatal("omission changed output")
				}
				for _, name := range []string{"AGENTS.md", "CLAUDE.md"} {
					if _, e := os.Lstat(filepath.Join(wd, name)); !os.IsNotExist(e) {
						t.Fatalf("omission wrote %s", name)
					}
				}
				return
			}
			setup, ok := result["harness_setup"].(map[string]any)
			if !ok {
				t.Fatalf("requested harness setup missing from result: %v", result)
			}
			if wantFailure {
				if setup["status"] != "incomplete" || !strings.Contains(diagnostic, "membership and workspace connection completed") || !strings.Contains(diagnostic, "--setup-only") {
					t.Fatalf("dishonest partial result=%v stderr=%s", result, diagnostic)
				}
			} else if setup["status"] != "prepared" {
				t.Fatalf("unexpected setup %v", setup)
			}
			if harness == "missing-claude" && !strings.Contains(diagnostic, "claude is required") {
				t.Fatalf("missing executable: %s", diagnostic)
			}
			if harness == "claude" && !strings.Contains(diagnostic, "installer-chatter") {
				t.Fatal("installer diagnostic not separated")
			}
			if actual == "codex" && !wantFailure && setup["start_command"] != "aw run codex" {
				t.Fatalf("codex guidance=%v", setup)
			}
			writeTool("claude", claudeScript)
			writeTool("pi", piScript)
			docsFailure.Store(false)
			identityBefore := snapshotJoinFiles(t, filepath.Join(wd, ".aw"))
			var docsBefore, pluginBefore map[string][32]byte
			for i := 0; i < 2; i++ {
				retried, diagnostic, err := run(nil, "team", "join", "--setup-only", "--harness", actual, "--json")
				if err != nil || retried["status"] != "prepared" {
					t.Fatalf("retry %d: %v %v %s", i, err, retried, diagnostic)
				}
				if !reflect.DeepEqual(identityBefore, snapshotJoinFiles(t, filepath.Join(wd, ".aw"))) {
					t.Fatal("setup retry changed identity files")
				}
				content, err := os.ReadFile(filepath.Join(wd, "AGENTS.md"))
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					docsBefore = snapshotJoinFiles(t, wd)
					pluginBefore = snapshotJoinFiles(t, configDir)
				} else if !reflect.DeepEqual(docsBefore, snapshotJoinFiles(t, wd)) || !reflect.DeepEqual(pluginBefore, snapshotJoinFiles(t, configDir)) {
					t.Fatal("repeat setup changed files")
				}
				if strings.Count(string(content), awDocsMarkerStart) != 1 {
					t.Fatalf("docs duplicated: %s", content)
				}
			}
			if admissionCalls.Load() != admissions+1 || connectCalls.Load() != connections+1 {
				t.Fatal("setup retry re-admitted or reconnected")
			}
			external := filepath.Join(home, "selected identity")
			if err := os.Rename(filepath.Join(wd, ".aw"), external); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(wd, ".aw"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(wd, ".aw", "sentinel"), []byte("unrelated"), 0600); err != nil {
				t.Fatal(err)
			}
			otherBefore := snapshotJoinFiles(t, filepath.Join(wd, ".aw"))
			cwdBefore := snapshotJoinFiles(t, wd)
			configBefore := snapshotJoinFiles(t, configDir)
			for _, explicit := range []bool{true, false} {
				for _, joinArgs := range [][]string{
					{"team", "join", "--setup-only", "--harness", actual, "--json"},
					{"team", "join", token, "--harness", actual, "--json"},
				} {
					env := []string{"AWEB_IDENTITY_HOME=" + external}
					if explicit {
						joinArgs = append([]string{"--identity-home", external}, joinArgs...)
						env = []string{"AWEB_IDENTITY_HOME=" + filepath.Join(wd, ".aw")}
					}
					a, c, d := admissionCalls.Load(), connectCalls.Load(), docsCalls.Load()
					_, diagnostic, err := run(env, joinArgs...)
					if err == nil || !strings.Contains(diagnostic, "not yet identity-home-aware") {
						t.Fatalf("external home must retain command-policy refusal: %v %s", err, diagnostic)
					}
					if admissionCalls.Load() != a || connectCalls.Load() != c || docsCalls.Load() != d {
						t.Fatal("external refusal made network calls")
					}
				}
			}
			if !reflect.DeepEqual(cwdBefore, snapshotJoinFiles(t, wd)) || !reflect.DeepEqual(configBefore, snapshotJoinFiles(t, configDir)) {
				t.Fatal("external refusal wrote docs or installer config")
			}

			if !reflect.DeepEqual(identityBefore, snapshotJoinFiles(t, external)) || !reflect.DeepEqual(otherBefore, snapshotJoinFiles(t, filepath.Join(wd, ".aw"))) {
				t.Fatal("external setup mutated identity")
			}
		})
	}
	t.Run("refusals", func(t *testing.T) {
		for _, args := range [][]string{
			{"token", "--harness", "invalid"}, {"token", "--harness", "claude", "--no-connect"},
			{"token", "--harness", "claude", "--setup-only"}, {"--setup-only"},
			{"--setup-only", "--harness", "codex", "--global"}, {"--setup-only", "--harness", "codex"},
		} {
			home := t.TempDir()
			before := snapshotJoinFiles(t, home)
			a, c, d := admissionCalls.Load(), connectCalls.Load(), docsCalls.Load()
			command := exec.CommandContext(ctx, bin, append([]string{"team", "join"}, args...)...)
			command.Dir = home
			command.Env = append(testCommandEnv(home), "AWEB_IDENTITY_HOME=", "AWEB_URL="+server.URL, "AW_NO_UPDATE_CHECK=1")
			out, err := command.CombinedOutput()
			if err == nil {
				t.Fatalf("refusal succeeded: %v: %s", args, out)
			}
			if !reflect.DeepEqual(before, snapshotJoinFiles(t, home)) {
				t.Fatalf("refusal wrote files: %v", args)
			}
			if admissionCalls.Load() != a || connectCalls.Load() != c || docsCalls.Load() != d {
				t.Fatalf("refusal performed network work: %v", args)
			}
		}
	})
}
