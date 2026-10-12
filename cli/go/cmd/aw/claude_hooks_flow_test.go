package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMaterializedHomeDoesNotInstallOrRemoveNotifyHook(t *testing.T) {
	withFakeClaudeOnPath(t)
	withFakeClaudePluginRunner(t, nil)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/instructions/active" {
			_ = json.NewEncoder(w).Encode(map[string]any{"document": map[string]any{"body_md": "Use aw."}})
			return
		}
		if r.URL.Path == "/v1/agents/heartbeat" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		t.Errorf("unexpected request %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	for _, installed := range []bool{false, true} {
		root := t.TempDir()
		writeWorkspaceBindingForTest(t, root, workspaceBinding(server.URL, "backend:demo", "notify-home", "workspace-1"))
		path := filepath.Join(root, ".claude", "settings.json")
		var before []byte
		if installed {
			writeNotifySettings(t, root, `{"other":42}`)
			result := SetupClaudeHooks(root, false)
			if result.Error != nil {
				t.Fatal(result.Error)
			}
			before, _ = os.ReadFile(path)
		}
		if err := configureMaterializedAgentHome(root); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(path)
		if installed {
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("materialization changed explicit fallback")
			}
		} else if !os.IsNotExist(err) {
			t.Fatalf("materialization installed hook: %s (%v)", after, err)
		}
		docs, err := os.ReadFile(filepath.Join(root, "AGENTS.md"))
		if err != nil || !strings.Contains(string(docs), "Use aw.") {
			t.Fatal("coordination instructions missing")
		}
	}
}

func TestGuidedClaudePollingFallbackExplainsLimitsAndRequiresOptIn(t *testing.T) {
	for _, answer := range []string{"n\n\n", "n\ny\n"} {
		root := t.TempDir()
		var out bytes.Buffer
		if err := runGuidedPostInitSetup(guidedOnboardingRequest{
			WorkingDir: root, AskPostCreateSetup: true, PromptIn: &singleByteReader{data: answer}, PromptOut: &out,
		}); err != nil {
			t.Fatal(err)
		}
		for _, limit := range []string{"chat only", "tool calls", "idle"} {
			if !strings.Contains(out.String(), limit) {
				t.Fatalf("missing %q: %s", limit, out.String())
			}
		}
		data, err := os.ReadFile(filepath.Join(root, ".claude", "settings.json"))
		if answer == "n\n\n" {
			if !os.IsNotExist(err) {
				t.Fatal("default installed fallback")
			}
		} else {
			if err != nil || !bytes.Contains(data, []byte("aw notify")) {
				t.Fatal("explicit fallback not installed")
			}
		}
	}
}

func TestClaudeHookCleanupCLIExplicitAndScoped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	root := t.TempDir()
	path := writeNotifySettings(t, root, `{"other":42}`)
	if result := SetupClaudeHooks(root, false); result.Error != nil {
		t.Fatal(result.Error)
	}
	before, _ := os.ReadFile(path)
	// Project-local alternate and user settings were not written by the installer.
	local := filepath.Join(root, ".claude", "settings.local.json")
	userRoot := t.TempDir()
	user := writeNotifySettings(t, userRoot, string(before))
	if err := os.WriteFile(local, before, 0640); err != nil {
		t.Fatal(err)
	}
	run := exec.CommandContext(ctx, bin, "init", "--remove-notify-hook")
	run.Dir = root
	run.Env = testCommandEnv(userRoot)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("cleanup command: %v: %s", err, out)
	}
	if !bytes.Contains(out, []byte("backup")) || !bytes.Contains(out, []byte("delete the backup once")) {
		t.Fatalf("missing backup notice: %s", out)
	}
	backupPaths, _ := filepath.Glob(path + ".aw-notify-backup-*")
	if len(backupPaths) != 1 {
		t.Fatalf("backups=%v", backupPaths)
	}
	backup, _ := os.ReadFile(backupPaths[0])
	if !bytes.Equal(before, backup) {
		t.Fatal("CLI backup differs")
	}
	for _, untouched := range []string{local, user} {
		data, _ := os.ReadFile(untouched)
		if !bytes.Equal(data, before) {
			t.Fatalf("changed %s", untouched)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".aw")); !os.IsNotExist(err) {
		t.Fatal("cleanup initialized an identity")
	}
	// Even with a connected identity, explicit cleanup must remain local.
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("local cleanup made a network request: %s", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	writeWorkspaceBindingForTest(t, root, workspaceBinding(server.URL, "backend:demo", "notify-cli", "workspace-1"))
	run = exec.CommandContext(ctx, bin, "init", "--remove-notify-hook", "--json")
	run.Dir = root
	run.Env = testCommandEnv(userRoot)
	out, err = run.CombinedOutput()
	if err != nil {
		t.Fatalf("repeat cleanup: %v: %s", err, out)
	}
	var repeated struct {
		Results []*claudeNotifyCleanupResult `json:"results"`
	}
	if err := json.Unmarshal(out, &repeated); err != nil {
		t.Fatalf("cleanup JSON: %v: %s", err, out)
	}
	if len(repeated.Results) != 1 || repeated.Results[0].Removed != 0 || repeated.Results[0].BackupPath != "" {
		t.Fatalf("repeat result=%+v", repeated)
	}
	backupPaths, _ = filepath.Glob(path + ".aw-notify-backup-*")
	if len(backupPaths) != 1 {
		t.Fatalf("repeat created another backup: %v", backupPaths)
	}
	run = exec.CommandContext(ctx, bin, "init", "--remove-notify-hook", "--setup-hooks")
	run.Dir = root
	run.Env = testCommandEnv(userRoot)
	if out, err := run.CombinedOutput(); err == nil || !bytes.Contains(out, []byte("cannot be combined")) {
		t.Fatalf("conflicting flags: %v %s", err, out)
	}
}

func TestCleanupClaudeNotifyHookReadOnlyLeavesSettings(t *testing.T) {
	root := t.TempDir()
	original := `{"hooks":{"PostToolUse":[{"command":"aw notify"}]}}`
	path := writeNotifySettings(t, root, original)
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	result := CleanupClaudeNotifyHook(root)
	if result.Error == nil || result.Removed != 0 {
		t.Fatalf("read-only result=%+v", result)
	}
	after, _ := os.ReadFile(path)
	if string(after) != original {
		t.Fatal("read-only file changed")
	}
}

func TestCleanupClaudeNotifyHookBackupFailureLeavesSettings(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := t.TempDir()
	original := `{"hooks":{"PostToolUse":[{"command":"aw notify"}]}}`
	path := writeNotifySettings(t, root, original)
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })
	result := CleanupClaudeNotifyHook(root)
	if result.Error == nil || result.Removed != 0 || result.BackupPath != "" {
		t.Fatalf("backup failure result=%+v", result)
	}
	after, _ := os.ReadFile(path)
	if string(after) != original {
		t.Fatal("settings changed without backup")
	}
}

func TestChannelSetupLeavesNotifyHookUntilExplicitRemoval(t *testing.T) {
	withFakeClaudeOnPath(t)
	for _, runnerErr := range []error{nil, os.ErrPermission} {
		withFakeClaudePluginRunner(t, runnerErr)
		root := t.TempDir()
		path := writeNotifySettings(t, root, `{"hooks":{"PostToolUse":[{"command":"aw notify"}]}}`)
		before, _ := os.ReadFile(path)
		result := SetupChannelMCP(root, false)
		if (result.Error != nil) != (runnerErr != nil) {
			t.Fatalf("plugin result=%+v", result)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			t.Fatal("plugin installation implicitly removed fallback")
		}
	}
}

func TestClaudeHookCleanupCLIMaterializedHomeInsideRepo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, scenario := range []string{"home-only", "both", "home-error", "both-errors"} {
		t.Run(scenario, func(t *testing.T) {
			repo, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			initGitRepoWithOrigin(t, repo, "https://example.test/repo.git")
			home := filepath.Join(repo, "agents", "instances", "alice")
			if err := os.MkdirAll(home, 0755); err != nil {
				t.Fatal(err)
			}
			original := `{"hooks":{"PostToolUse":[{"command":"aw notify"}]},"other":42}`
			homePath := writeNotifySettings(t, home, original)
			rootOriginal := `{"other":42}`
			if scenario == "both" {
				rootOriginal = original
			}
			if scenario == "home-error" || scenario == "both-errors" {
				writeNotifySettings(t, home, "{malformed")
			}
			if scenario == "both-errors" {
				rootOriginal = "{malformed"
			}
			rootPath := writeNotifySettings(t, repo, rootOriginal)
			run := exec.CommandContext(ctx, bin, "init", "--remove-notify-hook")
			run.Dir = home
			run.Env = testCommandEnv(t.TempDir())
			out, err := run.CombinedOutput()
			if (err != nil) != strings.Contains(scenario, "error") {
				t.Fatalf("cleanup: %v %s", err, out)
			}
			for _, path := range []string{homePath, rootPath} {
				if !bytes.Contains(out, []byte(path)) {
					t.Fatalf("missing result for %s: %s", path, out)
				}
			}
			homeData, _ := os.ReadFile(homePath)
			rootData, _ := os.ReadFile(rootPath)
			if strings.Contains(scenario, "error") {
				if string(homeData) != "{malformed" {
					t.Fatal("malformed home changed")
				}
			} else {
				if bytes.Contains(homeData, []byte("aw notify")) {
					t.Fatal("materialized home's hook survived")
				}
				backups, _ := filepath.Glob(homePath + ".aw-notify-backup-*")
				if len(backups) != 1 {
					t.Fatalf("home backups=%v", backups)
				}
				backup, _ := os.ReadFile(backups[0])
				if string(backup) != original {
					t.Fatal("home backup differs")
				}
			}
			backups, _ := filepath.Glob(rootPath + ".aw-notify-backup-*")
			if scenario == "both" {
				if bytes.Contains(rootData, []byte("aw notify")) || len(backups) != 1 {
					t.Fatal("root hook survived or backup missing")
				}
			} else if string(rootData) != rootOriginal || len(backups) != 0 {
				t.Fatal("unmatched/unsafe root changed")
			}
		})
	}
}

func TestClaudeHookCleanupCLISkipsEncryptionRenewal(t *testing.T) {
	t.Setenv(awconfig.IdentityHomeEnv, "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	var attempts atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if r.URL.Path == "/v1/messages/inbox" {
			json.NewEncoder(w).Encode(awid.InboxResponse{})
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	writeMessagingPrincipalForTest(t, root, server.URL, "alice", did, key)
	home := filepath.Join(root, ".aw")
	a := installMailReadEncryptionKeyForTest(t, root, home, did, key)
	state, err := awconfig.LoadEncryptionKeyStateFrom(filepath.Join(home, "encryption.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	a.CreatedAt = time.Now().Add(-80 * 24 * time.Hour).UTC().Format(time.RFC3339)
	a.NotBefore = a.CreatedAt
	a.ExpiresAt = time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if err := awid.SignEncryptionKeyAssertion(a, key); err != nil {
		t.Fatal(err)
	}
	if err := saveEncryptionAssertion(filepath.Join(home, state.ActiveRecord().AssertionPath), a); err != nil {
		t.Fatal(err)
	}
	writeNotifySettings(t, root, `{"hooks":{"PostToolUse":[{"command":"aw notify"}]}}`)
	before := fileDigestsForTest(t, home)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	run := exec.CommandContext(ctx, bin, "init", "--remove-notify-hook")
	run.Dir, run.Env = root, testCommandEnv(t.TempDir())
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("cleanup: %v %s", err, out)
	}
	if attempts.Load() != 0 || !reflect.DeepEqual(before, fileDigestsForTest(t, home)) {
		t.Fatal("cleanup performed encryption renewal network/state activity")
	}
	// Positive control: this identity really is due for automatic renewal.
	run = exec.CommandContext(ctx, bin, "mail", "inbox")
	run.Dir, run.Env = root, testCommandEnv(t.TempDir())
	out, err := run.CombinedOutput()
	if err != nil || attempts.Load() == 0 || !bytes.Contains(out, []byte("assertion renewal failed")) {
		t.Fatalf("renewal control: %v attempts=%d %s", err, attempts.Load(), out)
	}
}

func TestCleanupClaudeNotifyHookRefusesConcurrentChanges(t *testing.T) {
	for _, mutation := range []string{"bytes", "mode", "inode"} {
		t.Run(mutation, func(t *testing.T) {
			original := `{"hooks":{"PostToolUse":[{"command":"aw notify"}]}}`
			path := writeNotifySettings(t, t.TempDir(), original)
			edited := original
			beforeClaudeNotifyCleanupRecheck = func(target string) {
				if target != path {
					t.Fatal("unexpected recheck path")
				}
				switch mutation {
				case "bytes":
					edited = `{"hooks":{"PostToolUse":[{"command":"aw notify"}]},"new":"concurrent edit"}`
					if err := os.WriteFile(path, []byte(edited), 0644); err != nil {
						t.Fatal(err)
					}
				case "mode":
					if err := os.Chmod(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "inode":
					replacement := path + ".concurrent"
					if err := os.WriteFile(replacement, []byte(original), 0644); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Cleanup(func() { beforeClaudeNotifyCleanupRecheck = nil })
			result := CleanupClaudeNotifyHook(filepath.Dir(filepath.Dir(path)))
			if result.Error == nil || !strings.Contains(result.Error.Error(), "changed during cleanup") || result.Removed != 0 || result.BackupPath == "" {
				t.Fatalf("concurrent edit result=%+v", result)
			}
			after, _ := os.ReadFile(path)
			if string(after) != edited {
				t.Fatal("concurrent edit overwritten")
			}
			info, _ := os.Stat(path)
			if mutation == "mode" && info.Mode().Perm() != 0600 {
				t.Fatal("concurrent chmod overwritten")
			}
			backup, _ := os.ReadFile(result.BackupPath)
			if string(backup) != original {
				t.Fatal("original backup lost")
			}
		})
	}
}
