package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetAgentRuntimeGlobals(t *testing.T) {
	t.Helper()
	oldHome := agentHomeFlag
	oldRuntime := agentRuntimeFlag
	oldCommand := agentCommandFlag
	oldFollow := agentFollowLogs
	oldForce := agentRestartForce
	t.Cleanup(func() {
		agentHomeFlag = oldHome
		agentRuntimeFlag = oldRuntime
		agentCommandFlag = oldCommand
		agentFollowLogs = oldFollow
		agentRestartForce = oldForce
	})
	agentHomeFlag = ""
	agentRuntimeFlag = ""
	agentCommandFlag = ""
	agentFollowLogs = false
	agentRestartForce = false
}

func writeAgentRuntimeHome(t *testing.T, root string, assumptions string) string {
	t.Helper()
	home := filepath.Join(root, "agents", "instances", "developer")
	if err := os.MkdirAll(filepath.Join(home, ".aw", "profile"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "AGENTS.md"), []byte("# Developer\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	profile := "id: developer\nname: Developer\nversion: 0.1.0\nruntime_assumptions: " + assumptions + "\n"
	if err := os.WriteFile(filepath.Join(home, ".aw", "profile", "profile.yaml"), []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestAgentStartStatusLogsStopLocalShellRuntime(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	home := writeAgentRuntimeHome(t, root, "[local shell]")

	state, err := startAgentRuntime("developer", home, "", "printf started; sleep 30")
	if err != nil {
		t.Fatalf("startAgentRuntime: %v", err)
	}
	if state.Runtime != "custom" || state.PID == 0 {
		t.Fatalf("state=%+v", state)
	}
	status, err := loadAgentStatus("developer", home)
	if err != nil {
		t.Fatalf("loadAgentStatus: %v", err)
	}
	if status.Status != "running" {
		t.Fatalf("status=%+v", status)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, _ := os.ReadFile(state.LogPath)
		if strings.Contains(string(data), "started") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("log did not contain output, got %q", string(data))
		}
		time.Sleep(20 * time.Millisecond)
	}
	proc, _ := os.FindProcess(state.PID)
	_ = proc.Signal(os.Interrupt)
	_ = proc.Kill()
}

func TestAgentStatusReportsRuntimeExit(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	home := writeAgentRuntimeHome(t, root, "[local shell]")
	state, err := startAgentRuntime("developer", home, "", "printf done")
	if err != nil {
		t.Fatalf("startAgentRuntime: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for processAlive(state.PID) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	status, err := loadAgentStatus("developer", home)
	if err != nil {
		t.Fatalf("loadAgentStatus: %v", err)
	}
	if status.Status != "exited" {
		t.Fatalf("status=%+v", status)
	}
}

func TestAgentStartFailuresAreExplicit(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	missingHome := filepath.Join(root, "agents", "instances", "missing")
	if _, err := startAgentRuntime("missing", missingHome, "", ""); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing home error=%v", err)
	}

	emptyHome := filepath.Join(root, "agents", "instances", "empty")
	if err := os.MkdirAll(emptyHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := startAgentRuntime("empty", emptyHome, "", ""); err == nil || !strings.Contains(err.Error(), "profile materialization missing") {
		t.Fatalf("missing profile error=%v", err)
	}

	home := writeAgentRuntimeHome(t, root, "[claude-code]")
	if _, err := startAgentRuntime("developer", home, "", ""); err == nil || !strings.Contains(err.Error(), "runtime is required") || !strings.Contains(err.Error(), "claude-code|codex|pi|local-shell") {
		t.Fatalf("missing explicit runtime error=%v", err)
	}
	t.Setenv("PATH", filepath.Join(root, "no-bin"))
	if _, err := startAgentRuntime("developer", home, "claude-code", ""); err == nil || !strings.Contains(err.Error(), "missing provider") {
		t.Fatalf("missing provider error=%v", err)
	}
}

func TestAgentStartRejectsSymlinkedDefaultHomeParentBeforeRuntimeWrites(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	outside := t.TempDir()
	writeAgentRuntimeHome(t, outside, "[local shell]")
	if err := os.MkdirAll(filepath.Join(root, "agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "agents", "instances"), filepath.Join(root, "agents", "instances")); err != nil {
		t.Fatal(err)
	}
	agentCommandFlag = "printf should-not-run"

	err := runAgentStart(nil, []string{"developer"})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(outside, "agents", "instances", "developer", ".aw", "runtime")); !os.IsNotExist(statErr) {
		t.Fatalf("runtime state wrote through symlinked parent, stat err=%v", statErr)
	}
}

func TestAgentStartRejectsUnsafeDefaultNameUnlessHomeExplicit(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	if _, err := resolveAgentHome("../developer"); err == nil || !strings.Contains(err.Error(), "invalid agent name") {
		t.Fatalf("unsafe default name error=%v", err)
	}
	home := writeAgentRuntimeHome(t, root, "[local shell]")
	agentHomeFlag = home
	got, err := resolveAgentHome("../developer")
	if err != nil {
		t.Fatalf("explicit --home should allow non-default name token: %v", err)
	}
	if got != home {
		t.Fatalf("home=%q, want %q", got, home)
	}
}

func TestAgentStartRejectsExistingRuntimeSymlinkBeforeWrites(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	home := writeAgentRuntimeHome(t, root, "[local shell]")
	if err := os.Symlink(filepath.Join(root, "missing-runtime-target"), filepath.Join(home, ".aw", "runtime")); err != nil {
		t.Fatal(err)
	}
	if _, err := startAgentRuntime("developer", home, "", "printf should-not-run"); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("runtime symlink error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "missing-runtime-target")); !os.IsNotExist(statErr) {
		t.Fatalf("runtime symlink target was created, stat err=%v", statErr)
	}
}

func TestAgentStartRejectsRuntimeFileSymlinksBeforeProcessStart(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
	}{
		{name: "log", file: "agent.log"},
		{name: "state", file: "agent.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetAgentRuntimeGlobals(t)
			root := t.TempDir()
			home := writeAgentRuntimeHome(t, root, "[local shell]")
			runtimeDir := filepath.Join(home, ".aw", "runtime")
			if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
				t.Fatal(err)
			}
			outsideTarget := filepath.Join(root, "outside-"+tc.file)
			if err := os.Symlink(outsideTarget, filepath.Join(runtimeDir, tc.file)); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "started-marker")
			if _, err := startAgentRuntime("developer", home, "", "printf started > "+marker); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
				t.Fatalf("runtime file symlink error=%v", err)
			}
			if _, statErr := os.Lstat(outsideTarget); !os.IsNotExist(statErr) {
				t.Fatalf("outside runtime target was created/written, stat err=%v", statErr)
			}
			if _, statErr := os.Lstat(marker); !os.IsNotExist(statErr) {
				t.Fatalf("runtime command started despite preflight failure, stat err=%v", statErr)
			}
		})
	}
}

func TestAgentStartRejectsRuntimeFileNonRegularEntries(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	home := writeAgentRuntimeHome(t, root, "[local shell]")
	if err := os.MkdirAll(filepath.Join(home, ".aw", "runtime", "agent.log"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := startAgentRuntime("developer", home, "", "printf should-not-run"); err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("runtime file directory error=%v", err)
	}
}

func TestAgentStartRejectsBadTeamConfigWhenPresent(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	root := t.TempDir()
	home := writeAgentRuntimeHome(t, root, "[local shell]")
	if err := os.WriteFile(filepath.Join(home, ".aw", "workspace.yaml"), []byte("team: [bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := startAgentRuntime("developer", home, "", "printf hi"); err == nil || !strings.Contains(err.Error(), "bad team config") {
		t.Fatalf("bad team config error=%v", err)
	}
}
