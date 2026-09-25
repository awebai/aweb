package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/wake"
)

// serveOneWakeStatus answers the real control protocol (one JSON line in, one
// out) with a canned status, standing in for a daemon built from older code.
func serveOneWakeStatus(t *testing.T, socketPath string, status wake.Status) {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := bufio.NewReader(conn).ReadBytes('\n'); err != nil {
			return
		}
		data, _ := json.Marshal(wake.ControlResponse{OK: true, Status: &status})
		_, _ = conn.Write(append(data, '\n'))
	}()
}

func runWakeStatusJSONForTest(t *testing.T, stateDir string) map[string]any {
	t.Helper()
	t.Setenv(wakeStateDirEnv, stateDir)
	prevState, prevJSON := wakeStateDirFlag, jsonFlag
	wakeStateDirFlag, jsonFlag = "", true
	t.Cleanup(func() { wakeStateDirFlag, jsonFlag = prevState, prevJSON })
	var runErr error
	out := captureIDCommandStdout(t, func() { runErr = wakeStatusCmd.RunE(wakeStatusCmd, nil) })
	if runErr != nil {
		t.Fatalf("wake status: %v", runErr)
	}
	if strings.Contains(out, "9.9.9-cli") || strings.Contains(out, "cli-commit") {
		t.Fatalf("status leaked the invoking CLI's version:\n%s", out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode status JSON: %v\n%s", err, out)
	}
	return got
}

func withCLIVersionForTest(t *testing.T) {
	t.Helper()
	prevVersion, prevCommit := version, commit
	version, commit = "9.9.9-cli", "cli-commit"
	t.Cleanup(func() { version, commit = prevVersion, prevCommit })
}

func shortWakeStateDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "awwk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// A newer CLI must not mask an older running daemon: a daemon that predates
// version reporting is reported as unknown, never as the CLI's version.
func TestWakeStatusOlderDaemonVersionIsUnknownNotCLIVersion(t *testing.T) {
	withCLIVersionForTest(t)
	dir := shortWakeStateDir(t)
	serveOneWakeStatus(t, filepath.Join(dir, "control.sock"), wake.Status{
		StateDir: dir, DaemonRunning: true, DaemonPID: 4242, MaxStreams: 8,
		Streams: []wake.StreamStatus{}, Instances: []wake.InstanceStatus{},
	})
	got := runWakeStatusJSONForTest(t, dir)
	if got["daemon_running"] != true || got["daemon_pid"] != float64(4242) {
		t.Fatalf("existing fields changed: %v", got)
	}
	if _, present := got["daemon_version"]; present {
		t.Fatalf("daemon_version present for a daemon that did not report one: %v", got["daemon_version"])
	}
	if got["daemon_version_state"] != wake.DaemonVersionUnknown {
		t.Fatalf("daemon_version_state=%v, want %s", got["daemon_version_state"], wake.DaemonVersionUnknown)
	}
}

func TestWakeStatusReportsRunningDaemonVersionNotCLIVersion(t *testing.T) {
	withCLIVersionForTest(t)
	dir := shortWakeStateDir(t)
	serveOneWakeStatus(t, filepath.Join(dir, "control.sock"), wake.Status{
		StateDir: dir, DaemonRunning: true, DaemonPID: 4242, DaemonVersion: "1.36.1", DaemonCommit: "old-commit",
		MaxStreams: 8, Streams: []wake.StreamStatus{}, Instances: []wake.InstanceStatus{},
	})
	got := runWakeStatusJSONForTest(t, dir)
	if got["daemon_version"] != "1.36.1" || got["daemon_commit"] != "old-commit" {
		t.Fatalf("daemon version=%v commit=%v, want the daemon's own 1.36.1/old-commit", got["daemon_version"], got["daemon_commit"])
	}
	if got["daemon_version_state"] != wake.DaemonVersionReported {
		t.Fatalf("daemon_version_state=%v", got["daemon_version_state"])
	}
}

func TestWakeStatusDaemonDownIsNotRunning(t *testing.T) {
	withCLIVersionForTest(t)
	dir := shortWakeStateDir(t)
	got := runWakeStatusJSONForTest(t, dir)
	if got["daemon_running"] != false || got["daemon_version_state"] != wake.DaemonVersionNotRunning {
		t.Fatalf("daemon down: running=%v state=%v", got["daemon_running"], got["daemon_version_state"])
	}
	if _, present := got["daemon_version"]; present {
		t.Fatal("daemon_version present with no daemon")
	}
}
