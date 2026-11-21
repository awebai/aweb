package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/wake"
)

// Exercise an actual accepted Unix connection that closes during the exchange.
// No daemon status or resolution answer is synthesized by this transport fault.
func TestOATSWakeReadinessReportsAcceptedControlFailureAsUnavailable(t *testing.T) {
	bin, dir := buildDoctorBinary(t)
	stateDir, err := os.MkdirTemp("", "r26-wake-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(stateDir); err != nil {
			t.Error(err)
		}
	})
	store, err := wake.NewStore(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: store.SocketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	// Match StartControl so the client admits the socket and exercises the exchange.
	if err := os.Chmod(store.SocketPath(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- conn.Close()
	}()
	cmd := exec.Command(bin, "wake", "status", "--home", dir, "--min-daemon-version", "1.36.13", "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=", "AW_WAKE_STATE_DIR="+stateDir)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	commandErr := cmd.Run()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if commandErr != nil {
		t.Fatalf("accepted control failure lost the readiness verdict: %v\n%s\n%s", commandErr, stdout.String(), stderr.String())
	}
	var answer struct {
		Readiness    wake.ReadinessVerdict `json:"readiness"`
		ControlError string                `json:"control_error"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Readiness.Ready || answer.Readiness.Code != wake.ReadinessDaemonUnavailable || answer.Readiness.Home != dir || answer.ControlError == "" {
		t.Fatalf("control exchange failure became absence or readiness: %s", stdout.String())
	}
	// The store starts with an empty registry. The read must leave it empty.
	entries, err := os.ReadDir(filepath.Join(stateDir, "registry.d"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("readiness mutated registrations: %v", err)
	}
}
