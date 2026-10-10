package main

import (
	"context"
	"encoding/json"
	"github.com/awebai/aw/wake"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Actual CLI broker and Unix control server, with no registered instances or
// substituted services. Every process and path belongs to this test.
func TestWakeControlStartup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	for _, name := range []string{"long-default-home", "short-state-override", "unservable"} {
		t.Run(name, func(t *testing.T) {
			home := filepath.Join(root, name, strings.Repeat("h", 120))
			if err := os.MkdirAll(home, 0700); err != nil {
				t.Fatal(err)
			}
			env := []string{}
			for _, value := range os.Environ() {
				key := strings.SplitN(value, "=", 2)[0]
				if key == "HOME" || key == "XDG_CONFIG_HOME" || strings.HasPrefix(key, "AW") {
					continue
				}
				env = append(env, value)
			}
			env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+home, "AW_NO_UPDATE_CHECK=1")
			stateDir := filepath.Join(home, ".config", "aw", "wake")
			flags := []string{}
			if name != "long-default-home" {
				short, err := os.MkdirTemp("", "aw-wake-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(short)
				stateDir = filepath.Join(short, "w")
				flags = []string{"--state-dir", stateDir}
			}
			store, err := wake.NewStore(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			if name == "unservable" {
				path := store.SocketPath()
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "keep"), []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
				startup, stop := context.WithTimeout(ctx, 3*time.Second)
				defer stop()
				cmd := exec.CommandContext(startup, bin, append([]string{"wake", "run"}, flags...)...)
				cmd.Env = env
				output, err := cmd.CombinedOutput()
				if startup.Err() != nil {
					t.Fatalf("wake did not fail at startup: %s", output)
				}
				if err == nil || strings.Contains(string(output), "wake broker listening") {
					t.Fatalf("claimed readiness on failure: err=%v output=%s", err, output)
				}
				if !strings.Contains(string(output), "control") {
					t.Fatalf("missing control error: %s", output)
				}
				return
			}
			daemon := exec.CommandContext(ctx, bin, append([]string{"wake", "run"}, flags...)...)
			daemon.Env = env
			if err := daemon.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- daemon.Wait() }()
			defer func() {
				_ = daemon.Process.Signal(syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					_ = daemon.Process.Kill()
					<-done
				}
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				response, err := wake.Call(store.SocketPath(), wake.ControlRequest{Op: wake.OpStatus})
				if err == nil && response.Status != nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("control not reachable: %v", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			info, err := os.Stat(store.SocketPath())
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0600 {
				t.Fatalf("socket mode: %v", info.Mode())
			}
			if len(store.SocketPath()) > 100 {
				t.Fatalf("long socket: %s", store.SocketPath())
			}
			if name == "short-state-override" && store.SocketPath() != filepath.Join(stateDir, "control.sock") {
				t.Fatal("short explicit state path changed")
			}
			status := exec.CommandContext(ctx, bin, append([]string{"wake", "status", "--json"}, flags...)...)
			status.Env = env
			output, err := status.CombinedOutput()
			if err != nil {
				t.Fatalf("status: %v %s", err, output)
			}
			var result wake.Status
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatal(err)
			}
			if !result.DaemonRunning || result.DaemonPID != daemon.Process.Pid {
				t.Fatalf("wrong daemon: %+v", result)
			}
		})
	}
}
