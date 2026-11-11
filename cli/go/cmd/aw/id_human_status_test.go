package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/creack/pty"
)

// Run the production command tree, flags, terminal prompts and formatter in a
// separate process. Only OS keychain storage and DNS are test adapters; AWID is
// the real service. No production command hook bypasses humanAtTerminal.
func TestHumanEnrollmentStatusCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("controlling PTY harness is Unix-only")
	}
	for _, status := range []string{"prepared", "registered", "pending"} {
		for _, jsonOutput := range []bool{false, true} {
			name := status + "/text"
			if jsonOutput {
				name = status + "/json"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHumanEnrollmentStatusCommandHelper$")
				cmd.Env = append(os.Environ(), "AW_HUMAN_STATUS_TEST="+status, "AW_CONFIG_PATH=", "AW_NO_UPDATE_CHECK=1")
				if jsonOutput {
					cmd.Env = append(cmd.Env, "AW_HUMAN_STATUS_JSON=1")
				}
				for _, marker := range agentRuntimeMarkers {
					cmd.Env = append(cmd.Env, marker+"=")
				}
				var output bytes.Buffer
				cmd.Stdout = &output
				tty, err := pty.Start(cmd)
				if err != nil {
					t.Fatal(err)
				}
				defer tty.Close()
				terminalDone := make(chan string, 1)
				go func() {
					var terminal strings.Builder
					buf := make([]byte, 4096)
					answered := 0
					for {
						n, err := tty.Read(buf)
						terminal.Write(buf[:n])
						prompts := strings.Count(terminal.String(), "characters): ") + strings.Count(terminal.String(), "Type the passphrase again: ") + strings.Count(terminal.String(), "Passphrase for that human key: ")
						for answered < prompts {
							_, _ = io.WriteString(tty, humanPassphrase+"\n")
							answered++
						}
						if err != nil {
							break
						}
					}
					terminalDone <- terminal.String()
				}()
				err = cmd.Wait()
				terminal := <-terminalDone
				if err != nil {
					t.Fatalf("command: %v\nstdout: %s\nterminal: %s", err, output.String(), terminal)
				}
				got := output.String()
				if jsonOutput {
					var result map[string]any
					if err := json.Unmarshal(output.Bytes(), &result); err != nil {
						t.Fatalf("JSON: %v: %s", err, got)
					}
					field := "status"
					if status == "pending" {
						field = "registration"
					}
					if result[field] != status {
						t.Fatalf("%s: %s", field, got)
					}
				} else {
					switch status {
					case "prepared":
						if !strings.Contains(got, "Prepared locally; not registered at AWID") || !strings.Contains(got, "aw id parent request") || !strings.Contains(got, "aw id parent import") || strings.Contains(got, "Registered at AWID") {
							t.Fatalf("prepared output: %s", got)
						}
					case "registered":
						if !strings.Contains(got, "Registered at AWID") || strings.Contains(got, "pending") || strings.Contains(got, "Prepared locally") {
							t.Fatalf("registered output: %s", got)
						}
					case "pending":
						if !strings.Contains(got, "AWID registration is pending") || !strings.Contains(got, "run import again") || strings.Contains(got, "Registered at AWID") {
							t.Fatalf("pending output: %s", got)
						}
					}
				}
			})
		}
	}
}

func TestHumanEnrollmentStatusCommandHelper(t *testing.T) {
	status := os.Getenv("AW_HUMAN_STATUS_TEST")
	if status == "" {
		return
	}
	var child *childHarness
	var parent *parentRun
	if status == "pending" {
		parent = newParentRun(t, "")
		child = parent.child
	} else {
		child = newChildHarness(t, "")
	}
	key, err := awconfig.LoadControllerKey("example.com")
	if err != nil {
		t.Fatal(err)
	}
	controller := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	// Both sides resolve the same test DNS authority. The server still runs
	// its real registration, issuance, status and signature checks.
	t.Setenv("AWID_SKIP_DNS_VERIFY", "")
	t.Setenv("AWID_FIXTURE_DNS_DOMAIN", "example.com")
	t.Setenv("AWID_FIXTURE_DNS_CONTROLLER", controller)
	registryURL := realAWIDFixture(t)
	child.opts.RegistryURL = registryURL
	var args []string
	if status == "pending" {
		p := parent
		registry := awid.NewAWIDRegistryClient(nil, child.opts.TXTResolver)
		if err := ensureStandaloneNamespace(context.Background(), registry, &idCreatePlan{Domain: "example.com", ControllerDID: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), RegistryURL: registryURL}, key); err != nil {
			t.Fatal(err)
		}
		invitation := child.invite("human")
		request, raw, err := executeIDParentRequest(p.opts(), invitation.InvitationID, "", true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := executeIDChildReceive(context.Background(), child.opts, raw); err != nil {
			t.Fatal(err)
		}
		child.answer = true
		response, err := executeIDChildApprove(context.Background(), child.opts, request.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "response.json")
		if err := os.WriteFile(path, response, 0600); err != nil {
			t.Fatal(err)
		}
		args = []string{"id", "parent", "import", path, "--human", p.human.ID, "--domain", "example.com", "--registry", registryURL, "--no-register"}
	} else {
		args = []string{"id", "human", "init", "--domain", "example.com", "--registry", registryURL}
		if status == "registered" {
			args = append(args, "--as-root")
		}
	}
	serveRosterTXT(t, idCreateDNSRecordValue(controller, ""))
	if err := os.Chdir(child.opts.WorkingDir); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AW_HUMAN_STATUS_JSON") == "1" {
		args = append(args, "--json")
	}
	os.Args = append([]string{"aw"}, args...)
	Execute()
	// Keep the test runner's PASS line out of the command's JSON output. Return
	// normally (and run fixture cleanups); only redirect subsequent runner output.
	os.Stdout = os.Stderr
}
