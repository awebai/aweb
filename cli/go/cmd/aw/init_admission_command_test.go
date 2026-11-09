package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise Execute's exit status as well as the admission/hosted-invite path.
// A refused global join must not leave a newly created identity home behind,
// or remove unrelated material that was already there.
func TestInitAdmissionGlobalRefusalCommand(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, existing := range []bool{false, true} {
		for _, asJSON := range []bool{false, true} {
			name := "fresh"
			if existing {
				name = "existing_directory"
			}
			if asJSON {
				name += "_json"
			}
			t.Run(name, func(t *testing.T) {
				server := newLocalHTTPServerHandlerWithURL(t, func(origin string, w http.ResponseWriter, r *http.Request) {
					switch r.Method + " " + r.URL.Path {
					case "GET /api/v1/cli-auth/status":
						json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "scope": cliAuthScopeTeamAdmission, "resource": origin + "/cli", "account": map[string]string{"id": "acct-test"}})
					case "POST /api/v1/teams/shared:example.test/admission-invite":
						json.NewEncoder(w).Encode(teamAdmissionInviteResponse{InviteID: "invite-test", Token: "aw_inv_test", TeamID: "shared:example.test", ServerURL: origin, MaxUses: 1})
					default:
						t.Errorf("refused global join made unexpected request: %s %s", r.Method, r.URL.Path)
						http.Error(w, "unexpected request", http.StatusInternalServerError)
					}
				})
				home, target := t.TempDir(), t.TempDir()
				t.Setenv("HOME", home)
				saveTeamAdmissionLoginForTest(t, server.URL)
				awDir := filepath.Join(target, ".aw")
				if existing {
					if err := os.Mkdir(awDir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(awDir, "keep"), []byte("unrelated state"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{"init", "--global", "--name", "fixture", "--admission-team-id", "shared:example.test", "--expect-account", "acct-test", "--server-name", server.URL}
				if asJSON {
					args = append(args, "--json")
				}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir = target
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "USER=fixture", "AW_NO_UPDATE_CHECK=1"}
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				err := cmd.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 2 {
					t.Errorf("exit=%v; want usage refusal (2); stdout=%s stderr=%s", err, stdout.String(), stderr.String())
				}
				if !strings.Contains(stderr.String(), "requires an existing global identity") {
					t.Errorf("wrong refusal: %s", stderr.String())
				}
				if asJSON {
					if !json.Valid(stdout.Bytes()) || !strings.Contains(stdout.String(), "requires an existing global identity") {
						t.Errorf("missing JSON refusal: %s", stdout.String())
					}
				} else if stdout.Len() != 0 {
					t.Errorf("unexpected stdout: %s", stdout.String())
				}
				if !existing {
					if _, err := os.Stat(awDir); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("refused join left .aw state: stat error=%v", err)
					}
				} else {
					entries, err := os.ReadDir(awDir)
					if err != nil || len(entries) != 1 || entries[0].Name() != "keep" {
						t.Errorf("refusal changed existing .aw: entries=%v err=%v", entries, err)
					}
					data, err := os.ReadFile(filepath.Join(awDir, "keep"))
					if err != nil || string(data) != "unrelated state" {
						t.Errorf("refusal changed unrelated file: %q err=%v", data, err)
					}
				}
			})
		}
	}
}
