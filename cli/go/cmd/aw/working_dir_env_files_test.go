package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// aw reads its configuration from the process environment, flags and its own
// config files. Files named .env or .env.aweb in the working directory are not
// a configuration source.
func TestAwDoesNotReadEnvFilesFromWorkingDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	pub, priv, _ := ed25519.GenerateKey(nil)
	self := awid.ComputeDIDKey(pub)

	countingServer := func(t *testing.T) (*httptest.Server, *atomic.Int32) {
		var requests atomic.Int32
		server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			switch r.URL.Path {
			case "/v1/messages/inbox":
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
			case "/v1/agents/heartbeat":
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
		return server, &requests
	}

	for _, tc := range []struct {
		name          string
		envFile       string
		processEnvSet bool
	}{
		{name: "process_environment_set_with_env_file", envFile: ".env", processEnvSet: true},
		{name: "process_environment_set_with_env_aweb_file", envFile: ".env.aweb", processEnvSet: true},
		{name: "process_environment_unset_with_env_file", envFile: ".env"},
		{name: "process_environment_unset_with_env_aweb_file", envFile: ".env.aweb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configured, configuredRequests := countingServer(t)
			fromProcessEnv, processEnvRequests := countingServer(t)
			fromFile, fileRequests := countingServer(t)

			home := t.TempDir()
			writeSelectionFixtureForTest(t, home, testSelectionFixture{AwebURL: configured.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: self, Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: priv, CreatedAt: "2026-05-02T00:00:00Z"})
			if err := os.WriteFile(filepath.Join(home, tc.envFile), []byte("AWEB_URL="+fromFile.URL+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			run := exec.CommandContext(ctx, bin, "mail", "inbox")
			run.Env = append(envWithout(testCommandEnv(home), "AWEB_URL"), "AW_NO_UPDATE_CHECK=1", "AW_TRACE=0")
			used, usedRequests, unused, unusedRequests := configured, configuredRequests, fromProcessEnv, processEnvRequests
			if tc.processEnvSet {
				run.Env = append(run.Env, "AWEB_URL="+fromProcessEnv.URL)
				used, usedRequests, unused, unusedRequests = fromProcessEnv, processEnvRequests, configured, configuredRequests
			}
			run.Dir = home
			out, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("aw mail inbox failed: %v\n%s", err, out)
			}
			if got := fileRequests.Load(); got != 0 {
				t.Errorf("%d requests reached the AWEB_URL named in %s (%s); want 0\n%s", got, tc.envFile, fromFile.URL, out)
			}
			if got := usedRequests.Load(); got == 0 {
				t.Errorf("no requests reached the expected server %s\n%s", used.URL, out)
			}
			if got := unusedRequests.Load(); got != 0 {
				t.Errorf("%d requests reached %s; want 0\n%s", got, unused.URL, out)
			}
		})
	}
}
