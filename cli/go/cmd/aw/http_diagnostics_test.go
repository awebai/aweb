package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestHTTPDiagnosticsCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		name, setting string
		fail          bool
	}{
		{"transport_failure", "1", true},
		{"success_silent", "1", false},
		{"disabled_failure_silent", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const privateID = "private-message-canary"
			var calls atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/agents/heartbeat" {
					w.WriteHeader(http.StatusOK)
					return
				}
				if r.URL.Path != "/v1/messages/"+privateID+"/ack" {
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				calls.Add(1)
				if tc.fail {
					<-r.Context().Done()
					return
				}
				w.Header().Set("X-Private-Canary", "private-header-canary")
				_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: privateID})
			}))
			defer server.Close()
			home := t.TempDir()
			writeDefaultWorkspaceBindingForTest(t, home, server.URL)
			runCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			cmd := exec.CommandContext(runCtx, bin, "mail", "ack", privateID)
			cmd.Dir = home
			cmd.Env = append(testCommandEnv(home), "AWEB_HTTP_TIMEOUT=200ms", "AWEB_HTTP_DIAGNOSTICS="+tc.setting, "AWID_REGISTRY_URL=http://127.0.0.1:1")
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("unexpected command result: err=%v output=%s", err, out)
			}
			const prefix = "AW HTTP DIAGNOSTIC "
			records := []string{}
			for _, line := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(line, prefix) {
					records = append(records, strings.TrimPrefix(line, prefix))
				}
			}
			if tc.setting != "1" || !tc.fail {
				if len(records) != 0 {
					t.Fatalf("successful or disabled command emitted diagnostics: %v", records)
				}
				return
			}
			if len(records) != 1 {
				t.Fatalf("failed API command must report transport phase diagnostics once; got %d records, output=%s", len(records), out)
			}
			var record struct {
				Requests []struct{ Route, Stage string }
			}
			if err := json.Unmarshal([]byte(records[0]), &record); err != nil {
				t.Fatal(err)
			}
			if len(record.Requests) == 0 {
				t.Fatal("diagnostic lost the failed request")
			}
			last := record.Requests[len(record.Requests)-1]
			if last.Route != "mail_ack" || last.Stage != "await_response" {
				t.Fatalf("wrong failure boundary: %+v", last)
			}
			for _, private := range []string{privateID, "private-header-canary", home, server.URL, "Authorization", "http://"} {
				if strings.Contains(records[0], private) {
					t.Fatalf("diagnostic leaked private request data %q", private)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("diagnostic changed the request count: %d", calls.Load())
			}
		})
	}
}
