package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A server refusal with a coded detail {code, message} reads as the server's
// message in text mode; --debug also shows the raw response, and --json
// keeps the code as error.reason and the message as error.detail.
func TestCodedRefusalPrintsTheServersMessage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	coded := func(w http.ResponseWriter, status int, code, message string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]string{"code": code, "message": message}})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "backend:demo", Agents: []awid.AgentView{{AgentID: "agent-bob", Alias: "bob", DIDKey: "did:key:z6Mkbob"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			coded(w, http.StatusGone, "participant_retired", "bob has moved; start a new mail to bob in ops")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_roles_id": "roles-1", "active_team_roles_id": "roles-1", "team_id": "backend:demo", "version": 1, "updated_at": "2026-03-10T10:00:00Z", "roles": map[string]any{}, "adapters": map[string]any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/roles":
			coded(w, http.StatusForbidden, "admin_required", "Only an admin human can publish roles.")
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
		cmd.Dir = tmp
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return exitCode(err), stdout.String(), stderr.String()
		}
		return 0, stdout.String(), stderr.String()
	}

	bundle := `{"roles":{"developer":{"title":"Developer","playbook_md":"Ship code."}}}`
	for _, tc := range []struct {
		name, stdin, code, message string
		args                       []string
	}{
		{name: "participant retired", code: "participant_retired", message: "bob has moved; start a new mail to bob in ops",
			args: []string{"mail", "send", "--to", "bob", "--subject", "Status", "--body", "hello"}},
		{name: "admin required", stdin: bundle, code: "admin_required", message: "Only an admin human can publish roles.",
			args: []string{"roles", "set", "--bundle-file", "-"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, _, stderr := run(tc.stdin, tc.args...)
			if exit != 1 || strings.TrimSpace(stderr) != tc.message {
				t.Fatalf("exit=%d stderr=%q, want exit 1 and %q", exit, stderr, tc.message)
			}
			_, _, debug := run(tc.stdin, append([]string{"--debug"}, tc.args...)...)
			if !strings.Contains(debug, tc.message) || !strings.Contains(debug, `"code":"`+tc.code+`"`) {
				t.Fatalf("--debug does not keep the raw response:\n%s", debug)
			}
			_, stdout, _ := run(tc.stdin, append([]string{"--json"}, tc.args...)...)
			var envelope struct {
				Error map[string]any `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
				t.Fatalf("--json: %v %q", err, stdout)
			}
			if envelope.Error["code"] != "http_error" || envelope.Error["reason"] != tc.code || envelope.Error["detail"] != tc.message {
				t.Fatalf("--json envelope %v", envelope.Error)
			}
		})
	}
}
