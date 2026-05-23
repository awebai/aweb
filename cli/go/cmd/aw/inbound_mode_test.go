package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAwInboundModeShow(t *testing.T) {
	t.Parallel()

	var gotAuth bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/me/inbound-mode":
			if r.Method != http.MethodGet {
				t.Fatalf("method=%s", r.Method)
			}
			requireCertificateAuthForTest(t, r)
			gotAuth = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":       "agent-1",
				"team_id":        "backend:demo",
				"alias":          "alice",
				"identity_scope": "global",
				"inbound_mode":   "team_and_contacts",
				"configurable":   true,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "inbound-mode", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !gotAuth {
		t.Fatal("server did not receive certificate-authenticated request")
	}
	var resp map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &resp); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if resp["inbound_mode"] != "team_and_contacts" {
		t.Fatalf("inbound_mode=%v", resp["inbound_mode"])
	}
	if resp["label"] != "Team and contacts" {
		t.Fatalf("label=%v", resp["label"])
	}
	if resp["configurable"] != true {
		t.Fatalf("configurable=%v", resp["configurable"])
	}
}

func TestAwInboundModeSetContactsOnly(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/me/inbound-mode":
			if r.Method != http.MethodPatch {
				t.Fatalf("method=%s", r.Method)
			}
			requireCertificateAuthForTest(t, r)
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":       "agent-1",
				"team_id":        "backend:demo",
				"alias":          "alice",
				"identity_scope": "global",
				"inbound_mode":   "team_and_contacts",
				"configurable":   true,
			})
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "inbound-mode", "team-and-contacts", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotBody["inbound_mode"] != "team_and_contacts" {
		t.Fatalf("inbound_mode body=%v", gotBody["inbound_mode"])
	}
	if strings.Contains(string(out), "team-and-contacts") && !strings.Contains(string(out), "team_and_contacts") {
		t.Fatalf("json should expose canonical server value, got %s", string(out))
	}
}

func TestAwInboundModeRejectsUnknownValue(t *testing.T) {
	t.Parallel()

	if _, err := normalizeInboundModeCLIValue("team-only"); err == nil {
		t.Fatal("expected unknown inbound mode to fail")
	}
	if got, err := normalizeInboundModeCLIValue("all"); err != nil || got != "open" {
		t.Fatalf("all normalized to %q err=%v", got, err)
	}
}
