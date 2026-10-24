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

func TestAwInboundModeSetTeamAndContacts(t *testing.T) {
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

func TestAwInboundModeRefusesServerDowngrade(t *testing.T) {
	for _, mode := range []string{"team_and_contacts", "contacts_only"} {
		t.Run(mode, func(t *testing.T) { testInboundModeRefusesServerDowngrade(t, mode) })
	}
}
func testInboundModeRefusesServerDowngrade(t *testing.T, mode string) {
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/me/inbound-mode" || r.Method != "PATCH" {
			t.Errorf("unexpected mode request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		requireCertificateAuthForTest(t, r)
		var request map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request["inbound_mode"] != mode {
			t.Error("request did not preserve selected mode")
		}
		actual := "open"
		if mode == "contacts_only" {
			actual = "team_and_contacts"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "agent-1", "team_id": "backend:demo", "identity_scope": "global", "inbound_mode": actual, "configurable": true})
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, root, server.URL)
	cmd := exec.CommandContext(ctx, bin, "inbound-mode", strings.ReplaceAll(mode, "_", "-"), "--json")
	cmd.Dir = root
	cmd.Env = testCommandEnv(root)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("accepted server downgrade: %s", output)
	}
	if strings.Contains(string(output), `"inbound_mode": "open"`) {
		t.Error("printed a successful downgraded result")
	}
}

func TestContactsOnlyCanonicalMode(t *testing.T) {
	for _, value := range []string{"contacts-only", "contacts_only"} {
		got, err := normalizeInboundModeCLIValue(value)
		if err != nil || got != "contacts_only" {
			t.Fatalf("%q normalized to %q, err=%v; want contacts_only", value, got, err)
		}
	}
	if got := inboundModeLabel("contacts_only"); got != "Contacts only" {
		t.Fatalf("label=%q want Contacts only", got)
	}
}
