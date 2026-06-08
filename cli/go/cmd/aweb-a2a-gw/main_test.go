package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestA2AGatewayBuildsFromWorkspaceConfigServesCardAndSendsTask(t *testing.T) {
	tmp := t.TempDir()
	var posted awid.SendMessageRequest
	var sawCert bool
	recipientPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)
	recipientStableID := awid.ComputeStableID(recipientPub)
	awebServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatal("missing team certificate header")
			}
			sawCert = true
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-1", ConversationID: "conv-1", Status: "sent"})
		case "/v1/namespaces/a2a.aweb.ai/addresses/personal":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-personal",
				"domain":          "a2a.aweb.ai",
				"name":            "personal",
				"did_aw":          recipientStableID,
				"current_did_key": recipientDID,
				"reachability":    "open",
				"created_at":      "2026-06-07T00:00:00Z",
			})
		case "/v1/did/" + recipientStableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          recipientStableID,
				"current_did_key": recipientDID,
			})
		default:
			t.Fatalf("unexpected aweb request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer awebServer.Close()
	writeGatewayWorkspace(t, tmp, awebServer.URL)

	cfgPath := filepath.Join(tmp, "a2a-gw.yaml")
	writeConfig(t, cfgPath, tmp, awebServer.URL)
	gateway, err := buildGateway(mustLoadConfig(t, cfgPath))
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}
	cardResp := httptest.NewRecorder()
	gateway.ServeHTTP(cardResp, httptest.NewRequest(http.MethodGet, "/a2a/agents/r_personal/agent-card.json", nil))
	if cardResp.Code != http.StatusOK {
		t.Fatalf("card status=%d body=%s", cardResp.Code, cardResp.Body.String())
	}
	var card a2a.Card
	if err := json.Unmarshal(cardResp.Body.Bytes(), &card); err != nil {
		t.Fatal(err)
	}
	if err := a2a.ValidateCard(card, a2a.ValidationOptions{CardPath: "/a2a/agents/r_personal/agent-card.json", RequireJSONRPCOnly: true, DisallowDirectTenant: true, RequireMediaTypeModes: true}); err != nil {
		t.Fatalf("generated card invalid: %v", err)
	}

	body := `{"jsonrpc":"2.0","id":"req-1","method":"SendMessage","params":{"message":{"messageId":"m-1","contextId":"ctx-1","role":"ROLE_USER","parts":[{"text":"hello","mediaType":"text/plain"}]},"configuration":{"returnImmediately":true}}}`
	req := httptest.NewRequest(http.MethodPost, "/a2a/agents/r_personal/rpc", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-A2A-Caller-ID", "tester")
	resp := httptest.NewRecorder()
	gateway.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("rpc status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !sawCert {
		t.Fatal("gateway did not send through certificate-authenticated aweb client")
	}
	if posted.ToAddress != "a2a.aweb.ai/personal" {
		t.Fatalf("ToAddress=%q", posted.ToAddress)
	}
	if posted.ContentMode != awid.ContentModeLegacyPlaintextV1 {
		t.Fatalf("ContentMode=%q", posted.ContentMode)
	}
	for _, want := range []string{"```a2a-task", `"task_id":`, `"route_id": "r_personal"`, "Customer message (untrusted):", "hello"} {
		if !strings.Contains(posted.Body, want) {
			t.Fatalf("posted body missing %q:\n%s", want, posted.Body)
		}
	}
}

func TestA2AGatewayRunCheckPrintsDiagnostics(t *testing.T) {
	tmp := t.TempDir()
	awebServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("check mode should not call aweb server: %s %s", r.Method, r.URL.Path)
	}))
	defer awebServer.Close()
	writeGatewayWorkspace(t, tmp, awebServer.URL)
	cfgPath := filepath.Join(tmp, "a2a-gw.yaml")
	writeConfig(t, cfgPath, tmp, "")
	stdoutPath := filepath.Join(tmp, "stdout")
	stdout, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--config", cfgPath, "--check"}, stdout, os.Stderr); err != nil {
		t.Fatalf("run --check: %v", err)
	}
	if err := stdout.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"routes"`) || !strings.Contains(string(data), `"r_personal"`) {
		t.Fatalf("diagnostics output=%s", string(data))
	}
}

func writeGatewayWorkspace(t *testing.T, dir, awebURL string) {
	t.Helper()
	_, teamPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	memberStableID := awid.ComputeStableID(memberPub)
	teamID := "default:a2a.aweb.ai"
	cert, err := awid.SignTeamCertificate(teamPriv, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  memberDID,
		MemberDIDAW:   memberStableID,
		MemberAddress: "a2a.aweb.ai/gateway",
		Alias:         "gateway",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(dir, ".aw", "signing.key"), memberPriv); err != nil {
		t.Fatal(err)
	}
	certRel, err := awconfig.SaveTeamCertificateForTeam(dir, teamID, cert)
	if err != nil {
		t.Fatal(err)
	}
	workspace := &awconfig.WorktreeWorkspace{
		AwebURL: awebURL,
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:   teamID,
			Alias:    "gateway",
			CertPath: certRel,
		}},
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(dir, ".aw", "workspace.yaml"), workspace); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: teamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   teamID,
			Alias:    "gateway",
			CertPath: certRel,
			AwebURL:  awebURL,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if awid.ComputeDIDKey(memberPriv.Public().(ed25519.PublicKey)) != memberDID {
		t.Fatal("test signing key mismatch")
	}
}

func writeConfig(t *testing.T, path, workspaceDir, registryURL string) {
	t.Helper()
	registryLine := ""
	if strings.TrimSpace(registryURL) != "" {
		registryLine = "registry_url: \"" + strings.TrimSpace(registryURL) + "\"\n"
	}
	data := []byte(`listen: "127.0.0.1:0"
host: "a2a.aweb.ai"
workspace_dir: "` + filepath.ToSlash(workspaceDir) + `"
` + registryLine + `
root_card_mode: "router"
router_card:
  name: "aweb A2A Gateway"
  description: "Routes A2A tasks to aweb agents."
  provider:
    organization: "aweb"
    url: "https://aweb.ai"
  skills:
    - id: "route"
      name: "Route"
      description: "Route A2A tasks."
      tags: ["router"]
routes:
  - route_id: "r_personal"
    address: "a2a.aweb.ai/personal"
    response_timeout: "20ms"
    limits:
      rate_limit: "10/min"
      task_ttl: "1h"
    card:
      name: "A2A Personal"
      description: "Personal A2A agent."
      provider:
        organization: "aweb"
        url: "https://aweb.ai"
      skills:
        - id: "personal"
          name: "Personal"
          description: "Handles personal tasks."
          tags: ["personal"]
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustLoadConfig(t *testing.T, path string) fileConfig {
	t.Helper()
	cfg, err := loadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
