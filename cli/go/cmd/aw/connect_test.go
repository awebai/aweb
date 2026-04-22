package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestConnectBootstrapPersistent(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		persistentDidAW  string
		persistentDidKey string
		didRegistered    bool
		redeemBodyBytes  []byte
		redeemBody       map[string]any
		redeemAuth       string
		redeemTimestamp  string
		onboardingURL    string
	)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       onboardingURL,
				"registry_url":   onboardingURL,
				"version":        "1.7.0",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			persistentDidAW, _ = payload["did_aw"].(string)
			persistentDidKey, _ = payload["new_did_key"].(string)
			for _, field := range []string{"did_key", "server", "address", "handle"} {
				if _, ok := payload[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			didRegistered = true
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case r.Method == http.MethodGet && persistentDidAW != "" && r.URL.Path == "/v1/did/"+persistentDidAW+"/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          persistentDidAW,
				"current_did_key": persistentDidKey,
				"created_at":      "2026-04-07T00:00:00Z",
				"updated_at":      "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/bootstrap-redeem":
			redeemAuth = strings.TrimSpace(r.Header.Get("Authorization"))
			redeemTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
			var err error
			redeemBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(redeemBodyBytes, &redeemBody); err != nil {
				t.Fatal(err)
			}

			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:juanre.aweb.ai",
				MemberDIDKey:  persistentDidKey,
				MemberDIDAW:   persistentDidAW,
				MemberAddress: "juanre.aweb.ai/laptop-agent",
				Alias:         "laptop-agent",
				Lifetime:      awid.LifetimePersistent,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"certificate":    encoded,
				"team_id":        "default:juanre.aweb.ai",
				"lifetime":       "persistent",
				"alias":          "laptop-agent",
				"did_aw":         persistentDidAW,
				"member_address": "juanre.aweb.ai/laptop-agent",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			if !didRegistered {
				t.Fatal("bootstrap-redeem ran before DID registration")
			}
			if !strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "DIDKey ") {
				t.Fatalf("connect auth=%q", r.Header.Get("Authorization"))
			}
			if strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) == "" {
				t.Fatal("missing team certificate header")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:juanre.aweb.ai",
				"alias":        "laptop-agent",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "",
				"team_did_key": teamDIDKey,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "connect", "--bootstrap-token", "tok-123", "--address", "juanre.aweb.ai/laptop-agent", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("connect failed: %v\n%s", err, string(out))
	}

	if redeemBody["token"] != "tok-123" {
		t.Fatalf("token=%v", redeemBody["token"])
	}
	if redeemBody["did_key"] != persistentDidKey {
		t.Fatalf("did_key=%v want %v", redeemBody["did_key"], persistentDidKey)
	}
	if redeemBody["did_aw"] != persistentDidAW {
		t.Fatalf("did_aw=%v want %v", redeemBody["did_aw"], persistentDidAW)
	}

	parts := strings.Fields(redeemAuth)
	if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != persistentDidKey {
		t.Fatalf("Authorization=%q", redeemAuth)
	}
	if !verifyCloudDIDPayload(t, mustExtractPublicKey(t, persistentDidKey), http.MethodPost, "/api/v1/onboarding/bootstrap-redeem", redeemTimestamp, redeemBodyBytes, parts[2]) {
		t.Fatal("bootstrap-redeem signed payload did not verify")
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("identity.yaml missing: %v", err)
	}
	if identity.StableID != persistentDidAW {
		t.Fatalf("stable_id=%q want %q", identity.StableID, persistentDidAW)
	}
	if identity.Address != "juanre.aweb.ai/laptop-agent" {
		t.Fatalf("address=%q", identity.Address)
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("workspace.yaml missing: %v", err)
	}
	activeMembership := activeMembershipForTest(t, workspace)
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.ActiveTeam != "default:juanre.aweb.ai" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
	}
	if activeMembership.TeamID != "default:juanre.aweb.ai" {
		t.Fatalf("team_id=%q", activeMembership.TeamID)
	}
	if activeMembership.Alias != "laptop-agent" {
		t.Fatalf("alias=%q", activeMembership.Alias)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", filepath.FromSlash(activeMembership.CertPath))); err != nil {
		t.Fatalf("team certificate missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}

	if !strings.Contains(string(out), "Status:      connected") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestRegisterBootstrapDIDTreatsSameKeyAlreadyRegisteredAsSuccess(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	var (
		registerCalls int
		keyLookups    int
	)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			registerCalls++
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"detail":"did_aw already registered"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/key":
			keyLookups++
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did_aw":          stableID,
				"current_did_key": didKey,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/full":
			t.Fatal("same-key registration conflict should not fetch full mapping")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	registry := awid.NewAWIDRegistryClient(server.Client(), nil)
	if err := registry.SetFallbackRegistryURL(server.URL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := registerBootstrapDID(ctx, registry, didKey, stableID, priv); err != nil {
		t.Fatalf("registerBootstrapDID returned error for same-key conflict: %v", err)
	}
	if registerCalls != 1 {
		t.Fatalf("register_calls=%d want 1", registerCalls)
	}
	if keyLookups != 1 {
		t.Fatalf("key_lookups=%d want 1", keyLookups)
	}
}

func TestConnectBootstrapEphemeral(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var redeemBody map[string]any
	var onboardingURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       onboardingURL,
				"registry_url":   onboardingURL,
				"version":        "1.7.0",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			t.Fatal("ephemeral connect should not register did:aw")
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/bootstrap-redeem":
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &redeemBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := redeemBody["did_key"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "default:juanre.aweb.ai",
				MemberDIDKey: didKey,
				Alias:        "ci-runner-01",
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"certificate": encoded,
				"team_id":     "default:juanre.aweb.ai",
				"lifetime":    "ephemeral",
				"alias":       "ci-runner-01",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:juanre.aweb.ai",
				"alias":        "ci-runner-01",
				"agent_id":     "agent-2",
				"workspace_id": "ws-2",
				"repo_id":      "",
				"team_did_key": teamDIDKey,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "connect", "--bootstrap-token", "tok-ephemeral", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("connect failed: %v\n%s", err, string(out))
	}

	if _, exists := redeemBody["did_aw"]; exists {
		t.Fatalf("ephemeral redeem unexpectedly sent did_aw: %v", redeemBody["did_aw"])
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should not exist for ephemeral connect: %v", err)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("workspace.yaml missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", filepath.FromSlash(activeMembershipForTest(t, workspace).CertPath))); err != nil {
		t.Fatalf("team certificate missing: %v", err)
	}
	if !strings.Contains(string(out), "Alias:       ci-runner-01") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestConnectBootstrapMapsConflict(t *testing.T) {
	t.Parallel()

	var onboardingURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       onboardingURL,
				"registry_url":   onboardingURL,
				"version":        "1.7.0",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/bootstrap-redeem":
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"detail":"token already consumed"}`)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "connect", "--bootstrap-token", "tok-expired", "--mock-url", server.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected connect to fail:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Token expired or already used. Mint a fresh one from the dashboard.") {
		t.Fatalf("output=%q", string(out))
	}
}

func TestConnectBootstrapUsesDiscoveryAwebURLForConnect(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		persistentDidAW  string
		persistentDidKey string
		onboardingURL    string
		connectCalls     int
	)

	awebServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:juanre.aweb.ai",
				"alias":        "laptop-agent",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "",
				"team_did_key": teamDIDKey,
			})
		default:
			t.Fatalf("unexpected aweb %s %s", r.Method, r.URL.Path)
		}
	}))

	onboardingServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": onboardingURL,
				"aweb_url":       awebServer.URL,
				"registry_url":   onboardingURL,
				"version":        "1.7.0",
				"features":       []string{"bootstrap_tokens"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			persistentDidAW, _ = payload["did_aw"].(string)
			persistentDidKey, _ = payload["new_did_key"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case r.Method == http.MethodGet && persistentDidAW != "" && r.URL.Path == "/v1/did/"+persistentDidAW+"/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          persistentDidAW,
				"current_did_key": persistentDidKey,
				"created_at":      "2026-04-07T00:00:00Z",
				"updated_at":      "2026-04-07T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/bootstrap-redeem":
			var redeemBody map[string]any
			if err := json.NewDecoder(r.Body).Decode(&redeemBody); err != nil {
				t.Fatal(err)
			}
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:juanre.aweb.ai",
				MemberDIDKey:  persistentDidKey,
				MemberDIDAW:   persistentDidAW,
				MemberAddress: "juanre.aweb.ai/laptop-agent",
				Alias:         "laptop-agent",
				Lifetime:      awid.LifetimePersistent,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"certificate":    encoded,
				"team_id":        "default:juanre.aweb.ai",
				"lifetime":       "persistent",
				"alias":          "laptop-agent",
				"did_aw":         persistentDidAW,
				"member_address": "juanre.aweb.ai/laptop-agent",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			t.Fatal("connect should use discovered aweb_url, not the bootstrap base URL")
		default:
			t.Fatalf("unexpected bootstrap service request %s %s", r.Method, r.URL.Path)
		}
	}))
	onboardingURL = onboardingServer.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "connect", "--bootstrap-token", "tok-123", "--address", "juanre.aweb.ai/laptop-agent", "--mock-url", onboardingServer.URL)
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("connect failed: %v\n%s", err, string(out))
	}

	if connectCalls != 1 {
		t.Fatalf("connect_calls=%d", connectCalls)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("workspace.yaml missing: %v", err)
	}
	if workspace.AwebURL != awebServer.URL {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
}

func mustExtractPublicKey(t *testing.T, didKey string) ed25519.PublicKey {
	t.Helper()
	pub, err := awid.ExtractPublicKey(didKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
