package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	for _, want := range []string{"```a2a-task", `"task_id":`, `"route_id": "r_personal"`, `"gateway_identity": "a2a.aweb.ai/gateway"`, "Customer message (untrusted):", "hello"} {
		if !strings.Contains(posted.Body, want) {
			t.Fatalf("posted body missing %q:\n%s", want, posted.Body)
		}
	}
}

func TestA2AGatewayBuildsFromACRuntimeConfig(t *testing.T) {
	tmp := t.TempDir()
	var posted map[string]any
	var pollMu sync.Mutex
	var pollPath string

	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/a2a/gateway/config/gw-test":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"gateway_id":              "gw-test",
				"gateway_identity":        "did:aw:gateway",
				"gateway_identity_status": "active",
				"config_revision":         "rev-1",
				"expires_at":              time.Now().Add(time.Hour).Format(time.RFC3339),
				"route_counts":            map[string]any{"active": 1, "disabled": 0},
				"routes": []map[string]any{{
					"route_id":          "r_personal",
					"host":              "a2a.aweb.ai",
					"address":           "a2a.aweb.ai/personal",
					"mode":              "mail",
					"disabled":          false,
					"root_behavior":     "default_for_host",
					"verification_tier": "unsigned",
					"auth":              map[string]any{"mode": "none"},
					"limits": map[string]any{
						"rate_limit":               map[string]any{"requests_per_minute": 30},
						"max_message_bytes":        32768,
						"max_concurrent_tasks":     8,
						"task_ttl_seconds":         3600,
						"response_timeout_seconds": 30,
					},
					"card": map[string]any{
						"name":                 "Personal",
						"description":          "Personal agent",
						"provider":             map[string]any{"organization": "aweb", "url": "https://aweb.ai"},
						"version":              "1.0.0",
						"default_input_modes":  []string{"text/plain"},
						"default_output_modes": []string{"text/plain"},
						"skills":               []map[string]any{{"id": "personal", "name": "Personal", "description": "Personal task", "tags": []string{"a2a"}}},
					},
				}},
			})
		case "/api/v1/a2a/gateway/bridge/gw-test/messages":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-1", ConversationID: "conv-1", Status: "sent"})
		case "/api/v1/a2a/gateway/bridge/gw-test/conversations/conv-1":
			pollMu.Lock()
			pollPath = r.URL.String()
			pollMu.Unlock()
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		default:
			t.Fatalf("unexpected AC request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer acServer.Close()
	cfgPath := filepath.Join(tmp, "a2a-gw-ac.yaml")
	writeACConfig(t, cfgPath, "http://registry.invalid", acServer.URL, "gw-test", "test-token")
	cfg := mustLoadConfig(t, cfgPath)
	if err := applyACRuntimeConfig(&cfg); err != nil {
		t.Fatalf("applyACRuntimeConfig: %v", err)
	}
	if cfg.Host != "a2a.aweb.ai" || cfg.DefaultRouteID != "r_personal" || len(cfg.Routes) != 1 {
		t.Fatalf("unexpected merged config: %#v", cfg)
	}
	if cfg.Routes[0].Limits.RateLimit != "30/min" {
		t.Fatalf("RateLimit=%q", cfg.Routes[0].Limits.RateLimit)
	}
	gateway, err := buildGateway(cfg)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
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
	if posted["route_id"] != "r_personal" || posted["to_address"] != "a2a.aweb.ai/personal" {
		t.Fatalf("posted bridge payload=%#v", posted)
	}
	if posted["content_mode"] != string(awid.ContentModeLegacyPlaintextV1) {
		t.Fatalf("posted content_mode=%#v", posted["content_mode"])
	}
	if body, ok := posted["body"].(string); !ok || !strings.Contains(body, "hello") {
		t.Fatalf("posted body=%#v", posted["body"])
	}

	transport, err := acMailTransportFromConfig(cfg)
	if err != nil {
		t.Fatalf("acMailTransportFromConfig: %v", err)
	}
	if _, err := transport.MailConversationForRoute(context.Background(), "r_personal", "a2a.aweb.ai/personal", "conv-1", 20); err != nil {
		t.Fatalf("MailConversationForRoute: %v", err)
	}
	pollMu.Lock()
	observedPollPath := pollPath
	pollMu.Unlock()
	for _, want := range []string{"route_id=r_personal", "to_address=a2a.aweb.ai%2Fpersonal", "limit=20"} {
		if !strings.Contains(observedPollPath, want) {
			t.Fatalf("poll path %q missing %q", observedPollPath, want)
		}
	}
}

func TestA2AGatewayACRuntimeStaticSecretRefDisablesRouteWithoutBrickingGateway(t *testing.T) {
	cfg := fileConfig{
		Host: "a2a.aweb.ai",
		ACConfig: acConfig{
			BaseURL:     "http://ac.invalid",
			GatewayID:   "gw-test",
			BearerToken: "test-token",
		},
	}
	if err := mergeACRuntimeConfig(&cfg, acRuntimeConfigPayload{
		GatewayID:             "gw-test",
		GatewayIdentity:       "did:aw:gateway",
		GatewayIdentityStatus: "active",
		ConfigRevision:        "rev-static-auth",
		ExpiresAt:             time.Now().Add(time.Hour).Format(time.RFC3339),
		Routes: []acRuntimeRoute{{
			RouteID:      "r_private",
			Host:         "a2a.aweb.ai",
			Address:      "a2a.aweb.ai/private",
			Mode:         "mail",
			RootBehavior: "default_for_host",
			Auth:         acRuntimeAuth{Mode: "static_api_key", SecretRef: "server.api_keys:11111111-1111-4111-8111-111111111111"},
			Limits: acRuntimeLimits{
				TaskTTLSeconds:         3600,
				ResponseTimeoutSeconds: 30,
			},
			Card: acRuntimeCard{
				Name:               "Private",
				Description:        "Private agent",
				Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []skillYAML{{ID: "private", Name: "Private", Description: "Private task"}},
			},
		}},
	}); err != nil {
		t.Fatalf("mergeACRuntimeConfig: %v", err)
	}
	if !cfg.Routes[0].Disabled {
		t.Fatal("static_api_key route with secret_ref should be disabled until hosted secret resolution is supported")
	}
	gateway, err := buildGateway(cfg)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}
	resp := httptest.NewRecorder()
	gateway.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/a2a/agents/r_private/agent-card.json", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("card status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestA2AGatewayFallsBackToHostedEnvWhenConfigFileMissing(t *testing.T) {
	t.Setenv("AWEB_A2A_GATEWAY_CONFIG_TOKEN", "test-token")
	t.Setenv("AWEB_A2A_GW_REGISTRY_URL", "http://registry.invalid")
	t.Setenv("AWEB_A2A_GW_ID", "gw-test")

	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/a2a/gateway/config/gw-test" {
			t.Fatalf("unexpected AC request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gateway_id":              "gw-test",
			"gateway_identity":        "did:aw:gateway",
			"gateway_identity_status": "active",
			"config_revision":         "rev-env",
			"expires_at":              time.Now().Add(time.Hour).Format(time.RFC3339),
			"routes": []map[string]any{{
				"route_id":      "r_personal",
				"host":          "a2a.aweb.ai",
				"address":       "a2a.aweb.ai/personal",
				"mode":          "mail",
				"root_behavior": "default_for_host",
				"auth":          map[string]any{"mode": "none"},
				"limits": map[string]any{
					"task_ttl_seconds":         3600,
					"response_timeout_seconds": 30,
				},
				"card": map[string]any{
					"name":                 "Personal",
					"description":          "Personal agent",
					"provider":             map[string]any{"organization": "aweb", "url": "https://aweb.ai"},
					"default_input_modes":  []string{"text/plain"},
					"default_output_modes": []string{"text/plain"},
					"skills":               []map[string]any{{"id": "personal", "name": "Personal", "description": "Personal task"}},
				},
			}},
		})
	}))
	defer acServer.Close()
	t.Setenv("AWEB_A2A_GW_AC_BASE_URL", acServer.URL)

	cfg, err := loadConfigOrHostedEnv(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("loadConfigOrHostedEnv: %v", err)
	}
	if cfg.ACConfig.BaseURL != acServer.URL || cfg.ACConfig.GatewayID != "gw-test" || cfg.RegistryURL != "http://registry.invalid" {
		t.Fatalf("unexpected env config: %#v", cfg)
	}
	if err := applyACRuntimeConfig(&cfg); err != nil {
		t.Fatalf("applyACRuntimeConfig: %v", err)
	}
	if cfg.ACRuntime.ConfigRevision != "rev-env" || len(cfg.Routes) != 1 {
		t.Fatalf("unexpected runtime config: %#v", cfg)
	}
}

func TestA2AGatewayMissingConfigWithoutHostedEnvFailsActionably(t *testing.T) {
	t.Setenv("AWEB_A2A_GATEWAY_CONFIG_TOKEN", "")
	_, err := loadConfigOrHostedEnv(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected missing config error")
	}
	for _, want := range []string{"no such file", "AWEB_A2A_GATEWAY_CONFIG_TOKEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestA2AGatewayRejectsExpiredACRuntimeConfig(t *testing.T) {
	tmp := t.TempDir()
	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gateway_id":              "gw-test",
			"gateway_identity":        "did:aw:gateway",
			"gateway_identity_status": "active",
			"config_revision":         "rev-expired",
			"expires_at":              time.Now().Add(-time.Minute).Format(time.RFC3339),
			"routes":                  []map[string]any{},
		})
	}))
	defer acServer.Close()
	cfgPath := filepath.Join(tmp, "a2a-gw-ac.yaml")
	writeACConfig(t, cfgPath, "http://aweb.invalid", acServer.URL, "gw-test", "test-token")
	cfg := mustLoadConfig(t, cfgPath)
	if err := applyACRuntimeConfig(&cfg); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("applyACRuntimeConfig err=%v, want expired", err)
	}
}

func TestA2AGatewayManagedACStartsPendingWhenIdentityMissing(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.11"})
	}))
	defer registry.Close()
	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		http.Error(w, `{"detail":{"code":"gateway_identity_missing"}}`, http.StatusNotFound)
	}))
	defer acServer.Close()
	cfg := fileConfig{
		Host:        "a2a.aweb.ai",
		RegistryURL: registry.URL,
		ACConfig: acConfig{
			BaseURL:     acServer.URL,
			GatewayID:   "a2a-gateway",
			BearerToken: "test-token",
		},
	}
	snapshot, err := buildManagedACSnapshot(cfg, true)
	if err != nil {
		t.Fatalf("buildManagedACSnapshot: %v", err)
	}
	if len(snapshot.cfg.Routes) != 0 || snapshot.cfg.ACRuntime.FetchStatus != "pending" {
		t.Fatalf("unexpected pending config: %#v", snapshot.cfg)
	}
	resp := httptest.NewRecorder()
	runtimeHandler(snapshot.gateway, snapshot.cfg).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/health", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status=%d body=%s", resp.Code, resp.Body.String())
	}
	var health map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "pending" {
		t.Fatalf("health status=%#v", health["status"])
	}
	acConfig := health["ac_config"].(map[string]any)
	if acConfig["status"] != "pending" || acConfig["routes"].(float64) != 0 {
		t.Fatalf("unexpected ac_config health: %#v", acConfig)
	}
	cardResp := httptest.NewRecorder()
	snapshot.gateway.ServeHTTP(cardResp, httptest.NewRequest(http.MethodGet, "/.well-known/agent-card.json", nil))
	if cardResp.Code != http.StatusOK {
		t.Fatalf("root card status=%d body=%s", cardResp.Code, cardResp.Body.String())
	}
	routeResp := httptest.NewRecorder()
	snapshot.gateway.ServeHTTP(routeResp, httptest.NewRequest(http.MethodPost, "/a2a/agents/r_missing/rpc", strings.NewReader(`{}`)))
	if routeResp.Code != http.StatusNotFound {
		t.Fatalf("missing route status=%d body=%s", routeResp.Code, routeResp.Body.String())
	}
}

func TestA2AGatewayManagedACRejectsBadTokenAtStartup(t *testing.T) {
	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":{"code":"gateway_config_auth_invalid"}}`, http.StatusUnauthorized)
	}))
	defer acServer.Close()
	cfg := fileConfig{
		Host:        "a2a.aweb.ai",
		RegistryURL: "http://registry.invalid",
		ACConfig: acConfig{
			BaseURL:     acServer.URL,
			GatewayID:   "a2a-gateway",
			BearerToken: "wrong-token",
		},
	}
	if _, err := buildManagedACSnapshot(cfg, true); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("buildManagedACSnapshot err=%v, want HTTP 401", err)
	}
}

func TestA2AGatewayManagedACRefreshFailureKeepsLastGoodRoutes(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.11"})
	}))
	defer registry.Close()
	cfg := fileConfig{
		Host:        "a2a.aweb.ai",
		RegistryURL: registry.URL,
		ACConfig: acConfig{
			BaseURL:     "http://ac.invalid",
			GatewayID:   "a2a-gateway",
			BearerToken: "test-token",
		},
	}
	expiresAt := time.Now().Add(time.Hour).Format(time.RFC3339)
	if err := mergeACRuntimeConfig(&cfg, acRuntimeConfigPayload{
		GatewayID:             "a2a-gateway",
		GatewayIdentity:       "did:aw:gateway",
		GatewayIdentityStatus: "active",
		ConfigRevision:        "rev-good",
		ExpiresAt:             expiresAt,
		Routes: []acRuntimeRoute{{
			RouteID:      "r_personal",
			Host:         "a2a.aweb.ai",
			Address:      "a2a.aweb.ai/personal",
			Mode:         "mail",
			RootBehavior: "default_for_host",
			Auth:         acRuntimeAuth{Mode: "none"},
			Limits: acRuntimeLimits{
				TaskTTLSeconds:         3600,
				ResponseTimeoutSeconds: 30,
			},
			Card: acRuntimeCard{
				Name:               "Personal",
				Description:        "Personal agent",
				Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []skillYAML{{ID: "personal", Name: "Personal", Description: "Personal task"}},
			},
		}},
	}); err != nil {
		t.Fatalf("mergeACRuntimeConfig: %v", err)
	}
	gateway, err := buildGateway(cfg)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}
	manager := &managedACGateway{cfg: cfg, gateway: gateway}
	manager.markRefreshError(&acRuntimeConfigFetchError{StatusCode: http.StatusInternalServerError, Message: "fetch AC runtime config: HTTP 500: down"})

	cardResp := httptest.NewRecorder()
	manager.ServeHTTP(cardResp, httptest.NewRequest(http.MethodGet, "/a2a/agents/r_personal/agent-card.json", nil))
	if cardResp.Code != http.StatusOK {
		t.Fatalf("card status=%d body=%s", cardResp.Code, cardResp.Body.String())
	}
	healthResp := httptest.NewRecorder()
	manager.ServeHTTP(healthResp, httptest.NewRequest(http.MethodGet, "/health", nil))
	if healthResp.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", healthResp.Code, healthResp.Body.String())
	}
	var health map[string]any
	if err := json.Unmarshal(healthResp.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	acConfig := health["ac_config"].(map[string]any)
	if acConfig["status"] != "stale" || acConfig["config_revision"] != "rev-good" || acConfig["routes"].(float64) != 1 {
		t.Fatalf("unexpected stale health: %#v", acConfig)
	}
}

func TestA2AGatewayManagedACRefreshExtendsAcceptWindowForStableRevision(t *testing.T) {
	var posted map[string]any
	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/a2a/gateway/bridge/a2a-gateway/messages" {
			t.Fatalf("unexpected AC request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-1", ConversationID: "conv-1", Status: "sent"})
	}))
	defer acServer.Close()

	cfg := fileConfig{
		Host: "a2a.aweb.ai",
		ACConfig: acConfig{
			BaseURL:     acServer.URL,
			GatewayID:   "a2a-gateway",
			BearerToken: "test-token",
		},
	}
	expiresAt := time.Now().Add(2 * time.Second).Format(time.RFC3339)
	payload := acRuntimeConfigPayload{
		GatewayID:             "a2a-gateway",
		GatewayIdentity:       "did:aw:gateway",
		GatewayIdentityStatus: "active",
		ConfigRevision:        "rev-stable",
		ExpiresAt:             expiresAt,
		Routes: []acRuntimeRoute{{
			RouteID:      "r_personal",
			Host:         "a2a.aweb.ai",
			Address:      "a2a.aweb.ai/personal",
			Mode:         "mail",
			RootBehavior: "default_for_host",
			Auth:         acRuntimeAuth{Mode: "none"},
			Limits: acRuntimeLimits{
				TaskTTLSeconds:         3600,
				ResponseTimeoutSeconds: 30,
			},
			Card: acRuntimeCard{
				Name:               "Personal",
				Description:        "Personal agent",
				Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []skillYAML{{ID: "personal", Name: "Personal", Description: "Personal task"}},
			},
		}},
	}
	if err := mergeACRuntimeConfig(&cfg, payload); err != nil {
		t.Fatalf("mergeACRuntimeConfig: %v", err)
	}
	runtime, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildGatewayWithRuntime: %v", err)
	}
	manager := &managedACGateway{cfg: cfg, gateway: gateway, runtime: runtime}
	time.Sleep(2500 * time.Millisecond)

	next := fileConfig{
		Host:     "a2a.aweb.ai",
		ACConfig: cfg.ACConfig,
	}
	payload.ExpiresAt = time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	if err := mergeACRuntimeConfig(&next, payload); err != nil {
		t.Fatalf("mergeACRuntimeConfig next: %v", err)
	}
	if err := manager.applyRefreshSnapshot(next); err != nil {
		t.Fatalf("applyRefreshSnapshot: %v", err)
	}
	if manager.gateway != gateway {
		t.Fatal("unchanged config_revision should extend accept window without rebuilding gateway")
	}
	if manager.cfg.ACRuntime.ExpiresAt != next.ACRuntime.ExpiresAt {
		t.Fatalf("expires_at not refreshed: got %q want %q", manager.cfg.ACRuntime.ExpiresAt, next.ACRuntime.ExpiresAt)
	}

	body := `{"jsonrpc":"2.0","id":"req-1","method":"SendMessage","params":{"message":{"messageId":"m-1","contextId":"ctx-1","role":"ROLE_USER","parts":[{"text":"hello after stable refresh","mediaType":"text/plain"}]},"configuration":{"returnImmediately":true}}}`
	req := httptest.NewRequest(http.MethodPost, "/a2a/agents/r_personal/rpc", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-A2A-Caller-ID", "tester")
	resp := httptest.NewRecorder()
	manager.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("rpc status=%d body=%s", resp.Code, resp.Body.String())
	}
	if posted["to_address"] != "a2a.aweb.ai/personal" {
		t.Fatalf("posted bridge payload=%#v", posted)
	}
}

func TestA2AGatewayManagedACRefreshSwapsUnderLoad(t *testing.T) {
	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/messages") {
			t.Fatalf("unexpected AC request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-1", ConversationID: "conv-1", Status: "sent"})
	}))
	defer acServer.Close()

	payloadForRevision := func(revision string) acRuntimeConfigPayload {
		return acRuntimeConfigPayload{
			GatewayID:             "a2a-gateway",
			GatewayIdentity:       "did:aw:gateway-" + revision,
			GatewayIdentityStatus: "active",
			ConfigRevision:        revision,
			ExpiresAt:             time.Now().Add(time.Hour).Format(time.RFC3339),
			Routes: []acRuntimeRoute{{
				RouteID:      "r_personal",
				Host:         "a2a.aweb.ai",
				Address:      "a2a.aweb.ai/personal",
				Mode:         "mail",
				RootBehavior: "default_for_host",
				Auth:         acRuntimeAuth{Mode: "none"},
				Limits: acRuntimeLimits{
					TaskTTLSeconds:         3600,
					ResponseTimeoutSeconds: 30,
				},
				Card: acRuntimeCard{
					Name:               "Personal " + revision,
					Description:        "Personal agent",
					Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
					DefaultInputModes:  []string{"text/plain"},
					DefaultOutputModes: []string{"text/plain"},
					Skills:             []skillYAML{{ID: "personal", Name: "Personal", Description: "Personal task"}},
				},
			}},
		}
	}
	base := fileConfig{
		Host: "a2a.aweb.ai",
		ACConfig: acConfig{
			BaseURL:     acServer.URL,
			GatewayID:   "a2a-gateway",
			BearerToken: "test-token",
		},
	}
	cfg := base
	if err := mergeACRuntimeConfig(&cfg, payloadForRevision("rev-1")); err != nil {
		t.Fatalf("mergeACRuntimeConfig: %v", err)
	}
	runtime, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildGatewayWithRuntime: %v", err)
	}
	manager := &managedACGateway{cfg: cfg, gateway: gateway, runtime: runtime}

	errCh := make(chan error, 16)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"req-%d-%d","method":"SendMessage","params":{"message":{"messageId":"m-%d-%d","contextId":"ctx-%d-%d","role":"ROLE_USER","parts":[{"text":"hello","mediaType":"text/plain"}]},"configuration":{"returnImmediately":true}}}`, worker, i, worker, i, worker, i)
				req := httptest.NewRequest(http.MethodPost, "/a2a/agents/r_personal/rpc", bytes.NewBufferString(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-A2A-Caller-ID", fmt.Sprintf("tester-%d", worker))
				resp := httptest.NewRecorder()
				manager.ServeHTTP(resp, req)
				if resp.Code != http.StatusOK {
					select {
					case errCh <- fmt.Errorf("worker %d request %d status=%d body=%s", worker, i, resp.Code, resp.Body.String()):
					default:
					}
					return
				}
			}
		}(worker)
	}
	for i := 2; i <= 8; i++ {
		next := base
		if err := mergeACRuntimeConfig(&next, payloadForRevision(fmt.Sprintf("rev-%d", i))); err != nil {
			t.Fatalf("mergeACRuntimeConfig next: %v", err)
		}
		if err := manager.applyRefreshSnapshot(next); err != nil {
			t.Fatalf("applyRefreshSnapshot rev-%d: %v", i, err)
		}
	}
	wg.Wait()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
	if manager.gateway == gateway {
		t.Fatal("changed config_revision should rebuild and swap the gateway")
	}
}

func TestA2AGatewayRuntimeHealthReportsACManagedConfig(t *testing.T) {
	tmp := t.TempDir()
	expiresAt := time.Now().Add(time.Hour).Format(time.RFC3339)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.11"})
	}))
	defer registry.Close()
	acServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v1/a2a/gateway/config/gw-test" {
			t.Fatalf("unexpected AC request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gateway_id":              "gw-test",
			"gateway_identity":        "did:aw:gateway",
			"gateway_identity_status": "active",
			"config_revision":         "gw-test:42",
			"expires_at":              expiresAt,
			"routes": []map[string]any{{
				"route_id":      "r_personal",
				"host":          "a2a.aweb.ai",
				"address":       "a2a.aweb.ai/personal",
				"mode":          "mail",
				"root_behavior": "default_for_host",
				"auth":          map[string]any{"mode": "none"},
				"limits": map[string]any{
					"task_ttl_seconds":         3600,
					"response_timeout_seconds": 30,
				},
				"card": map[string]any{
					"name":                 "Personal",
					"description":          "Personal agent",
					"provider":             map[string]any{"organization": "aweb", "url": "https://aweb.ai"},
					"default_input_modes":  []string{"text/plain"},
					"default_output_modes": []string{"text/plain"},
					"skills":               []map[string]any{{"id": "personal", "name": "Personal", "description": "Personal task"}},
				},
			}},
		})
	}))
	defer acServer.Close()

	cfgPath := filepath.Join(tmp, "a2a-gw-ac-health.yaml")
	writeACConfig(t, cfgPath, registry.URL, acServer.URL, "gw-test", "test-token")
	cfg := mustLoadConfig(t, cfgPath)
	if err := applyACRuntimeConfig(&cfg); err != nil {
		t.Fatalf("applyACRuntimeConfig: %v", err)
	}
	gateway, err := buildGateway(cfg)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}

	resp := httptest.NewRecorder()
	runtimeHandler(gateway, cfg).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/health", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", resp.Code, resp.Body.String())
	}
	var health map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	acConfig := health["ac_config"].(map[string]any)
	if acConfig["enabled"] != true || acConfig["gateway_id"] != "gw-test" || acConfig["config_revision"] != "gw-test:42" || acConfig["expired"] != false || acConfig["routes"].(float64) != 1 {
		t.Fatalf("unexpected ac_config health: %#v", acConfig)
	}
	gatewayIdentity := health["gateway_identity"].(map[string]any)
	if gatewayIdentity["identity"] != "did:aw:gateway" || gatewayIdentity["status"] != "active" || gatewayIdentity["usable"] != true {
		t.Fatalf("unexpected gateway_identity health: %#v", gatewayIdentity)
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

func TestA2AGatewayRuntimeHealthReportsBuildAndRegistry(t *testing.T) {
	oldVersion, oldReleaseTag, oldCommit, oldDate := version, releaseTag, commit, date
	version = "1.26.9"
	releaseTag = "a2a-gw-v1.26.9"
	commit = "abc123"
	date = "2026-06-08T00:00:00Z"
	defer func() {
		version, releaseTag, commit, date = oldVersion, oldReleaseTag, oldCommit, oldDate
	}()

	tmp := t.TempDir()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.11"})
	}))
	defer registry.Close()
	writeGatewayWorkspace(t, tmp, "http://aweb.invalid")
	cfgPath := filepath.Join(tmp, "a2a-gw.yaml")
	writeConfig(t, cfgPath, tmp, registry.URL)
	gateway, err := buildGateway(mustLoadConfig(t, cfgPath))
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}

	resp := httptest.NewRecorder()
	runtimeHandler(gateway, mustLoadConfig(t, cfgPath)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/health", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", resp.Code, resp.Body.String())
	}
	var health map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "healthy" || health["aweb_version"] != "1.26.9" || health["awid_service_version"] != ">=0.5.11" {
		t.Fatalf("unexpected health payload: %#v", health)
	}
	build := health["build"].(map[string]any)
	if build["release_tag"] != "a2a-gw-v1.26.9" || build["git_sha"] != "abc123" {
		t.Fatalf("unexpected build payload: %#v", build)
	}
	awidRegistry := health["awid_registry"].(map[string]any)
	if awidRegistry["reachable"] != true || awidRegistry["compatible"] != true || awidRegistry["version"] != "0.5.11" || awidRegistry["minimum_version"] != "0.5.11" {
		t.Fatalf("unexpected registry payload: %#v", awidRegistry)
	}
}

func TestA2AGatewayRuntimeHealthRejectsOldRegistryVersion(t *testing.T) {
	tmp := t.TempDir()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.10"})
	}))
	defer registry.Close()
	writeGatewayWorkspace(t, tmp, "http://aweb.invalid")
	cfgPath := filepath.Join(tmp, "a2a-gw.yaml")
	writeConfig(t, cfgPath, tmp, registry.URL)
	gateway, err := buildGateway(mustLoadConfig(t, cfgPath))
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}

	resp := httptest.NewRecorder()
	runtimeHandler(gateway, mustLoadConfig(t, cfgPath)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/health", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status=%d body=%s", resp.Code, resp.Body.String())
	}
	var health map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "unhealthy" {
		t.Fatalf("unexpected health payload: %#v", health)
	}
	awidRegistry := health["awid_registry"].(map[string]any)
	if awidRegistry["reachable"] != true || awidRegistry["compatible"] != false || awidRegistry["version"] != "0.5.10" || awidRegistry["status"] != "version_below_minimum" {
		t.Fatalf("unexpected registry payload: %#v", awidRegistry)
	}
}

func TestA2AGatewayRuntimeHealthRejectsRegistryWithoutVersion(t *testing.T) {
	tmp := t.TempDir()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy"})
	}))
	defer registry.Close()
	writeGatewayWorkspace(t, tmp, "http://aweb.invalid")
	cfgPath := filepath.Join(tmp, "a2a-gw.yaml")
	writeConfig(t, cfgPath, tmp, registry.URL)
	gateway, err := buildGateway(mustLoadConfig(t, cfgPath))
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}

	resp := httptest.NewRecorder()
	runtimeHandler(gateway, mustLoadConfig(t, cfgPath)).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/health", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("health status=%d body=%s", resp.Code, resp.Body.String())
	}
	var health map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	awidRegistry := health["awid_registry"].(map[string]any)
	if awidRegistry["reachable"] != true || awidRegistry["compatible"] != false || awidRegistry["status"] != "missing_version" {
		t.Fatalf("unexpected registry payload: %#v", awidRegistry)
	}
}

func TestA2AGatewayVersionAtLeast(t *testing.T) {
	tests := []struct {
		got     string
		minimum string
		want    bool
	}{
		{got: "0.5.11", minimum: "0.5.11", want: true},
		{got: "0.5.12", minimum: "0.5.11", want: true},
		{got: "0.6.0", minimum: "0.5.11", want: true},
		{got: "v0.5.11", minimum: "0.5.11", want: true},
		{got: "0.5.11+build", minimum: "0.5.11", want: true},
		{got: "0.5.10", minimum: "0.5.11", want: false},
		{got: "0.5", minimum: "0.5.1", want: false},
		{got: "bad", minimum: "0.5.11", want: false},
		{got: "0..11", minimum: "0.5.11", want: false},
	}
	for _, tt := range tests {
		if got := versionAtLeast(tt.got, tt.minimum); got != tt.want {
			t.Fatalf("versionAtLeast(%q, %q)=%v, want %v", tt.got, tt.minimum, got, tt.want)
		}
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

func writeACConfig(t *testing.T, path, registryURL, acBaseURL, gatewayID, token string) {
	t.Helper()
	data := fmt.Sprintf(`
registry_url: %q
poll_interval: "10ms"
poll_timeout: "10ms"
require_verified_replies: false
allow_unverified_local_reply: true
ac_config:
  base_url: %q
  gateway_id: %q
  bearer_token: %q
`, registryURL, acBaseURL, gatewayID, token)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
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
