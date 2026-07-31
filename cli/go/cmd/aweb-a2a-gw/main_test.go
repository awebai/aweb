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
	"github.com/awebai/aw/a2agw"
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
		case "/v1/messages/conversations/conv-1":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
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

func TestA2AGatewayBuildsFromManagedRuntimeConfig(t *testing.T) {
	tmp := t.TempDir()
	var posted map[string]any
	var pollMu sync.Mutex
	var pollPath string

	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/runtime/config/gw-test":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"gateway_id":              "gw-test",
				"gateway_identity":        "did:aw:gateway",
				"gateway_identity_status": "active",
				"config_revision":         "rev-1",
				"expires_at":              time.Now().Add(time.Hour).Format(time.RFC3339),
				"provider_extension":      map[string]any{"ignored": true},
				"routes": []map[string]any{{
					"provider_extension": map[string]any{"ignored": true},
					"route_id":           "r_personal",
					"host":               "a2a.aweb.ai",
					"address":            "a2a.aweb.ai/personal",
					"mode":               "mail",
					"disabled":           false,
					"root_behavior":      "default_for_host",
					"verification_tier":  "unsigned",
					"auth":               map[string]any{"mode": "none"},
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
		case "/runtime/bridge/gw-test/messages":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-1", ConversationID: "conv-1", Status: "sent"})
		case "/runtime/bridge/gw-test/conversations/conv-1":
			pollMu.Lock()
			pollPath = r.URL.String()
			pollMu.Unlock()
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		default:
			t.Fatalf("unexpected managed request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer managedServer.Close()
	cfgPath := filepath.Join(tmp, "a2a-gw-managed.yaml")
	writeManagedConfig(t, cfgPath, "http://registry.invalid", managedServer.URL, "gw-test", "test-token")
	cfg := mustLoadConfig(t, cfgPath)
	if err := applyManagedRuntimeConfig(&cfg); err != nil {
		t.Fatalf("applyManagedRuntimeConfig: %v", err)
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

	transport, err := managedBridgeTransportFromConfig(cfg)
	if err != nil {
		t.Fatalf("managedBridgeTransportFromConfig: %v", err)
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

func TestA2AGatewayManagedRuntimeDisabledRouteDoesNotBrickGateway(t *testing.T) {
	cfg := fileConfig{
		Host:          "a2a.aweb.ai",
		ManagedConfig: managedConfigForTest("http://ac.invalid", "gw-test", "test-token"),
	}
	if err := mergeManagedRuntimeConfig(&cfg, managedRuntimeConfigPayload{
		GatewayID:             "gw-test",
		GatewayIdentity:       "did:aw:gateway",
		GatewayIdentityStatus: "active",
		ConfigRevision:        "rev-static-auth",
		ExpiresAt:             time.Now().Add(time.Hour).Format(time.RFC3339),
		Routes: []managedRuntimeRoute{{
			RouteID:      "r_private",
			Host:         "a2a.aweb.ai",
			Address:      "a2a.aweb.ai/private",
			Mode:         "mail",
			RootBehavior: "default_for_host",
			Disabled:     true,
			Auth:         managedRuntimeAuth{Mode: "none"},
			Limits: managedRuntimeLimits{
				TaskTTLSeconds:         3600,
				ResponseTimeoutSeconds: 30,
			},
			Card: managedRuntimeCard{
				Name:               "Private",
				Description:        "Private agent",
				Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []skillYAML{{ID: "private", Name: "Private", Description: "Private task"}},
			},
		}},
	}); err != nil {
		t.Fatalf("mergeManagedRuntimeConfig: %v", err)
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

func TestManagedConfigValidationReportsMissingFieldsDeterministically(t *testing.T) {
	cfg := managedConfig{ConfigURL: "https://control.example/config", BearerToken: "token"}
	for i := 0; i < 20; i++ {
		err := validateManagedConfig(cfg)
		if err == nil || err.Error() != "managed_config.bridge_url is required" {
			t.Fatalf("validation %d error=%v", i, err)
		}
	}
}

func TestManagedRuntimeConfigRejectsMissingAndMismatchedTopLevelFields(t *testing.T) {
	valid := map[string]any{
		"gateway_id":              "gw-test",
		"gateway_identity":        "did:aw:gateway",
		"gateway_identity_status": "active",
		"config_revision":         "rev-1",
		"expires_at":              time.Now().Add(time.Hour).Format(time.RFC3339),
		"routes":                  []any{},
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "missing gateway id", mutate: func(v map[string]any) { delete(v, "gateway_id") }, want: "gateway_id is required"},
		{name: "mismatched gateway id", mutate: func(v map[string]any) { v["gateway_id"] = "other" }, want: "does not match"},
		{name: "missing identity", mutate: func(v map[string]any) { delete(v, "gateway_identity") }, want: "gateway_identity is required"},
		{name: "missing identity status", mutate: func(v map[string]any) { delete(v, "gateway_identity_status") }, want: "gateway_identity_status is required"},
		{name: "missing revision", mutate: func(v map[string]any) { delete(v, "config_revision") }, want: "config_revision is required"},
		{name: "missing expiry", mutate: func(v map[string]any) { delete(v, "expires_at") }, want: "expires_at is required"},
		{name: "missing routes", mutate: func(v map[string]any) { delete(v, "routes") }, want: "routes is required"},
		{name: "null routes", mutate: func(v map[string]any) { v["routes"] = nil }, want: "routes is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := make(map[string]any, len(valid))
			for key, item := range valid {
				value[key] = item
			}
			tt.mutate(value)
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var payload managedRuntimeConfigPayload
			if err := json.Unmarshal(data, &payload); err != nil {
				t.Fatal(err)
			}
			cfg := fileConfig{ManagedConfig: managedConfig{GatewayID: "gw-test"}}
			err = mergeManagedRuntimeConfig(&cfg, payload)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("mergeManagedRuntimeConfig error=%v, want %q", err, tt.want)
			}
		})
	}
}

func TestManagedConfigURLsMustBeAbsoluteHTTP(t *testing.T) {
	tests := []struct {
		name      string
		configURL string
		bridgeURL string
		wantError bool
	}{
		{name: "valid http", configURL: "http://control.example/config", bridgeURL: "http://bridge.example/a2a"},
		{name: "valid https", configURL: "https://control.example/config", bridgeURL: "https://bridge.example/a2a"},
		{name: "malformed config", configURL: ":// not-a-url", bridgeURL: "https://bridge.example/a2a", wantError: true},
		{name: "relative config", configURL: "/config", bridgeURL: "https://bridge.example/a2a", wantError: true},
		{name: "missing config host", configURL: "https:///config", bridgeURL: "https://bridge.example/a2a", wantError: true},
		{name: "port-only config authority", configURL: "http://:8080/config", bridgeURL: "https://bridge.example/a2a", wantError: true},
		{name: "malformed bridge", configURL: "https://control.example/config", bridgeURL: ":// not-a-url", wantError: true},
		{name: "relative bridge", configURL: "https://control.example/config", bridgeURL: "/bridge", wantError: true},
		{name: "missing bridge host", configURL: "https://control.example/config", bridgeURL: "https:///bridge", wantError: true},
		{name: "port-only bridge authority", configURL: "https://control.example/config", bridgeURL: "http://:8080/bridge", wantError: true},
	}
	for _, tt := range tests {
		t.Run("yaml "+tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.yaml")
			data := fmt.Sprintf("managed_config:\n  config_url: %q\n  bridge_url: %q\n  gateway_id: gw-test\n  bearer_token: token\n", tt.configURL, tt.bridgeURL)
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadFileConfig(path)
			if (err != nil) != tt.wantError {
				t.Fatalf("loadFileConfig error=%v wantError=%v", err, tt.wantError)
			}
		})
		t.Run("environment "+tt.name, func(t *testing.T) {
			t.Setenv("AWEB_A2A_GW_HOST", "gateway.example")
			t.Setenv("AWEB_A2A_GW_REGISTRY_URL", "https://registry.example")
			t.Setenv("AWEB_A2A_GW_MANAGED_CONFIG_URL", tt.configURL)
			t.Setenv("AWEB_A2A_GW_MANAGED_BRIDGE_URL", tt.bridgeURL)
			t.Setenv("AWEB_A2A_GW_MANAGED_GATEWAY_ID", "gw-test")
			t.Setenv("AWEB_A2A_GW_MANAGED_BEARER_TOKEN", "token")
			_, _, err := managedEnvConfig()
			if (err != nil) != tt.wantError {
				t.Fatalf("managedEnvConfig error=%v wantError=%v", err, tt.wantError)
			}
		})
	}
}

func TestManagedRuntimeConfigRoutesJSONShape(t *testing.T) {
	prefix := `{"gateway_id":"gw-test","gateway_identity":"did:aw:gateway","gateway_identity_status":"active","config_revision":"rev-1","expires_at":"2099-01-01T00:00:00Z","routes":`
	tests := []struct {
		name       string
		routesJSON string
		decodeFail bool
		mergeFail  bool
		wantRoutes int
	}{
		{name: "plain null", routesJSON: `null`, mergeFail: true},
		{name: "whitespace null", routesJSON: " \n null \t", mergeFail: true},
		{name: "non array", routesJSON: `{}`, decodeFail: true},
		{name: "empty array", routesJSON: `[]`, wantRoutes: 0},
		{name: "populated array", routesJSON: `[{"route_id":"r-1","address":"gateway.example/agent","mode":"mail"}]`, wantRoutes: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload managedRuntimeConfigPayload
			err := json.Unmarshal([]byte(prefix+tt.routesJSON+`}`), &payload)
			if tt.decodeFail {
				if err == nil {
					t.Fatal("expected routes JSON decode failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			cfg := fileConfig{ManagedConfig: managedConfig{GatewayID: "gw-test"}}
			err = mergeManagedRuntimeConfig(&cfg, payload)
			if tt.mergeFail {
				if err == nil || !strings.Contains(err.Error(), "routes is required") {
					t.Fatalf("merge error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("merge: %v", err)
			}
			if len(cfg.Routes) != tt.wantRoutes {
				t.Fatalf("routes=%d want %d", len(cfg.Routes), tt.wantRoutes)
			}
		})
	}
}

func TestManagedRuntimeConfigRejectsUnusableRouteBinding(t *testing.T) {
	validRoute := managedRuntimeRoute{RouteID: "r-1", Address: "gateway.example/agent", Mode: "mail"}
	tests := []struct {
		name   string
		mutate func(*managedRuntimeRoute)
		want   string
	}{
		{name: "missing route id", mutate: func(route *managedRuntimeRoute) { route.RouteID = "" }, want: "route_id is required"},
		{name: "missing address", mutate: func(route *managedRuntimeRoute) { route.Address = "" }, want: "address is required"},
		{name: "missing mode", mutate: func(route *managedRuntimeRoute) { route.Mode = "" }, want: "mode must be mail"},
		{name: "unsupported mode", mutate: func(route *managedRuntimeRoute) { route.Mode = "webhook" }, want: "mode must be mail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := validRoute
			tt.mutate(&route)
			payload := managedRuntimeConfigPayload{
				GatewayID: "gw-test", GatewayIdentity: "did:aw:gateway", GatewayIdentityStatus: "active",
				ConfigRevision: "rev-1", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Routes: []managedRuntimeRoute{route},
			}
			cfg := fileConfig{ManagedConfig: managedConfig{GatewayID: "gw-test"}}
			err := mergeManagedRuntimeConfig(&cfg, payload)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("merge error=%v want %q", err, tt.want)
			}
		})
	}
}

func TestManagedRuntimeConfigRejectsAmbiguousRouteTopology(t *testing.T) {
	baseRoute := managedRuntimeRoute{RouteID: "r-one", Address: "gateway.example/one", Mode: "mail", RootBehavior: "default_for_host"}
	tests := []struct {
		name   string
		routes []managedRuntimeRoute
		want   string
	}{
		{name: "duplicate normalized address", routes: []managedRuntimeRoute{baseRoute, {RouteID: "r-two", Address: " GATEWAY.EXAMPLE/ONE ", Mode: "mail"}}, want: "duplicates route"},
		{name: "multiple defaults", routes: []managedRuntimeRoute{baseRoute, {RouteID: "r-two", Address: "gateway.example/two", Mode: "mail", RootBehavior: "default_for_host"}}, want: "multiple default_for_host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := managedRuntimeConfigPayload{
				GatewayID: "gw-test", GatewayIdentity: "did:aw:gateway", GatewayIdentityStatus: "active",
				ConfigRevision: "rev-1", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Routes: tt.routes,
			}
			cfg := fileConfig{ManagedConfig: managedConfig{GatewayID: "gw-test"}}
			err := mergeManagedRuntimeConfig(&cfg, payload)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("merge error=%v want %q", err, tt.want)
			}
		})
	}
}

func TestManagedBridgePreservesRouteAddressBinding(t *testing.T) {
	var gotRouteID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		gotRouteID, _ = payload["route_id"].(string)
		_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "m-1", ConversationID: "c-1", Status: "sent"})
	}))
	defer server.Close()
	cfg := fileConfig{
		ManagedConfig: managedConfig{BridgeURL: server.URL, GatewayID: "gw-test", BearerToken: "token"},
		Routes:        []routeConfig{{RouteID: "r-one", Address: "gateway.example/one"}, {RouteID: "r-two", Address: "gateway.example/two"}},
	}
	transport, err := managedBridgeTransportFromConfig(cfg)
	if err != nil {
		t.Fatalf("managedBridgeTransportFromConfig: %v", err)
	}
	if _, err := transport.SendMessage(context.Background(), &awid.SendMessageRequest{ToAddress: "gateway.example/one", Body: "hello"}); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if gotRouteID != "r-one" {
		t.Fatalf("provider route_id=%q want r-one", gotRouteID)
	}
}

func TestManagedBridgeCapturedOldGenerationFailsClosedAfterRouteRevision(t *testing.T) {
	for _, identityAuth := range []bool{false, true} {
		t.Run(fmt.Sprintf("identity_auth_%t", identityAuth), func(t *testing.T) {
			var mu sync.Mutex
			var emittedRoutes []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				emittedRoutes = append(emittedRoutes, payload["route_id"].(string))
				mu.Unlock()
				_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "m-1", ConversationID: "c-1", Status: "sent"})
			}))
			defer server.Close()

			oldConfig := fileConfig{
				ManagedConfig: managedConfig{BridgeURL: server.URL, GatewayID: "gw-test", BearerToken: "token"},
				Routes:        []routeConfig{{RouteID: "old-route", Address: "gateway.example/agent"}},
			}
			transport, err := managedBridgeTransportFromConfig(oldConfig)
			if err != nil {
				t.Fatal(err)
			}
			bridge, err := a2agw.NewMailBridge(a2agw.MailBridgeConfig{Client: transport, UseIdentityAuth: identityAuth})
			if err != nil {
				t.Fatal(err)
			}
			capturedSend := a2agw.BridgeTask{RouteID: "old-route", Address: "gateway.example/agent", TaskID: "task-old", ContextID: "ctx-old", Text: "hello"}
			if err := bridge.SendTask(context.Background(), capturedSend); err != nil {
				t.Fatalf("old generation initial send: %v", err)
			}

			newConfig := oldConfig
			newConfig.Routes = []routeConfig{{RouteID: "new-route", Address: "gateway.example/agent"}}
			transport.UpdateFromConfig(newConfig)
			if err := bridge.SendTask(context.Background(), capturedSend); err == nil || !strings.Contains(err.Error(), "route binding changed") {
				t.Fatalf("captured old send error=%v", err)
			}
			capturedCancel := a2agw.BridgeCancel{RouteID: "old-route", Address: "gateway.example/agent", TaskID: "task-old", ContextID: "ctx-old"}
			if err := bridge.CancelTask(context.Background(), capturedCancel); err == nil || !strings.Contains(err.Error(), "route binding changed") {
				t.Fatalf("captured old cancel error=%v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(emittedRoutes) != 1 || emittedRoutes[0] != "old-route" {
				t.Fatalf("provider emissions=%v; old captured operations must never emit as new-route", emittedRoutes)
			}
		})
	}
}

func TestManagedGatewayCapturedGenerationFailsClosedAcrossRefresh(t *testing.T) {
	var mu sync.Mutex
	var emittedRoutes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: nil})
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		emittedRoutes = append(emittedRoutes, payload["route_id"].(string))
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "m-1", ConversationID: "c-1", Status: "sent"})
	}))
	defer server.Close()

	payloadFor := func(revision, routeID string) managedRuntimeConfigPayload {
		return managedRuntimeConfigPayload{
			GatewayID: "gw-test", GatewayIdentity: "did:aw:gateway", GatewayIdentityStatus: "active",
			ConfigRevision: revision, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
			Routes: []managedRuntimeRoute{{
				RouteID: routeID, Host: "gateway.example", Address: "gateway.example/agent", Mode: "mail", RootBehavior: "default_for_host",
				Auth:   managedRuntimeAuth{Mode: "none"},
				Limits: managedRuntimeLimits{TaskTTLSeconds: 3600, ResponseTimeoutSeconds: 1},
				Card:   managedRuntimeCard{Name: "Agent", Description: "Agent", Provider: providerYAML{Organization: "Example", URL: "https://example.com"}, DefaultInputModes: []string{"text/plain"}, DefaultOutputModes: []string{"text/plain"}, Skills: []skillYAML{{ID: "agent", Name: "Agent", Description: "Agent"}}},
			}},
		}
	}
	base := fileConfig{Host: "gateway.example", ManagedConfig: managedConfigForTest(server.URL, "gw-test", "token")}
	oldConfig := base
	if err := mergeManagedRuntimeConfig(&oldConfig, payloadFor("old-revision", "old-route")); err != nil {
		t.Fatal(err)
	}
	runtime, oldGateway, err := buildGatewayWithRuntime(oldConfig, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager := &managedGateway{cfg: oldConfig, gateway: oldGateway, runtime: runtime}

	call := func(gateway *a2agw.Gateway, path, body string, headers map[string]string) map[string]any {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-A2A-Caller-ID", "captured-caller")
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		resp := httptest.NewRecorder()
		gateway.ServeHTTP(resp, req)
		var decoded map[string]any
		if err := json.Unmarshal(resp.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("decode RPC response status=%d body=%s: %v", resp.Code, resp.Body.String(), err)
		}
		return decoded
	}
	sendBody := `{"jsonrpc":"2.0","id":"send-old","method":"SendMessage","params":{"message":{"messageId":"message-old","contextId":"context-old","role":"ROLE_USER","parts":[{"text":"hello","mediaType":"text/plain"}]},"configuration":{"returnImmediately":true}}}`
	initial := call(oldGateway, "/a2a/agents/old-route/rpc", sendBody, nil)
	result, ok := initial["result"].(map[string]any)
	if !ok {
		t.Fatalf("initial send failed: %#v", initial)
	}
	task, _ := result["task"].(map[string]any)
	taskID, _ := task["id"].(string)
	metadata, _ := task["metadata"].(map[string]any)
	token, _ := metadata["task_bearer_token"].(string)
	if taskID == "" || token == "" {
		t.Fatalf("initial task missing id/token: %#v", initial)
	}

	newConfig := base
	if err := mergeManagedRuntimeConfig(&newConfig, payloadFor("new-revision", "new-route")); err != nil {
		t.Fatal(err)
	}
	if err := manager.applyRefreshSnapshot(newConfig); err != nil {
		t.Fatal(err)
	}
	if manager.gateway == oldGateway || manager.runtime != runtime {
		t.Fatal("refresh must swap gateway generation while preserving shared runtime")
	}

	getBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":"get-old","method":"GetTask","params":{"id":%q}}`, taskID)
	preserved := call(oldGateway, "/a2a/agents/old-route/rpc", getBody, map[string]string{"X-A2A-Task-Token": token})
	if preserved["result"] == nil {
		t.Fatalf("old task state was not preserved: %#v", preserved)
	}
	postRefreshSend := call(oldGateway, "/a2a/agents/old-route/rpc", strings.Replace(sendBody, "message-old", "message-after-refresh", 1), nil)
	if postRefreshSend["error"] == nil {
		t.Fatalf("captured old-generation send did not fail closed: %#v", postRefreshSend)
	}
	cancelBody := fmt.Sprintf(`{"jsonrpc":"2.0","id":"cancel-old","method":"CancelTask","params":{"id":%q}}`, taskID)
	postRefreshCancel := call(oldGateway, "/a2a/agents/old-route/rpc", cancelBody, map[string]string{"X-A2A-Task-Token": token})
	if postRefreshCancel["result"] == nil {
		t.Fatalf("captured old task state was not retained for cancel: %#v", postRefreshCancel)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(emittedRoutes) != 1 || emittedRoutes[0] != "old-route" {
		t.Fatalf("provider emissions=%v; captured old generation must never emit as new-route", emittedRoutes)
	}
}

func TestA2AGatewayRejectsUnknownNestedAndSecondDocumentYAML(t *testing.T) {
	removedPrivateKey := "a" + "c_config"
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "removed private key", data: removedPrivateKey + ": {}\n", want: "field " + removedPrivateKey},
		{name: "unknown top level", data: "manged_config: {}\n", want: "field manged_config"},
		{name: "unknown nested", data: "managed_config:\n  config_urll: https://control.example/config\n", want: "field config_urll"},
		{name: "second document", data: "host: gateway.example\n---\nhost: other.example\n", want: "exactly one YAML document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.yaml")
			if err := os.WriteFile(path, []byte(tt.data), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadFileConfig(path)
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("loadFileConfig error=%v, want config path and %q", err, tt.want)
			}
		})
	}
}

func TestA2AGatewayLoadsExplicitManagedEnvWhenConfigFileMissing(t *testing.T) {
	t.Setenv("AWEB_A2A_GW_MANAGED_BEARER_TOKEN", "test-token")
	t.Setenv("AWEB_A2A_GW_REGISTRY_URL", "http://registry.invalid")
	t.Setenv("AWEB_A2A_GW_HOST", "gateway.example")
	t.Setenv("AWEB_A2A_GW_MANAGED_GATEWAY_ID", "gw-test")

	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/runtime/config/gw-test" {
			t.Fatalf("unexpected managed request %s %s", r.Method, r.URL.Path)
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
	defer managedServer.Close()
	t.Setenv("AWEB_A2A_GW_MANAGED_CONFIG_URL", managedServer.URL+"/runtime/config/gw-test")
	t.Setenv("AWEB_A2A_GW_MANAGED_BRIDGE_URL", managedServer.URL+"/runtime/bridge")

	cfg, err := loadConfigOrHostedEnv(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("loadConfigOrHostedEnv: %v", err)
	}
	if cfg.ManagedConfig.ConfigURL != managedServer.URL+"/runtime/config/gw-test" || cfg.ManagedConfig.GatewayID != "gw-test" || cfg.RegistryURL != "http://registry.invalid" {
		t.Fatalf("unexpected env config: %#v", cfg)
	}
	if err := applyManagedRuntimeConfig(&cfg); err != nil {
		t.Fatalf("applyManagedRuntimeConfig: %v", err)
	}
	if cfg.ManagedRuntime.ConfigRevision != "rev-env" || len(cfg.Routes) != 1 {
		t.Fatalf("unexpected runtime config: %#v", cfg)
	}
}

func TestA2AGatewayMissingConfigWithoutManagedEnvFailsActionably(t *testing.T) {
	t.Setenv("AWEB_A2A_GW_MANAGED_CONFIG_URL", "")
	_, err := loadConfigOrHostedEnv(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("expected missing config error")
	}
	for _, want := range []string{"no such file", "managed gateway environment"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err.Error(), want)
		}
	}
}

func TestA2AGatewayRejectsExpiredManagedRuntimeConfig(t *testing.T) {
	tmp := t.TempDir()
	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"gateway_id":              "gw-test",
			"gateway_identity":        "did:aw:gateway",
			"gateway_identity_status": "active",
			"config_revision":         "rev-expired",
			"expires_at":              time.Now().Add(-time.Minute).Format(time.RFC3339),
			"routes":                  []map[string]any{},
		})
	}))
	defer managedServer.Close()
	cfgPath := filepath.Join(tmp, "a2a-gw-managed.yaml")
	writeManagedConfig(t, cfgPath, "http://aweb.invalid", managedServer.URL, "gw-test", "test-token")
	cfg := mustLoadConfig(t, cfgPath)
	if err := applyManagedRuntimeConfig(&cfg); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("applyManagedRuntimeConfig err=%v, want expired", err)
	}
}

func TestA2AGatewayManagedStartsPendingWhenIdentityMissing(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.11"})
	}))
	defer registry.Close()
	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		http.Error(w, `{"detail":{"code":"gateway_identity_missing"}}`, http.StatusNotFound)
	}))
	defer managedServer.Close()
	cfg := fileConfig{
		Host:          "a2a.aweb.ai",
		RegistryURL:   registry.URL,
		ManagedConfig: managedConfigForTest(managedServer.URL, "a2a-gateway", "test-token"),
	}
	snapshot, err := buildManagedSnapshot(cfg, true)
	if err != nil {
		t.Fatalf("buildManagedSnapshot: %v", err)
	}
	if len(snapshot.cfg.Routes) != 0 || snapshot.cfg.ManagedRuntime.FetchStatus != "pending" {
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
	managedConfig := health["managed_config"].(map[string]any)
	if managedConfig["status"] != "pending" || managedConfig["routes"].(float64) != 0 {
		t.Fatalf("unexpected managed_config health: %#v", managedConfig)
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

func TestA2AGatewayManagedRejectsBadTokenAtStartup(t *testing.T) {
	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":{"code":"gateway_config_auth_invalid"}}`, http.StatusUnauthorized)
	}))
	defer managedServer.Close()
	cfg := fileConfig{
		Host:          "a2a.aweb.ai",
		RegistryURL:   "http://registry.invalid",
		ManagedConfig: managedConfigForTest(managedServer.URL, "a2a-gateway", "wrong-token"),
	}
	if _, err := buildManagedSnapshot(cfg, true); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("buildManagedSnapshot err=%v, want HTTP 401", err)
	}
}

func TestA2AGatewayManagedRefreshFailureKeepsLastGoodRoutes(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.11"})
	}))
	defer registry.Close()
	cfg := fileConfig{
		Host:          "a2a.aweb.ai",
		RegistryURL:   registry.URL,
		ManagedConfig: managedConfigForTest("http://ac.invalid", "a2a-gateway", "test-token"),
	}
	expiresAt := time.Now().Add(time.Hour).Format(time.RFC3339)
	if err := mergeManagedRuntimeConfig(&cfg, managedRuntimeConfigPayload{
		GatewayID:             "a2a-gateway",
		GatewayIdentity:       "did:aw:gateway",
		GatewayIdentityStatus: "active",
		ConfigRevision:        "rev-good",
		ExpiresAt:             expiresAt,
		Routes: []managedRuntimeRoute{{
			RouteID:      "r_personal",
			Host:         "a2a.aweb.ai",
			Address:      "a2a.aweb.ai/personal",
			Mode:         "mail",
			RootBehavior: "default_for_host",
			Auth:         managedRuntimeAuth{Mode: "none"},
			Limits: managedRuntimeLimits{
				TaskTTLSeconds:         3600,
				ResponseTimeoutSeconds: 30,
			},
			Card: managedRuntimeCard{
				Name:               "Personal",
				Description:        "Personal agent",
				Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []skillYAML{{ID: "personal", Name: "Personal", Description: "Personal task"}},
			},
		}},
	}); err != nil {
		t.Fatalf("mergeManagedRuntimeConfig: %v", err)
	}
	gateway, err := buildGateway(cfg)
	if err != nil {
		t.Fatalf("buildGateway: %v", err)
	}
	manager := &managedGateway{cfg: cfg, gateway: gateway}
	manager.markRefreshError(&managedRuntimeConfigFetchError{StatusCode: http.StatusInternalServerError, Message: "fetch managed runtime config: HTTP 500: down"})

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
	managedConfig := health["managed_config"].(map[string]any)
	if managedConfig["status"] != "stale" || managedConfig["config_revision"] != "rev-good" || managedConfig["routes"].(float64) != 1 {
		t.Fatalf("unexpected stale health: %#v", managedConfig)
	}
}

func TestA2AGatewayManagedRefreshExtendsAcceptWindowForStableRevision(t *testing.T) {
	var posted map[string]any
	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/runtime/bridge/a2a-gateway/messages":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-1", ConversationID: "conv-1", Status: "sent"})
		case "/runtime/bridge/a2a-gateway/conversations/conv-1":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		default:
			t.Fatalf("unexpected managed request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer managedServer.Close()

	cfg := fileConfig{
		Host:          "a2a.aweb.ai",
		ManagedConfig: managedConfigForTest(managedServer.URL, "a2a-gateway", "test-token"),
	}
	expiresAt := time.Now().Add(2 * time.Second).Format(time.RFC3339)
	payload := managedRuntimeConfigPayload{
		GatewayID:             "a2a-gateway",
		GatewayIdentity:       "did:aw:gateway",
		GatewayIdentityStatus: "active",
		ConfigRevision:        "rev-stable",
		ExpiresAt:             expiresAt,
		Routes: []managedRuntimeRoute{{
			RouteID:      "r_personal",
			Host:         "a2a.aweb.ai",
			Address:      "a2a.aweb.ai/personal",
			Mode:         "mail",
			RootBehavior: "default_for_host",
			Auth:         managedRuntimeAuth{Mode: "none"},
			Limits: managedRuntimeLimits{
				TaskTTLSeconds:         3600,
				ResponseTimeoutSeconds: 30,
			},
			Card: managedRuntimeCard{
				Name:               "Personal",
				Description:        "Personal agent",
				Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []skillYAML{{ID: "personal", Name: "Personal", Description: "Personal task"}},
			},
		}},
	}
	if err := mergeManagedRuntimeConfig(&cfg, payload); err != nil {
		t.Fatalf("mergeManagedRuntimeConfig: %v", err)
	}
	runtime, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildGatewayWithRuntime: %v", err)
	}
	manager := &managedGateway{cfg: cfg, gateway: gateway, runtime: runtime}
	time.Sleep(2500 * time.Millisecond)

	next := fileConfig{
		Host:          "a2a.aweb.ai",
		ManagedConfig: cfg.ManagedConfig,
	}
	payload.ExpiresAt = time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	if err := mergeManagedRuntimeConfig(&next, payload); err != nil {
		t.Fatalf("mergeManagedRuntimeConfig next: %v", err)
	}
	if err := manager.applyRefreshSnapshot(next); err != nil {
		t.Fatalf("applyRefreshSnapshot: %v", err)
	}
	if manager.gateway != gateway {
		t.Fatal("unchanged config_revision should extend accept window without rebuilding gateway")
	}
	if manager.cfg.ManagedRuntime.ExpiresAt != next.ManagedRuntime.ExpiresAt {
		t.Fatalf("expires_at not refreshed: got %q want %q", manager.cfg.ManagedRuntime.ExpiresAt, next.ManagedRuntime.ExpiresAt)
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

func TestA2AGatewayManagedRefreshSwapsUnderLoad(t *testing.T) {
	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/conversations/") {
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: nil})
			return
		}
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/messages") {
			http.Error(w, "unexpected managed request", http.StatusNotFound)
			t.Errorf("unexpected managed request %s %s", r.Method, r.URL.Path)
			return
		}
		_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-1", ConversationID: "conv-1", Status: "sent"})
	}))
	defer managedServer.Close()

	payloadForRevision := func(revision string) managedRuntimeConfigPayload {
		return managedRuntimeConfigPayload{
			GatewayID:             "a2a-gateway",
			GatewayIdentity:       "did:aw:gateway-" + revision,
			GatewayIdentityStatus: "active",
			ConfigRevision:        revision,
			ExpiresAt:             time.Now().Add(time.Hour).Format(time.RFC3339),
			Routes: []managedRuntimeRoute{{
				RouteID:      "r_personal",
				Host:         "a2a.aweb.ai",
				Address:      "a2a.aweb.ai/personal",
				Mode:         "mail",
				RootBehavior: "default_for_host",
				Auth:         managedRuntimeAuth{Mode: "none"},
				Limits: managedRuntimeLimits{
					TaskTTLSeconds:         3600,
					ResponseTimeoutSeconds: 30,
				},
				Card: managedRuntimeCard{
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
		Host:          "a2a.aweb.ai",
		ManagedConfig: managedConfigForTest(managedServer.URL, "a2a-gateway", "test-token"),
	}
	cfg := base
	if err := mergeManagedRuntimeConfig(&cfg, payloadForRevision("rev-1")); err != nil {
		t.Fatalf("mergeManagedRuntimeConfig: %v", err)
	}
	runtime, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildGatewayWithRuntime: %v", err)
	}
	manager := &managedGateway{cfg: cfg, gateway: gateway, runtime: runtime}

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
		if err := mergeManagedRuntimeConfig(&next, payloadForRevision(fmt.Sprintf("rev-%d", i))); err != nil {
			t.Fatalf("mergeManagedRuntimeConfig next: %v", err)
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

func TestA2AGatewayRuntimeHealthReportsManagedConfig(t *testing.T) {
	tmp := t.TempDir()
	expiresAt := time.Now().Add(time.Hour).Format(time.RFC3339)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "healthy", "version": "0.5.11"})
	}))
	defer registry.Close()
	managedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/runtime/config/gw-test" {
			t.Fatalf("unexpected managed request %s %s", r.Method, r.URL.Path)
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
	defer managedServer.Close()

	cfgPath := filepath.Join(tmp, "a2a-gw-managed-health.yaml")
	writeManagedConfig(t, cfgPath, registry.URL, managedServer.URL, "gw-test", "test-token")
	cfg := mustLoadConfig(t, cfgPath)
	if err := applyManagedRuntimeConfig(&cfg); err != nil {
		t.Fatalf("applyManagedRuntimeConfig: %v", err)
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
	managedConfig := health["managed_config"].(map[string]any)
	if managedConfig["enabled"] != true || managedConfig["gateway_id"] != "gw-test" || managedConfig["config_revision"] != "gw-test:42" || managedConfig["expired"] != false || managedConfig["routes"].(float64) != 1 {
		t.Fatalf("unexpected managed_config health: %#v", managedConfig)
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

func TestGatewayBaseURLPrefersWorkspaceOverTeamMembership(t *testing.T) {
	tests := []struct {
		name         string
		workspaceURL string
		teamURL      string
		want         string
	}{
		{
			name:         "workspace top-level wins when both present",
			workspaceURL: "https://workspace.example",
			teamURL:      "https://teams.example",
			want:         "https://workspace.example",
		},
		{
			name:         "teams membership is fallback when workspace empty",
			workspaceURL: "",
			teamURL:      "https://teams.example",
			want:         "https://teams.example",
		},
		{
			name:         "empty when neither present",
			workspaceURL: "",
			teamURL:      "",
			want:         "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ws := &awconfig.WorktreeWorkspace{AwebURL: tt.workspaceURL}
			membership := &awconfig.TeamMembership{AwebURL: tt.teamURL}
			if got := gatewayBaseURL(ws, membership); got != tt.want {
				t.Fatalf("gatewayBaseURL()=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestGatewayWorkspaceRootIgnoresAwIdentityHome(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gatewayRoot := filepath.Join(root, "gateway")
	externalIdentityHome := filepath.Join(root, "aw-principal")
	if err := os.MkdirAll(externalIdentityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(awconfig.IdentityHomeEnv, externalIdentityHome)
	writeGatewayWorkspace(t, gatewayRoot, "https://gateway.example")
	for _, path := range []string{
		filepath.Join(gatewayRoot, ".aw", "workspace.yaml"),
		filepath.Join(gatewayRoot, ".aw", "teams.yaml"),
		filepath.Join(gatewayRoot, ".aw", "signing.key"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("gateway root missing %s: %v", path, err)
		}
	}
	entries, err := os.ReadDir(externalIdentityHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("gateway contaminated aw principal root: %v", entries)
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

func managedConfigForTest(controlURL, gatewayID, token string) managedConfig {
	return managedConfig{
		ConfigURL:   controlURL + "/runtime/config/" + gatewayID,
		BridgeURL:   controlURL + "/runtime/bridge",
		GatewayID:   gatewayID,
		BearerToken: token,
	}
}

func writeManagedConfig(t *testing.T, path, registryURL, controlURL, gatewayID, token string) {
	t.Helper()
	data := fmt.Sprintf(`
registry_url: %q
poll_interval: "10ms"
poll_timeout: "10ms"
require_verified_replies: false
allow_unverified_local_reply: true
managed_config:
  config_url: %q
  bridge_url: %q
  gateway_id: %q
  bearer_token: %q
`, registryURL, controlURL+"/runtime/config/"+gatewayID, controlURL+"/runtime/bridge", gatewayID, token)
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

// aweb-aaxi: /health publishes git_sha, and that SHA resolves in a different repository
// depending on which artifact is running - goreleaser builds this binary in the derived
// aw repository, while the gateway image is built from aweb. One binary name, two builds,
// two different correct answers, so the payload must say which one it means.
func TestA2AGatewayRuntimeHealthNamesTheRepositoryItsGitSHAResolvesIn(t *testing.T) {
	oldVersion, oldReleaseTag, oldCommit, oldCommitRepo, oldDate := version, releaseTag, commit, commitRepo, date
	version = "1.26.9"
	releaseTag = "a2a-gw-v1.26.9"
	commit = "abc123"
	// Deliberately not either real answer. A handler that ignored commitRepo and named a
	// plausible repository would satisfy an assertion written against the value it was
	// likely to invent, so the fixture uses one nothing would arrive at on its own. The
	// same constant sets and asserts it, so the two cannot drift apart.
	const stampedRepo = "github.com/awebai/only-the-stamp-produces-this"
	commitRepo = stampedRepo
	date = "2026-06-08T00:00:00Z"
	defer func() {
		version, releaseTag, commit, commitRepo, date = oldVersion, oldReleaseTag, oldCommit, oldCommitRepo, oldDate
	}()

	tmp := t.TempDir()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	var health map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	build := health["build"].(map[string]any)
	if build["git_sha_repo"] != stampedRepo {
		t.Fatalf("health does not say where git_sha resolves, so a reader cannot reach the\n"+
			"source from a running gateway: %#v", build)
	}
}

// The other direction: a build not told its origin must not invent one. Unstamped, the
// field is omitted rather than reporting an empty or guessed repository.
//
// This goes through runtimeHandler for the same reason its sibling does. Marshalling a
// runtimeBuild the test builds itself asserts only that omitempty is on the struct tag,
// which was never the risk - a handler that ignored commitRepo and substituted a name
// would satisfy it. The risk is the handler ceasing to pass the stamp through, and only
// the handler can be asked about that.
func TestA2AGatewayRuntimeHealthClaimsNoRepositoryWhenItWasNotGivenOne(t *testing.T) {
	oldCommitRepo := commitRepo
	commitRepo = ""
	defer func() { commitRepo = oldCommitRepo }()

	tmp := t.TempDir()
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if strings.Contains(resp.Body.String(), "git_sha_repo") {
		t.Fatalf("a gateway never told where its commit resolves named a repository anyway,\n"+
			"which a reader would then trust: %s", resp.Body.String())
	}
}
