package a2agw

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/a2a"
)

func TestGatewaySingleRouteDefaultsRootCard(t *testing.T) {
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Routes: []Route{supportRoute("r_support")}})
	if gw.config.RootCardMode != RootCardDefaultAgent {
		t.Fatalf("root mode: got %s, want %s", gw.config.RootCardMode, RootCardDefaultAgent)
	}
	card := fetchCard(t, gw, a2a.WellKnownAgentCardPath)
	if got := card["name"]; got != "Aweb Support" {
		t.Fatalf("root card name: got %v", got)
	}
	assertCardValid(t, card, a2a.WellKnownAgentCardPath)
}

func TestGatewayMultiRouteExplicitDefault(t *testing.T) {
	gw := newTestGateway(t, Config{
		Host:           "acme.com",
		RootCardMode:   RootCardDefaultAgent,
		DefaultRouteID: "r_help",
		Routes:         []Route{helpRoute("r_help"), researchRoute("r_research")},
	})
	root := fetchCard(t, gw, a2a.WellKnownAgentCardPath)
	if got := root["name"]; got != "Acme Help" {
		t.Fatalf("root card name: got %v", got)
	}
	perAddress := fetchCard(t, gw, "/a2a/agents/r_research/agent-card.json")
	if got := perAddress["name"]; got != "Acme Research" {
		t.Fatalf("per-address card name: got %v", got)
	}
	assertCardValid(t, perAddress, "/a2a/agents/r_research/agent-card.json")
}

func TestGatewayMultiRouteRouter(t *testing.T) {
	gw := newTestGateway(t, Config{
		Host:         "acme.com",
		RootCardMode: RootCardRouter,
		RouterCard: RouterCard{
			Name:        "Acme A2A Gateway",
			Description: "A2A gateway for Acme agents. Exact agent cards are published in the Acme/aweb directory.",
			Provider:    a2a.Provider{Organization: "Acme", URL: "https://acme.com"},
			Skills:      []a2a.Skill{{ID: "route-to-agent", Name: "Route to Acme agents", Description: "Routes customer tasks to configured Acme agents when enough information is provided.", Tags: []string{"router"}}},
		},
		Routes: []Route{helpRoute("r_help"), researchRoute("r_research")},
	})
	root := fetchCard(t, gw, a2a.WellKnownAgentCardPath)
	if got := root["name"]; got != "Acme A2A Gateway" {
		t.Fatalf("router root name: got %v", got)
	}
	interfaces := root["supportedInterfaces"].([]any)
	if got := interfaces[0].(map[string]any)["url"]; got != "https://acme.com/a2a/rpc" {
		t.Fatalf("router rpc url: got %v", got)
	}
}

func TestGatewayMultiRouteMissingRootFails(t *testing.T) {
	_, err := New(Config{Host: "acme.com", Routes: []Route{helpRoute("r_help"), researchRoute("r_research")}})
	if err == nil || !strings.Contains(err.Error(), "root_card mode is required") {
		t.Fatalf("New error: got %v, want root_card requirement", err)
	}
}

func TestGatewayDiagnosticsAndRPCMethodGuard(t *testing.T) {
	gw := newTestGateway(t, Config{Host: "team.aweb.ai", Routes: []Route{supportRoute("r_support")}})
	health := fetchJSON(t, gw, "/health", http.StatusOK)
	if health["task_execution"] != false {
		t.Fatalf("health task_execution: got %v, want false", health["task_execution"])
	}
	diag := fetchJSON(t, gw, "/config", http.StatusOK)
	if diag["task_execution"] != false {
		t.Fatalf("config task_execution: got %v, want false", diag["task_execution"])
	}
	rpc := fetchJSON(t, gw, "/a2a/agents/r_support/rpc", http.StatusMethodNotAllowed)
	if rpc["error"] != "method_not_allowed" {
		t.Fatalf("rpc error: got %v", rpc["error"])
	}
	missing := fetchJSON(t, gw, "/a2a/agents/missing/rpc", http.StatusNotFound)
	if missing["error"] != "route_not_found" {
		t.Fatalf("missing rpc route error: got %v", missing["error"])
	}
}

func TestGatewayRejectsUnsafeRouteID(t *testing.T) {
	_, err := New(Config{Host: "acme.com", Routes: []Route{helpRoute("../escape")}})
	if err == nil || !strings.Contains(err.Error(), "path-safe") {
		t.Fatalf("New error: got %v, want path-safe route rejection", err)
	}
	_, err = New(Config{Host: "acme.com", Routes: []Route{helpRoute(".")}})
	if err == nil || !strings.Contains(err.Error(), "path-safe") {
		t.Fatalf("New error: got %v, want path-safe route rejection", err)
	}
}

func TestGatewayRejectsInvalidRouteRuntimeConfig(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Route)
		want string
	}{
		{
			name: "static api key requires secret",
			edit: func(route *Route) {
				route.Auth = AuthConfig{Mode: "static_api_key"}
			},
			want: "StaticAPIKey",
		},
		{
			name: "bearer requires token",
			edit: func(route *Route) {
				route.Auth = AuthConfig{Mode: "bearer"}
			},
			want: "BearerToken",
		},
		{
			name: "rate limit syntax",
			edit: func(route *Route) {
				route.Limits.RateLimit = "100/x"
			},
			want: "invalid rate limit",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			route := helpRoute("r_help")
			tc.edit(&route)
			_, err := New(Config{Host: "acme.com", Routes: []Route{route}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error: got %v, want %q", err, tc.want)
			}
		})
	}
}

func newTestGateway(t *testing.T, config Config) *Gateway {
	t.Helper()
	gw, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return gw
}

func fetchCard(t *testing.T, handler http.Handler, path string) map[string]any {
	t.Helper()
	card := fetchJSON(t, handler, path, http.StatusOK)
	assertCardValid(t, card, path)
	return card
}

func fetchJSON(t *testing.T, handler http.Handler, path string, wantStatus int) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s status: got %d, want %d; body=%s", path, rec.Code, wantStatus, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertCardValid(t *testing.T, card map[string]any, path string) {
	t.Helper()
	if err := a2a.ValidateCardMap(card, a2a.ValidationOptions{CardPath: path, RequireJSONRPCOnly: true, DisallowDirectTenant: true, RequireMediaTypeModes: true}); err != nil {
		t.Fatalf("card validation for %s: %v", path, err)
	}
}

func supportRoute(routeID string) Route {
	return Route{
		RouteID:         routeID,
		Address:         "team.aweb.ai/support",
		Mode:            "local",
		ResponseTimeout: 30 * time.Second,
		Auth:            AuthConfig{Mode: "none"},
		Card: RouteCard{
			Name:        "Aweb Support",
			Description: "Hosted support agent for aweb users.",
			Provider:    a2a.Provider{Organization: "aweb", URL: "https://aweb.ai"},
			Skills:      []a2a.Skill{{ID: "support", Name: "Support", Description: "Answers product and onboarding questions.", Tags: []string{"support", "onboarding"}}},
		},
	}
}

func helpRoute(routeID string) Route {
	return Route{
		RouteID: routeID,
		Address: "acme.com/help",
		Auth:    AuthConfig{Mode: "none"},
		Card: RouteCard{
			Name:        "Acme Help",
			Description: "Customer support agent for Acme products.",
			Provider:    a2a.Provider{Organization: "Acme", URL: "https://acme.com"},
			Skills:      []a2a.Skill{{ID: "order-status", Name: "Order status", Description: "Look up order status from an order ID.", Tags: []string{"support", "orders"}}},
		},
	}
}

func researchRoute(routeID string) Route {
	return Route{
		RouteID: routeID,
		Address: "acme.com/research",
		Auth:    AuthConfig{Mode: "none"},
		Card: RouteCard{
			Name:               "Acme Research",
			Description:        "Research agent for Acme technical investigations.",
			Provider:           a2a.Provider{Organization: "Acme", URL: "https://acme.com"},
			Streaming:          true,
			DefaultOutputModes: []string{"text/plain", "application/json"},
			Skills:             []a2a.Skill{{ID: "technical-research", Name: "Technical research", Description: "Investigates technical questions and returns concise findings.", Tags: []string{"research", "technical"}}},
		},
	}
}
