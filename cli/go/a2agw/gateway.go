package a2agw

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/awebai/aw/a2a"
)

type RootCardMode string

const (
	RootCardDefaultAgent RootCardMode = "default_agent"
	RootCardRouter       RootCardMode = "router"
)

type Config struct {
	Host                string
	RootCardMode        RootCardMode
	DefaultRouteID      string
	RouterCard          RouterCard
	Routes              []Route
	Bridge              Bridge
	Audit               AuditSink
	AcceptNewTasksUntil time.Time
}

type Route struct {
	RouteID         string
	Address         string
	Mode            string
	Disabled        bool
	ResponseTimeout time.Duration
	Auth            AuthConfig
	Limits          Limits
	Card            RouteCard
	AWIDPublication *AWIDPublicationExpectation
}

type RouteCard struct {
	Name               string
	Description        string
	Provider           a2a.Provider
	Version            string
	Streaming          bool
	PushNotifications  bool
	DefaultInputModes  []string
	DefaultOutputModes []string
	Skills             []a2a.Skill
}

type RouterCard struct {
	Name               string
	Description        string
	Provider           a2a.Provider
	Version            string
	Streaming          bool
	PushNotifications  bool
	DefaultInputModes  []string
	DefaultOutputModes []string
	Skills             []a2a.Skill
}

type AuthConfig struct {
	Mode         string
	StaticAPIKey string
	BearerToken  string
}

type Limits struct {
	MaxMessageBytes    int
	RateLimit          string
	MaxConcurrentTasks int
	TaskTTL            time.Duration
}

type AWIDPublicationExpectation struct {
	Address    string
	CardDigest string
	Required   bool
}

type Gateway struct {
	config        Config
	rootCard      a2a.Card
	routeCards    map[string]a2a.Card
	routeConfigs  map[string]Route
	bridge        Bridge
	tasks         *taskStore
	rateLimiter   *rateLimiter
	acceptUntil   atomic.Int64
	taskExecution bool
	auditSink     AuditSink
}

type Health struct {
	Status        string       `json:"status"`
	Host          string       `json:"host"`
	RootCardMode  RootCardMode `json:"root_card_mode"`
	Routes        int          `json:"routes"`
	TaskExecution bool         `json:"task_execution"`
}

type Diagnostics struct {
	Host           string            `json:"host"`
	RootCardMode   RootCardMode      `json:"root_card_mode"`
	DefaultRouteID string            `json:"default_route_id,omitempty"`
	TaskExecution  bool              `json:"task_execution"`
	Routes         []RouteDiagnostic `json:"routes"`
}

type RouteDiagnostic struct {
	RouteID          string `json:"route_id"`
	Address          string `json:"address"`
	Mode             string `json:"mode,omitempty"`
	CardPath         string `json:"card_path"`
	RPCPath          string `json:"rpc_path"`
	AuthMode         string `json:"auth_mode,omitempty"`
	Disabled         bool   `json:"disabled,omitempty"`
	RateLimit        string `json:"rate_limit,omitempty"`
	AWIDRequired     bool   `json:"awid_required"`
	VerificationTier string `json:"verification_tier"`
}

func New(config Config) (*Gateway, error) {
	return newGateway(config, nil)
}

func NewPreservingRuntime(config Config, previous *Gateway) (*Gateway, error) {
	return newGateway(config, previous)
}

func newGateway(config Config, previous *Gateway) (*Gateway, error) {
	if strings.TrimSpace(config.Host) == "" {
		return nil, fmt.Errorf("host is required")
	}
	routeCards := make(map[string]a2a.Card, len(config.Routes))
	routeConfigs := make(map[string]Route, len(config.Routes))
	for _, route := range config.Routes {
		route.RouteID = strings.TrimSpace(route.RouteID)
		if route.RouteID == "" {
			return nil, fmt.Errorf("route_id is required")
		}
		if _, exists := routeCards[route.RouteID]; exists {
			return nil, fmt.Errorf("duplicate route_id %q", route.RouteID)
		}
		if err := validateRouteRuntimeConfig(route); err != nil {
			return nil, err
		}
		card, err := a2a.PerAddressCard(a2a.CardConfig{
			Host:               config.Host,
			RouteID:            route.RouteID,
			Name:               route.Card.Name,
			Description:        route.Card.Description,
			Provider:           route.Card.Provider,
			Version:            route.Card.Version,
			Streaming:          route.Card.Streaming,
			PushNotifications:  route.Card.PushNotifications,
			DefaultInputModes:  route.Card.DefaultInputModes,
			DefaultOutputModes: route.Card.DefaultOutputModes,
			Skills:             route.Card.Skills,
		})
		if err != nil {
			return nil, fmt.Errorf("route %s card: %w", route.RouteID, err)
		}
		if err := a2a.ValidateCard(card, a2a.ValidationOptions{CardPath: a2a.DirectCardPath(route.RouteID), RequireJSONRPCOnly: true, DisallowDirectTenant: true, RequireMediaTypeModes: true}); err != nil {
			return nil, fmt.Errorf("route %s card validation: %w", route.RouteID, err)
		}
		if route.AWIDPublication != nil && route.AWIDPublication.Required {
			digest, err := a2a.CardDigest(card)
			if err != nil {
				return nil, fmt.Errorf("route %s card digest: %w", route.RouteID, err)
			}
			if strings.TrimSpace(route.AWIDPublication.CardDigest) != digest.Value {
				return nil, fmt.Errorf("route %s card digest %s does not match AWID publication digest %s", route.RouteID, digest.Value, strings.TrimSpace(route.AWIDPublication.CardDigest))
			}
		}
		routeCards[route.RouteID] = card
		routeConfigs[route.RouteID] = route
	}
	mode := config.RootCardMode
	if mode == "" && len(config.Routes) == 1 {
		mode = RootCardDefaultAgent
		config.DefaultRouteID = config.Routes[0].RouteID
	}
	if mode == "" && len(config.Routes) == 0 {
		mode = RootCardRouter
	}
	if mode == "" {
		return nil, fmt.Errorf("root_card mode is required when multiple routes are configured")
	}
	var rootCard a2a.Card
	switch mode {
	case RootCardDefaultAgent:
		defaultRoute, ok := routeConfigs[strings.TrimSpace(config.DefaultRouteID)]
		if !ok {
			return nil, fmt.Errorf("default_route_id %q is not a configured route", config.DefaultRouteID)
		}
		card, err := a2a.RootDefaultCard(a2a.CardConfig{
			Host:               config.Host,
			RouteID:            defaultRoute.RouteID,
			Name:               defaultRoute.Card.Name,
			Description:        defaultRoute.Card.Description,
			Provider:           defaultRoute.Card.Provider,
			Version:            defaultRoute.Card.Version,
			Streaming:          defaultRoute.Card.Streaming,
			PushNotifications:  defaultRoute.Card.PushNotifications,
			DefaultInputModes:  defaultRoute.Card.DefaultInputModes,
			DefaultOutputModes: defaultRoute.Card.DefaultOutputModes,
			Skills:             defaultRoute.Card.Skills,
		})
		if err != nil {
			return nil, err
		}
		rootCard = card
	case RootCardRouter:
		card, err := a2a.RootRouterCard(a2a.RouterCardConfig{
			Host:               config.Host,
			Name:               config.RouterCard.Name,
			Description:        config.RouterCard.Description,
			Provider:           config.RouterCard.Provider,
			Version:            config.RouterCard.Version,
			Streaming:          config.RouterCard.Streaming,
			PushNotifications:  config.RouterCard.PushNotifications,
			DefaultInputModes:  config.RouterCard.DefaultInputModes,
			DefaultOutputModes: config.RouterCard.DefaultOutputModes,
			Skills:             config.RouterCard.Skills,
		})
		if err != nil {
			return nil, err
		}
		rootCard = card
	default:
		return nil, fmt.Errorf("unsupported root_card mode %q", mode)
	}
	if err := a2a.ValidateCard(rootCard, a2a.ValidationOptions{CardPath: a2a.WellKnownAgentCardPath, RequireJSONRPCOnly: true, RequireMediaTypeModes: true}); err != nil {
		return nil, fmt.Errorf("root card validation: %w", err)
	}
	config.RootCardMode = mode
	bridge := config.Bridge
	taskExecution := true
	if bridge == nil {
		bridge = notReadyBridge{}
		taskExecution = false
	}
	tasks := newTaskStore(time.Now)
	rateLimiter := newRateLimiter(time.Now)
	if previous != nil {
		if previous.tasks != nil {
			tasks = previous.tasks
		}
		if previous.rateLimiter != nil {
			rateLimiter = previous.rateLimiter
		}
	}
	gateway := &Gateway{config: config, rootCard: rootCard, routeCards: routeCards, routeConfigs: routeConfigs, bridge: bridge, tasks: tasks, rateLimiter: rateLimiter, taskExecution: taskExecution, auditSink: config.Audit}
	gateway.SetAcceptNewTasksUntil(config.AcceptNewTasksUntil)
	return gateway, nil
}

func (g *Gateway) SetAcceptNewTasksUntil(until time.Time) {
	var nanos int64
	if !until.IsZero() {
		nanos = until.UnixNano()
	}
	g.acceptUntil.Store(nanos)
}

func (g *Gateway) AcceptNewTasksUntil() time.Time {
	nanos := g.acceptUntil.Load()
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

func validateRouteRuntimeConfig(route Route) error {
	switch normalizedAuthMode(route.Auth.Mode) {
	case "", "none":
	case "static_api_key":
		if strings.TrimSpace(route.Auth.StaticAPIKey) == "" && !route.Disabled {
			return fmt.Errorf("route %s: static_api_key mode requires Auth.StaticAPIKey", route.RouteID)
		}
	case "bearer":
		if strings.TrimSpace(route.Auth.BearerToken) == "" && !route.Disabled {
			return fmt.Errorf("route %s: bearer mode requires Auth.BearerToken", route.RouteID)
		}
	default:
		return fmt.Errorf("route %s: unsupported auth mode %q", route.RouteID, route.Auth.Mode)
	}
	if raw := strings.TrimSpace(route.Limits.RateLimit); raw != "" {
		if _, err := parseRateLimit(raw); err != nil {
			return fmt.Errorf("route %s: invalid rate limit %q: %w", route.RouteID, raw, err)
		}
	}
	return nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/health":
		writeJSON(w, http.StatusOK, g.Health())
	case r.URL.Path == "/config":
		writeJSON(w, http.StatusOK, g.Diagnostics())
	case r.URL.Path == a2a.WellKnownAgentCardPath:
		if g.config.RootCardMode == RootCardDefaultAgent {
			if route := g.routeConfigs[strings.TrimSpace(g.config.DefaultRouteID)]; route.Disabled {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "route_disabled"})
				return
			}
		}
		writeJSON(w, http.StatusOK, g.rootCard)
	case strings.HasPrefix(r.URL.Path, "/a2a/agents/") && strings.HasSuffix(r.URL.Path, "/agent-card.json"):
		routeID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/a2a/agents/"), "/agent-card.json")
		card, ok := g.routeCards[routeID]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "route_not_found"})
			return
		}
		if route := g.routeConfigs[routeID]; route.Disabled {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "route_disabled"})
			return
		}
		writeJSON(w, http.StatusOK, card)
	case strings.HasPrefix(r.URL.Path, "/a2a/agents/") && strings.HasSuffix(r.URL.Path, "/rpc"):
		routeID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/a2a/agents/"), "/rpc")
		if _, ok := g.routeConfigs[routeID]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "route_not_found"})
			return
		}
		g.serveRPC(w, r, routeID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func (g *Gateway) Health() Health {
	return Health{Status: "ok", Host: g.config.Host, RootCardMode: g.config.RootCardMode, Routes: len(g.routeCards), TaskExecution: g.taskExecution}
}

func (g *Gateway) Diagnostics() Diagnostics {
	routeIDs := make([]string, 0, len(g.routeConfigs))
	for routeID := range g.routeConfigs {
		routeIDs = append(routeIDs, routeID)
	}
	sort.Strings(routeIDs)
	routes := make([]RouteDiagnostic, 0, len(routeIDs))
	for _, routeID := range routeIDs {
		route := g.routeConfigs[routeID]
		awidRequired := route.AWIDPublication != nil && route.AWIDPublication.Required
		routes = append(routes, RouteDiagnostic{
			RouteID:          route.RouteID,
			Address:          route.Address,
			Mode:             route.Mode,
			CardPath:         a2a.DirectCardPath(route.RouteID),
			RPCPath:          a2a.DirectRPCPath(route.RouteID),
			AuthMode:         route.Auth.Mode,
			Disabled:         route.Disabled,
			RateLimit:        route.Limits.RateLimit,
			AWIDRequired:     awidRequired,
			VerificationTier: "unsigned",
		})
	}
	return Diagnostics{Host: g.config.Host, RootCardMode: g.config.RootCardMode, DefaultRouteID: g.config.DefaultRouteID, TaskExecution: g.taskExecution, Routes: routes}
}

func (g *Gateway) ApplyBridgeReply(reply BridgeReply) (Task, bool, error) {
	record, ok, err := g.tasks.applyReply(reply)
	if err != nil || !ok {
		return Task{}, ok, err
	}
	return record.Task, true, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
