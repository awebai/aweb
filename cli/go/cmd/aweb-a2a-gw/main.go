package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/a2agw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

var (
	version    = "dev"
	releaseTag = "dev"
	commit     = "unknown"
	// Set by the build that stamps commit, naming the repository that commit resolves
	// in. Empty for any build that did not set it (aweb-aaxi).
	commitRepo = ""
	date       = "unknown"
)

const minimumAWIDServiceVersion = "0.5.11"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "aweb-a2a-gw:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, _ *os.File) error {
	fs := flag.NewFlagSet("aweb-a2a-gw", flag.ContinueOnError)
	configPath := fs.String("config", strings.TrimSpace(os.Getenv("AWEB_A2A_GW_CONFIG")), "gateway YAML config")
	listenOverride := fs.String("listen", "", "listen address override")
	workspaceOverride := fs.String("workspace-dir", "", "workspace directory override")
	checkOnly := fs.Bool("check", false, "validate configuration and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfigOrHostedEnv(*configPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*listenOverride) != "" {
		cfg.Listen = strings.TrimSpace(*listenOverride)
	}
	if strings.TrimSpace(*workspaceOverride) != "" {
		cfg.WorkspaceDir = strings.TrimSpace(*workspaceOverride)
	}
	listen := firstNonEmpty(cfg.Listen, ":8080")
	if managedConfigEnabled(cfg.ManagedConfig) && !*checkOnly {
		return runManagedGateway(cfg, listen)
	}
	if err := applyManagedRuntimeConfig(&cfg); err != nil {
		return err
	}
	gateway, err := buildGateway(cfg)
	if err != nil {
		return err
	}
	if *checkOnly {
		return json.NewEncoder(stdout).Encode(gateway.Diagnostics())
	}
	server := &http.Server{
		Addr:              listen,
		Handler:           runtimeHandler(gateway, cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

type runtimeHealth struct {
	Status             string                     `json:"status"`
	Build              runtimeBuild               `json:"build"`
	AwebVersion        string                     `json:"aweb_version"`
	AWIDServiceVersion string                     `json:"awid_service_version"`
	AWIDRegistry       runtimeRegistryHealth      `json:"awid_registry"`
	ManagedConfig      runtimeManagedConfigHealth `json:"managed_config"`
	GatewayIdentity    runtimeIdentityHealth      `json:"gateway_identity"`
	Gateway            map[string]interface{}     `json:"gateway"`
}

type runtimeBuild struct {
	ReleaseTag string `json:"release_tag"`
	GitSHA     string `json:"git_sha"`
	// The repository GitSHA resolves in. This binary is built two ways - by goreleaser
	// in the derived aw repository, and from aweb by the gateway image workflow - so the
	// SHA alone does not say where to look. Omitted when the build was not told, rather
	// than guessing the repository the reader happens to be standing in (aweb-aaxi).
	GitSHARepo string `json:"git_sha_repo,omitempty"`
	Date       string `json:"date,omitempty"`
}

type runtimeRegistryHealth struct {
	URL            string `json:"url,omitempty"`
	Reachable      bool   `json:"reachable"`
	Compatible     bool   `json:"compatible"`
	Status         string `json:"status"`
	Version        string `json:"version,omitempty"`
	MinimumVersion string `json:"minimum_version,omitempty"`
	Error          string `json:"error,omitempty"`
}

type runtimeManagedConfigHealth struct {
	Enabled        bool   `json:"enabled"`
	GatewayID      string `json:"gateway_id,omitempty"`
	ConfigRevision string `json:"config_revision,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	Expired        bool   `json:"expired"`
	Routes         int    `json:"routes"`
	Status         string `json:"status,omitempty"`
	Error          string `json:"error,omitempty"`
}

type runtimeIdentityHealth struct {
	Identity string `json:"identity,omitempty"`
	Status   string `json:"status"`
	Usable   bool   `json:"usable"`
}

func runtimeHandler(gateway *a2agw.Gateway, cfg fileConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			gateway.ServeHTTP(w, r)
			return
		}
		writeRuntimeHealth(w, gateway, cfg)
	})
}

type managedGateway struct {
	mu      sync.RWMutex
	cfg     fileConfig
	gateway *a2agw.Gateway
	runtime *gatewayRuntime
}

func runManagedGateway(base fileConfig, listen string) error {
	initial, err := buildManagedSnapshot(base, true)
	if err != nil {
		return err
	}
	manager := &managedGateway{cfg: initial.cfg, gateway: initial.gateway, runtime: initial.runtime}
	go manager.refreshLoop(base)
	server := &http.Server{
		Addr:              listen,
		Handler:           manager,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

type managedSnapshot struct {
	cfg     fileConfig
	gateway *a2agw.Gateway
	runtime *gatewayRuntime
}

func buildManagedSnapshot(base fileConfig, allowDegraded bool) (managedSnapshot, error) {
	cfg, err := loadManagedConfig(base, allowDegraded)
	if err != nil {
		return managedSnapshot{}, err
	}
	runtime, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	if err != nil {
		return managedSnapshot{}, err
	}
	return managedSnapshot{cfg: cfg, gateway: gateway, runtime: runtime}, nil
}

func loadManagedConfig(base fileConfig, allowDegraded bool) (fileConfig, error) {
	cfg := base
	if err := applyManagedRuntimeConfig(&cfg); err != nil {
		if isFatalInitialManagedRuntimeConfigError(err) {
			return fileConfig{}, err
		}
		if !allowDegraded {
			return fileConfig{}, err
		}
		return degradedManagedConfig(base, err), nil
	}
	return cfg, nil
}

func (m *managedGateway) refreshLoop(base fileConfig) {
	interval := managedConfigPollInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		cfg, err := loadManagedConfig(base, false)
		if err != nil {
			m.markRefreshError(err)
			continue
		}
		if err := m.applyRefreshSnapshot(cfg); err != nil {
			m.markRefreshError(err)
		}
	}
}

func (m *managedGateway) applyRefreshSnapshot(cfg fileConfig) error {
	acceptUntil, err := managedAcceptNewTasksUntil(cfg)
	if err != nil {
		return err
	}
	m.mu.RLock()
	sameRevision := strings.TrimSpace(cfg.ManagedRuntime.ConfigRevision) != "" &&
		strings.TrimSpace(cfg.ManagedRuntime.ConfigRevision) == strings.TrimSpace(m.cfg.ManagedRuntime.ConfigRevision)
	runtime := m.runtime
	previous := m.gateway
	m.mu.RUnlock()
	if sameRevision {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.cfg.ManagedRuntime = cfg.ManagedRuntime
		m.cfg.GatewayIdentity = cfg.GatewayIdentity
		if m.gateway != nil {
			m.gateway.SetAcceptNewTasksUntil(acceptUntil)
		}
		return nil
	}
	runtime, gateway, err := buildGatewayWithRuntime(cfg, runtime, previous)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	runtime.applyConfig(cfg, gateway, gatewayIdentityFromConfig(cfg))
	m.cfg = cfg
	m.gateway = gateway
	m.runtime = runtime
	return nil
}

func (m *managedGateway) markRefreshError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.ManagedRuntime.FetchStatus = "stale"
	m.cfg.ManagedRuntime.FetchError = err.Error()
}

func (m *managedGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	gateway := m.gateway
	cfg := m.cfg
	m.mu.RUnlock()
	if r.URL.Path == "/health" {
		writeRuntimeHealth(w, gateway, cfg)
		return
	}
	gateway.ServeHTTP(w, r)
}

func managedConfigPollInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("AWEB_A2A_GW_CONFIG_POLL_INTERVAL"))
	if raw == "" {
		return 10 * time.Second
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < time.Second {
		return 10 * time.Second
	}
	return parsed
}

func writeRuntimeHealth(w http.ResponseWriter, gateway *a2agw.Gateway, cfg fileConfig) {
	health := runtimeHealth{
		Status:             "healthy",
		Build:              runtimeBuild{ReleaseTag: releaseTag, GitSHA: commit, GitSHARepo: commitRepo, Date: date},
		AwebVersion:        version,
		AWIDServiceVersion: ">=" + minimumAWIDServiceVersion,
		AWIDRegistry:       checkRegistryHealth(cfg.RegistryURL),
		ManagedConfig:      managedConfigHealth(cfg),
		GatewayIdentity:    gatewayIdentityHealth(cfg),
		Gateway:            map[string]interface{}{},
	}
	gatewayHealthBytes, err := json.Marshal(gateway.Health())
	if err == nil {
		_ = json.Unmarshal(gatewayHealthBytes, &health.Gateway)
	}
	if health.ManagedConfig.Status == "pending" {
		health.Status = "pending"
	}
	if health.ManagedConfig.Status == "stale" && health.ManagedConfig.ConfigRevision == "" {
		health.Status = "unhealthy"
	}
	if !health.AWIDRegistry.Reachable || !health.AWIDRegistry.Compatible || health.ManagedConfig.Expired || (health.ManagedConfig.Routes > 0 && !health.GatewayIdentity.Usable) {
		health.Status = "unhealthy"
	}
	status := http.StatusOK
	if health.Status != "healthy" {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(health)
}

func managedConfigHealth(cfg fileConfig) runtimeManagedConfigHealth {
	out := runtimeManagedConfigHealth{
		Enabled:        managedConfigEnabled(cfg.ManagedConfig),
		GatewayID:      strings.TrimSpace(cfg.ManagedConfig.GatewayID),
		ConfigRevision: strings.TrimSpace(cfg.ManagedRuntime.ConfigRevision),
		ExpiresAt:      strings.TrimSpace(cfg.ManagedRuntime.ExpiresAt),
		Routes:         len(cfg.Routes),
		Status:         strings.TrimSpace(cfg.ManagedRuntime.FetchStatus),
		Error:          strings.TrimSpace(cfg.ManagedRuntime.FetchError),
	}
	if out.Status == "" && out.Enabled {
		out.Status = "ok"
	}
	if out.ExpiresAt != "" {
		if parsed, err := time.Parse(time.RFC3339, out.ExpiresAt); err == nil {
			out.Expired = time.Now().After(parsed)
		}
	}
	return out
}

func gatewayIdentityHealth(cfg fileConfig) runtimeIdentityHealth {
	identity := strings.TrimSpace(cfg.GatewayIdentity)
	status := strings.TrimSpace(cfg.ManagedRuntime.GatewayIdentityStatus)
	if !managedConfigEnabled(cfg.ManagedConfig) && identity == "" {
		return runtimeIdentityHealth{Status: "workspace", Usable: true}
	}
	if status == "" && identity != "" {
		status = "active"
	}
	usable := identity != "" && (status == "" || status == "active")
	if status == "" {
		status = "missing"
	}
	return runtimeIdentityHealth{Identity: identity, Status: status, Usable: usable}
}

func checkRegistryHealth(registryURL string) runtimeRegistryHealth {
	registryURL = strings.TrimRight(strings.TrimSpace(registryURL), "/")
	if registryURL == "" {
		return runtimeRegistryHealth{Reachable: false, Compatible: false, MinimumVersion: minimumAWIDServiceVersion, Status: "missing_registry_url", Error: "registry_url is required for runtime health"}
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(registryURL + "/health")
	if err != nil {
		return runtimeRegistryHealth{URL: registryURL, Reachable: false, Compatible: false, MinimumVersion: minimumAWIDServiceVersion, Status: "unreachable", Error: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := runtimeRegistryHealth{URL: registryURL, Reachable: resp.StatusCode >= 200 && resp.StatusCode < 300, Compatible: false, MinimumVersion: minimumAWIDServiceVersion, Status: http.StatusText(resp.StatusCode)}
	if len(body) > 0 {
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err == nil {
			if value := stringField(payload, "version"); value != "" {
				out.Version = value
			} else if value := stringField(payload, "service_version"); value != "" {
				out.Version = value
			}
			if value := stringField(payload, "status"); value != "" {
				out.Status = value
			}
		}
	}
	if !out.Reachable && out.Error == "" {
		out.Error = fmt.Sprintf("registry health returned HTTP %d", resp.StatusCode)
	}
	if out.Reachable {
		switch {
		case out.Version == "":
			out.Status = "missing_version"
			out.Error = "registry health did not report version or service_version"
		case !versionAtLeast(out.Version, minimumAWIDServiceVersion):
			out.Status = "version_below_minimum"
			out.Error = fmt.Sprintf("registry version %s is below required %s", out.Version, minimumAWIDServiceVersion)
		default:
			out.Compatible = true
		}
	}
	return out
}

func versionAtLeast(got, minimum string) bool {
	gotParts, ok := parseDottedVersion(got)
	if !ok {
		return false
	}
	minParts, ok := parseDottedVersion(minimum)
	if !ok {
		return false
	}
	n := len(gotParts)
	if len(minParts) > n {
		n = len(minParts)
	}
	for i := 0; i < n; i++ {
		var gotValue, minValue int
		if i < len(gotParts) {
			gotValue = gotParts[i]
		}
		if i < len(minParts) {
			minValue = minParts[i]
		}
		if gotValue > minValue {
			return true
		}
		if gotValue < minValue {
			return false
		}
	}
	return true
}

func parseDottedVersion(raw string) ([]int, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "v"))
	if raw == "" {
		return nil, false
	}
	if idx := strings.IndexAny(raw, "-+"); idx >= 0 {
		raw = raw[:idx]
	}
	parts := strings.Split(raw, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, false
		}
		out = append(out, value)
	}
	return out, true
}

func stringField(payload map[string]interface{}, key string) string {
	value, ok := payload[key]
	if !ok {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}

type fileConfig struct {
	Listen                    string             `yaml:"listen"`
	Host                      string             `yaml:"host"`
	WorkspaceDir              string             `yaml:"workspace_dir"`
	TeamID                    string             `yaml:"team_id"`
	RootCardMode              string             `yaml:"root_card_mode"`
	DefaultRouteID            string             `yaml:"default_route_id"`
	GatewayIdentity           string             `yaml:"gateway_identity"`
	RegistryURL               string             `yaml:"registry_url"`
	PollInterval              string             `yaml:"poll_interval"`
	PollTimeout               string             `yaml:"poll_timeout"`
	UseIdentityAuth           *bool              `yaml:"use_identity_auth"`
	RequireVerifiedReplies    *bool              `yaml:"require_verified_replies"`
	AllowUnverifiedLocalReply bool               `yaml:"allow_unverified_local_reply"`
	AllowQuestionReply        bool               `yaml:"allow_question_reply"`
	RouterCard                cardConfig         `yaml:"router_card"`
	Routes                    []routeConfig      `yaml:"routes"`
	Audit                     auditConfig        `yaml:"audit"`
	ManagedConfig             managedConfig      `yaml:"managed_config"`
	ManagedRuntime            managedRuntimeMeta `yaml:"-"`
}

type managedConfig struct {
	ConfigURL      string `yaml:"config_url"`
	BridgeURL      string `yaml:"bridge_url"`
	GatewayID      string `yaml:"gateway_id"`
	BearerToken    string `yaml:"bearer_token"`
	BearerTokenEnv string `yaml:"bearer_token_env"`
}

type managedRuntimeMeta struct {
	GatewayIdentityStatus string
	ConfigRevision        string
	ExpiresAt             string
	FetchStatus           string
	FetchError            string
}

type routeConfig struct {
	RouteID         string                 `yaml:"route_id"`
	Address         string                 `yaml:"address"`
	Mode            string                 `yaml:"mode"`
	Disabled        bool                   `yaml:"disabled"`
	ResponseTimeout string                 `yaml:"response_timeout"`
	Auth            authConfig             `yaml:"auth"`
	Limits          limitsConfig           `yaml:"limits"`
	Card            cardConfig             `yaml:"card"`
	AWIDPublication *awidPublicationConfig `yaml:"awid_publication"`
}

type cardConfig struct {
	Name               string       `yaml:"name"`
	Description        string       `yaml:"description"`
	Provider           providerYAML `yaml:"provider"`
	Version            string       `yaml:"version"`
	Streaming          bool         `yaml:"streaming"`
	PushNotifications  bool         `yaml:"push_notifications"`
	DefaultInputModes  []string     `yaml:"default_input_modes"`
	DefaultOutputModes []string     `yaml:"default_output_modes"`
	Skills             []skillYAML  `yaml:"skills"`
}

type providerYAML struct {
	Organization string `yaml:"organization"`
	URL          string `yaml:"url"`
}

type skillYAML struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

type authConfig struct {
	Mode            string `yaml:"mode"`
	StaticAPIKey    string `yaml:"static_api_key"`
	StaticAPIKeyEnv string `yaml:"static_api_key_env"`
	BearerToken     string `yaml:"bearer_token"`
	BearerTokenEnv  string `yaml:"bearer_token_env"`
}

type limitsConfig struct {
	MaxMessageBytes    int    `yaml:"max_message_bytes"`
	RateLimit          string `yaml:"rate_limit"`
	MaxConcurrentTasks int    `yaml:"max_concurrent_tasks"`
	TaskTTL            string `yaml:"task_ttl"`
}

type awidPublicationConfig struct {
	Address    string `yaml:"address"`
	CardDigest string `yaml:"card_digest"`
	Required   bool   `yaml:"required"`
}

type auditConfig struct {
	JSONL string `yaml:"jsonl"`
}

func loadFileConfig(path string) (fileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fileConfig{}, err
	}
	var cfg fileConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return fileConfig{}, fmt.Errorf("decode gateway config %s: %w", path, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return fileConfig{}, fmt.Errorf("decode gateway config %s: %w", path, err)
		}
		return fileConfig{}, fmt.Errorf("decode gateway config %s: exactly one YAML document is required", path)
	}
	if err := validateManagedConfig(cfg.ManagedConfig); err != nil {
		return fileConfig{}, fmt.Errorf("gateway config %s: %w", path, err)
	}
	return cfg, nil
}

func loadConfigOrHostedEnv(path string) (fileConfig, error) {
	cfg, err := loadFileConfig(path)
	if err == nil {
		return cfg, nil
	}
	if path != "" && !os.IsNotExist(err) {
		return fileConfig{}, err
	}
	envCfg, ok, envErr := managedEnvConfig()
	if envErr != nil {
		return fileConfig{}, envErr
	}
	if ok {
		return envCfg, nil
	}
	if path == "" {
		return fileConfig{}, fmt.Errorf("--config or AWEB_A2A_GW_CONFIG is required unless explicit managed gateway environment variables are set")
	}
	return fileConfig{}, fmt.Errorf("open %s: no such file or directory; set a mounted config file or explicit managed gateway environment variables", path)
}

func managedEnvConfig() (fileConfig, bool, error) {
	values := map[string]string{
		"AWEB_A2A_GW_MANAGED_CONFIG_URL":   strings.TrimSpace(os.Getenv("AWEB_A2A_GW_MANAGED_CONFIG_URL")),
		"AWEB_A2A_GW_MANAGED_BRIDGE_URL":   strings.TrimSpace(os.Getenv("AWEB_A2A_GW_MANAGED_BRIDGE_URL")),
		"AWEB_A2A_GW_MANAGED_GATEWAY_ID":   strings.TrimSpace(os.Getenv("AWEB_A2A_GW_MANAGED_GATEWAY_ID")),
		"AWEB_A2A_GW_MANAGED_BEARER_TOKEN": strings.TrimSpace(os.Getenv("AWEB_A2A_GW_MANAGED_BEARER_TOKEN")),
		"AWEB_A2A_GW_HOST":                 strings.TrimSpace(os.Getenv("AWEB_A2A_GW_HOST")),
		"AWEB_A2A_GW_REGISTRY_URL":         strings.TrimSpace(os.Getenv("AWEB_A2A_GW_REGISTRY_URL")),
	}
	active := false
	for name, value := range values {
		if strings.HasPrefix(name, "AWEB_A2A_GW_MANAGED_") && value != "" {
			active = true
		}
	}
	if active {
		required := []string{
			"AWEB_A2A_GW_HOST",
			"AWEB_A2A_GW_REGISTRY_URL",
			"AWEB_A2A_GW_MANAGED_CONFIG_URL",
			"AWEB_A2A_GW_MANAGED_BRIDGE_URL",
			"AWEB_A2A_GW_MANAGED_GATEWAY_ID",
			"AWEB_A2A_GW_MANAGED_BEARER_TOKEN",
		}
		for _, name := range required {
			if values[name] == "" {
				return fileConfig{}, false, fmt.Errorf("%s is required for managed gateway environment startup", name)
			}
		}
		cfg := fileConfig{
			Host:        values["AWEB_A2A_GW_HOST"],
			RegistryURL: values["AWEB_A2A_GW_REGISTRY_URL"],
			ManagedConfig: managedConfig{
				ConfigURL:   values["AWEB_A2A_GW_MANAGED_CONFIG_URL"],
				BridgeURL:   values["AWEB_A2A_GW_MANAGED_BRIDGE_URL"],
				GatewayID:   values["AWEB_A2A_GW_MANAGED_GATEWAY_ID"],
				BearerToken: values["AWEB_A2A_GW_MANAGED_BEARER_TOKEN"],
			},
		}
		if err := validateManagedConfig(cfg.ManagedConfig); err != nil {
			return fileConfig{}, false, fmt.Errorf("managed gateway environment: %w", err)
		}
		return cfg, true, nil
	}
	return fileConfig{}, false, nil
}

type managedRuntimeConfigPayload struct {
	GatewayID             string                `json:"gateway_id"`
	GatewayIdentity       string                `json:"gateway_identity"`
	GatewayIdentityStatus string                `json:"gateway_identity_status"`
	ConfigRevision        string                `json:"config_revision"`
	ExpiresAt             string                `json:"expires_at"`
	Routes                []managedRuntimeRoute `json:"routes"`
	routesPresent         bool
}

func (p *managedRuntimeConfigPayload) UnmarshalJSON(data []byte) error {
	type payloadAlias managedRuntimeConfigPayload
	var decoded payloadAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	routes, present := fields["routes"]
	decoded.routesPresent = present && !bytes.Equal(bytes.TrimSpace(routes), []byte("null"))
	*p = managedRuntimeConfigPayload(decoded)
	return nil
}

type managedRuntimeRoute struct {
	RouteID          string               `json:"route_id"`
	Host             string               `json:"host"`
	Address          string               `json:"address"`
	Mode             string               `json:"mode"`
	Disabled         bool                 `json:"disabled"`
	RootBehavior     string               `json:"root_behavior"`
	VerificationTier string               `json:"verification_tier"`
	CardDigest       string               `json:"card_digest"`
	Auth             managedRuntimeAuth   `json:"auth"`
	Limits           managedRuntimeLimits `json:"limits"`
	Card             managedRuntimeCard   `json:"card"`
}

type managedRuntimeAuth struct {
	Mode string `json:"mode"`
}

type managedRuntimeLimits struct {
	RateLimit              map[string]interface{} `json:"rate_limit"`
	MaxMessageBytes        int                    `json:"max_message_bytes"`
	MaxConcurrentTasks     int                    `json:"max_concurrent_tasks"`
	TaskTTLSeconds         int                    `json:"task_ttl_seconds"`
	ResponseTimeoutSeconds int                    `json:"response_timeout_seconds"`
}

type managedRuntimeCard struct {
	Name               string       `json:"name"`
	Description        string       `json:"description"`
	Provider           providerYAML `json:"provider"`
	Version            string       `json:"version"`
	Streaming          bool         `json:"streaming"`
	PushNotifications  bool         `json:"push_notifications"`
	DefaultInputModes  []string     `json:"default_input_modes"`
	DefaultOutputModes []string     `json:"default_output_modes"`
	Skills             []skillYAML  `json:"skills"`
}

type managedRuntimeConfigFetchError struct {
	StatusCode int
	Message    string
}

func (e *managedRuntimeConfigFetchError) Error() string {
	return e.Message
}

func applyManagedRuntimeConfig(cfg *fileConfig) error {
	url, err := managedConfigURL(cfg.ManagedConfig)
	if err != nil {
		return err
	}
	if url == "" {
		return nil
	}
	token := managedBearerToken(cfg.ManagedConfig)
	if token == "" {
		return fmt.Errorf("managed config bearer token is required")
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return &managedRuntimeConfigFetchError{Message: fmt.Sprintf("fetch managed runtime config: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &managedRuntimeConfigFetchError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("fetch managed runtime config: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	var payload managedRuntimeConfigPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode managed runtime config: %w", err)
	}
	return mergeManagedRuntimeConfig(cfg, payload)
}

func isFatalInitialManagedRuntimeConfigError(err error) bool {
	var fetchErr *managedRuntimeConfigFetchError
	if err != nil && strings.Contains(err.Error(), "bearer token is required") {
		return true
	}
	if err != nil && errors.As(err, &fetchErr) {
		return fetchErr.StatusCode == http.StatusUnauthorized || fetchErr.StatusCode == http.StatusForbidden
	}
	return false
}

func degradedManagedConfig(base fileConfig, err error) fileConfig {
	cfg := base
	cfg.Routes = nil
	cfg.DefaultRouteID = ""
	cfg.RootCardMode = string(a2agw.RootCardRouter)
	if strings.TrimSpace(cfg.Host) == "" {
		cfg.Host = firstNonEmpty(os.Getenv("AWEB_A2A_GW_HOST"), "a2a.aweb.ai")
	}
	if strings.TrimSpace(cfg.RouterCard.Name) == "" {
		cfg.RouterCard = defaultRouterCard(cfg.Host)
	}
	cfg.GatewayIdentity = ""
	cfg.ManagedRuntime = managedRuntimeMeta{
		GatewayIdentityStatus: "missing",
		FetchStatus:           "pending",
		FetchError:            err.Error(),
	}
	return cfg
}

func mergeManagedRuntimeConfig(cfg *fileConfig, payload managedRuntimeConfigPayload) error {
	required := []struct {
		name  string
		value string
	}{
		{name: "gateway_id", value: payload.GatewayID},
		{name: "gateway_identity", value: payload.GatewayIdentity},
		{name: "gateway_identity_status", value: payload.GatewayIdentityStatus},
		{name: "config_revision", value: payload.ConfigRevision},
		{name: "expires_at", value: payload.ExpiresAt},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("managed runtime config %s is required", field.name)
		}
	}
	if !payload.routesPresent && payload.Routes == nil {
		return fmt.Errorf("managed runtime config routes is required and must be an array")
	}
	if configuredID := strings.TrimSpace(cfg.ManagedConfig.GatewayID); configuredID != "" && configuredID != strings.TrimSpace(payload.GatewayID) {
		return fmt.Errorf("managed runtime config gateway_id %q does not match configured gateway_id %q", payload.GatewayID, configuredID)
	}
	if strings.TrimSpace(payload.GatewayIdentityStatus) != "active" {
		return fmt.Errorf("managed runtime config gateway identity is not active: %s", payload.GatewayIdentityStatus)
	}
	if expiresAt := strings.TrimSpace(payload.ExpiresAt); expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return fmt.Errorf("managed runtime config expires_at: %w", err)
		}
		if time.Now().After(parsed) {
			return fmt.Errorf("managed runtime config expired at %s", expiresAt)
		}
	}
	if strings.TrimSpace(payload.GatewayIdentity) != "" {
		cfg.GatewayIdentity = strings.TrimSpace(payload.GatewayIdentity)
	}
	if cfg.ManagedConfig.GatewayID == "" {
		cfg.ManagedConfig.GatewayID = strings.TrimSpace(payload.GatewayID)
	}
	cfg.ManagedRuntime = managedRuntimeMeta{
		GatewayIdentityStatus: strings.TrimSpace(payload.GatewayIdentityStatus),
		ConfigRevision:        strings.TrimSpace(payload.ConfigRevision),
		ExpiresAt:             strings.TrimSpace(payload.ExpiresAt),
		FetchStatus:           "ok",
	}
	cfg.Routes = make([]routeConfig, 0, len(payload.Routes))
	defaultRouteID := ""
	routerRoutes := 0
	routeAddresses := make(map[string]string, len(payload.Routes))
	for index, route := range payload.Routes {
		if strings.TrimSpace(route.RouteID) == "" {
			return fmt.Errorf("managed runtime config routes[%d].route_id is required", index)
		}
		if strings.TrimSpace(route.Address) == "" {
			return fmt.Errorf("managed runtime config routes[%d].address is required", index)
		}
		if strings.TrimSpace(route.Mode) != "mail" {
			return fmt.Errorf("managed runtime config routes[%d].mode must be mail", index)
		}
		normalizedAddress := strings.ToLower(strings.TrimSpace(route.Address))
		if existingRouteID, duplicate := routeAddresses[normalizedAddress]; duplicate {
			return fmt.Errorf("managed runtime config routes[%d].address %q duplicates route %q", index, normalizedAddress, existingRouteID)
		}
		routeAddresses[normalizedAddress] = strings.TrimSpace(route.RouteID)
		if strings.TrimSpace(route.RootBehavior) == "default_for_host" && defaultRouteID != "" {
			return fmt.Errorf("managed runtime config has multiple default_for_host routes: %q and %q", defaultRouteID, route.RouteID)
		}
		converted := routeConfig{
			RouteID:         strings.TrimSpace(route.RouteID),
			Address:         strings.TrimSpace(route.Address),
			Mode:            strings.TrimSpace(route.Mode),
			Disabled:        route.Disabled,
			ResponseTimeout: secondsDuration(route.Limits.ResponseTimeoutSeconds),
			Auth:            authConfig{Mode: strings.TrimSpace(route.Auth.Mode)},
			Limits: limitsConfig{
				MaxMessageBytes:    route.Limits.MaxMessageBytes,
				RateLimit:          rateLimitFromManaged(route.Limits.RateLimit),
				MaxConcurrentTasks: route.Limits.MaxConcurrentTasks,
				TaskTTL:            secondsDuration(route.Limits.TaskTTLSeconds),
			},
			Card: cardConfig{
				Name:               strings.TrimSpace(route.Card.Name),
				Description:        strings.TrimSpace(route.Card.Description),
				Provider:           providerYAML{Organization: strings.TrimSpace(route.Card.Provider.Organization), URL: strings.TrimSpace(route.Card.Provider.URL)},
				Version:            strings.TrimSpace(route.Card.Version),
				Streaming:          route.Card.Streaming,
				PushNotifications:  route.Card.PushNotifications,
				DefaultInputModes:  route.Card.DefaultInputModes,
				DefaultOutputModes: route.Card.DefaultOutputModes,
				Skills:             route.Card.Skills,
			},
		}
		if strings.TrimSpace(route.CardDigest) != "" && strings.TrimSpace(route.Address) != "" {
			converted.AWIDPublication = &awidPublicationConfig{
				Address:    strings.TrimSpace(route.Address),
				CardDigest: strings.TrimSpace(route.CardDigest),
				Required:   strings.TrimSpace(route.VerificationTier) == "awid_published" || strings.TrimSpace(route.VerificationTier) == "delegated",
			}
		}
		if cfg.Host == "" {
			cfg.Host = strings.TrimSpace(route.Host)
		}
		switch strings.TrimSpace(route.RootBehavior) {
		case "default_for_host":
			if defaultRouteID == "" {
				defaultRouteID = converted.RouteID
			}
		case "router_member":
			routerRoutes++
		}
		cfg.Routes = append(cfg.Routes, converted)
	}
	if defaultRouteID != "" {
		cfg.RootCardMode = string(a2agw.RootCardDefaultAgent)
		cfg.DefaultRouteID = defaultRouteID
	} else if routerRoutes > 0 || len(cfg.Routes) > 1 {
		cfg.RootCardMode = string(a2agw.RootCardRouter)
		if strings.TrimSpace(cfg.RouterCard.Name) == "" {
			cfg.RouterCard = defaultRouterCard(cfg.Host)
		}
	} else if len(cfg.Routes) == 0 {
		cfg.RootCardMode = string(a2agw.RootCardRouter)
		if strings.TrimSpace(cfg.RouterCard.Name) == "" {
			cfg.RouterCard = defaultRouterCard(cfg.Host)
		}
	}
	return nil
}

func secondsDuration(seconds int) string {
	if seconds <= 0 {
		return ""
	}
	return (time.Duration(seconds) * time.Second).String()
}

func rateLimitFromManaged(value map[string]interface{}) string {
	if len(value) == 0 {
		return ""
	}
	if raw, ok := value["raw"].(string); ok && strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw)
	}
	if perMinute, ok := numericMapValue(value, "requests_per_minute"); ok && perMinute > 0 {
		return fmt.Sprintf("%d/min", perMinute)
	}
	return ""
}

func managedConfigEnabled(cfg managedConfig) bool {
	return strings.TrimSpace(cfg.ConfigURL) != "" ||
		strings.TrimSpace(cfg.BridgeURL) != "" ||
		strings.TrimSpace(cfg.GatewayID) != "" ||
		strings.TrimSpace(cfg.BearerToken) != "" ||
		strings.TrimSpace(cfg.BearerTokenEnv) != ""
}

func validateManagedConfig(cfg managedConfig) error {
	if !managedConfigEnabled(cfg) {
		return nil
	}
	required := []struct {
		name  string
		value string
	}{
		{name: "config_url", value: cfg.ConfigURL},
		{name: "bridge_url", value: cfg.BridgeURL},
		{name: "gateway_id", value: cfg.GatewayID},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("managed_config.%s is required", field.name)
		}
	}
	if strings.TrimSpace(cfg.BearerToken) != "" && strings.TrimSpace(cfg.BearerTokenEnv) != "" {
		return fmt.Errorf("managed_config.bearer_token and managed_config.bearer_token_env are mutually exclusive")
	}
	if managedBearerToken(cfg) == "" {
		return fmt.Errorf("managed_config bearer token is required")
	}
	if err := validateManagedURL("config_url", cfg.ConfigURL); err != nil {
		return err
	}
	if err := validateManagedURL("bridge_url", cfg.BridgeURL); err != nil {
		return err
	}
	return nil
}

func validateManagedURL(field, value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return fmt.Errorf("managed_config.%s must be an absolute HTTP(S) URL", field)
	}
	return nil
}

func managedBearerToken(cfg managedConfig) string {
	return firstNonEmpty(cfg.BearerToken, envValue(cfg.BearerTokenEnv))
}

func managedConfigURL(cfg managedConfig) (string, error) {
	if raw := strings.TrimSpace(cfg.ConfigURL); raw != "" {
		return raw, nil
	}
	if strings.TrimSpace(cfg.BridgeURL) != "" {
		return "", fmt.Errorf("managed_config.config_url is required")
	}
	return "", nil
}

func managedBridgeURL(cfg managedConfig) (string, error) {
	if raw := strings.TrimSpace(cfg.BridgeURL); raw != "" {
		return strings.TrimRight(raw, "/"), nil
	}
	if strings.TrimSpace(cfg.ConfigURL) != "" {
		return "", fmt.Errorf("managed_config.bridge_url is required")
	}
	return "", nil
}

func numericMapValue(value map[string]interface{}, key string) (int, bool) {
	raw, ok := value[key]
	if !ok {
		return 0, false
	}
	switch typed := raw.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	default:
		return 0, false
	}
}

func defaultRouterCard(host string) cardConfig {
	return cardConfig{
		Name:               "aweb A2A Gateway",
		Description:        "A2A gateway for aweb agents.",
		Provider:           providerYAML{Organization: "aweb", URL: "https://aweb.ai"},
		Version:            "1.0.0",
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills:             []skillYAML{{ID: "route", Name: "Route A2A tasks", Description: "Route A2A tasks to configured aweb agents.", Tags: []string{"a2a", host}}},
	}
}

type gatewayRuntime struct {
	audit            a2agw.AuditSink
	bridge           *a2agw.MailBridge
	managedTransport *managedBridgeTransport
}

func (r *gatewayRuntime) applyConfig(cfg fileConfig, gateway *a2agw.Gateway, gatewayIdentity string) {
	if r == nil {
		return
	}
	if r.managedTransport != nil {
		r.managedTransport.UpdateFromConfig(cfg)
	}
	if r.bridge != nil {
		r.bridge.SetGatewayIdentity(gatewayIdentity)
		r.bridge.SetReplyApplier(gateway)
	}
}

func buildGateway(cfg fileConfig) (*a2agw.Gateway, error) {
	_, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	return gateway, err
}

func buildGatewayWithRuntime(cfg fileConfig, runtime *gatewayRuntime, previous *a2agw.Gateway) (*gatewayRuntime, *a2agw.Gateway, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, nil, fmt.Errorf("host is required")
	}
	var err error
	createdRuntime := runtime == nil
	if runtime == nil {
		runtime = &gatewayRuntime{}
		runtime.audit, err = auditSinkFromConfig(cfg.Audit)
		if err != nil {
			return nil, nil, err
		}
	}
	client, gatewayIdentity, err := mailTransportFromConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	pollInterval, err := parseOptionalDuration("poll_interval", cfg.PollInterval)
	if err != nil {
		return nil, nil, err
	}
	pollTimeout, err := parseOptionalDuration("poll_timeout", cfg.PollTimeout)
	if err != nil {
		return nil, nil, err
	}
	requireVerified := true
	if cfg.RequireVerifiedReplies != nil {
		requireVerified = *cfg.RequireVerifiedReplies
	}
	useIdentityAuth := true
	if cfg.UseIdentityAuth != nil {
		useIdentityAuth = *cfg.UseIdentityAuth
	}
	if managedTransport, ok := client.(*managedBridgeTransport); ok {
		if runtime.managedTransport == nil {
			if !createdRuntime {
				return nil, nil, fmt.Errorf("existing gateway runtime is missing managed bridge transport")
			}
			runtime.managedTransport = managedTransport
		}
		client = runtime.managedTransport
	}
	if runtime.bridge == nil {
		if !createdRuntime {
			return nil, nil, fmt.Errorf("existing gateway runtime is missing mail bridge")
		}
		runtime.bridge, err = a2agw.NewMailBridge(a2agw.MailBridgeConfig{
			Client:                    client,
			GatewayIdentity:           gatewayIdentity,
			UseIdentityAuth:           useIdentityAuth,
			PollInterval:              pollInterval,
			PollTimeout:               pollTimeout,
			RequireVerifiedReplies:    requireVerified,
			AllowUnverifiedLocalReply: cfg.AllowUnverifiedLocalReply,
			AllowQuestionReply:        cfg.AllowQuestionReply,
			Audit:                     runtime.audit,
		})
		if err != nil {
			return nil, nil, err
		}
	}
	gatewayConfig, err := gatewayConfigFromFile(cfg, runtime.bridge, runtime.audit)
	if err != nil {
		return nil, nil, err
	}
	gateway, err := a2agw.NewPreservingRuntime(gatewayConfig, previous)
	if err != nil {
		return nil, nil, err
	}
	if createdRuntime {
		runtime.applyConfig(cfg, gateway, gatewayIdentity)
	}
	return runtime, gateway, nil
}

func mailTransportFromConfig(cfg fileConfig) (a2agw.MailTransport, string, error) {
	if managedConfigEnabled(cfg.ManagedConfig) {
		client, err := managedBridgeTransportFromConfig(cfg)
		if err != nil {
			return nil, "", err
		}
		return client, firstNonEmpty(cfg.GatewayIdentity, cfg.ManagedConfig.GatewayID), nil
	}
	workspaceDir := strings.TrimSpace(cfg.WorkspaceDir)
	if workspaceDir == "" {
		workspaceDir = "."
	}
	return workspaceMailClient(workspaceDir, cfg.TeamID, cfg.RegistryURL, cfg.GatewayIdentity)
}

func gatewayIdentityFromConfig(cfg fileConfig) string {
	if managedConfigEnabled(cfg.ManagedConfig) {
		return firstNonEmpty(cfg.GatewayIdentity, cfg.ManagedConfig.GatewayID)
	}
	return strings.TrimSpace(cfg.GatewayIdentity)
}

func gatewayConfigFromFile(cfg fileConfig, bridge a2agw.Bridge, audit a2agw.AuditSink) (a2agw.Config, error) {
	routes := make([]a2agw.Route, 0, len(cfg.Routes))
	for _, route := range cfg.Routes {
		converted, err := convertRoute(route)
		if err != nil {
			return a2agw.Config{}, err
		}
		routes = append(routes, converted)
	}
	if len(routes) == 0 && strings.TrimSpace(cfg.RootCardMode) == "" {
		cfg.RootCardMode = string(a2agw.RootCardRouter)
	}
	if a2agw.RootCardMode(strings.TrimSpace(cfg.RootCardMode)) == a2agw.RootCardRouter && strings.TrimSpace(cfg.RouterCard.Name) == "" {
		cfg.RouterCard = defaultRouterCard(cfg.Host)
	}
	acceptUntil, err := managedAcceptNewTasksUntil(cfg)
	if err != nil {
		return a2agw.Config{}, err
	}
	return a2agw.Config{
		Host:                strings.TrimSpace(cfg.Host),
		RootCardMode:        a2agw.RootCardMode(strings.TrimSpace(cfg.RootCardMode)),
		DefaultRouteID:      strings.TrimSpace(cfg.DefaultRouteID),
		RouterCard:          convertRouterCard(cfg.RouterCard),
		Routes:              routes,
		Bridge:              bridge,
		Audit:               audit,
		AcceptNewTasksUntil: acceptUntil,
	}, nil
}

func managedAcceptNewTasksUntil(cfg fileConfig) (time.Time, error) {
	if !managedConfigEnabled(cfg.ManagedConfig) {
		return time.Time{}, nil
	}
	expiresAt := strings.TrimSpace(cfg.ManagedRuntime.ExpiresAt)
	if expiresAt == "" {
		if strings.TrimSpace(cfg.ManagedRuntime.FetchStatus) == "pending" {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("managed runtime config expires_at is required in managed mode")
	}
	parsed, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("managed runtime config expires_at: %w", err)
	}
	return parsed, nil
}

func convertRoute(route routeConfig) (a2agw.Route, error) {
	responseTimeout, err := parseOptionalDuration("response_timeout", route.ResponseTimeout)
	if err != nil {
		return a2agw.Route{}, err
	}
	taskTTL, err := parseOptionalDuration("task_ttl", route.Limits.TaskTTL)
	if err != nil {
		return a2agw.Route{}, err
	}
	return a2agw.Route{
		RouteID:         strings.TrimSpace(route.RouteID),
		Address:         strings.TrimSpace(route.Address),
		Mode:            strings.TrimSpace(route.Mode),
		Disabled:        route.Disabled,
		ResponseTimeout: responseTimeout,
		Auth: a2agw.AuthConfig{
			Mode:         strings.TrimSpace(route.Auth.Mode),
			StaticAPIKey: firstNonEmpty(route.Auth.StaticAPIKey, envValue(route.Auth.StaticAPIKeyEnv)),
			BearerToken:  firstNonEmpty(route.Auth.BearerToken, envValue(route.Auth.BearerTokenEnv)),
		},
		Limits: a2agw.Limits{
			MaxMessageBytes:    route.Limits.MaxMessageBytes,
			RateLimit:          strings.TrimSpace(route.Limits.RateLimit),
			MaxConcurrentTasks: route.Limits.MaxConcurrentTasks,
			TaskTTL:            taskTTL,
		},
		Card:            convertRouteCard(route.Card),
		AWIDPublication: convertAWIDPublication(route.AWIDPublication),
	}, nil
}

func convertRouteCard(card cardConfig) a2agw.RouteCard {
	return a2agw.RouteCard{
		Name:               strings.TrimSpace(card.Name),
		Description:        strings.TrimSpace(card.Description),
		Provider:           a2a.Provider{Organization: strings.TrimSpace(card.Provider.Organization), URL: strings.TrimSpace(card.Provider.URL)},
		Version:            firstNonEmpty(card.Version, "1.0.0"),
		Streaming:          card.Streaming,
		PushNotifications:  card.PushNotifications,
		DefaultInputModes:  defaultStrings(card.DefaultInputModes, []string{"text/plain"}),
		DefaultOutputModes: defaultStrings(card.DefaultOutputModes, []string{"text/plain"}),
		Skills:             convertSkills(card.Skills),
	}
}

func convertRouterCard(card cardConfig) a2agw.RouterCard {
	return a2agw.RouterCard{
		Name:               strings.TrimSpace(card.Name),
		Description:        strings.TrimSpace(card.Description),
		Provider:           a2a.Provider{Organization: strings.TrimSpace(card.Provider.Organization), URL: strings.TrimSpace(card.Provider.URL)},
		Version:            firstNonEmpty(card.Version, "1.0.0"),
		Streaming:          card.Streaming,
		PushNotifications:  card.PushNotifications,
		DefaultInputModes:  defaultStrings(card.DefaultInputModes, []string{"text/plain"}),
		DefaultOutputModes: defaultStrings(card.DefaultOutputModes, []string{"text/plain"}),
		Skills:             convertSkills(card.Skills),
	}
}

func convertSkills(skills []skillYAML) []a2a.Skill {
	out := make([]a2a.Skill, 0, len(skills))
	for _, skill := range skills {
		out = append(out, a2a.Skill{
			ID:          strings.TrimSpace(skill.ID),
			Name:        strings.TrimSpace(skill.Name),
			Description: strings.TrimSpace(skill.Description),
			Tags:        defaultStrings(skill.Tags, []string{"a2a"}),
		})
	}
	return out
}

func convertAWIDPublication(in *awidPublicationConfig) *a2agw.AWIDPublicationExpectation {
	if in == nil {
		return nil
	}
	return &a2agw.AWIDPublicationExpectation{
		Address:    strings.TrimSpace(in.Address),
		CardDigest: strings.TrimSpace(in.CardDigest),
		Required:   in.Required,
	}
}

func workspaceMailClient(workspaceDir, teamIDOverride, registryURLOverride, gatewayIdentityOverride string) (*awid.Client, string, error) {
	workspace, teamState, root, err := awconfig.LoadWorkspaceAndTeamState(workspaceDir)
	if err != nil {
		return nil, "", fmt.Errorf("load workspace: %w", err)
	}
	teamID := strings.TrimSpace(teamIDOverride)
	if teamID == "" {
		teamID = strings.TrimSpace(teamState.ActiveTeam)
	}
	workspaceMembership := workspace.Membership(teamID)
	if workspaceMembership == nil {
		return nil, "", fmt.Errorf("team %q is not present in workspace.yaml", teamID)
	}
	teamMembership := teamState.Membership(teamID)
	if teamMembership == nil {
		return nil, "", fmt.Errorf("team %q is not present in teams.yaml", teamID)
	}
	certPath := strings.TrimSpace(teamMembership.CertPath)
	if certPath == "" {
		certPath = strings.TrimSpace(workspaceMembership.CertPath)
	}
	if certPath == "" {
		return nil, "", fmt.Errorf("team %q is missing cert_path", teamID)
	}
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(root, ".aw", filepath.FromSlash(certPath))
	}
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return nil, "", fmt.Errorf("load team certificate: %w", err)
	}
	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(root))
	if err != nil {
		return nil, "", fmt.Errorf("load signing key: %w", err)
	}
	if did := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); did != strings.TrimSpace(cert.MemberDIDKey) {
		return nil, "", fmt.Errorf("signing key did:key %s does not match certificate member_did_key %s", did, strings.TrimSpace(cert.MemberDIDKey))
	}
	baseURL := gatewayBaseURL(workspace, teamMembership)
	if baseURL == "" {
		return nil, "", fmt.Errorf("workspace is missing aweb_url")
	}
	client, err := awid.NewWithCertificate(baseURL, signingKey, cert)
	if err != nil {
		return nil, "", err
	}
	address := firstNonEmpty(cert.MemberAddress, workspaceMembership.Alias, cert.Alias)
	client.SetAddress(address)
	client.SetStableID(strings.TrimSpace(cert.MemberDIDAW))
	client.SetRequireRecipientBindingForDirectAddresses(true)
	resolver := awid.NewRegistryResolver(client.HTTPClient(), nil)
	if registryURL := firstNonEmpty(registryURLOverride, teamMembership.RegistryURL); registryURL != "" {
		if err := resolver.SetFallbackRegistryURL(registryURL); err != nil {
			return nil, "", fmt.Errorf("registry_url: %w", err)
		}
	}
	client.SetResolver(resolver)
	gatewayIdentity := firstNonEmpty(gatewayIdentityOverride, cert.MemberAddress, cert.MemberDIDAW, cert.MemberDIDKey, cert.Alias)
	return client, gatewayIdentity, nil
}

// gatewayBaseURL resolves the aweb-server base URL for the mail client with the
// same precedence every other reader uses: the worktree's workspace.yaml
// top-level aweb_url is primary; the teams.yaml membership aweb_url is a
// fallback for the migration-leftover spine.
func gatewayBaseURL(workspace *awconfig.WorktreeWorkspace, teamMembership *awconfig.TeamMembership) string {
	workspaceURL := ""
	if workspace != nil {
		workspaceURL = workspace.AwebURL
	}
	membershipURL := ""
	if teamMembership != nil {
		membershipURL = teamMembership.AwebURL
	}
	return firstNonEmpty(workspaceURL, membershipURL)
}

type managedBridgeTransport struct {
	mu             sync.RWMutex
	httpClient     *http.Client
	bridgeURL      string
	gatewayID      string
	bearerToken    string
	routeByAddress map[string]string
}

func managedBridgeTransportFromConfig(cfg fileConfig) (*managedBridgeTransport, error) {
	bridgeURL, err := managedBridgeURL(cfg.ManagedConfig)
	if err != nil {
		return nil, err
	}
	gatewayID := strings.TrimSpace(cfg.ManagedConfig.GatewayID)
	if gatewayID == "" {
		return nil, fmt.Errorf("managed_config.gateway_id is required")
	}
	token := managedBearerToken(cfg.ManagedConfig)
	if token == "" {
		return nil, fmt.Errorf("managed config bearer token is required")
	}
	routeByAddress := make(map[string]string, len(cfg.Routes))
	for _, route := range cfg.Routes {
		address := strings.TrimSpace(route.Address)
		routeID := strings.TrimSpace(route.RouteID)
		if address == "" || routeID == "" {
			continue
		}
		routeByAddress[address] = routeID
	}
	return &managedBridgeTransport{
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		bridgeURL:      bridgeURL,
		gatewayID:      gatewayID,
		bearerToken:    token,
		routeByAddress: routeByAddress,
	}, nil
}

func (t *managedBridgeTransport) UpdateFromConfig(cfg fileConfig) {
	bridgeURL, bridgeErr := managedBridgeURL(cfg.ManagedConfig)
	token := managedBearerToken(cfg.ManagedConfig)
	gatewayID := strings.TrimSpace(cfg.ManagedConfig.GatewayID)
	routeByAddress := make(map[string]string, len(cfg.Routes))
	for _, route := range cfg.Routes {
		address := strings.TrimSpace(route.Address)
		routeID := strings.TrimSpace(route.RouteID)
		if address == "" || routeID == "" {
			continue
		}
		routeByAddress[address] = routeID
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if bridgeErr == nil && strings.TrimSpace(bridgeURL) != "" {
		t.bridgeURL = bridgeURL
	}
	if gatewayID != "" {
		t.gatewayID = gatewayID
	}
	if token != "" {
		t.bearerToken = token
	}
	t.routeByAddress = routeByAddress
}

func (t *managedBridgeTransport) SendMessage(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	return t.send(ctx, req)
}

func (t *managedBridgeTransport) SendMessageByIdentity(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	return t.send(ctx, req)
}

func (t *managedBridgeTransport) send(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("send request is required")
	}
	address := strings.TrimSpace(req.ToAddress)
	t.mu.RLock()
	routeID := strings.TrimSpace(t.routeByAddress[address])
	t.mu.RUnlock()
	return t.SendMessageForRoute(ctx, routeID, address, false, req)
}

func (t *managedBridgeTransport) SendMessageForRoute(ctx context.Context, expectedRouteID, expectedAddress string, _ bool, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("send request is required")
	}
	routeID := strings.TrimSpace(expectedRouteID)
	address := strings.TrimSpace(expectedAddress)
	if address == "" || address != strings.TrimSpace(req.ToAddress) {
		return nil, fmt.Errorf("managed A2A bridge route binding has mismatched to_address")
	}
	t.mu.RLock()
	currentRouteID := strings.TrimSpace(t.routeByAddress[address])
	gatewayID := t.gatewayID
	bridgeURL := t.bridgeURL
	bearerToken := t.bearerToken
	if routeID == "" || currentRouteID != routeID {
		t.mu.RUnlock()
		return nil, fmt.Errorf("managed A2A bridge route binding changed for address %s: expected %s", address, routeID)
	}
	t.mu.RUnlock()
	payload := map[string]interface{}{
		"route_id":        routeID,
		"to_address":      address,
		"conversation_id": strings.TrimSpace(req.ConversationID),
		"subject":         req.Subject,
		"body":            req.Body,
		"content_mode":    awid.ContentModeLegacyPlaintextV1,
		"priority":        string(req.Priority),
		"message_id":      strings.TrimSpace(req.MessageID),
	}
	if payload["priority"] == "" {
		payload["priority"] = string(awid.PriorityNormal)
	}
	var out awid.SendMessageResponse
	if err := t.doJSONWithSnapshot(ctx, bridgeURL, bearerToken, http.MethodPost, "/"+url.PathEscape(gatewayID)+"/messages", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (t *managedBridgeTransport) MailConversation(ctx context.Context, conversationID string, limit int) (*awid.InboxResponse, error) {
	return t.MailConversationForRoute(ctx, "", "", conversationID, limit)
}

func (t *managedBridgeTransport) MailConversationForRoute(ctx context.Context, routeID, address, conversationID string, limit int) (*awid.InboxResponse, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil, fmt.Errorf("conversation_id is required")
	}
	t.mu.RLock()
	gatewayID := t.gatewayID
	t.mu.RUnlock()
	path := "/" + url.PathEscape(gatewayID) + "/conversations/" + url.PathEscape(conversationID)
	query := make([]string, 0, 3)
	if strings.TrimSpace(routeID) != "" {
		query = append(query, "route_id="+url.QueryEscape(strings.TrimSpace(routeID)))
	}
	if strings.TrimSpace(address) != "" {
		query = append(query, "to_address="+url.QueryEscape(strings.TrimSpace(address)))
	}
	if limit > 0 {
		query = append(query, "limit="+strconv.Itoa(limit))
	}
	if len(query) > 0 {
		path += "?" + strings.Join(query, "&")
	}
	var out awid.InboxResponse
	if err := t.doJSON(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (t *managedBridgeTransport) doJSON(ctx context.Context, method, path string, payload interface{}, out interface{}) error {
	t.mu.RLock()
	bridgeURL := t.bridgeURL
	bearerToken := t.bearerToken
	t.mu.RUnlock()
	return t.doJSONWithSnapshot(ctx, bridgeURL, bearerToken, method, path, payload, out)
}

func (t *managedBridgeTransport) doJSONWithSnapshot(ctx context.Context, bridgeURL, bearerToken, method, path string, payload interface{}, out interface{}) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(bridgeURL, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("managed bridge %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode managed bridge response: %w", err)
	}
	return nil
}

func parseOptionalDuration(field, raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return d, nil
}

func auditSinkFromConfig(cfg auditConfig) (a2agw.AuditSink, error) {
	if strings.TrimSpace(cfg.JSONL) == "" {
		return nil, nil
	}
	return newJSONLAuditSink(cfg.JSONL)
}

func envValue(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}

func defaultStrings(values, fallback []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), fallback...)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
