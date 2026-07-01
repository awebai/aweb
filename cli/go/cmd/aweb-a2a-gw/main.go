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
	if acConfigEnabled(cfg.ACConfig) && !*checkOnly {
		return runManagedACGateway(cfg, listen)
	}
	if err := applyACRuntimeConfig(&cfg); err != nil {
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
	Status             string                 `json:"status"`
	Build              runtimeBuild           `json:"build"`
	AwebVersion        string                 `json:"aweb_version"`
	AWIDServiceVersion string                 `json:"awid_service_version"`
	AWIDRegistry       runtimeRegistryHealth  `json:"awid_registry"`
	ACConfig           runtimeACConfigHealth  `json:"ac_config"`
	GatewayIdentity    runtimeIdentityHealth  `json:"gateway_identity"`
	Gateway            map[string]interface{} `json:"gateway"`
}

type runtimeBuild struct {
	ReleaseTag string `json:"release_tag"`
	GitSHA     string `json:"git_sha"`
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

type runtimeACConfigHealth struct {
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

type managedACGateway struct {
	mu      sync.RWMutex
	cfg     fileConfig
	gateway *a2agw.Gateway
	runtime *gatewayRuntime
}

func runManagedACGateway(base fileConfig, listen string) error {
	initial, err := buildManagedACSnapshot(base, true)
	if err != nil {
		return err
	}
	manager := &managedACGateway{cfg: initial.cfg, gateway: initial.gateway, runtime: initial.runtime}
	go manager.refreshLoop(base)
	server := &http.Server{
		Addr:              listen,
		Handler:           manager,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
}

type managedACSnapshot struct {
	cfg     fileConfig
	gateway *a2agw.Gateway
	runtime *gatewayRuntime
}

func buildManagedACSnapshot(base fileConfig, allowDegraded bool) (managedACSnapshot, error) {
	cfg, err := loadManagedACConfig(base, allowDegraded)
	if err != nil {
		return managedACSnapshot{}, err
	}
	runtime, gateway, err := buildGatewayWithRuntime(cfg, nil, nil)
	if err != nil {
		return managedACSnapshot{}, err
	}
	return managedACSnapshot{cfg: cfg, gateway: gateway, runtime: runtime}, nil
}

func loadManagedACConfig(base fileConfig, allowDegraded bool) (fileConfig, error) {
	cfg := base
	if err := applyACRuntimeConfig(&cfg); err != nil {
		if isFatalInitialACRuntimeConfigError(err) {
			return fileConfig{}, err
		}
		if !allowDegraded {
			return fileConfig{}, err
		}
		return degradedACConfig(base, err), nil
	}
	return cfg, nil
}

func (m *managedACGateway) refreshLoop(base fileConfig) {
	interval := acConfigPollInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		cfg, err := loadManagedACConfig(base, false)
		if err != nil {
			m.markRefreshError(err)
			continue
		}
		if err := m.applyRefreshSnapshot(cfg); err != nil {
			m.markRefreshError(err)
		}
	}
}

func (m *managedACGateway) applyRefreshSnapshot(cfg fileConfig) error {
	acceptUntil, err := acAcceptNewTasksUntil(cfg)
	if err != nil {
		return err
	}
	m.mu.RLock()
	sameRevision := strings.TrimSpace(cfg.ACRuntime.ConfigRevision) != "" &&
		strings.TrimSpace(cfg.ACRuntime.ConfigRevision) == strings.TrimSpace(m.cfg.ACRuntime.ConfigRevision)
	runtime := m.runtime
	previous := m.gateway
	m.mu.RUnlock()
	if sameRevision {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.cfg.ACRuntime = cfg.ACRuntime
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

func (m *managedACGateway) markRefreshError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.ACRuntime.FetchStatus = "stale"
	m.cfg.ACRuntime.FetchError = err.Error()
}

func (m *managedACGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func acConfigPollInterval() time.Duration {
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
		Build:              runtimeBuild{ReleaseTag: releaseTag, GitSHA: commit, Date: date},
		AwebVersion:        version,
		AWIDServiceVersion: ">=" + minimumAWIDServiceVersion,
		AWIDRegistry:       checkRegistryHealth(cfg.RegistryURL),
		ACConfig:           acConfigHealth(cfg),
		GatewayIdentity:    gatewayIdentityHealth(cfg),
		Gateway:            map[string]interface{}{},
	}
	gatewayHealthBytes, err := json.Marshal(gateway.Health())
	if err == nil {
		_ = json.Unmarshal(gatewayHealthBytes, &health.Gateway)
	}
	if health.ACConfig.Status == "pending" {
		health.Status = "pending"
	}
	if health.ACConfig.Status == "stale" && health.ACConfig.ConfigRevision == "" {
		health.Status = "unhealthy"
	}
	if !health.AWIDRegistry.Reachable || !health.AWIDRegistry.Compatible || health.ACConfig.Expired || (health.ACConfig.Routes > 0 && !health.GatewayIdentity.Usable) {
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

func acConfigHealth(cfg fileConfig) runtimeACConfigHealth {
	out := runtimeACConfigHealth{
		Enabled:        acConfigEnabled(cfg.ACConfig),
		GatewayID:      strings.TrimSpace(cfg.ACConfig.GatewayID),
		ConfigRevision: strings.TrimSpace(cfg.ACRuntime.ConfigRevision),
		ExpiresAt:      strings.TrimSpace(cfg.ACRuntime.ExpiresAt),
		Routes:         len(cfg.Routes),
		Status:         strings.TrimSpace(cfg.ACRuntime.FetchStatus),
		Error:          strings.TrimSpace(cfg.ACRuntime.FetchError),
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
	status := strings.TrimSpace(cfg.ACRuntime.GatewayIdentityStatus)
	if !acConfigEnabled(cfg.ACConfig) && identity == "" {
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
	Listen                    string        `yaml:"listen"`
	Host                      string        `yaml:"host"`
	WorkspaceDir              string        `yaml:"workspace_dir"`
	TeamID                    string        `yaml:"team_id"`
	RootCardMode              string        `yaml:"root_card_mode"`
	DefaultRouteID            string        `yaml:"default_route_id"`
	GatewayIdentity           string        `yaml:"gateway_identity"`
	RegistryURL               string        `yaml:"registry_url"`
	PollInterval              string        `yaml:"poll_interval"`
	PollTimeout               string        `yaml:"poll_timeout"`
	UseIdentityAuth           *bool         `yaml:"use_identity_auth"`
	RequireVerifiedReplies    *bool         `yaml:"require_verified_replies"`
	AllowUnverifiedLocalReply bool          `yaml:"allow_unverified_local_reply"`
	AllowQuestionReply        bool          `yaml:"allow_question_reply"`
	RouterCard                cardConfig    `yaml:"router_card"`
	Routes                    []routeConfig `yaml:"routes"`
	Audit                     auditConfig   `yaml:"audit"`
	ACConfig                  acConfig      `yaml:"ac_config"`
	ACRuntime                 acRuntimeMeta `yaml:"-"`
}

type acConfig struct {
	BaseURL        string `yaml:"base_url"`
	URL            string `yaml:"url"`
	BridgeURL      string `yaml:"bridge_url"`
	GatewayID      string `yaml:"gateway_id"`
	BearerToken    string `yaml:"bearer_token"`
	BearerTokenEnv string `yaml:"bearer_token_env"`
}

type acRuntimeMeta struct {
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
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fileConfig{}, err
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
	envCfg, ok := hostedEnvConfig()
	if ok {
		return envCfg, nil
	}
	if path == "" {
		return fileConfig{}, fmt.Errorf("--config or AWEB_A2A_GW_CONFIG is required unless AWEB_A2A_GATEWAY_CONFIG_TOKEN is set")
	}
	return fileConfig{}, fmt.Errorf("open %s: no such file or directory; set a mounted config file or set AWEB_A2A_GATEWAY_CONFIG_TOKEN for hosted AC-managed env config", path)
}

func hostedEnvConfig() (fileConfig, bool) {
	if strings.TrimSpace(os.Getenv("AWEB_A2A_GATEWAY_CONFIG_TOKEN")) == "" {
		return fileConfig{}, false
	}
	return fileConfig{
		Host:        firstNonEmpty(os.Getenv("AWEB_A2A_GW_HOST"), "a2a.aweb.ai"),
		RegistryURL: firstNonEmpty(os.Getenv("AWEB_A2A_GW_REGISTRY_URL"), "https://api.awid.ai"),
		ACConfig: acConfig{
			BaseURL:        firstNonEmpty(os.Getenv("AWEB_A2A_GW_AC_BASE_URL"), "https://app.aweb.ai"),
			GatewayID:      firstNonEmpty(os.Getenv("AWEB_A2A_GW_ID"), "a2a-gateway"),
			BearerTokenEnv: "AWEB_A2A_GATEWAY_CONFIG_TOKEN",
		},
	}, true
}

type acRuntimeConfigPayload struct {
	GatewayID             string                 `json:"gateway_id"`
	GatewayIdentity       string                 `json:"gateway_identity"`
	GatewayIdentityStatus string                 `json:"gateway_identity_status"`
	ConfigRevision        string                 `json:"config_revision"`
	ExpiresAt             string                 `json:"expires_at"`
	Routes                []acRuntimeRoute       `json:"routes"`
	RouteCounts           map[string]interface{} `json:"route_counts"`
}

type acRuntimeRoute struct {
	RouteID          string                 `json:"route_id"`
	Host             string                 `json:"host"`
	Address          string                 `json:"address"`
	Mode             string                 `json:"mode"`
	Disabled         bool                   `json:"disabled"`
	RootBehavior     string                 `json:"root_behavior"`
	VerificationTier string                 `json:"verification_tier"`
	CardDigest       string                 `json:"card_digest"`
	CardRevision     string                 `json:"card_revision"`
	Auth             acRuntimeAuth          `json:"auth"`
	Limits           acRuntimeLimits        `json:"limits"`
	Card             acRuntimeCard          `json:"card"`
	AWIDPublication  acRuntimeAWID          `json:"awid_publication"`
	Extra            map[string]interface{} `json:"-"`
}

type acRuntimeAuth struct {
	Mode      string `json:"mode"`
	SecretRef string `json:"secret_ref"`
}

type acRuntimeLimits struct {
	RateLimit              map[string]interface{} `json:"rate_limit"`
	MaxMessageBytes        int                    `json:"max_message_bytes"`
	MaxConcurrentTasks     int                    `json:"max_concurrent_tasks"`
	TaskTTLSeconds         int                    `json:"task_ttl_seconds"`
	ResponseTimeoutSeconds int                    `json:"response_timeout_seconds"`
}

type acRuntimeCard struct {
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

type acRuntimeAWID struct {
	PublicationID        string `json:"publication_id"`
	PublicationDigest    string `json:"publication_digest"`
	PublicationStatus    string `json:"publication_status"`
	PublicationExpiresAt string `json:"publication_expires_at"`
	DelegationID         string `json:"delegation_id"`
	DelegationDigest     string `json:"delegation_digest"`
	DelegationStatus     string `json:"delegation_status"`
	DelegationExpiresAt  string `json:"delegation_expires_at"`
}

type acRuntimeConfigFetchError struct {
	StatusCode int
	Message    string
}

func (e *acRuntimeConfigFetchError) Error() string {
	return e.Message
}

func applyACRuntimeConfig(cfg *fileConfig) error {
	url, err := acConfigURL(cfg.ACConfig)
	if err != nil {
		return err
	}
	if url == "" {
		return nil
	}
	token := acBearerToken(cfg.ACConfig)
	if token == "" {
		return fmt.Errorf("ac_config bearer token is required")
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return &acRuntimeConfigFetchError{Message: fmt.Sprintf("fetch AC runtime config: %v", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &acRuntimeConfigFetchError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("fetch AC runtime config: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	var payload acRuntimeConfigPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode AC runtime config: %w", err)
	}
	return mergeACRuntimeConfig(cfg, payload)
}

func isFatalInitialACRuntimeConfigError(err error) bool {
	var fetchErr *acRuntimeConfigFetchError
	if err != nil && strings.Contains(err.Error(), "bearer token is required") {
		return true
	}
	if err != nil && errors.As(err, &fetchErr) {
		return fetchErr.StatusCode == http.StatusUnauthorized || fetchErr.StatusCode == http.StatusForbidden
	}
	return false
}

func degradedACConfig(base fileConfig, err error) fileConfig {
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
	cfg.ACRuntime = acRuntimeMeta{
		GatewayIdentityStatus: "missing",
		FetchStatus:           "pending",
		FetchError:            err.Error(),
	}
	return cfg
}

func mergeACRuntimeConfig(cfg *fileConfig, payload acRuntimeConfigPayload) error {
	if strings.TrimSpace(payload.GatewayIdentityStatus) != "active" {
		return fmt.Errorf("AC runtime config gateway identity is not active: %s", payload.GatewayIdentityStatus)
	}
	if expiresAt := strings.TrimSpace(payload.ExpiresAt); expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return fmt.Errorf("AC runtime config expires_at: %w", err)
		}
		if time.Now().After(parsed) {
			return fmt.Errorf("AC runtime config expired at %s", expiresAt)
		}
	}
	if strings.TrimSpace(payload.GatewayIdentity) != "" {
		cfg.GatewayIdentity = strings.TrimSpace(payload.GatewayIdentity)
	}
	if cfg.ACConfig.GatewayID == "" {
		cfg.ACConfig.GatewayID = strings.TrimSpace(payload.GatewayID)
	}
	cfg.ACRuntime = acRuntimeMeta{
		GatewayIdentityStatus: strings.TrimSpace(payload.GatewayIdentityStatus),
		ConfigRevision:        strings.TrimSpace(payload.ConfigRevision),
		ExpiresAt:             strings.TrimSpace(payload.ExpiresAt),
		FetchStatus:           "ok",
	}
	cfg.Routes = make([]routeConfig, 0, len(payload.Routes))
	defaultRouteID := ""
	routerRoutes := 0
	for _, route := range payload.Routes {
		converted := routeConfig{
			RouteID:         strings.TrimSpace(route.RouteID),
			Address:         strings.TrimSpace(route.Address),
			Mode:            strings.TrimSpace(route.Mode),
			Disabled:        route.Disabled || acRuntimeAuthRequiresUnavailableSecret(route.Auth),
			ResponseTimeout: secondsDuration(route.Limits.ResponseTimeoutSeconds),
			Auth:            authConfig{Mode: strings.TrimSpace(route.Auth.Mode)},
			Limits: limitsConfig{
				MaxMessageBytes:    route.Limits.MaxMessageBytes,
				RateLimit:          rateLimitFromAC(route.Limits.RateLimit),
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

func acRuntimeAuthRequiresUnavailableSecret(auth acRuntimeAuth) bool {
	return strings.TrimSpace(auth.Mode) == "static_api_key" && strings.TrimSpace(auth.SecretRef) != ""
}

func secondsDuration(seconds int) string {
	if seconds <= 0 {
		return ""
	}
	return (time.Duration(seconds) * time.Second).String()
}

func rateLimitFromAC(value map[string]interface{}) string {
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

func acConfigEnabled(cfg acConfig) bool {
	return strings.TrimSpace(cfg.URL) != "" ||
		strings.TrimSpace(cfg.BaseURL) != "" ||
		strings.TrimSpace(cfg.BridgeURL) != ""
}

func acBearerToken(cfg acConfig) string {
	return firstNonEmpty(cfg.BearerToken, envValue(cfg.BearerTokenEnv))
}

func acConfigURL(cfg acConfig) (string, error) {
	if raw := strings.TrimSpace(cfg.URL); raw != "" {
		return raw, nil
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	gatewayID := strings.TrimSpace(cfg.GatewayID)
	if base == "" {
		return "", nil
	}
	if gatewayID == "" {
		return "", fmt.Errorf("ac_config.gateway_id is required when ac_config.base_url is used")
	}
	return base + "/api/v1/a2a/gateway/config/" + url.PathEscape(gatewayID), nil
}

func acBridgeURL(cfg acConfig) (string, error) {
	if raw := strings.TrimSpace(cfg.BridgeURL); raw != "" {
		return strings.TrimRight(raw, "/"), nil
	}
	if base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"); base != "" {
		return base + "/api/v1/a2a/gateway/bridge", nil
	}
	rawConfigURL := strings.TrimSpace(cfg.URL)
	if rawConfigURL == "" {
		return "", fmt.Errorf("ac_config bridge URL is required")
	}
	const marker = "/api/v1/a2a/gateway/config/"
	idx := strings.Index(rawConfigURL, marker)
	if idx < 0 {
		return "", fmt.Errorf("ac_config.bridge_url is required when ac_config.url is not an AC config endpoint")
	}
	return strings.TrimRight(rawConfigURL[:idx], "/") + "/api/v1/a2a/gateway/bridge", nil
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
	audit       a2agw.AuditSink
	bridge      *a2agw.MailBridge
	acTransport *acMailTransport
}

func (r *gatewayRuntime) applyConfig(cfg fileConfig, gateway *a2agw.Gateway, gatewayIdentity string) {
	if r == nil {
		return
	}
	if r.acTransport != nil {
		r.acTransport.UpdateFromConfig(cfg)
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
	if acTransport, ok := client.(*acMailTransport); ok {
		if runtime.acTransport == nil {
			if !createdRuntime {
				return nil, nil, fmt.Errorf("existing gateway runtime is missing AC mail transport")
			}
			runtime.acTransport = acTransport
		}
		client = runtime.acTransport
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
	if acConfigEnabled(cfg.ACConfig) {
		client, err := acMailTransportFromConfig(cfg)
		if err != nil {
			return nil, "", err
		}
		return client, firstNonEmpty(cfg.GatewayIdentity, cfg.ACConfig.GatewayID), nil
	}
	workspaceDir := strings.TrimSpace(cfg.WorkspaceDir)
	if workspaceDir == "" {
		workspaceDir = "."
	}
	return workspaceMailClient(workspaceDir, cfg.TeamID, cfg.RegistryURL, cfg.GatewayIdentity)
}

func gatewayIdentityFromConfig(cfg fileConfig) string {
	if acConfigEnabled(cfg.ACConfig) {
		return firstNonEmpty(cfg.GatewayIdentity, cfg.ACConfig.GatewayID)
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
	acceptUntil, err := acAcceptNewTasksUntil(cfg)
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

func acAcceptNewTasksUntil(cfg fileConfig) (time.Time, error) {
	if !acConfigEnabled(cfg.ACConfig) {
		return time.Time{}, nil
	}
	expiresAt := strings.TrimSpace(cfg.ACRuntime.ExpiresAt)
	if expiresAt == "" {
		if strings.TrimSpace(cfg.ACRuntime.FetchStatus) == "pending" {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("AC runtime config expires_at is required in AC-managed mode")
	}
	parsed, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("AC runtime config expires_at: %w", err)
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

type acMailTransport struct {
	mu             sync.RWMutex
	httpClient     *http.Client
	bridgeURL      string
	gatewayID      string
	bearerToken    string
	routeByAddress map[string]string
}

func acMailTransportFromConfig(cfg fileConfig) (*acMailTransport, error) {
	bridgeURL, err := acBridgeURL(cfg.ACConfig)
	if err != nil {
		return nil, err
	}
	gatewayID := strings.TrimSpace(cfg.ACConfig.GatewayID)
	if gatewayID == "" {
		return nil, fmt.Errorf("ac_config.gateway_id is required")
	}
	token := acBearerToken(cfg.ACConfig)
	if token == "" {
		return nil, fmt.Errorf("ac_config bearer token is required")
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
	return &acMailTransport{
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		bridgeURL:      bridgeURL,
		gatewayID:      gatewayID,
		bearerToken:    token,
		routeByAddress: routeByAddress,
	}, nil
}

func (t *acMailTransport) UpdateFromConfig(cfg fileConfig) {
	bridgeURL, bridgeErr := acBridgeURL(cfg.ACConfig)
	token := acBearerToken(cfg.ACConfig)
	gatewayID := strings.TrimSpace(cfg.ACConfig.GatewayID)
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

func (t *acMailTransport) SendMessage(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	return t.send(ctx, req)
}

func (t *acMailTransport) SendMessageByIdentity(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	return t.send(ctx, req)
}

func (t *acMailTransport) send(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("send request is required")
	}
	address := strings.TrimSpace(req.ToAddress)
	if address == "" {
		return nil, fmt.Errorf("AC-managed A2A bridge requires to_address")
	}
	t.mu.RLock()
	routeID := strings.TrimSpace(t.routeByAddress[address])
	gatewayID := t.gatewayID
	t.mu.RUnlock()
	if routeID == "" {
		return nil, fmt.Errorf("AC-managed A2A bridge has no route for address %s", address)
	}
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
	if err := t.doJSON(ctx, http.MethodPost, "/"+url.PathEscape(gatewayID)+"/messages", payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (t *acMailTransport) MailConversation(ctx context.Context, conversationID string, limit int) (*awid.InboxResponse, error) {
	return t.MailConversationForRoute(ctx, "", "", conversationID, limit)
}

func (t *acMailTransport) MailConversationForRoute(ctx context.Context, routeID, address, conversationID string, limit int) (*awid.InboxResponse, error) {
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

func (t *acMailTransport) doJSON(ctx context.Context, method, path string, payload interface{}, out interface{}) error {
	t.mu.RLock()
	bridgeURL := t.bridgeURL
	bearerToken := t.bearerToken
	t.mu.RUnlock()
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
		return fmt.Errorf("AC bridge %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode AC bridge response: %w", err)
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
