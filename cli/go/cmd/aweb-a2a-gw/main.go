package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/a2agw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

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
	if strings.TrimSpace(*configPath) == "" {
		return fmt.Errorf("--config or AWEB_A2A_GW_CONFIG is required")
	}
	cfg, err := loadFileConfig(*configPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*listenOverride) != "" {
		cfg.Listen = strings.TrimSpace(*listenOverride)
	}
	if strings.TrimSpace(*workspaceOverride) != "" {
		cfg.WorkspaceDir = strings.TrimSpace(*workspaceOverride)
	}
	gateway, err := buildGateway(cfg)
	if err != nil {
		return err
	}
	if *checkOnly {
		return json.NewEncoder(stdout).Encode(gateway.Diagnostics())
	}
	listen := firstNonEmpty(cfg.Listen, ":8080")
	server := &http.Server{
		Addr:              listen,
		Handler:           gateway,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return server.ListenAndServe()
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

func buildGateway(cfg fileConfig) (*a2agw.Gateway, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("host is required")
	}
	workspaceDir := strings.TrimSpace(cfg.WorkspaceDir)
	if workspaceDir == "" {
		workspaceDir = "."
	}
	client, gatewayIdentity, err := workspaceMailClient(workspaceDir, cfg.TeamID, cfg.RegistryURL, cfg.GatewayIdentity)
	if err != nil {
		return nil, err
	}
	audit, err := auditSinkFromConfig(cfg.Audit)
	if err != nil {
		return nil, err
	}
	pollInterval, err := parseOptionalDuration("poll_interval", cfg.PollInterval)
	if err != nil {
		return nil, err
	}
	pollTimeout, err := parseOptionalDuration("poll_timeout", cfg.PollTimeout)
	if err != nil {
		return nil, err
	}
	requireVerified := true
	if cfg.RequireVerifiedReplies != nil {
		requireVerified = *cfg.RequireVerifiedReplies
	}
	useIdentityAuth := true
	if cfg.UseIdentityAuth != nil {
		useIdentityAuth = *cfg.UseIdentityAuth
	}
	bridge, err := a2agw.NewMailBridge(a2agw.MailBridgeConfig{
		Client:                    client,
		GatewayIdentity:           gatewayIdentity,
		UseIdentityAuth:           useIdentityAuth,
		PollInterval:              pollInterval,
		PollTimeout:               pollTimeout,
		RequireVerifiedReplies:    requireVerified,
		AllowUnverifiedLocalReply: cfg.AllowUnverifiedLocalReply,
		AllowQuestionReply:        cfg.AllowQuestionReply,
		Audit:                     audit,
	})
	if err != nil {
		return nil, err
	}
	gatewayConfig, err := gatewayConfigFromFile(cfg, bridge, audit)
	if err != nil {
		return nil, err
	}
	gateway, err := a2agw.New(gatewayConfig)
	if err != nil {
		return nil, err
	}
	bridge.SetReplyApplier(gateway)
	return gateway, nil
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
	return a2agw.Config{
		Host:           strings.TrimSpace(cfg.Host),
		RootCardMode:   a2agw.RootCardMode(strings.TrimSpace(cfg.RootCardMode)),
		DefaultRouteID: strings.TrimSpace(cfg.DefaultRouteID),
		RouterCard:     convertRouterCard(cfg.RouterCard),
		Routes:         routes,
		Bridge:         bridge,
		Audit:          audit,
	}, nil
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
	baseURL := firstNonEmpty(teamMembership.AwebURL, workspace.AwebURL)
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
