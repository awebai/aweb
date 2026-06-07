package a2a

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	awid "github.com/awebai/aw/awid"
)

const (
	ProtocolBindingJSONRPC = "JSONRPC"
	ProtocolVersion10      = "1.0"

	WellKnownAgentCardPath = "/.well-known/agent-card.json"
)

var (
	falseBool = false
	trueBool  = true
)

type Card struct {
	Name                 string                    `json:"name"`
	Description          string                    `json:"description"`
	Provider             *Provider                 `json:"provider,omitempty"`
	Version              string                    `json:"version"`
	DocumentationURL     string                    `json:"documentationUrl,omitempty"`
	Capabilities         *Capabilities             `json:"capabilities"`
	SecuritySchemes      map[string]SecurityScheme `json:"securitySchemes,omitempty"`
	SecurityRequirements []SecurityRequirement     `json:"securityRequirements,omitempty"`
	DefaultInputModes    []string                  `json:"defaultInputModes"`
	DefaultOutputModes   []string                  `json:"defaultOutputModes"`
	SupportedInterfaces  []Interface               `json:"supportedInterfaces"`
	Skills               []Skill                   `json:"skills"`
	Signatures           []Signature               `json:"signatures,omitempty"`
	IconURL              string                    `json:"iconUrl,omitempty"`
}

type Provider struct {
	Organization string `json:"organization"`
	URL          string `json:"url"`
}

type Capabilities struct {
	Streaming         *bool       `json:"streaming,omitempty"`
	PushNotifications *bool       `json:"pushNotifications,omitempty"`
	Extensions        []Extension `json:"extensions,omitempty"`
	ExtendedAgentCard *bool       `json:"extendedAgentCard,omitempty"`
}

type Extension struct {
	URI         string         `json:"uri"`
	Description string         `json:"description,omitempty"`
	Required    bool           `json:"required,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
}

type Interface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion"`
	Tenant          string `json:"tenant,omitempty"`
}

type Skill struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	Description          string                `json:"description"`
	Tags                 []string              `json:"tags"`
	Examples             []string              `json:"examples,omitempty"`
	InputModes           []string              `json:"inputModes,omitempty"`
	OutputModes          []string              `json:"outputModes,omitempty"`
	SecurityRequirements []SecurityRequirement `json:"securityRequirements,omitempty"`
}

type Signature struct {
	Protected string         `json:"protected"`
	Signature string         `json:"signature"`
	Header    map[string]any `json:"header,omitempty"`
}

type SecurityRequirement map[string][]string

// SecurityScheme is intentionally permissive at this layer. The A2A v1 schema
// allows several OpenAPI-derived oneof shapes; route auth hardening lives in
// the gateway/auth slices.
type SecurityScheme map[string]any

type CardConfig struct {
	Host               string
	RouteID            string
	Name               string
	Description        string
	Provider           Provider
	Version            string
	Streaming          bool
	PushNotifications  bool
	Extensions         []Extension
	DefaultInputModes  []string
	DefaultOutputModes []string
	Skills             []Skill
}

type RouterCardConfig struct {
	Host               string
	Name               string
	Description        string
	Provider           Provider
	Version            string
	Streaming          bool
	PushNotifications  bool
	Extensions         []Extension
	DefaultInputModes  []string
	DefaultOutputModes []string
	Skills             []Skill
}

type Digest struct {
	CanonicalNoSignatures string
	Value                 string
}

type ValidationOptions struct {
	CardPath              string
	RequireJSONRPCOnly    bool
	DisallowDirectTenant  bool
	RequireMediaTypeModes bool
}

type VerificationTier int

const (
	VerificationTier0 VerificationTier = iota
	VerificationTier1
	VerificationTier2
)

type VerificationStatus string

const (
	VerificationIgnored      VerificationStatus = "ignored"
	VerificationUnsigned     VerificationStatus = "unsigned"
	VerificationSignatureOK  VerificationStatus = "signature_ok"
	VerificationAWIDVerified VerificationStatus = "awid_verified"
	VerificationAWIDRequired VerificationStatus = "awid_required"
	VerificationFailed       VerificationStatus = "failed"
)

type VerificationResult struct {
	Tier    VerificationTier   `json:"tier"`
	Status  VerificationStatus `json:"status"`
	Code    string             `json:"code,omitempty"`
	Message string             `json:"message,omitempty"`
	Digest  string             `json:"digest,omitempty"`
}

func AWIDPublicationExtension() Extension {
	return Extension{
		URI:         "https://aweb.ai/a2a/ext/awid-publication/v1",
		Description: "AWID publication and delegation metadata",
	}
}

func Bool(value bool) *bool {
	if value {
		return &trueBool
	}
	return &falseBool
}

func PerAddressCard(config CardConfig) (Card, error) {
	if err := validateRouteConfig(config.Host, config.RouteID); err != nil {
		return Card{}, err
	}
	host := strings.TrimSpace(config.Host)
	routeID := strings.TrimSpace(config.RouteID)
	card := baseCard(config)
	card.SupportedInterfaces = []Interface{{
		URL:             "https://" + host + DirectRPCPath(routeID),
		ProtocolBinding: ProtocolBindingJSONRPC,
		ProtocolVersion: ProtocolVersion10,
	}}
	if err := validateCardBasics(card); err != nil {
		return Card{}, err
	}
	return card, nil
}

func RootDefaultCard(config CardConfig) (Card, error) {
	if err := validateRouteConfig(config.Host, config.RouteID); err != nil {
		return Card{}, err
	}
	host := strings.TrimSpace(config.Host)
	routeID := strings.TrimSpace(config.RouteID)
	card := baseCard(config)
	card.SupportedInterfaces = []Interface{{
		URL:             "https://" + host + DirectRPCPath(routeID),
		ProtocolBinding: ProtocolBindingJSONRPC,
		ProtocolVersion: ProtocolVersion10,
	}}
	if err := validateCardBasics(card); err != nil {
		return Card{}, err
	}
	return card, nil
}

func RootRouterCard(config RouterCardConfig) (Card, error) {
	if err := validateHost(config.Host); err != nil {
		return Card{}, err
	}
	host := strings.TrimSpace(config.Host)
	if len(config.Skills) == 0 {
		return Card{}, fmt.Errorf("at least one skill is required")
	}
	card := Card{
		Name:        strings.TrimSpace(config.Name),
		Description: strings.TrimSpace(config.Description),
		Provider:    &config.Provider,
		Version:     defaultVersion(config.Version),
		Capabilities: &Capabilities{
			Streaming:         Bool(config.Streaming),
			PushNotifications: Bool(config.PushNotifications),
			Extensions:        defaultExtensions(config.Extensions),
		},
		DefaultInputModes:   defaultModes(config.DefaultInputModes),
		DefaultOutputModes:  defaultModes(config.DefaultOutputModes),
		SupportedInterfaces: []Interface{{URL: "https://" + host + "/a2a/rpc", ProtocolBinding: ProtocolBindingJSONRPC, ProtocolVersion: ProtocolVersion10}},
		Skills:              config.Skills,
	}
	if err := validateCardBasics(card); err != nil {
		return Card{}, err
	}
	return card, nil
}

func DirectCardPath(routeID string) string {
	return "/a2a/agents/" + routeID + "/agent-card.json"
}

func DirectRPCPath(routeID string) string {
	return "/a2a/agents/" + routeID + "/rpc"
}

func CardDigest(card Card) (Digest, error) {
	value, err := cardToMap(card)
	if err != nil {
		return Digest{}, err
	}
	delete(value, "signatures")
	canonical, err := awid.CanonicalJSONValue(value)
	if err != nil {
		return Digest{}, err
	}
	sum := sha256.Sum256([]byte(canonical))
	return Digest{
		CanonicalNoSignatures: canonical,
		Value:                 "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

func ValidateCard(card Card, options ValidationOptions) error {
	value, err := cardToMap(card)
	if err != nil {
		return err
	}
	if err := ValidateCardMap(value, options); err != nil {
		return err
	}
	return nil
}

func ValidateCardMap(card map[string]any, options ValidationOptions) error {
	if err := requireAllowedKeys("AgentCard", card, agentCardFields); err != nil {
		return err
	}
	for _, field := range []string{"protocolVersion", "url", "stateTransitionHistory", "security"} {
		if _, ok := card[field]; ok {
			return fmt.Errorf("agent card must not contain legacy/non-v1 top-level field %q", field)
		}
	}
	if version, _ := card["version"].(string); version == "" {
		return fmt.Errorf("agent card version is required")
	} else if version == ProtocolVersion10 {
		return fmt.Errorf("agent card version %q looks like protocol version; supportedInterfaces[].protocolVersion carries protocol version", version)
	}
	if options.RequireMediaTypeModes {
		for _, field := range []string{"defaultInputModes", "defaultOutputModes"} {
			if err := validateMediaModes(field, card[field]); err != nil {
				return err
			}
		}
	}
	if capabilities, ok := card["capabilities"].(map[string]any); ok {
		if err := requireAllowedKeys("AgentCapabilities", capabilities, agentCapabilitiesFields); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("agent card capabilities object is required")
	}
	interfaces, ok := card["supportedInterfaces"].([]any)
	if !ok || len(interfaces) == 0 {
		return fmt.Errorf("agent card supportedInterfaces must be a non-empty array")
	}
	for _, value := range interfaces {
		iface, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("supportedInterfaces entry is not an object")
		}
		if err := requireAllowedKeys("AgentInterface", iface, agentInterfaceFields); err != nil {
			return err
		}
		if options.RequireJSONRPCOnly {
			if iface["protocolBinding"] != ProtocolBindingJSONRPC {
				return fmt.Errorf("protocolBinding: got %v, want %s", iface["protocolBinding"], ProtocolBindingJSONRPC)
			}
			if iface["protocolVersion"] != ProtocolVersion10 {
				return fmt.Errorf("protocolVersion: got %v, want %s", iface["protocolVersion"], ProtocolVersion10)
			}
		}
		if options.DisallowDirectTenant && strings.HasPrefix(options.CardPath, "/a2a/agents/") {
			if _, ok := iface["tenant"]; ok {
				return fmt.Errorf("direct per-address cards must omit supportedInterfaces[].tenant by default")
			}
		}
		if options.CardPath != "" && strings.HasPrefix(options.CardPath, "/a2a/agents/") {
			urlValue, _ := iface["url"].(string)
			routePrefix := strings.TrimSuffix(options.CardPath, "/agent-card.json")
			if !strings.HasSuffix(urlValue, routePrefix+"/rpc") {
				return fmt.Errorf("per-address rpc URL %q does not match card path %q", urlValue, options.CardPath)
			}
		}
	}
	if skills, ok := card["skills"].([]any); ok {
		if len(skills) == 0 {
			return fmt.Errorf("agent card skills must be non-empty")
		}
		for _, value := range skills {
			skill, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("skills entry is not an object")
			}
			if err := requireAllowedKeys("AgentSkill", skill, agentSkillFields); err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("agent card skills must be a non-empty array")
	}
	return nil
}

func VerifyTier0(card Card) (VerificationResult, error) {
	digest, err := CardDigest(card)
	if err != nil {
		return VerificationResult{}, err
	}
	return VerificationResult{Tier: VerificationTier0, Status: VerificationIgnored, Digest: digest.Value}, nil
}

func VerifyTier2Unavailable(card Card) (VerificationResult, error) {
	digest, err := CardDigest(card)
	if err != nil {
		return VerificationResult{}, err
	}
	return VerificationResult{
		Tier:    VerificationTier2,
		Status:  VerificationAWIDRequired,
		Code:    "awid_publication_verification_unavailable",
		Message: "AWID publication and delegation verification is not implemented in this build",
		Digest:  digest.Value,
	}, nil
}

func baseCard(config CardConfig) Card {
	return Card{
		Name:        strings.TrimSpace(config.Name),
		Description: strings.TrimSpace(config.Description),
		Provider:    &config.Provider,
		Version:     defaultVersion(config.Version),
		Capabilities: &Capabilities{
			Streaming:         Bool(config.Streaming),
			PushNotifications: Bool(config.PushNotifications),
			Extensions:        defaultExtensions(config.Extensions),
		},
		DefaultInputModes:  defaultModes(config.DefaultInputModes),
		DefaultOutputModes: defaultModes(config.DefaultOutputModes),
		Skills:             config.Skills,
	}
}

func validateCardBasics(card Card) error {
	if card.Name == "" {
		return fmt.Errorf("agent card name is required")
	}
	if card.Description == "" {
		return fmt.Errorf("agent card description is required")
	}
	if card.Provider == nil || strings.TrimSpace(card.Provider.Organization) == "" || strings.TrimSpace(card.Provider.URL) == "" {
		return fmt.Errorf("agent card provider organization and url are required")
	}
	if card.Version == "" {
		return fmt.Errorf("agent card version is required")
	}
	if card.Capabilities == nil {
		return fmt.Errorf("agent card capabilities are required")
	}
	if len(card.DefaultInputModes) == 0 || len(card.DefaultOutputModes) == 0 {
		return fmt.Errorf("default input and output modes are required")
	}
	if len(card.Skills) == 0 {
		return fmt.Errorf("at least one skill is required")
	}
	return nil
}

func validateRouteConfig(host, routeID string) error {
	if err := validateHost(host); err != nil {
		return err
	}
	routeID = strings.TrimSpace(routeID)
	if routeID == "" || routeID == "." || strings.Contains(routeID, "..") {
		return fmt.Errorf("route_id must be a non-empty path-safe segment")
	}
	for _, r := range routeID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("route_id must be a non-empty path-safe segment")
	}
	return nil
}

func validateHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, `/\`) {
		return fmt.Errorf("host must be a bare hostname")
	}
	parsed, err := url.Parse("https://" + host)
	if err != nil {
		return fmt.Errorf("host is invalid: %w", err)
	}
	if parsed.Host != host {
		return fmt.Errorf("host must be a bare hostname")
	}
	return nil
}

func defaultVersion(version string) string {
	if strings.TrimSpace(version) == "" {
		return "1.0.0"
	}
	return strings.TrimSpace(version)
}

func defaultModes(values []string) []string {
	if len(values) == 0 {
		return []string{"text/plain"}
	}
	return values
}

func defaultExtensions(values []Extension) []Extension {
	if len(values) == 0 {
		return []Extension{AWIDPublicationExtension()}
	}
	return values
}

func cardToMap(card Card) (map[string]any, error) {
	body, err := json.Marshal(card)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func requireAllowedKeys(label string, object map[string]any, fields map[string]bool) error {
	for key := range object {
		if !fields[key] {
			return fmt.Errorf("%s field %q is not in pinned A2A generated schema field set", label, key)
		}
	}
	return nil
}

func validateMediaModes(field string, value any) error {
	values, ok := value.([]any)
	if !ok || len(values) == 0 {
		return fmt.Errorf("%s must be a non-empty array", field)
	}
	for _, raw := range values {
		mode, ok := raw.(string)
		if !ok || !strings.Contains(mode, "/") {
			return fmt.Errorf("%s value %v is not a media type", field, raw)
		}
	}
	return nil
}

func fieldSet(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

var agentCardFields = fieldSet(
	"capabilities",
	"defaultInputModes",
	"defaultOutputModes",
	"description",
	"documentationUrl",
	"iconUrl",
	"name",
	"provider",
	"securityRequirements",
	"securitySchemes",
	"signatures",
	"skills",
	"supportedInterfaces",
	"version",
)

var agentInterfaceFields = fieldSet("protocolBinding", "protocolVersion", "tenant", "url")

var agentCapabilitiesFields = fieldSet("extendedAgentCard", "extensions", "pushNotifications", "streaming")

var agentSkillFields = fieldSet("description", "examples", "id", "inputModes", "name", "outputModes", "securityRequirements", "tags")
