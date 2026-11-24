package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/termtext"
	"github.com/spf13/cobra"
)

var (
	a2aCardAddress   string
	a2aCardRegistry  string
	a2aContextID     string
	a2aSendBodyFile  string
	a2aWait          bool
	a2aNoWait        bool
	a2aDataJSON      string
	a2aHistoryLength int

	a2aPublishAddress         string
	a2aPublishRegistry        string
	a2aPublishGatewayIdentity string
	a2aPublishRouteID         string
	a2aPublishRPCURL          string
	a2aPublishCardRevision    string
	a2aPublishAssertionID     string
	a2aPublishDelegationID    string
	a2aPublishExpiresDays     int
	a2aPublishDefaultForHost  bool

	a2aHTTPClient = func() *http.Client {
		return &http.Client{Timeout: 30 * time.Second, Transport: awid.NewAPITransport()}
	}
)

type a2aSendInput struct {
	CardURL    string
	Text       string
	ContextID  string
	DataJSON   string
	Completion a2aCompletionPolicy
}

type a2aCompletionPolicy uint8

const (
	a2aReturnImmediately a2aCompletionPolicy = iota
	a2aWaitForReply
)

type a2aSendResult struct {
	Task           a2a.Task
	TokenSaveError error
}

type a2aTaskQuery struct {
	CardURL       string
	TaskID        string
	HistoryLength int
}

type a2aPublishInput struct {
	CardURL         string
	Address         string
	RegistryURL     string
	GatewayIdentity string
	RouteID         string
	RPCURL          string
	CardRevision    string
	AssertionID     string
	DelegationID    string
	ExpiresDays     int
	DefaultForHost  bool
}

// writeA2AOutput gives every A2A command the same JSON shape and checked output.
func writeA2AOutput[T any](cmd *cobra.Command, value T, formatter func(T) string) error {
	if jsonFlag {
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
	_, err := io.WriteString(cmd.OutOrStdout(), termtext.Body(formatter(value)))
	return err
}

type a2aCredentialsFile struct {
	Credentials []a2aCredentialEntry `yaml:"credentials"`
}

type a2aCredentialEntry struct {
	URL         string `yaml:"url,omitempty"`
	Host        string `yaml:"host,omitempty"`
	APIKey      string `yaml:"api_key,omitempty"`
	BearerToken string `yaml:"bearer_token,omitempty"`
	CallerID    string `yaml:"caller_id,omitempty"`
	TaskToken   string `yaml:"task_token,omitempty"`
	TaskID      string `yaml:"task_id,omitempty"`
	CreatedAt   string `yaml:"created_at,omitempty"`
}

type a2aCardOutput struct {
	URL          string                 `json:"url"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Version      string                 `json:"version"`
	Digest       string                 `json:"digest"`
	Interfaces   []a2a.Interface        `json:"interfaces"`
	Skills       []a2a.Skill            `json:"skills"`
	Verification a2a.VerificationResult `json:"verification"`
}

type a2aTaskEnvelope struct {
	Task a2a.Task `json:"task"`
}

type a2aPublishOutput struct {
	Address         string                 `json:"address"`
	RegistryURL     string                 `json:"registry_url"`
	CardURL         string                 `json:"card_url"`
	RPCURL          string                 `json:"rpc_url"`
	RouteID         string                 `json:"route_id"`
	GatewayIdentity string                 `json:"gateway_identity"`
	CardDigest      string                 `json:"card_digest"`
	CardRevision    string                 `json:"card_revision"`
	Delegation      *awid.A2AWriteResponse `json:"delegation,omitempty"`
	Publication     *awid.A2AWriteResponse `json:"publication"`
	Verification    a2a.VerificationResult `json:"verification"`
}

var a2aCmd = &cobra.Command{
	Use:   "a2a",
	Short: "Inspect and call A2A agents",
}

var a2aCardCmd = &cobra.Command{
	Use:   "card <url>",
	Short: "Fetch and verify an A2A Agent Card",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		out, err := buildA2ACardOutput(ctx, args[0], a2aCardAddress, a2aCardRegistry)
		if err != nil {
			return err
		}
		return writeA2AOutput(cmd, out, formatA2ACardOutput)
	},
}

var a2aSendCmd = &cobra.Command{
	Use:   "send <card-url> [message]",
	Short: "Send a task message to an A2A agent",
	Long:  shellExpandedInlineHelp("Send a task message to an A2A agent", "--body-file"),
	Args:  exactArgsWithBodyFile,
	RunE: func(cmd *cobra.Command, args []string) error {
		if a2aWait && a2aNoWait {
			return usageError("--wait and --no-wait are mutually exclusive")
		}
		message, err := resolvePositionalMessage(cmd, args)
		if err != nil {
			return err
		}
		// Agent task completion can involve a wait; keep the explicit ninety-second task budget.
		ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
		defer cancel()
		completion := a2aReturnImmediately
		if a2aWait && !a2aNoWait {
			completion = a2aWaitForReply
		}
		result, err := runA2ASend(ctx, a2aSendInput{CardURL: args[0], Text: message, ContextID: a2aContextID, DataJSON: a2aDataJSON, Completion: completion})
		if err != nil {
			return err
		}
		if err := writeA2AOutput(cmd, result.Task, formatA2ATask); err != nil {
			return err
		}
		if result.TokenSaveError != nil {
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Warning: task was delivered, but its token was not saved: %v. Keep task_bearer_token from this result for status or cancel; repair .aw/a2a-credentials.yaml before sending again.\n", result.TokenSaveError); err != nil {
				return err
			}
		}
		return a2aTaskExitError(result.Task)
	},
}

var a2aStatusCmd = &cobra.Command{
	Use:   "status <card-url> <task-id>",
	Short: "Fetch an A2A task",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		task, err := runA2AStatus(ctx, a2aTaskQuery{CardURL: args[0], TaskID: args[1], HistoryLength: a2aHistoryLength})
		if err != nil {
			return err
		}
		if err := writeA2AOutput(cmd, task, formatA2ATask); err != nil {
			return err
		}
		return a2aTaskExitError(task)
	},
}

var a2aCancelCmd = &cobra.Command{
	Use:   "cancel <card-url> <task-id>",
	Short: "Cancel an A2A task",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		task, err := runA2ACancel(ctx, a2aTaskQuery{CardURL: args[0], TaskID: args[1]})
		if err != nil {
			return err
		}
		return writeA2AOutput(cmd, task, formatA2ATask)
	},
}

var a2aPublishCmd = &cobra.Command{
	Use:   "publish <card-url>",
	Short: "Publish an A2A Agent Card route to AWID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Card publication fetches, verifies and registers a route; keep its explicit forty-five-second workflow budget.
		ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
		defer cancel()
		out, err := runA2APublish(ctx, a2aPublishInput{CardURL: args[0], Address: a2aPublishAddress, RegistryURL: a2aPublishRegistry, GatewayIdentity: a2aPublishGatewayIdentity, RouteID: a2aPublishRouteID, RPCURL: a2aPublishRPCURL, CardRevision: a2aPublishCardRevision, AssertionID: a2aPublishAssertionID, DelegationID: a2aPublishDelegationID, ExpiresDays: a2aPublishExpiresDays, DefaultForHost: a2aPublishDefaultForHost})
		if err != nil {
			return err
		}
		return writeA2AOutput(cmd, out, formatA2APublishOutput)
	},
}

func init() {
	a2aCmd.GroupID = groupNetwork
	a2aCardCmd.Flags().StringVar(&a2aCardAddress, "address", "", "aweb address to verify through AWID, e.g. acme.com/help")
	a2aCardCmd.Flags().StringVar(&a2aCardRegistry, "registry-url", "", "AWID registry URL for verification")
	a2aSendCmd.Flags().StringVar(&a2aContextID, "context", "", "A2A context ID")
	a2aSendCmd.Flags().StringVar(&a2aSendBodyFile, "body-file", "", safeFileInputHelp("message body"))
	a2aSendCmd.Flags().BoolVar(&a2aWait, "wait", false, "Wait for terminal or interrupted task state")
	a2aSendCmd.Flags().BoolVar(&a2aNoWait, "no-wait", false, "Return immediately after task creation")
	a2aSendCmd.Flags().StringVar(&a2aDataJSON, "data", "", "Additional JSON metadata object")
	a2aStatusCmd.Flags().IntVar(&a2aHistoryLength, "history", -1, "History length to request; -1 uses server default")
	a2aPublishCmd.Flags().StringVar(&a2aPublishAddress, "address", "", "aweb address to publish; defaults to current identity address")
	a2aPublishCmd.Flags().StringVar(&a2aPublishRegistry, "registry-url", "", "AWID registry URL override")
	a2aPublishCmd.Flags().StringVar(&a2aPublishGatewayIdentity, "gateway-identity", "", "did:aw of the A2A gateway identity; defaults to current identity for direct publication")
	a2aPublishCmd.Flags().StringVar(&a2aPublishRouteID, "route-id", "", "Route id override; defaults to the card URL route")
	a2aPublishCmd.Flags().StringVar(&a2aPublishRPCURL, "rpc-url", "", "RPC URL override; defaults to supportedInterfaces[0].url")
	a2aPublishCmd.Flags().StringVar(&a2aPublishCardRevision, "card-revision", "", "Card revision recorded in AWID; defaults to Agent Card version")
	a2aPublishCmd.Flags().StringVar(&a2aPublishAssertionID, "assertion-id", "", "Publication assertion id override")
	a2aPublishCmd.Flags().StringVar(&a2aPublishDelegationID, "delegation-id", "", "Bridge delegation id override")
	a2aPublishCmd.Flags().IntVar(&a2aPublishExpiresDays, "expires-days", 30, "Publication/delegation lifetime in days")
	a2aPublishCmd.Flags().BoolVar(&a2aPublishDefaultForHost, "default-for-host", false, "Mark this route as the default A2A route for the host")
	a2aCmd.AddCommand(a2aCardCmd, a2aSendCmd, a2aStatusCmd, a2aCancelCmd, a2aPublishCmd)
}

func buildA2ACardOutput(ctx context.Context, cardURL, address, registryURL string) (a2aCardOutput, error) {
	card, _, err := a2a.FetchCard(ctx, a2aHTTPClient(), cardURL)
	if err != nil {
		return a2aCardOutput{}, err
	}
	cardPath := ""
	if parsed, err := url.Parse(cardURL); err == nil {
		cardPath = parsed.Path
	}
	if err := a2a.ValidateCard(card, a2a.ValidationOptions{CardPath: cardPath, RequireJSONRPCOnly: true, DisallowDirectTenant: true, RequireMediaTypeModes: true}); err != nil {
		return a2aCardOutput{}, err
	}
	digest, err := a2a.CardDigest(card)
	if err != nil {
		return a2aCardOutput{}, err
	}
	verification := a2a.VerificationResult{Tier: a2a.VerificationTier0, Status: a2a.VerificationUnsigned, Digest: digest.Value}
	if len(card.Signatures) > 0 {
		verification.Message = "Agent Card contains signatures; aw a2a does not verify JWS yet. Use --address for AWID publication verification."
	}
	if strings.TrimSpace(address) != "" {
		verification = verifyA2ACardWithAWID(ctx, a2aCardVerification{CardURL: cardURL, Digest: digest.Value, Address: strings.TrimSpace(address), RegistryURL: strings.TrimSpace(registryURL), ExplicitRegistryURL: registryURL})
	}
	return a2aCardOutput{
		URL:          strings.TrimSpace(cardURL),
		Name:         card.Name,
		Description:  card.Description,
		Version:      card.Version,
		Digest:       digest.Value,
		Interfaces:   card.SupportedInterfaces,
		Skills:       card.Skills,
		Verification: verification,
	}, nil
}

type a2aPublicationAvailability string

const a2aPublicationAvailable a2aPublicationAvailability = "awid_publication_available"

type a2aCardVerification struct{ CardURL, Digest, Address, RegistryURL, ExplicitRegistryURL string }

type a2aRegistryChoice struct{ FallbackURL, ExplicitURL string }

// newA2ARegistryClient passes operator choice to the shared registry trust owner.
// Stored or discovered fallback URLs do not acquire operator authority
// (awid/registry_pin.go:139-141).
func newA2ARegistryClient(choice a2aRegistryChoice) (*awid.RegistryClient, error) {
	registry := awid.NewAWIDRegistryClient(a2aHTTPClient(), nil)
	if explicit := strings.TrimSpace(choice.ExplicitURL); explicit != "" {
		if err := registry.Resolver.TrustRegistryOrigin(explicit); err != nil {
			return nil, err
		}
	}
	if fallback := strings.TrimSpace(choice.FallbackURL); fallback != "" {
		if err := registry.SetFallbackRegistryURL(fallback); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func verifyA2ACardWithAWID(ctx context.Context, input a2aCardVerification) a2a.VerificationResult {
	cardURL, digestValue, address, registryURL := input.CardURL, input.Digest, input.Address, input.RegistryURL
	domain, name, err := splitA2AAddress(address)
	if err != nil {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_address_invalid", Message: err.Error(), Digest: digestValue}
	}
	registry, err := newA2ARegistryClient(a2aRegistryChoice{FallbackURL: registryURL, ExplicitURL: input.ExplicitRegistryURL})
	if err != nil {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_registry_url_invalid", Message: "Invalid A2A registry URL. Set --registry-url to an absolute registry origin and retry.", Digest: digestValue}
	}
	registry.RequestID = "aw-a2a-" + time.Now().UTC().Format("20060102T150405.000000000")
	lookup, _, err := registry.GetA2APublication(ctx, domain, name)
	if err != nil {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "awid_lookup_failed", Message: redactedRegistryError(err), Digest: digestValue}
	}
	if lookup == nil || lookup.A2A == nil {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_publication_missing", Message: "AWID has no active A2A publication for this address.", Digest: digestValue}
	}
	if strings.TrimSpace(lookup.A2A.Status) != awid.A2AStatusActive {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_publication_unavailable", Message: "AWID A2A publication is not active. Ask the address owner to publish an active route, then retry.", Digest: digestValue}
	}
	if a2aPublicationAvailability(strings.TrimSpace(lookup.A2A.Verification)) != a2aPublicationAvailable {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_publication_unavailable", Message: "AWID publication is not available. Ask the address owner to check publication and delegation, then retry.", Digest: digestValue}
	}
	if lookup.A2A.CardDigest != digestValue {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: awid.A2APublicationCodeCardDigestMismatch, Message: "Served card digest does not match active AWID publication.", Digest: digestValue}
	}
	if strings.TrimSpace(lookup.A2A.CardURL) != strings.TrimSpace(cardURL) {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_card_url_mismatch", Message: "Served card URL does not match active AWID publication. Use the card URL published by the address owner.", Digest: digestValue}
	}
	return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationAWIDVerified, Code: "awid_publication_verified", Message: "AWID publication active; served card digest matches.", Digest: digestValue}
}

func runA2ASend(ctx context.Context, input a2aSendInput) (a2aSendResult, error) {
	cardURL, text := input.CardURL, input.Text
	text = strings.TrimSpace(text)
	if text == "" {
		return a2aSendResult{}, usageError("message must not be empty")
	}
	_, rpcURL, credential, err := resolveA2ACallTarget(ctx, cardURL)
	if err != nil {
		return a2aSendResult{}, err
	}
	message := a2a.NewUserTextMessage(input.ContextID, text)
	params := a2a.SendMessageParams{
		Message: message,
		Configuration: a2a.SendConfiguration{
			ReturnImmediately:   input.Completion == a2aReturnImmediately,
			AcceptedOutputModes: []string{"text/plain", "application/json"},
		},
	}
	if strings.TrimSpace(input.DataJSON) != "" {
		var metadata map[string]any
		if err := json.Unmarshal([]byte(input.DataJSON), &metadata); err != nil {
			return a2aSendResult{}, usageError("--data must be a JSON object: %v", err)
		}
		params.Metadata = metadata
	}
	var resp a2aTaskEnvelope
	if err := (&a2a.Client{HTTPClient: a2aHTTPClient(), UserAgent: "aw/" + version}).Call(ctx, rpcURL, a2a.MethodSendMessage, params, credential, &resp); err != nil {
		return a2aSendResult{}, err
	}
	return a2aSendResult{Task: resp.Task, TokenSaveError: saveA2ATaskToken(rpcURL, resp.Task)}, nil
}

func runA2AStatus(ctx context.Context, input a2aTaskQuery) (a2a.Task, error) {
	cardURL, taskID := input.CardURL, input.TaskID
	_, rpcURL, credential, err := resolveA2ACallTarget(ctx, cardURL)
	if err != nil {
		return a2a.Task{}, err
	}
	token, err := loadA2ATaskToken(a2aCredentialQuery{CardURL: cardURL, RPCURL: rpcURL, TaskID: taskID})
	if err != nil {
		return a2a.Task{}, err
	}
	if token != "" {
		credential.TaskToken = token
	}
	params := map[string]any{"id": strings.TrimSpace(taskID)}
	if input.HistoryLength >= 0 {
		params["historyLength"] = input.HistoryLength
	}
	var task a2a.Task
	if err := (&a2a.Client{HTTPClient: a2aHTTPClient(), UserAgent: "aw/" + version}).Call(ctx, rpcURL, a2a.MethodGetTask, params, credential, &task); err != nil {
		return a2a.Task{}, err
	}
	return task, nil
}

func runA2ACancel(ctx context.Context, input a2aTaskQuery) (a2a.Task, error) {
	cardURL, taskID := input.CardURL, input.TaskID
	_, rpcURL, credential, err := resolveA2ACallTarget(ctx, cardURL)
	if err != nil {
		return a2a.Task{}, err
	}
	token, err := loadA2ATaskToken(a2aCredentialQuery{CardURL: cardURL, RPCURL: rpcURL, TaskID: taskID})
	if err != nil {
		return a2a.Task{}, err
	}
	if token != "" {
		credential.TaskToken = token
	}
	var task a2a.Task
	if err := (&a2a.Client{HTTPClient: a2aHTTPClient(), UserAgent: "aw/" + version}).Call(ctx, rpcURL, a2a.MethodCancelTask, map[string]any{"id": strings.TrimSpace(taskID)}, credential, &task); err != nil {
		return a2a.Task{}, err
	}
	return task, nil
}

func runA2APublish(ctx context.Context, input a2aPublishInput) (a2aPublishOutput, error) {
	cardURL := input.CardURL
	card, _, err := a2a.FetchCard(ctx, a2aHTTPClient(), cardURL)
	if err != nil {
		return a2aPublishOutput{}, err
	}
	cardPath := ""
	if parsed, err := url.Parse(cardURL); err == nil {
		cardPath = parsed.Path
	}
	if err := a2a.ValidateCard(card, a2a.ValidationOptions{CardPath: cardPath, RequireJSONRPCOnly: true, DisallowDirectTenant: true, RequireMediaTypeModes: true}); err != nil {
		return a2aPublishOutput{}, err
	}
	iface, err := a2a.SelectJSONRPCInterface(card)
	if err != nil {
		return a2aPublishOutput{}, err
	}
	if strings.TrimSpace(iface.Tenant) != "" {
		return a2aPublishOutput{}, usageError("aw a2a publish supports path-routed per-address cards only; remove supportedInterfaces[].tenant")
	}
	digest, err := a2a.CardDigest(card)
	if err != nil {
		return a2aPublishOutput{}, err
	}
	selection, err := awconfig.ResolveWorkspace(awconfig.ResolveOptions{AllowEnvOverrides: true})
	if err != nil {
		return a2aPublishOutput{}, err
	}
	signingKey, err := loadA2APublishSigningKey(selection)
	if err != nil {
		return a2aPublishOutput{}, err
	}
	pub := signingKey.Public().(ed25519.PublicKey)
	currentDIDKey := awid.ComputeDIDKey(pub)
	didAW := awid.ComputeStableID(pub)
	address := strings.TrimSpace(input.Address)
	if address == "" {
		address = strings.TrimSpace(selection.Address)
	}
	if address == "" {
		return a2aPublishOutput{}, usageError("A2A publication requires a global identity address; pass --address or run from a global identity workspace")
	}
	if strings.TrimSpace(selection.Address) != "" && !strings.EqualFold(address, strings.TrimSpace(selection.Address)) {
		return a2aPublishOutput{}, usageError("--address %s does not match current identity address %s; publish from the address identity workspace", address, selection.Address)
	}
	if strings.TrimSpace(selection.StableID) != "" && strings.TrimSpace(selection.StableID) != didAW {
		return a2aPublishOutput{}, usageError("current identity stable_id %s does not match signing key %s; repair .aw/identity.yaml before publishing", selection.StableID, didAW)
	}
	if strings.TrimSpace(selection.DID) != "" && strings.TrimSpace(selection.DID) != currentDIDKey {
		return a2aPublishOutput{}, usageError("current identity did %s does not match signing key %s; repair .aw/identity.yaml before publishing", selection.DID, currentDIDKey)
	}
	registryURL := strings.TrimSpace(input.RegistryURL)
	if registryURL == "" {
		registryURL = strings.TrimSpace(selection.RegistryURL)
	}
	registry, err := newA2ARegistryClient(a2aRegistryChoice{FallbackURL: registryURL, ExplicitURL: input.RegistryURL})
	if err != nil {
		return a2aPublishOutput{}, fmt.Errorf("registry-url: %w. Set --registry-url to an absolute registry origin and retry", err)
	}
	registry.RequestID = "aw-a2a-publish-" + time.Now().UTC().Format("20060102T150405.000000000")
	if registryURL == "" {
		domain, _, err := splitA2AAddress(address)
		if err != nil {
			return a2aPublishOutput{}, err
		}
		registryURL, err = resolveRegistryAuthority(ctx, registryAuthorityRequest{Kind: registryDomainRoute, Registry: registry, Domain: domain})
		if err != nil {
			return a2aPublishOutput{}, fmt.Errorf("discover AWID registry for %s: %w", domain, err)
		}
	}
	routeID := strings.TrimSpace(input.RouteID)
	if routeID == "" {
		routeID, err = routeIDFromA2ACardURL(cardURL)
		if err != nil {
			return a2aPublishOutput{}, err
		}
	}
	rpcURL := strings.TrimSpace(input.RPCURL)
	if rpcURL == "" {
		rpcURL = strings.TrimSpace(iface.URL)
	}
	cardRevision := strings.TrimSpace(input.CardRevision)
	if cardRevision == "" {
		cardRevision = strings.TrimSpace(card.Version)
	}
	if cardRevision == "" {
		cardRevision = time.Now().UTC().Format("2006-01-02T150405Z")
	}
	if input.ExpiresDays <= 0 {
		return a2aPublishOutput{}, usageError("--expires-days must be positive")
	}
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(time.Duration(input.ExpiresDays) * 24 * time.Hour).Format(time.RFC3339)
	gatewayIdentity := strings.TrimSpace(input.GatewayIdentity)
	if gatewayIdentity == "" {
		gatewayIdentity = didAW
	}
	delegationID := strings.TrimSpace(input.DelegationID)
	if delegationID == "" {
		delegationID = a2AAssertionID("del", now, address, routeID, gatewayIdentity, digest.Value)
	}
	assertionID := strings.TrimSpace(input.AssertionID)
	if assertionID == "" {
		assertionID = a2AAssertionID("pub", now, address, routeID, gatewayIdentity, digest.Value)
	}

	var delegationResp *awid.A2AWriteResponse
	delegationDigest := ""
	if gatewayIdentity != didAW {
		delegationFields := awid.A2ADelegationFields{
			Operation:                awid.A2ADelegationOperation,
			DelegationID:             delegationID,
			DelegatorDIDAW:           didAW,
			DelegatorCurrentDIDKey:   currentDIDKey,
			DelegatedGatewayIdentity: gatewayIdentity,
			Address:                  address,
			RouteID:                  routeID,
			CardURL:                  cardURL,
			RPCURL:                   rpcURL,
			AllowedOperations:        awid.A2AAllowedOperations,
			CardDigestAlg:            awid.A2ACardDigestAlgSHA256,
			CardDigest:               digest.Value,
			CustodyMode:              awid.A2ACustodyDelegatedBridge,
			AuthoritySource:          awid.A2AAuthoritySelfDelegation,
			SignerDID:                currentDIDKey,
			SignerKID:                currentDIDKey + "#ed25519",
			IssuedAt:                 now.Format(time.RFC3339),
			ExpiresAt:                expiresAt,
			Status:                   awid.A2AStatusActive,
			RegistryURL:              registryURL,
		}
		delegationResp, err = registry.PublishA2ADelegationAt(ctx, registryURL, awid.A2ADelegationParams{
			A2ADelegationFields: delegationFields,
			SigningKey:          signingKey,
		})
		if err != nil {
			return a2aPublishOutput{}, a2aPublishError("publish A2A bridge delegation", err)
		}
		delegationDigest = delegationResp.AssertionDigest
	}
	publicationResp, err := registry.PublishA2APublicationAt(ctx, registryURL, awid.A2APublicationParams{
		A2APublicationFields: awid.A2APublicationFields{
			Operation:        awid.A2APublicationOperation,
			AssertionID:      assertionID,
			Address:          address,
			DIDAW:            didAW,
			CurrentDIDKey:    currentDIDKey,
			SignerDID:        currentDIDKey,
			SignerKID:        currentDIDKey + "#ed25519",
			CardURL:          cardURL,
			RPCURL:           rpcURL,
			RouteID:          routeID,
			GatewayIdentity:  gatewayIdentity,
			DelegationID:     strings.TrimSpace(delegationIDForPublication(gatewayIdentity, didAW, delegationID)),
			DelegationDigest: strings.TrimSpace(delegationDigest),
			CardDigestAlg:    awid.A2ACardDigestAlgSHA256,
			CardDigest:       digest.Value,
			CardRevision:     cardRevision,
			DefaultForHost:   input.DefaultForHost,
			Status:           awid.A2AStatusActive,
			PublishedAt:      now.Format(time.RFC3339),
			ExpiresAt:        expiresAt,
			RegistryURL:      registryURL,
			IdentityCustody:  string(awid.AddressClaimCustodySelf),
			AuthoritySource:  awid.A2AAuthoritySelfIdentityKey,
		},
		SigningKey: signingKey,
	})
	if err != nil {
		return a2aPublishOutput{}, a2aPublishError("publish A2A route", err)
	}
	verification := verifyA2ACardWithAWID(ctx, a2aCardVerification{CardURL: cardURL, Digest: digest.Value, Address: address, RegistryURL: registryURL, ExplicitRegistryURL: input.RegistryURL})
	return a2aPublishOutput{
		Address:         address,
		RegistryURL:     registryURL,
		CardURL:         strings.TrimSpace(cardURL),
		RPCURL:          strings.TrimSpace(rpcURL),
		RouteID:         strings.TrimSpace(routeID),
		GatewayIdentity: gatewayIdentity,
		CardDigest:      digest.Value,
		CardRevision:    cardRevision,
		Delegation:      delegationResp,
		Publication:     publicationResp,
		Verification:    verification,
	}, nil
}

func loadA2APublishSigningKey(selection *awconfig.Selection) (ed25519.PrivateKey, error) {
	if selection == nil {
		return nil, usageError("A2A publication requires a current global self-custodial identity")
	}
	if strings.TrimSpace(selection.Custody) != awid.CustodySelf {
		return nil, usageError("A2A publication currently requires a self-custodial identity; hosted-custodial publication must be performed by the hosted service")
	}
	signingKeyPath := strings.TrimSpace(selection.SigningKey)
	if signingKeyPath == "" {
		if strings.TrimSpace(selection.IdentityHome) != "" {
			signingKeyPath = filepath.Join(selection.IdentityHome, "signing.key")
		} else {
			signingKeyPath = awconfig.WorktreeSigningKeyPath(selection.WorkingDir)
		}
	}
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load A2A publication signing key %s: %w", signingKeyPath, err)
	}
	return signingKey, nil
}

func routeIDFromA2ACardURL(cardURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(cardURL))
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) == 4 && parts[0] == "a2a" && parts[1] == "agents" && parts[3] == "agent-card.json" && strings.TrimSpace(parts[2]) != "" {
		return parts[2], nil
	}
	return "", usageError("--route-id is required when card URL is not /a2a/agents/<route-id>/agent-card.json")
}

func a2AAssertionID(prefix string, timestamp time.Time, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return fmt.Sprintf("%s_%s_%x", prefix, timestamp.UTC().Format("20060102T150405Z"), sum[:8])
}

func delegationIDForPublication(gatewayIdentity, didAW, delegationID string) string {
	if strings.TrimSpace(gatewayIdentity) == strings.TrimSpace(didAW) {
		return ""
	}
	return strings.TrimSpace(delegationID)
}

func a2aPublishError(action string, err error) error {
	var conflict *awid.A2APublicationConflictError
	if errors.As(err, &conflict) {
		switch conflict.Code {
		case awid.A2APublicationCodeDelegationMissing:
			return usageError("%s: bridge delegation is missing; publish from the address identity with --gateway-identity so aw can create the delegation first", action)
		case awid.A2APublicationCodeDelegationDigestMismatch:
			return usageError("%s: bridge delegation digest mismatch; fetch the current card and rerun aw a2a publish so delegation and publication use the same card digest", action)
		case awid.A2APublicationCodeCardDigestMismatch:
			return usageError("%s: card digest mismatch; confirm the served card at the URL is the card you intend to publish", action)
		case awid.A2APublicationCodeAddressNotRegistered:
			return usageError("%s: address is not registered in AWID; create the global identity/address before publishing A2A", action)
		case awid.A2APublicationCodeNamespaceNotRegistered:
			return usageError("%s: namespace is not registered in AWID; run the namespace registration flow before publishing A2A", action)
		case awid.A2APublicationCodeAuthoritySourceInvalid:
			return usageError("%s: authority source invalid for this custody path; self-custodial publication requires the address identity signing key, hosted publication must be done by the hosted service", action)
		case awid.A2APublicationCodeIdentitySignatureInvalid, awid.A2APublicationCodeDelegationSignatureInvalid:
			return usageError("%s: signature invalid; run from the workspace that holds the current signing key for the address identity", action)
		case awid.A2APublicationCodePrimitiveDisabled, awid.A2APublicationCodePrimitiveNotSupported:
			return usageError("%s: AWID registry does not support A2A publication yet; upgrade awid-service and retry", action)
		default:
			return fmt.Errorf("%s: %s: %s", action, conflict.Code, strings.TrimSpace(conflict.Message))
		}
	}
	return fmt.Errorf("%s: %w", action, err)
}

func resolveA2ACallTarget(ctx context.Context, cardURL string) (a2a.Card, string, a2a.Credential, error) {
	card, _, err := a2a.FetchCard(ctx, a2aHTTPClient(), cardURL)
	if err != nil {
		return a2a.Card{}, "", a2a.Credential{}, err
	}
	if err := a2a.ValidateCard(card, a2a.ValidationOptions{RequireJSONRPCOnly: true, RequireMediaTypeModes: true}); err != nil {
		return a2a.Card{}, "", a2a.Credential{}, err
	}
	iface, err := a2a.SelectJSONRPCInterface(card)
	if err != nil {
		return a2a.Card{}, "", a2a.Credential{}, err
	}
	if err := a2a.ValidateRPCOrigin(a2a.OriginPair{Source: cardURL, Destination: iface.URL}); err != nil {
		return a2a.Card{}, "", a2a.Credential{}, err
	}
	credential, err := loadA2ACredential(a2aCredentialQuery{CardURL: cardURL, RPCURL: iface.URL})
	if err != nil {
		return a2a.Card{}, "", a2a.Credential{}, err
	}
	if strings.TrimSpace(iface.Tenant) != "" {
		return a2a.Card{}, "", a2a.Credential{}, usageError("A2A tenant-routed interfaces are not supported by aw a2a yet; use a path-routed per-address card")
	}
	return card, iface.URL, credential, nil
}

func formatA2ACardOutput(out a2aCardOutput) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Name:       %s\n", termtext.Line(out.Name)))
	sb.WriteString(fmt.Sprintf("Version:    %s\n", termtext.Line(out.Version)))
	sb.WriteString(fmt.Sprintf("Digest:     %s\n", termtext.Line(out.Digest)))
	sb.WriteString(fmt.Sprintf("Verification: %s", out.Verification.Status))
	if out.Verification.Code != "" {
		sb.WriteString(" (" + out.Verification.Code + ")")
	}
	sb.WriteString("\n")
	if out.Verification.Message != "" {
		sb.WriteString(fmt.Sprintf("Note:       %s\n", termtext.Line(out.Verification.Message)))
	}
	for _, iface := range out.Interfaces {
		sb.WriteString(fmt.Sprintf("Interface:  %s\n", termtext.Line(fmt.Sprintf("%s %s %s", iface.ProtocolBinding, iface.ProtocolVersion, iface.URL))))
	}
	for _, skill := range out.Skills {
		sb.WriteString(fmt.Sprintf("Skill:      %s\n", termtext.Line(fmt.Sprintf("%s — %s", skill.ID, skill.Name))))
	}
	return sb.String()
}

func formatA2APublishOutput(out a2aPublishOutput) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Published A2A route for %s\n", out.Address))
	sb.WriteString(fmt.Sprintf("Card:      %s\n", out.CardURL))
	sb.WriteString(fmt.Sprintf("RPC:       %s\n", out.RPCURL))
	sb.WriteString(fmt.Sprintf("Route:     %s\n", out.RouteID))
	sb.WriteString(fmt.Sprintf("Digest:    %s\n", out.CardDigest))
	sb.WriteString(fmt.Sprintf("Gateway:   %s\n", out.GatewayIdentity))
	if out.Delegation != nil {
		sb.WriteString(fmt.Sprintf("Delegation: %s (%s)\n", out.Delegation.Status, out.Delegation.DelegationID))
	}
	if out.Publication != nil {
		sb.WriteString(fmt.Sprintf("Publication: %s (%s)\n", out.Publication.Status, out.Publication.AssertionID))
	}
	sb.WriteString(fmt.Sprintf("Verification: %s", out.Verification.Status))
	if out.Verification.Code != "" {
		sb.WriteString(" (" + out.Verification.Code + ")")
	}
	sb.WriteString("\n")
	if out.Verification.Message != "" {
		sb.WriteString(fmt.Sprintf("Note:      %s\n", out.Verification.Message))
	}
	return sb.String()
}

func formatA2ATask(task a2a.Task) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Task:    %s\n", termtext.Line(task.ID)))
	if task.ContextID != "" {
		sb.WriteString(fmt.Sprintf("Context: %s\n", termtext.Line(task.ContextID)))
	}
	sb.WriteString(fmt.Sprintf("State:   %s\n", termtext.Line(task.Status.State)))
	if verification, ok := task.Metadata["reply_verification"].(string); ok {
		sb.WriteString(fmt.Sprintf("Reply:   %s\n", termtext.Line(verification)))
	}
	if text := a2aTaskText(task); text != "" {
		sb.WriteString(fmt.Sprintf("Text:    %s\n", termtext.Block(text)))
	}
	if token, ok := task.Metadata["task_bearer_token"].(string); ok && token != "" {
		sb.WriteString(fmt.Sprintf("Token:   %s\n", termtext.Line(token)))
	}
	return sb.String()
}

func a2aTaskText(task a2a.Task) string {
	if task.Status.Message != nil {
		for _, part := range task.Status.Message.Parts {
			if strings.TrimSpace(part.Text) != "" {
				return part.Text
			}
		}
	}
	for _, artifact := range task.Artifacts {
		for _, part := range artifact.Parts {
			if strings.TrimSpace(part.Text) != "" {
				return part.Text
			}
		}
	}
	return ""
}

func a2aTaskExitError(task a2a.Task) error {
	switch task.Status.State {
	case a2a.TaskStateInputRequired, a2a.TaskStateAuthRequired:
		return &cliError{code: 3, msg: "A2A task needs input or authentication: " + task.Status.State}
	case a2a.TaskStateFailed, a2a.TaskStateCanceled, a2a.TaskStateRejected:
		return &cliError{code: 1, msg: "A2A task ended unsuccessfully: " + task.Status.State}
	default:
		return nil
	}
}

func splitA2AAddress(address string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(address), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("address must be domain/name")
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

func urlHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return parsed.Host
}

func redactedRegistryError(err error) string {
	if err == nil {
		return ""
	}
	var target *awid.RegistryError
	if errors.As(err, &target) && target.Code != "" {
		return target.Code
	}
	if errors.As(err, &target) {
		return fmt.Sprintf("registry http %d", target.StatusCode)
	}
	return err.Error()
}
