package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	a2aCardAddress   string
	a2aCardRegistry  string
	a2aContextID     string
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
		return &http.Client{Timeout: 30 * time.Second}
	}
)

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
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		out, err := buildA2ACardOutput(ctx, args[0], a2aCardAddress, a2aCardRegistry)
		if err != nil {
			return err
		}
		if jsonFlag {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
		}
		fmt.Fprint(cmd.OutOrStdout(), formatA2ACardOutput(out))
		return nil
	},
}

var a2aSendCmd = &cobra.Command{
	Use:   "send <card-url> <message>",
	Short: "Send a task message to an A2A agent",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if a2aWait && a2aNoWait {
			return usageError("--wait and --no-wait are mutually exclusive")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
		defer cancel()
		task, err := runA2ASend(ctx, args[0], args[1])
		if err != nil {
			return err
		}
		if jsonFlag {
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(task); err != nil {
				return err
			}
			return a2aTaskExitError(task)
		}
		fmt.Fprint(cmd.OutOrStdout(), formatA2ATask(task))
		return a2aTaskExitError(task)
	},
}

var a2aStatusCmd = &cobra.Command{
	Use:   "status <card-url> <task-id>",
	Short: "Fetch an A2A task",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		task, err := runA2AStatus(ctx, args[0], args[1])
		if err != nil {
			return err
		}
		if jsonFlag {
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(task); err != nil {
				return err
			}
			return a2aTaskExitError(task)
		}
		fmt.Fprint(cmd.OutOrStdout(), formatA2ATask(task))
		return a2aTaskExitError(task)
	},
}

var a2aCancelCmd = &cobra.Command{
	Use:   "cancel <card-url> <task-id>",
	Short: "Cancel an A2A task",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		defer cancel()
		task, err := runA2ACancel(ctx, args[0], args[1])
		if err != nil {
			return err
		}
		if jsonFlag {
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(task); err != nil {
				return err
			}
			return nil
		}
		fmt.Fprint(cmd.OutOrStdout(), formatA2ATask(task))
		return nil
	},
}

var a2aPublishCmd = &cobra.Command{
	Use:   "publish <card-url>",
	Short: "Publish an A2A Agent Card route to AWID",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
		defer cancel()
		out, err := runA2APublish(ctx, args[0])
		if err != nil {
			return err
		}
		printOutput(out, formatA2APublishOutput)
		return nil
	},
}

func init() {
	a2aCmd.GroupID = groupNetwork
	a2aCardCmd.Flags().StringVar(&a2aCardAddress, "address", "", "aweb address to verify through AWID, e.g. acme.com/help")
	a2aCardCmd.Flags().StringVar(&a2aCardRegistry, "registry-url", "", "AWID registry URL for verification")
	a2aSendCmd.Flags().StringVar(&a2aContextID, "context", "", "A2A context ID")
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
		verification = verifyA2ACardWithAWID(ctx, cardURL, digest.Value, strings.TrimSpace(address), strings.TrimSpace(registryURL))
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

func verifyA2ACardWithAWID(ctx context.Context, cardURL, digestValue, address, registryURL string) a2a.VerificationResult {
	domain, name, err := splitA2AAddress(address)
	if err != nil {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_address_invalid", Message: err.Error(), Digest: digestValue}
	}
	registry := awid.NewAWIDRegistryClient(a2aHTTPClient(), nil)
	registry.RequestID = "aw-a2a-" + time.Now().UTC().Format("20060102T150405.000000000")
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_registry_url_invalid", Message: err.Error(), Digest: digestValue}
		}
	}
	lookup, _, err := registry.GetA2APublication(ctx, domain, name)
	if err != nil {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "awid_lookup_failed", Message: redactedRegistryError(err), Digest: digestValue}
	}
	if lookup == nil || lookup.A2A == nil {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_publication_missing", Message: "AWID has no active A2A publication for this address.", Digest: digestValue}
	}
	if strings.TrimSpace(lookup.A2A.Status) != "" && strings.TrimSpace(lookup.A2A.Status) != "active" {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_publication_unavailable", Message: "AWID A2A publication is not active.", Digest: digestValue}
	}
	if strings.TrimSpace(lookup.A2A.Verification) != "" && strings.TrimSpace(lookup.A2A.Verification) != "awid_publication_available" {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_publication_unavailable", Message: "AWID publication is not available.", Digest: digestValue}
	}
	if lookup.A2A.CardDigest != digestValue {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: awid.A2APublicationCodeCardDigestMismatch, Message: "Served card digest does not match active AWID publication.", Digest: digestValue}
	}
	if strings.TrimSpace(lookup.A2A.CardURL) != "" && strings.TrimSpace(lookup.A2A.CardURL) != strings.TrimSpace(cardURL) {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_card_url_mismatch", Message: "Served card URL does not match active AWID publication.", Digest: digestValue}
	}
	return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationAWIDVerified, Code: "awid_publication_verified", Message: "AWID publication active; served card digest matches.", Digest: digestValue}
}

func runA2ASend(ctx context.Context, cardURL, text string) (a2a.Task, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return a2a.Task{}, usageError("message must not be empty")
	}
	card, rpcURL, credential, err := resolveA2ACallTarget(ctx, cardURL)
	if err != nil {
		return a2a.Task{}, err
	}
	_ = card
	message := a2a.NewUserTextMessage(a2aContextID, text)
	params := a2a.SendMessageParams{
		Message: message,
		Configuration: a2a.SendConfiguration{
			ReturnImmediately:   !a2aWait || a2aNoWait,
			AcceptedOutputModes: []string{"text/plain", "application/json"},
		},
	}
	if strings.TrimSpace(a2aDataJSON) != "" {
		var metadata map[string]any
		if err := json.Unmarshal([]byte(a2aDataJSON), &metadata); err != nil {
			return a2a.Task{}, usageError("--data must be a JSON object: %v", err)
		}
		params.Metadata = metadata
	}
	var resp a2aTaskEnvelope
	if err := (&a2a.Client{HTTPClient: a2aHTTPClient(), UserAgent: "aw/" + version}).Call(ctx, rpcURL, a2a.MethodSendMessage, params, credential, &resp); err != nil {
		return a2a.Task{}, err
	}
	saveA2ATaskTokenBestEffort(rpcURL, resp.Task)
	return resp.Task, nil
}

const maxStoredA2ATaskTokens = 50

// saveA2ATaskTokenBestEffort persists the task bearer token issued by the
// gateway so later `aw a2a status`/`aw a2a cancel` calls can present it.
// Without it, scoped routes correctly answer task_not_found to the async
// caller the contract tells to poll. Saving requires an existing .aw
// directory; otherwise the token is only printed.
func saveA2ATaskTokenBestEffort(rpcURL string, task a2a.Task) {
	taskID := strings.TrimSpace(task.ID)
	token, _ := task.Metadata["task_bearer_token"].(string)
	token = strings.TrimSpace(token)
	if taskID == "" || token == "" {
		return
	}
	if info, err := os.Stat(".aw"); err != nil || !info.IsDir() {
		return
	}
	path := filepath.Join(".aw", "a2a-credentials.yaml")
	var file a2aCredentialsFile
	if data, err := os.ReadFile(path); err == nil {
		_ = yaml.Unmarshal(data, &file)
	}
	kept := file.Credentials[:0]
	var taskEntries []a2aCredentialEntry
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) == "" {
			kept = append(kept, entry)
			continue
		}
		if strings.TrimSpace(entry.TaskID) == taskID {
			continue
		}
		taskEntries = append(taskEntries, entry)
	}
	taskEntries = append(taskEntries, a2aCredentialEntry{
		URL:       strings.TrimSpace(rpcURL),
		Host:      urlHost(rpcURL),
		TaskID:    taskID,
		TaskToken: token,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if len(taskEntries) > maxStoredA2ATaskTokens {
		taskEntries = taskEntries[len(taskEntries)-maxStoredA2ATaskTokens:]
	}
	file.Credentials = append(kept, taskEntries...)
	data, err := yaml.Marshal(file)
	if err != nil {
		return
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not persist task token: %v\n", err)
		return
	}
	// WriteFile only applies the mode on create; tighten pre-existing files.
	_ = os.Chmod(path, 0o600)
}

// loadA2ATaskTokenBestEffort returns the stored token for a specific task.
func loadA2ATaskTokenBestEffort(cardURL, rpcURL, taskID string) string {
	data, err := os.ReadFile(filepath.Join(".aw", "a2a-credentials.yaml"))
	if err != nil {
		return ""
	}
	var file a2aCredentialsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return ""
	}
	cardHost := urlHost(cardURL)
	rpcHost := urlHost(rpcURL)
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.TaskID) != strings.TrimSpace(taskID) {
			continue
		}
		host := strings.TrimSpace(entry.Host)
		url := strings.TrimSpace(entry.URL)
		if url == strings.TrimSpace(rpcURL) || url == strings.TrimSpace(cardURL) || host == cardHost || host == rpcHost {
			return strings.TrimSpace(entry.TaskToken)
		}
	}
	return ""
}

func runA2AStatus(ctx context.Context, cardURL, taskID string) (a2a.Task, error) {
	_, rpcURL, credential, err := resolveA2ACallTarget(ctx, cardURL)
	if err != nil {
		return a2a.Task{}, err
	}
	if token := loadA2ATaskTokenBestEffort(cardURL, rpcURL, taskID); token != "" {
		credential.TaskToken = token
	}
	params := map[string]any{"id": strings.TrimSpace(taskID)}
	if a2aHistoryLength >= 0 {
		params["historyLength"] = a2aHistoryLength
	}
	var task a2a.Task
	if err := (&a2a.Client{HTTPClient: a2aHTTPClient(), UserAgent: "aw/" + version}).Call(ctx, rpcURL, a2a.MethodGetTask, params, credential, &task); err != nil {
		return a2a.Task{}, err
	}
	return task, nil
}

func runA2ACancel(ctx context.Context, cardURL, taskID string) (a2a.Task, error) {
	_, rpcURL, credential, err := resolveA2ACallTarget(ctx, cardURL)
	if err != nil {
		return a2a.Task{}, err
	}
	if token := loadA2ATaskTokenBestEffort(cardURL, rpcURL, taskID); token != "" {
		credential.TaskToken = token
	}
	var task a2a.Task
	if err := (&a2a.Client{HTTPClient: a2aHTTPClient(), UserAgent: "aw/" + version}).Call(ctx, rpcURL, a2a.MethodCancelTask, map[string]any{"id": strings.TrimSpace(taskID)}, credential, &task); err != nil {
		return a2a.Task{}, err
	}
	return task, nil
}

func runA2APublish(ctx context.Context, cardURL string) (a2aPublishOutput, error) {
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
	address := strings.TrimSpace(a2aPublishAddress)
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
	registry := awid.NewAWIDRegistryClient(a2aHTTPClient(), nil)
	registry.RequestID = "aw-a2a-publish-" + time.Now().UTC().Format("20060102T150405.000000000")
	registryURL := strings.TrimSpace(a2aPublishRegistry)
	if registryURL == "" {
		registryURL = strings.TrimSpace(selection.RegistryURL)
	}
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return a2aPublishOutput{}, fmt.Errorf("registry-url: %w", err)
		}
	} else {
		domain, _, err := splitA2AAddress(address)
		if err != nil {
			return a2aPublishOutput{}, err
		}
		registryURL, err = registry.DiscoverRegistry(ctx, domain)
		if err != nil {
			return a2aPublishOutput{}, fmt.Errorf("discover AWID registry for %s: %w", domain, err)
		}
	}
	routeID := strings.TrimSpace(a2aPublishRouteID)
	if routeID == "" {
		routeID, err = routeIDFromA2ACardURL(cardURL)
		if err != nil {
			return a2aPublishOutput{}, err
		}
	}
	rpcURL := strings.TrimSpace(a2aPublishRPCURL)
	if rpcURL == "" {
		rpcURL = strings.TrimSpace(iface.URL)
	}
	cardRevision := strings.TrimSpace(a2aPublishCardRevision)
	if cardRevision == "" {
		cardRevision = strings.TrimSpace(card.Version)
	}
	if cardRevision == "" {
		cardRevision = time.Now().UTC().Format("2006-01-02T150405Z")
	}
	if a2aPublishExpiresDays <= 0 {
		return a2aPublishOutput{}, usageError("--expires-days must be positive")
	}
	now := time.Now().UTC().Truncate(time.Second)
	expiresAt := now.Add(time.Duration(a2aPublishExpiresDays) * 24 * time.Hour).Format(time.RFC3339)
	gatewayIdentity := strings.TrimSpace(a2aPublishGatewayIdentity)
	if gatewayIdentity == "" {
		gatewayIdentity = didAW
	}
	delegationID := strings.TrimSpace(a2aPublishDelegationID)
	if delegationID == "" {
		delegationID = a2AAssertionID("del", now, address, routeID, gatewayIdentity, digest.Value)
	}
	assertionID := strings.TrimSpace(a2aPublishAssertionID)
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
			DefaultForHost:   a2aPublishDefaultForHost,
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
	verification := verifyA2ACardWithAWID(ctx, cardURL, digest.Value, address, registryURL)
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
		signingKeyPath = awconfig.WorktreeSigningKeyPath(selection.WorkingDir)
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
	credential := loadA2ACredentialBestEffort(cardURL, iface.URL)
	if strings.TrimSpace(iface.Tenant) != "" {
		return a2a.Card{}, "", a2a.Credential{}, usageError("A2A tenant-routed interfaces are not supported by aw a2a yet; use a path-routed per-address card")
	}
	return card, iface.URL, credential, nil
}

func loadA2ACredentialBestEffort(cardURL, rpcURL string) a2a.Credential {
	path := filepath.Join(".aw", "a2a-credentials.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return a2a.Credential{}
	}
	var file a2aCredentialsFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return a2a.Credential{}
	}
	cardHost := urlHost(cardURL)
	rpcHost := urlHost(rpcURL)
	for _, entry := range file.Credentials {
		if strings.TrimSpace(entry.URL) != "" && (strings.TrimSpace(entry.URL) == strings.TrimSpace(cardURL) || strings.TrimSpace(entry.URL) == strings.TrimSpace(rpcURL)) {
			return credentialFromEntry(entry)
		}
		if host := strings.TrimSpace(entry.Host); host != "" && (host == cardHost || host == rpcHost) {
			return credentialFromEntry(entry)
		}
	}
	return a2a.Credential{}
}

func credentialFromEntry(entry a2aCredentialEntry) a2a.Credential {
	return a2a.Credential{
		APIKey:      strings.TrimSpace(entry.APIKey),
		BearerToken: strings.TrimSpace(entry.BearerToken),
		CallerID:    strings.TrimSpace(entry.CallerID),
		TaskToken:   strings.TrimSpace(entry.TaskToken),
	}
}

func formatA2ACardOutput(out a2aCardOutput) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Name:       %s\n", out.Name))
	sb.WriteString(fmt.Sprintf("Version:    %s\n", out.Version))
	sb.WriteString(fmt.Sprintf("Digest:     %s\n", out.Digest))
	sb.WriteString(fmt.Sprintf("Verification: %s", out.Verification.Status))
	if out.Verification.Code != "" {
		sb.WriteString(" (" + out.Verification.Code + ")")
	}
	sb.WriteString("\n")
	if out.Verification.Message != "" {
		sb.WriteString(fmt.Sprintf("Note:       %s\n", out.Verification.Message))
	}
	for _, iface := range out.Interfaces {
		sb.WriteString(fmt.Sprintf("Interface:  %s %s %s\n", iface.ProtocolBinding, iface.ProtocolVersion, iface.URL))
	}
	for _, skill := range out.Skills {
		sb.WriteString(fmt.Sprintf("Skill:      %s — %s\n", skill.ID, skill.Name))
	}
	return sb.String()
}

func formatA2APublishOutput(v any) string {
	out := v.(a2aPublishOutput)
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
	sb.WriteString(fmt.Sprintf("Task:    %s\n", task.ID))
	if task.ContextID != "" {
		sb.WriteString(fmt.Sprintf("Context: %s\n", task.ContextID))
	}
	sb.WriteString(fmt.Sprintf("State:   %s\n", task.Status.State))
	if text := a2aTaskText(task); text != "" {
		sb.WriteString(fmt.Sprintf("Text:    %s\n", text))
	}
	if token, _ := task.Metadata["task_bearer_token"].(string); token != "" {
		sb.WriteString(fmt.Sprintf("Token:   %s\n", token))
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
