package main

import (
	"context"
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

func init() {
	a2aCmd.GroupID = groupNetwork
	a2aCardCmd.Flags().StringVar(&a2aCardAddress, "address", "", "aweb address to verify through AWID, e.g. acme.com/help")
	a2aCardCmd.Flags().StringVar(&a2aCardRegistry, "registry-url", "", "AWID registry URL for verification")
	a2aSendCmd.Flags().StringVar(&a2aContextID, "context", "", "A2A context ID")
	a2aSendCmd.Flags().BoolVar(&a2aWait, "wait", false, "Wait for terminal or interrupted task state")
	a2aSendCmd.Flags().BoolVar(&a2aNoWait, "no-wait", false, "Return immediately after task creation")
	a2aSendCmd.Flags().StringVar(&a2aDataJSON, "data", "", "Additional JSON metadata object")
	a2aStatusCmd.Flags().IntVar(&a2aHistoryLength, "history", -1, "History length to request; -1 uses server default")
	a2aCmd.AddCommand(a2aCardCmd, a2aSendCmd, a2aStatusCmd, a2aCancelCmd)
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
		verification = a2a.VerificationResult{Tier: a2a.VerificationTier1, Status: a2a.VerificationSignatureOK, Digest: digest.Value, Message: "Agent Card contains JWS signatures; AWID publication not checked."}
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
		if lookup != nil && lookup.Verification.Status != "" && lookup.Verification.Status != "awid_publication_available" {
			return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: firstNonEmpty(lookup.Verification.Code, "a2a_publication_unavailable"), Message: firstNonEmpty(lookup.Verification.Message, "AWID publication is not available."), Digest: digestValue}
		}
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_publication_missing", Message: "AWID has no active A2A publication for this address.", Digest: digestValue}
	}
	if lookup.A2A.CardDigest != digestValue {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: awid.A2APublicationCodeCardDigestMismatch, Message: "Served card digest does not match active AWID publication.", Digest: digestValue}
	}
	if strings.TrimSpace(lookup.A2A.CardURL) != "" && strings.TrimSpace(lookup.A2A.CardURL) != strings.TrimSpace(cardURL) {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: "a2a_card_url_mismatch", Message: "Served card URL does not match active AWID publication.", Digest: digestValue}
	}
	if lookup.Verification.Status != "" && lookup.Verification.Status != "awid_publication_available" {
		return a2a.VerificationResult{Tier: a2a.VerificationTier2, Status: a2a.VerificationFailed, Code: firstNonEmpty(lookup.Verification.Code, "a2a_publication_unavailable"), Message: firstNonEmpty(lookup.Verification.Message, "AWID publication is not available."), Digest: digestValue}
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
	return resp.Task, nil
}

func runA2AStatus(ctx context.Context, cardURL, taskID string) (a2a.Task, error) {
	_, rpcURL, credential, err := resolveA2ACallTarget(ctx, cardURL)
	if err != nil {
		return a2a.Task{}, err
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
	var task a2a.Task
	if err := (&a2a.Client{HTTPClient: a2aHTTPClient(), UserAgent: "aw/" + version}).Call(ctx, rpcURL, a2a.MethodCancelTask, map[string]any{"id": strings.TrimSpace(taskID)}, credential, &task); err != nil {
		return a2a.Task{}, err
	}
	return task, nil
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

func a2aHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}
