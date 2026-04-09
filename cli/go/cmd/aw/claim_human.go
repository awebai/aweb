package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	claimHumanEmail   string
	claimHumanMockURL string
)

var claimHumanCmd = &cobra.Command{
	Use:   "claim-human",
	Short: "Attach an email address to your CLI-created account",
	RunE:  runClaimHuman,
}

func init() {
	claimHumanCmd.GroupID = groupIdentity
	claimHumanCmd.Flags().StringVar(&claimHumanEmail, "email", "", "Email address to attach to the current CLI-created account")
	claimHumanCmd.Flags().StringVar(&claimHumanMockURL, "mock-url", "", "Override the bootstrap base URL for local development")
	rootCmd.AddCommand(claimHumanCmd)
}

func runClaimHuman(cmd *cobra.Command, args []string) error {
	email := strings.TrimSpace(claimHumanEmail)
	if email == "" {
		return usageError("missing required flag: --email")
	}

	baseURL, err := resolveClaimHumanBaseURL(claimHumanMockURL)
	if err != nil {
		return err
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	resp, username, err := claimHumanWithOptions(claimHumanOptions{
		WorkingDir: workingDir,
		BaseURL:    baseURL,
		Email:      email,
	})
	if err != nil {
		return err
	}

	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
			"status":   resp.Status,
			"email":    resp.Email,
			"username": username,
		})
	}

	return printClaimHumanSuccess(cmd.OutOrStdout(), email, resp)
}

type claimHumanOptions struct {
	WorkingDir string
	BaseURL    string
	Email      string
}

func claimHumanWithOptions(opts claimHumanOptions) (*awid.ClaimHumanResponse, string, error) {
	email := strings.TrimSpace(opts.Email)
	if email == "" {
		return nil, "", usageError("missing required flag: --email")
	}

	identity, err := awconfig.ResolveIdentity(opts.WorkingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, "", usageError("No identity found. Run aw init first to create an agent, then claim-human to attach an email.")
		}
		return nil, "", err
	}

	username, err := usernameFromMemberAddress(identity.Address)
	if err != nil {
		return nil, "", err
	}

	didKey := strings.TrimSpace(identity.DID)
	if didKey == "" {
		return nil, "", fmt.Errorf("current identity is missing did in %s", identity.IdentityPath)
	}

	signingKeyPath := strings.TrimSpace(identity.SigningKeyPath)
	if signingKeyPath == "" {
		return nil, "", usageError("current identity has no local signing key")
	}
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load signing key: %w", err)
	}
	client, err := awid.NewWithIdentity(strings.TrimSpace(opts.BaseURL), signingKey, didKey)
	if err != nil {
		return nil, "", fmt.Errorf("invalid identity configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ClaimHuman(ctx, &awid.ClaimHumanRequest{
		Username: username,
		Email:    email,
		DIDKey:   didKey,
	})
	if err != nil {
		return nil, "", mapClaimHumanError(err)
	}
	return resp, username, nil
}

func printClaimHumanSuccess(out io.Writer, requestedEmail string, resp *awid.ClaimHumanResponse) error {
	finalEmail := strings.TrimSpace(requestedEmail)
	if resp != nil && strings.TrimSpace(resp.Email) != "" {
		finalEmail = strings.TrimSpace(resp.Email)
	}
	_, err := fmt.Fprintf(out, "Verification email sent to %s. Click the link in the email to activate your dashboard login.\n", finalEmail)
	return err
}

func resolveClaimHumanBaseURL(mockURL string) (string, error) {
	urls, err := resolveOnboardingServiceURLs(mockURL)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(urls.OnboardingURL), nil
}

func usernameFromMemberAddress(address string) (string, error) {
	domain, _, ok := strings.Cut(strings.TrimSpace(address), "/")
	if !ok || strings.TrimSpace(domain) == "" {
		return "", fmt.Errorf("current identity is missing member_address in .aw/identity.yaml")
	}
	const managedSuffix = ".aweb.ai"
	if !strings.HasSuffix(domain, managedSuffix) {
		return "", errors.New("claim-human is only for managed aweb.ai accounts; BYOD identities are not supported by this command")
	}
	username := strings.TrimSuffix(domain, managedSuffix)
	if strings.TrimSpace(username) == "" {
		return "", fmt.Errorf("current identity address %q does not contain a username", address)
	}
	return username, nil
}

func mapClaimHumanError(err error) error {
	status, ok := awid.HTTPStatusCode(err)
	if !ok {
		return err
	}
	switch status {
	case 404:
		return errors.New("Username not registered. Run aw init first.")
	case 401:
		return errors.New("Your signing key does not match the registered agent. Check .aw/signing.key is intact.")
	case 409:
		if msg := claimHumanServerMessage(err); msg != "" {
			return errors.New(msg)
		}
		return errors.New("claim-human failed with status 409")
	default:
		return err
	}
}

func claimHumanServerMessage(err error) string {
	body, ok := awid.HTTPErrorBody(err)
	if !ok {
		return ""
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}

	var envelope map[string]any
	if json.Unmarshal([]byte(body), &envelope) == nil {
		for _, key := range []string{"detail", "error", "message"} {
			if msg, ok := envelope[key].(string); ok && strings.TrimSpace(msg) != "" {
				return strings.TrimSpace(msg)
			}
		}
	}
	return body
}
