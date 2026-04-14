package main

import (
	"context"
	"crypto/ed25519"
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
	claimHumanEmail    string
	claimHumanMockURL  string
	claimHumanUsername string
)

var claimHumanCmd = &cobra.Command{
	Use:   "claim-human",
	Short: "Attach an email address to your CLI-created account",
	RunE:  runClaimHuman,
}

func init() {
	claimHumanCmd.GroupID = groupWorkspace
	claimHumanCmd.Flags().StringVar(&claimHumanEmail, "email", "", "Email address to attach to the current CLI-created account")
	claimHumanCmd.Flags().StringVar(&claimHumanUsername, "username", "", "Override the default dashboard username derived from the registered domain")
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
		Username:   strings.TrimSpace(claimHumanUsername),
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
	Username   string
}

func claimHumanWithOptions(opts claimHumanOptions) (*awid.ClaimHumanResponse, string, error) {
	email := strings.TrimSpace(opts.Email)
	if email == "" {
		return nil, "", usageError("missing required flag: --email")
	}

	didKey, signingKey, identityAddress, err := resolveClaimHumanIdentity(opts.WorkingDir)
	if err != nil {
		return nil, "", err
	}
	username, err := resolveClaimHumanUsername(opts.WorkingDir, identityAddress, opts.Username)
	if err != nil {
		return nil, "", err
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

func resolveClaimHumanIdentity(workingDir string) (string, ed25519.PrivateKey, string, error) {
	identity, err := awconfig.ResolveIdentity(workingDir)
	identityMissing := errors.Is(err, os.ErrNotExist)
	if err != nil && !identityMissing {
		return "", nil, "", err
	}

	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	didKey := ""
	address := ""
	if !identityMissing {
		signingKeyPath = strings.TrimSpace(identity.SigningKeyPath)
		didKey = strings.TrimSpace(identity.DID)
		address = strings.TrimSpace(identity.Address)
		if didKey == "" {
			return "", nil, "", fmt.Errorf("current identity is missing did in %s", identity.IdentityPath)
		}
		if signingKeyPath == "" {
			return "", nil, "", usageError("current identity has no local signing key")
		}
	}

	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if identityMissing {
				return "", nil, "", usageError("No identity found. Run aw init first to create an agent, then claim-human to attach an email.")
			}
			return "", nil, "", usageError("current identity has no local signing key")
		}
		return "", nil, "", fmt.Errorf("failed to load signing key: %w", err)
	}
	if didKey == "" {
		didKey = awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	}
	return didKey, signingKey, address, nil
}

func resolveClaimHumanUsername(workingDir, address, override string) (string, error) {
	if username := strings.TrimSpace(override); username != "" {
		return username, nil
	}
	if strings.TrimSpace(address) != "" {
		return usernameFromMemberAddress(address)
	}

	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", usageError("No identity found. Run aw init first to create an agent, then claim-human to attach an email.")
		}
		return "", fmt.Errorf("failed to load workspace: %w", err)
	}
	activeMembership := workspace.ActiveMembership()
	if activeMembership == nil {
		return "", usageError("current workspace is missing active_team membership; run `aw init` first")
	}
	teamDomain, _, err := awid.ParseTeamID(strings.TrimSpace(activeMembership.TeamID))
	if err != nil {
		return "", fmt.Errorf("current workspace has invalid team_id %q: %w", activeMembership.TeamID, err)
	}
	return usernameFromManagedDomain(teamDomain)
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
	return usernameFromManagedDomain(domain)
}

func usernameFromManagedDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("current identity domain is empty")
	}
	const managedSuffix = ".aweb.ai"
	if !strings.HasSuffix(domain, managedSuffix) {
		return domain, nil
	}
	username := strings.TrimSuffix(domain, managedSuffix)
	if strings.TrimSpace(username) == "" {
		return "", fmt.Errorf("current identity domain %q does not contain a username", domain)
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
