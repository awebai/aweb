package main

import (
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
	"github.com/awebai/aw/internal/termtext"
	"github.com/spf13/cobra"
)

var (
	claimHumanEmail          string
	claimHumanMockURL        string
	claimHumanUsername       string
	claimHumanControllerFile string
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
	claimHumanCmd.Flags().StringVar(&claimHumanControllerFile, "controller-claim-file", "", "Controller-signed claim artifact from aw id team claim-human-request (member credential still required)")
	rootCmd.AddCommand(claimHumanCmd)
}

func runClaimHuman(cmd *cobra.Command, args []string) error {
	email := strings.TrimSpace(claimHumanEmail)
	if email == "" {
		return usageError("missing required flag: --email")
	}

	if cmd.Flags().Changed("controller-claim-file") && strings.TrimSpace(claimHumanControllerFile) == "" {
		return usageError("--controller-claim-file requires a file from aw id team claim-human-request")
	}

	baseURL, err := resolveClaimHumanBaseURL(claimHumanMockURL)
	if err != nil {
		return err
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	resp, username, err := claimHumanWithOptions(claimHumanOptions{
		WorkingDir:          workingDir,
		IdentityHome:        externalIdentityHomeRoot(home),
		BaseURL:             baseURL,
		Email:               email,
		Username:            strings.TrimSpace(claimHumanUsername),
		ControllerClaimFile: claimHumanControllerFile,
	})
	if err != nil {
		return err
	}

	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(claimHumanCommandOutput{
			Status: resp.Status, Email: resp.Email, Username: username, EmailSent: resp.EmailSent, EmailMessage: resp.EmailMessage,
		})
	}

	return printClaimHumanSuccess(cmd.OutOrStdout(), email, resp)
}

type claimHumanCommandOutput struct {
	Status       string `json:"status"`
	Email        string `json:"email"`
	Username     string `json:"username"`
	EmailSent    *bool  `json:"email_sent,omitempty"`
	EmailMessage string `json:"email_message,omitempty"`
}

type claimHumanOptions struct {
	ControllerClaimFile string
	WorkingDir          string
	IdentityHome        string
	BaseURL             string
	Email               string
	Username            string
}

func claimHumanWithOptions(opts claimHumanOptions) (*awid.ClaimHumanResponse, string, error) {
	email := strings.TrimSpace(opts.Email)
	if email == "" {
		return nil, "", usageError("missing required flag: --email")
	}

	didKey, signingKey, identityAddress, err := resolveClaimHumanIdentity(opts.WorkingDir, opts.IdentityHome)
	if err != nil {
		return nil, "", err
	}
	username, err := resolveClaimHumanUsername(opts.WorkingDir, opts.IdentityHome, identityAddress, opts.Username)
	if err != nil {
		return nil, "", err
	}
	var controllerClaim *awid.SignedUnownedTeamClaim
	if strings.TrimSpace(opts.ControllerClaimFile) != "" {
		target := normalizeClaimHumanTarget(claimHumanTarget{Username: username, Email: email})
		artifact, err := readClaimHumanControllerFile(claimHumanControllerInput{Path: opts.ControllerClaimFile, Target: target, Now: time.Now()})
		if err != nil {
			return nil, "", err
		}
		controllerClaim = &artifact
		username, email = target.Username, target.Email
	}
	client, err := awid.NewWithIdentity(strings.TrimSpace(opts.BaseURL), signingKey, didKey)
	if err != nil {
		return nil, "", fmt.Errorf("invalid identity configuration: %w", err)
	}

	ctx, cancel := commandAPIContext(nil)
	defer cancel()

	resp, err := client.ClaimHuman(ctx, &awid.ClaimHumanRequest{
		Username:        username,
		Email:           email,
		DIDKey:          didKey,
		ControllerClaim: controllerClaim,
	})
	if err != nil {
		return nil, "", mapClaimHumanError(claimHumanErrorInput{Cause: err, ControllerClaim: controllerClaim})
	}
	return resp, username, nil
}

func resolveClaimHumanIdentity(workingDir, identityHome string) (string, ed25519.PrivateKey, string, error) {
	var identity *awconfig.ResolvedIdentity
	var err error
	if strings.TrimSpace(identityHome) != "" {
		identity, err = awconfig.ResolveIdentityFromHome(workingDir, identityHome)
	} else {
		identity, err = awconfig.ResolveIdentity(workingDir)
	}
	identityMissing := errors.Is(err, os.ErrNotExist)
	if err != nil && !identityMissing {
		return "", nil, "", err
	}

	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if strings.TrimSpace(identityHome) != "" {
		signingKeyPath, err = awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "signing.key")
		if err != nil {
			return "", nil, "", err
		}
	}
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

func resolveClaimHumanUsername(workingDir, identityHome, address, override string) (string, error) {
	if username := strings.TrimSpace(override); username != "" {
		return username, nil
	}
	if strings.TrimSpace(address) != "" {
		return usernameFromMemberAddress(address)
	}

	var workspace *awconfig.WorktreeWorkspace
	var teamState *awconfig.TeamState
	var err error
	if strings.TrimSpace(identityHome) != "" {
		workspace, teamState, _, err = awconfig.LoadWorkspaceAndTeamStateFromIdentityHome(identityHome)
	} else {
		workspace, teamState, _, err = awconfig.LoadWorkspaceAndTeamState(workingDir)
	}
	if err != nil {
		if workspace == nil && errors.Is(err, os.ErrNotExist) {
			return "", usageError("No identity found. Run aw init first to create an agent, then claim-human to attach an email.")
		}
		return "", fmt.Errorf("failed to load workspace: %w", err)
	}
	activeMembership := awconfig.ActiveMembershipFor(workspace, teamState)
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
	status := awid.ClaimHumanStatus("")
	if resp != nil {
		status = awid.ClaimHumanStatus(strings.TrimSpace(resp.Status))
	}
	finalEmail = termtext.Line(finalEmail)
	if resp != nil && (status == awid.ClaimHumanVerificationSent || status == awid.ClaimHumanApprovalSent) && resp.EmailSent != nil && !*resp.EmailSent {
		message := strings.TrimSpace(resp.EmailMessage)
		if message == "" {
			message = "The verification email could not be sent. Run the command again to request a new one."
			if status == awid.ClaimHumanApprovalSent {
				message = "The approval email could not be sent. Run the command again to request a new one."
			}
		}
		_, err := fmt.Fprintln(out, termtext.Line(message))
		return err
	}
	switch status {
	case awid.ClaimHumanAlreadyAttached:
		_, err := fmt.Fprintf(out, "Human account %s is already attached. No verification email was sent.\n", finalEmail)
		return err
	case awid.ClaimHumanAttached:
		_, err := fmt.Fprintf(out, "Human account %s is attached. No verification email was sent because the email is already verified.\n", finalEmail)
		return err
	case awid.ClaimHumanVerificationSent:
		_, err := fmt.Fprintf(out, "Verification email requested for %s. Click the link in the email to activate your dashboard login.\n", finalEmail)
		return err
	case awid.ClaimHumanApprovalSent:
		_, err := fmt.Fprintln(out, "Approval email requested. Follow the instructions in that email to approve this claim.")
		return err
	default:
		_, err := fmt.Fprintf(out, "Claim-human completed for %s with status %q.\n", finalEmail, status)
		return err
	}
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
		return "", usageError("cannot infer dashboard username from a BYOD domain; pass --username")
	}
	username := strings.TrimSuffix(domain, managedSuffix)
	if strings.TrimSpace(username) == "" {
		return "", fmt.Errorf("current identity domain %q does not contain a username", domain)
	}
	return username, nil
}

type claimHumanErrorInput struct {
	Cause           error
	ControllerClaim *awid.SignedUnownedTeamClaim
}

// mapClaimHumanError preserves controller pin refusal evidence for a submitted
// controller claim (docs/trust-model.md:476; docs/unowned-team-claim.md).
// Other 401s retain the member-key remedy, including the released no-file path.
func mapClaimHumanError(input claimHumanErrorInput) error {
	err := input.Cause
	status, ok := awid.HTTPStatusCode(err)
	if !ok {
		return err
	}
	switch status {
	case 404:
		if input.ControllerClaim != nil && awid.RefusalCode(err) == "awid_team_not_found" {
			return err
		}
		return errors.New("Username not registered. Run aw init first.")
	case 401:
		if input.ControllerClaim != nil {
			detail := awid.DescribeError(err).Detail
			if detail == "team_key_unverified" || strings.HasPrefix(detail, "team_key_unverified:") {
				return err
			}
		}
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
