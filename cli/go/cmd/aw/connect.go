package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	connectBootstrapToken string
	connectAddress        string
	connectMockURL        string
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect this directory to a team using a bootstrap token",
	RunE:  runConnect,
}

func init() {
	connectCmd.GroupID = groupWorkspace
	connectCmd.Flags().StringVar(&connectBootstrapToken, "bootstrap-token", "", "One-time bootstrap token from the dashboard")
	connectCmd.Flags().StringVar(&connectAddress, "address", "", "Persistent public address from the dashboard copy command")
	connectCmd.Flags().StringVar(&connectMockURL, "mock-url", "", "Override the bootstrap/aweb base URL for local development")
	connectCmd.Hidden = true
	rootCmd.AddCommand(connectCmd)
}

func runConnect(cmd *cobra.Command, args []string) error {
	token := strings.TrimSpace(connectBootstrapToken)
	if token == "" {
		return usageError("missing required flag: --bootstrap-token")
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	address := strings.TrimSpace(connectAddress)
	if err := ensureConnectTargetClean(workingDir); err != nil {
		return err
	}

	serviceURLs, err := resolveOnboardingServiceURLs(connectMockURL)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := bootstrapConnect(ctx, workingDir, serviceURLs, token, address)
	if err != nil {
		return err
	}

	printOutput(result, formatConnect)
	return nil
}

func bootstrapConnect(ctx context.Context, workingDir string, serviceURLs onboardingServiceURLs, token, address string) (connectOutput, error) {
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return connectOutput{}, err
	}
	didKey := awid.ComputeDIDKey(pub)

	redeemReq := &awid.BootstrapRedeemRequest{
		Token:  token,
		DIDKey: didKey,
	}

	var (
		stableID    string
		registryURL string
	)
	if address != "" {
		if err := validateConnectAddress(address); err != nil {
			return connectOutput{}, err
		}

		stableID = awid.ComputeStableID(pub)
		registry, err := newConfiguredRegistryClient(nil, serviceURLs.OnboardingURL)
		if err != nil {
			return connectOutput{}, err
		}
		if strings.TrimSpace(serviceURLs.RegistryURL) != "" {
			if err := registry.SetFallbackRegistryURL(serviceURLs.RegistryURL); err != nil {
				return connectOutput{}, err
			}
		}
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
		// The dashboard-minted bootstrap token already carries the member address;
		// the CLI publishes only the did:aw identity before redeeming it.
		if err := registerBootstrapDID(ctx, registry, didKey, stableID, signingKey); err != nil {
			return connectOutput{}, err
		}
		redeemReq.DIDAW = stableID
	}

	client, err := awid.NewWithIdentity(serviceURLs.OnboardingURL, signingKey, didKey)
	if err != nil {
		return connectOutput{}, fmt.Errorf("invalid bootstrap identity: %w", err)
	}

	redeemResp, err := client.BootstrapRedeem(ctx, redeemReq)
	if err != nil {
		return connectOutput{}, mapBootstrapRedeemError(err)
	}

	cert, err := validateBootstrapRedeemResponse(redeemResp, didKey, stableID, address)
	if err != nil {
		return connectOutput{}, err
	}

	if err := persistBootstrapConnectState(workingDir, signingKey, cert, redeemResp, didKey, stableID, address, registryURL); err != nil {
		return connectOutput{}, err
	}

	return initCertificateConnectWithOptions(workingDir, serviceURLs.AwebURL, certificateConnectOptions{})
}

func validateConnectAddress(address string) error {
	domain, alias, ok := strings.Cut(strings.TrimSpace(address), "/")
	if !ok || strings.TrimSpace(domain) == "" || strings.TrimSpace(alias) == "" {
		return usageError("invalid --address %q; expected <domain>/<alias>", address)
	}
	return nil
}

func ensureConnectTargetClean(workingDir string) error {
	paths := []string{
		awconfig.WorktreeSigningKeyPath(workingDir),
		filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()),
		awconfig.TeamCertificatesDir(workingDir),
		filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath()),
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return usageError("refusing to overwrite existing %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func registerBootstrapDID(
	ctx context.Context,
	registry *awid.RegistryClient,
	didKey, stableID string,
	signingKey ed25519.PrivateKey,
) error {
	if registry == nil {
		return fmt.Errorf("nil registry client")
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		_, err := registry.RegisterIdentity(ctx, registry.DefaultRegistryURL, didKey, stableID, signingKey)
		if already := new(awid.AlreadyRegisteredError); errors.As(err, &already) {
			if strings.TrimSpace(already.ExistingDIDKey) == didKey {
				return nil
			}
		}
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("failed to register did:aw before redeeming the bootstrap token: %w", lastErr)
}

func validateBootstrapRedeemResponse(
	resp *awid.BootstrapRedeemResponse,
	didKey, stableID, address string,
) (*awid.TeamCertificate, error) {
	if resp == nil {
		return nil, fmt.Errorf("missing bootstrap redeem response")
	}
	cert, err := awid.DecodeTeamCertificateHeader(strings.TrimSpace(resp.Certificate))
	if err != nil {
		return nil, fmt.Errorf("decode bootstrap certificate: %w", err)
	}
	if cert.MemberDIDKey != didKey {
		return nil, fmt.Errorf("bootstrap certificate member_did_key %q does not match generated did:key %q", cert.MemberDIDKey, didKey)
	}

	switch strings.TrimSpace(resp.Lifetime) {
	case awid.LifetimePersistent:
		if strings.TrimSpace(stableID) == "" || strings.TrimSpace(address) == "" {
			return nil, fmt.Errorf("persistent bootstrap redeem requires a did:aw and address")
		}
		if strings.TrimSpace(resp.DIDAW) != stableID {
			return nil, fmt.Errorf("bootstrap redeem returned did_aw %q, expected %q", resp.DIDAW, stableID)
		}
		if strings.TrimSpace(resp.MemberAddress) != strings.TrimSpace(address) {
			return nil, fmt.Errorf("bootstrap redeem returned member_address %q, expected %q", resp.MemberAddress, address)
		}
		if cert.MemberDIDAW != stableID {
			return nil, fmt.Errorf("bootstrap certificate member_did_aw %q does not match %q", cert.MemberDIDAW, stableID)
		}
		if cert.MemberAddress != strings.TrimSpace(address) {
			return nil, fmt.Errorf("bootstrap certificate member_address %q does not match %q", cert.MemberAddress, address)
		}
	case awid.LifetimeEphemeral:
		if strings.TrimSpace(address) != "" {
			return nil, fmt.Errorf("dashboard minted an ephemeral bootstrap token; re-run the exact command without --address")
		}
		if strings.TrimSpace(resp.DIDAW) != "" || strings.TrimSpace(resp.MemberAddress) != "" {
			return nil, fmt.Errorf("ephemeral bootstrap redeem unexpectedly returned persistent identity fields")
		}
		if strings.TrimSpace(cert.MemberDIDAW) != "" || strings.TrimSpace(cert.MemberAddress) != "" {
			return nil, fmt.Errorf("ephemeral bootstrap certificate unexpectedly contains persistent identity fields")
		}
	default:
		return nil, fmt.Errorf("unsupported bootstrap lifetime %q", resp.Lifetime)
	}

	return cert, nil
}

func persistBootstrapConnectState(
	workingDir string,
	signingKey ed25519.PrivateKey,
	cert *awid.TeamCertificate,
	resp *awid.BootstrapRedeemResponse,
	didKey, stableID, address, registryURL string,
) error {
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if err := awid.SaveSigningKey(signingKeyPath, signingKey); err != nil {
		return err
	}

	if _, err := awconfig.SaveTeamCertificateForTeam(workingDir, cert.Team, cert); err != nil {
		return err
	}

	if strings.TrimSpace(resp.Lifetime) != awid.LifetimePersistent {
		return nil
	}

	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	return awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{
		DID:            didKey,
		StableID:       stableID,
		Address:        strings.TrimSpace(address),
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    strings.TrimSpace(registryURL),
		RegistryStatus: "registered",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	})
}

func mapBootstrapRedeemError(err error) error {
	status, ok := awid.HTTPStatusCode(err)
	if !ok {
		return err
	}
	body := strings.ToLower(strings.TrimSpace(claimHumanServerMessage(err)))

	switch status {
	case 400:
		if strings.Contains(body, "did_aw") || strings.Contains(body, "address") || strings.Contains(body, "persistent") {
			return fmt.Errorf("The address does not match what was minted. Copy the exact command from the dashboard.")
		}
		return err
	case 409:
		if strings.Contains(body, "did:aw") || strings.Contains(body, "mismatch") || strings.Contains(body, "address") {
			return fmt.Errorf("The address does not match what was minted. Copy the exact command from the dashboard.")
		}
		return fmt.Errorf("Token expired or already used. Mint a fresh one from the dashboard.")
	case 500:
		return fmt.Errorf("The token was consumed but something failed downstream. Mint a fresh token and try again.")
	default:
		return err
	}
}
