package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type hostedInitOutput struct {
	Status          string `json:"status"`
	Username        string `json:"username"`
	Alias           string `json:"alias"`
	DIDKey          string `json:"did_key"`
	DIDAW           string `json:"did_aw"`
	NamespaceDomain string `json:"namespace_domain"`
	TeamAddress     string `json:"team_address"`
	MemberAddress   string `json:"member_address"`
	Certificate     string `json:"certificate"`
}

func runHostedInit(cmd *cobra.Command) error {
	if !initHosted {
		return usageError("--username and --awid-url require --hosted")
	}
	username := strings.TrimSpace(initHostedUsername)
	if username == "" {
		return usageError("missing required flag: --username")
	}
	alias := strings.TrimSpace(initAlias)
	if alias == "" {
		return usageError("missing required flag: --alias")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := ensureConnectTargetClean(workingDir); err != nil {
		return err
	}

	serviceURLs, err := resolveOnboardingServiceURLs(initCloudURL)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	checkResp, err := awid.CheckUsername(ctx, serviceURLs.CloudURL, username)
	if err != nil {
		return err
	}
	if checkResp != nil && !checkResp.Available {
		reason := strings.TrimSpace(checkResp.Reason)
		if reason == "" {
			reason = "unavailable"
		}
		return usageError("username %q is not available (%s)", username, reason)
	}

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	didKey := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	memberAddress := fmt.Sprintf("%s.aweb.ai/%s", username, alias)

	registry, err := newConfiguredRegistryClient(nil, serviceURLs.CloudURL)
	if err != nil {
		return err
	}
	overrideAWIDURL := strings.TrimSpace(initHostedAWIDURL)
	registryURL := strings.TrimSpace(serviceURLs.AwidURL)
	if overrideAWIDURL != "" {
		registryURL = overrideAWIDURL
	}
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			if overrideAWIDURL != "" {
				return fmt.Errorf("invalid --awid-url: %w", err)
			}
			return fmt.Errorf("invalid discovered awid url: %w", err)
		}
	}
	if _, err := registry.RegisterDID(
		ctx,
		registry.DefaultRegistryURL,
		"",
		memberAddress,
		alias,
		didKey,
		stableID,
		signingKey,
	); err != nil {
		return fmt.Errorf("failed to register hosted did:aw before cli-signup: %w", err)
	}

	resp, err := awid.CliSignup(ctx, serviceURLs.CloudURL, &awid.CliSignupRequest{
		Username: username,
		DIDKey:   didKey,
		DIDAW:    stableID,
		Alias:    alias,
	}, signingKey)
	if err != nil {
		return err
	}
	if err := persistHostedInitState(workingDir, registry.DefaultRegistryURL, signingKey, didKey, stableID, resp); err != nil {
		return err
	}

	out := hostedInitOutput{
		Status:          "signed_up",
		Username:        strings.TrimSpace(resp.Username),
		Alias:           alias,
		DIDKey:          didKey,
		DIDAW:           stableID,
		NamespaceDomain: strings.TrimSpace(resp.NamespaceDomain),
		TeamAddress:     strings.TrimSpace(resp.TeamAddress),
		MemberAddress:   strings.TrimSpace(resp.MemberAddress),
		Certificate:     strings.TrimSpace(resp.Certificate),
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Hosted init complete for %s.\n", out.MemberAddress)
	return err
}

func persistHostedInitState(
	workingDir, registryURL string,
	signingKey []byte,
	didKey, stableID string,
	resp *awid.CliSignupResponse,
) error {
	if resp == nil {
		return fmt.Errorf("missing cli-signup response")
	}

	cert, err := awid.DecodeTeamCertificateHeader(strings.TrimSpace(resp.Certificate))
	if err != nil {
		return fmt.Errorf("decode cli-signup certificate: %w", err)
	}
	if cert.MemberDIDKey != didKey {
		return fmt.Errorf("cli-signup certificate member_did_key %q does not match generated did:key %q", cert.MemberDIDKey, didKey)
	}
	if cert.MemberDIDAW != stableID {
		return fmt.Errorf("cli-signup certificate member_did_aw %q does not match generated did:aw %q", cert.MemberDIDAW, stableID)
	}
	if strings.TrimSpace(resp.MemberAddress) == "" {
		return fmt.Errorf("cli-signup response missing member_address")
	}
	if cert.MemberAddress != strings.TrimSpace(resp.MemberAddress) {
		return fmt.Errorf("cli-signup certificate member_address %q does not match response %q", cert.MemberAddress, resp.MemberAddress)
	}

	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), signingKey); err != nil {
		return err
	}
	if err := awid.SaveTeamCertificate(filepath.Join(workingDir, ".aw", "team-cert.pem"), cert); err != nil {
		return err
	}
	return awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:            didKey,
		StableID:       stableID,
		Address:        strings.TrimSpace(resp.MemberAddress),
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    strings.TrimSpace(registryURL),
		RegistryStatus: "registered",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	})
}
