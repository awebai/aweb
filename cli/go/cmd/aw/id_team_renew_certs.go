package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var renewCertsTeam, renewCertsNamespace, renewCertsRegistry string

var teamRenewCertsCmd = &cobra.Command{
	Use:   "renew-certs",
	Short: "Controller: safely renew certificates due under the team's lifetime policy",
	Long: "Reissue due memberships with the same key, alias, identity and address, using atomic AWID rollover.\n" +
		"Finite policies renew in the final third, or when the old certificate has no expiry or exceeds the limit.\n" +
		"Removing a limit replaces finite certificates with certificates without expiry. Revoked members are excluded.\n" +
		"Requires the team's controller key; a member or session grant cannot renew membership.\n" +
		"Certificate v2 issuance remains gated at the registry until verifier adoption is measured.",
	Args: cobra.NoArgs,
	RunE: runTeamRenewCerts,
}

func init() {
	teamRenewCertsCmd.Flags().StringVar(&renewCertsTeam, "team", "", "Team name")
	teamRenewCertsCmd.Flags().StringVar(&renewCertsNamespace, "namespace", "", "Namespace domain")
	teamRenewCertsCmd.Flags().StringVar(&renewCertsRegistry, "registry", "", "AWID registry origin")
	teamCmd.AddCommand(teamRenewCertsCmd)
}

func runTeamRenewCerts(cmd *cobra.Command, args []string) error {
	domain, name := strings.TrimSpace(renewCertsNamespace), strings.TrimSpace(renewCertsTeam)
	if domain == "" || name == "" {
		return usageError("--team and --namespace are required")
	}
	key, err := loadReissueCertController(domain, name)
	if err != nil {
		return err
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := strings.TrimSpace(renewCertsRegistry)
	if registryURL == "" {
		if meta, err := awconfig.LoadControllerMeta(domain); err == nil && meta != nil {
			registryURL = meta.RegistryURL
		}
	}
	if registryURL == "" {
		registryURL = registry.DefaultRegistryURL
	}
	if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
		return err
	}
	policy, err := registry.GetTeamCredentialPolicy(cmd.Context(), registryURL, domain, name)
	if err != nil {
		return fmt.Errorf("read current team lifetime policy: %w", err)
	}
	certs, err := registry.ListCertificatesWithLifetimes(cmd.Context(), registryURL, domain, name, true, key)
	if err != nil {
		return err
	}
	renewed := []string{}
	for _, old := range certs {
		if old.RevokedAt != "" {
			continue
		}
		class := old.ValidityClass
		if class == "" {
			class = "member"
		}
		field := "member_certificate"
		if class == "ephemeral" {
			field = "ephemeral_certificate"
		} else if class != "member" {
			return fmt.Errorf("invalid stored certificate validity class")
		}
		var maximum int64
		if policy != nil && policy[field] != nil {
			maximum = int64(policy[field].(float64))
		}
		if !certificateRenewalDue(old, maximum, time.Now()) {
			continue
		}
		expiry := ""
		if maximum > 0 {
			expiry = time.Now().UTC().Truncate(time.Second).Add(time.Duration(maximum) * time.Second).Format(time.RFC3339)
		}
		fresh, err := awid.SignTeamCertificate(key, awid.TeamCertificateFields{
			Team: awid.BuildTeamID(domain, name), MemberDIDKey: old.MemberDIDKey, MemberDIDAW: old.MemberDIDAW,
			MemberAddress: old.MemberAddress, Alias: old.Alias, IdentityScope: old.IdentityScope, Version: 2, ValidityClass: class, ExpiresAt: expiry,
		})
		if err != nil {
			return err
		}
		if err := registry.RolloverCertificate(cmd.Context(), registryURL, domain, name, old.CertificateID, fresh, key); err != nil {
			return fmt.Errorf("renew %s: %w", old.Alias, err)
		}
		renewed = append(renewed, old.Alias)
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"team_id": awid.BuildTeamID(domain, name), "renewed": renewed})
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Renewed %d certificates for %s\n", len(renewed), awid.BuildTeamID(domain, name))
	return nil
}

func certificateRenewalDue(cert awid.RegistryCertificate, maximum int64, now time.Time) bool {
	if cert.ExpiresAt == "" {
		return maximum > 0
	}
	if maximum == 0 {
		return true
	}
	issued, issueErr := time.Parse(time.RFC3339Nano, cert.IssuedAt)
	expires, expiryErr := time.Parse(time.RFC3339Nano, cert.ExpiresAt)
	if issueErr != nil || expiryErr != nil || !expires.After(issued) {
		return true
	}
	return expires.Sub(issued) > time.Duration(maximum)*time.Second || !now.Before(expires.Add(-expires.Sub(issued)/3))
}
