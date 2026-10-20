package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
	"strings"
	"time"
)

var renewCertsTeam, renewCertsNamespace, renewCertsRegistry string
var teamRenewCertsCmd = &cobra.Command{
	Use: "renew-certs", Short: "Controller: safely renew certificates due under the team's lifetime policy",
	Long: "Reissue due memberships from verified old certificates, using atomic AWID rollover.\n" +
		"Finite policies renew in the final third, or when the old certificate has no expiry or exceeds the limit.\n" +
		"Removing a limit replaces finite certificates with certificates without expiry. Revoked members are excluded.\n" +
		"Requires the team's controller key; a member or session grant cannot renew membership.\n" +
		"Certificate v2 issuance remains gated at the registry until verifier adoption is measured.",
	Args: cobra.NoArgs, RunE: runTeamRenewCerts,
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
	controllerDID := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	policy, err := registry.GetTeamCredentialPolicy(cmd.Context(), registryURL, domain, name, controllerDID)
	if err != nil {
		return fmt.Errorf("read current team lifetime policy: %w", err)
	}
	if policy != nil && policy["team_did_key"] != controllerDID {
		return fmt.Errorf("policy is not signed by this team's controller")
	}
	certs, err := registry.ListCertificatesWithLifetimes(cmd.Context(), registryURL, domain, name, false, key)
	if err != nil {
		return err
	}
	renewed := []string{}
	failed := []map[string]string{}
	for _, listed := range certs {
		// Renewal includes expired artifacts, while the active roster excludes them.
		if listed.RevokedAt != "" {
			continue
		}
		alias, didRenew, renewalErr := func() (string, bool, error) {
			// The listing supplies locators only. Membership comes exclusively from an
			// artifact authenticated under the controller's own public key.
			old, err := registry.FetchTeamCertificateForRenewal(cmd.Context(), registryURL, domain, name, listed.CertificateID, key)
			if err != nil {
				return "", false, err
			}
			if old.CertificateID != listed.CertificateID || old.Team != awid.BuildTeamID(domain, name) || old.TeamDIDKey != controllerDID {
				return "", false, fmt.Errorf("old certificate binding mismatch")
			}
			if err := awid.VerifyTeamCertificateSignature(old, key.Public().(ed25519.PublicKey)); err != nil {
				return "", false, err
			}
			class := old.ValidityClass
			if old.Version == 1 {
				class = "member"
			}
			field := "member_certificate"
			if class == "ephemeral" {
				field = "ephemeral_certificate"
			} else if class != "member" {
				return old.Alias, false, fmt.Errorf("invalid stored certificate validity class")
			}
			var maximum int64
			if policy != nil && policy[field] != nil {
				maximum = int64(policy[field].(float64))
			}
			metadata := awid.RegistryCertificate{CertificateID: old.CertificateID, IssuedAt: old.IssuedAt, ExpiresAt: old.ExpiresAt}
			if !certificateRenewalDue(metadata, maximum, time.Now()) {
				return old.Alias, false, nil
			}
			expiry := ""
			if maximum > 0 {
				expiry = time.Now().UTC().Truncate(time.Second).Add(time.Duration(maximum) * time.Second).Format(time.RFC3339)
			}
			fresh, err := awid.SignTeamCertificate(key, awid.TeamCertificateFields{Team: old.Team, MemberDIDKey: old.MemberDIDKey, MemberDIDAW: old.MemberDIDAW, MemberAddress: old.MemberAddress, Alias: old.Alias, IdentityScope: old.IdentityScope, Version: 2, ValidityClass: class, ExpiresAt: expiry})
			if err != nil {
				return old.Alias, false, err
			}
			if err := registry.RolloverCertificate(cmd.Context(), registryURL, domain, name, old.CertificateID, fresh, key); err != nil {
				return old.Alias, false, err
			}
			return old.Alias, true, nil
		}()
		if renewalErr != nil {
			failed = append(failed, map[string]string{"certificate_id": listed.CertificateID, "error": renewalErr.Error()})
			continue
		}
		if didRenew {
			renewed = append(renewed, alias)
		}
	}
	if jsonFlag {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"team_id": awid.BuildTeamID(domain, name), "renewed": renewed, "failed": failed}); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Renewed %d certificates for %s; %d failed\n", len(renewed), awid.BuildTeamID(domain, name), len(failed))
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d certificate renewals failed", len(failed))
	}
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
